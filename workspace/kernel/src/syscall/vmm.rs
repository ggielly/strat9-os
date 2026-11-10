/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! s9vm — handlers for the `SYS_VMM_*` syscalls (ABI block 560–589).
//!
//! P0 scope: management of the world registry (`CREATE`, `DESTROY`,
//! `INFO`) and the execution surface driven by the injected exits. The
//! appended P1 calls `LIST` (584) and `STATS` (585) expose the world registry
//! and the cumulative engine counters without growing `VmmInfo`; `LOAD_IMAGE`
//! (586) and `ACPI` (587) prepare a guest, and the per-vCPU introspection pair
//! `VCPU_LIST` (588) / `VCPU_REGS` (589) publishes the vCPU snapshot and
//! register block.
//! The calls that depend on guest execution (`MAP_MEM`, `SET_REGS`, `RUN`,
//! `INJECT_IRQ`, `EXIT_HANDLER`, `IRQ_WAIT`) are implemented by the vCPU
//! layer; their ABI is frozen.
//!
//! Access control: `CREATE` requires silo administration; the other calls
//! take a **capability handle** returned by `CREATE`
//! (`ResourceType::Vmm`) or `CREATE_VCPU` (`ResourceType::Vcpu`). The handle
//! is opaque to user space; internal identifiers are never accepted
//! directly.

use super::error::SyscallError;
use crate::{
    capability::{get_capability_manager, CapId, CapPermissions, ResourceType},
    memory::{UserSliceRead, UserSliceWrite},
    process::current_task_clone,
    s9vm,
    s9vm::{
        memmap::MapError,
        vm::{self, VmError},
    },
    silo,
};
use alloc::vec;
use strat9_abi::vmm::{
    state, vcpu_flags, VmmImageInfo, VmmInfo, VmmRegs, VmmVcpuInfo, VmmWorldEntry, VmmWorldStats,
    VMM_ABI_VERSION, VMM_LIST_MAX, VMM_NAME_MAX, VMM_VCPU_LIST_MAX,
};

/// Maximum size of a structure read from user space.
const MAX_STRUCT: usize = 192;

/// Maximum size of a guest image accepted by `SYS_VMM_LOAD_IMAGE`.
///
/// The bytes are copied into a temporary kernel buffer before the loader parses
/// them, so this bound also protects kernel memory.
const MAX_IMAGE_BYTES: u64 = 16 * 1024 * 1024;

/// Maximum number of entries written by one `SYS_VMM_LIST` call.
///
/// Mirrors [`VMM_LIST_MAX`] and the kernel world bound; clamping here keeps a
/// single syscall bounded even if the caller passes a huge capacity.
const MAX_LIST_ENTRIES: usize = VMM_LIST_MAX;

/// Maximum number of entries written by one `SYS_VMM_VCPU_LIST` call.
///
/// Mirrors [`VMM_VCPU_LIST_MAX`] and the kernel per-world vCPU bound; clamping
/// here keeps a single syscall bounded even if the caller passes a huge
/// capacity.
const MAX_VCPU_LIST_ENTRIES: usize = VMM_VCPU_LIST_MAX;

// The ABI bound must mirror the engine bound: reporting more would need more
// entries than a world can ever hold, and reporting fewer would truncate a
// per-world listing.
const _: () = assert!(VMM_VCPU_LIST_MAX == vm::MAX_VCPUS_PER_WORLD);

/// Rights of a world creator: read, write, revoke.
const VMM_OWNER: CapPermissions = CapPermissions {
    read: true,
    write: true,
    execute: false,
    grant: false,
    revoke: true,
};

/// Rights of a vCPU: read, write, execute (`RUN`).
const VCPU_OWNER: CapPermissions = CapPermissions {
    read: true,
    write: true,
    execute: true,
    grant: false,
    revoke: true,
};

/// `CREATE` remains a silo administration operation: creating a world is
/// not covered by an existing capability.
fn require_control() -> Result<(), SyscallError> {
    silo::require_silo_admin()
}

/// Installs a capability in the current task and returns its handle.
fn install_handle(
    resource_type: ResourceType,
    resource: u64,
    permissions: CapPermissions,
) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let capability =
        get_capability_manager().create_capability(resource_type, resource as usize, permissions);
    // SAFETY: the task's capability table is protected by the
    // `CapabilityTable` API; the pattern is identical to the other kernel
    // handle creations.
    let id = unsafe { (&mut *task.process.capabilities.get()).insert(capability) };
    Ok(id.as_u64())
}

/// Resolves a capability handle to an internal resource identifier.
fn resolve_handle(
    handle: u64,
    expected: ResourceType,
    required: CapPermissions,
) -> Result<u64, SyscallError> {
    if handle == 0 {
        return Err(SyscallError::InvalidArgument);
    }
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    // SAFETY: read under the protection of `CapabilityTable`.
    let capabilities = unsafe { &*task.process.capabilities.get() };
    let capability = capabilities
        .get_with_permissions(CapId::from_raw(handle), required)
        .ok_or(SyscallError::PermissionDenied)?;
    if capability.resource_type != expected {
        return Err(SyscallError::BadHandle);
    }
    Ok(capability.resource as u64)
}

/// Revokes a handle (removes the capability from the task and from the
/// global registry).
fn revoke_handle(handle: u64) {
    let Some(task) = current_task_clone() else {
        return;
    };
    // SAFETY: mutation under the protection of `CapabilityTable`.
    let mut capabilities = unsafe { &mut *task.process.capabilities.get() };
    let _ = capabilities.remove(CapId::from_raw(handle));
}

/// Resolves a world handle (`ResourceType::Vmm`).
fn vmm_world(handle: u64, required: CapPermissions) -> Result<u64, SyscallError> {
    resolve_handle(handle, ResourceType::Vmm, required)
}

/// Resolves a vCPU handle (`ResourceType::Vcpu`).
fn vcpu_target(handle: u64, required: CapPermissions) -> Result<u64, SyscallError> {
    resolve_handle(handle, ResourceType::Vcpu, required)
}

fn read_struct<T: Copy>(ptr: u64) -> Result<T, SyscallError> {
    if ptr == 0 {
        return Err(SyscallError::Fault);
    }
    let size = core::mem::size_of::<T>();
    let mut raw = [0u8; MAX_STRUCT];
    if size == 0 || size > raw.len() {
        return Err(SyscallError::InvalidArgument);
    }
    let slice = UserSliceRead::new(ptr, size)?;
    if slice.copy_to(&mut raw[..size]) != size {
        return Err(SyscallError::Fault);
    }
    // SAFETY: `raw[..size]` is fully initialized and `T: Copy`.
    Ok(unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const T) })
}

fn write_struct<T: Copy>(ptr: u64, value: &T) -> Result<(), SyscallError> {
    if ptr == 0 {
        return Err(SyscallError::Fault);
    }
    let size = core::mem::size_of::<T>();
    let slice = UserSliceWrite::new(ptr, size)?;
    // SAFETY: read of `size` bytes from a valid reference.
    let bytes = unsafe { core::slice::from_raw_parts(value as *const T as *const u8, size) };
    slice.copy_from(bytes);
    Ok(())
}

/// SYS_VMM_CREATE (560): creates a virtual world.
pub fn sys_vmm_create(name_ptr: u64, name_len: u64, silo_id: u64) -> Result<u64, SyscallError> {
    require_control()?;
    if !s9vm::detected() {
        return Err(SyscallError::NotSupported);
    }
    if name_len == 0 || name_len > vm::NAME_MAX as u64 {
        return Err(SyscallError::InvalidArgument);
    }
    if silo_id > u32::MAX as u64 {
        return Err(SyscallError::InvalidArgument);
    }
    let mut name = [0u8; vm::NAME_MAX];
    let slice = UserSliceRead::new(name_ptr, name_len as usize)?;
    if slice.copy_to(&mut name[..name_len as usize]) != name_len as usize {
        return Err(SyscallError::Fault);
    }
    let record =
        vm::create(&name[..name_len as usize], silo_id as u32).ok_or(SyscallError::OutOfMemory)?;
    match install_handle(ResourceType::Vmm, record.id, VMM_OWNER) {
        Ok(handle) => Ok(handle),
        Err(error) => {
            let _ = vm::destroy(record.id);
            Err(error)
        }
    }
}

/// SYS_VMM_DESTROY (561): destroys a world.
pub fn sys_vmm_destroy(vmm_handle: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        revoke: true,
        ..VMM_OWNER
    };
    let world = vmm_world(vmm_handle, required)?;
    vm::destroy(world).ok_or(SyscallError::NotFound)?;
    revoke_handle(vmm_handle);
    Ok(0)
}

/// SYS_VMM_MAP_MEM (562): maps guest RAM into a world.
///
/// `perms`: bits 1 = read, 2 = write, 4 = execute (0 = read).
/// `memtype`: 0 = write-back (the only type supported for now).
pub fn sys_vmm_map_mem(
    vmm_id: u64,
    gpa: u64,
    len: u64,
    perms: u64,
    memtype: u64,
) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        write: true,
        ..CapPermissions::none()
    };
    let world = vmm_world(vmm_id, required)?;
    let caps = s9vm::detect().ok_or(SyscallError::NotSupported)?;
    if perms > 0b111 || memtype > 6 {
        return Err(SyscallError::InvalidArgument);
    }
    if memtype != 0 && memtype != 6 {
        return Err(SyscallError::NotSupported);
    }
    vm::map_memory(world, &caps, gpa, len, perms as u32, memtype as u8).map_err(map_vm_error)
}

/// SYS_VMM_SET_REGS (563): writes a vCPU's register block.
pub fn sys_vmm_set_regs(vcpu_handle: u64, regs_ptr: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        write: true,
        ..CapPermissions::none()
    };
    let vcpu = vcpu_target(vcpu_handle, required)?;
    let regs: VmmRegs = read_struct(regs_ptr)?;
    vm::set_vcpu_regs(vcpu, &regs).map_err(map_vcpu_error)?;
    Ok(0)
}

/// SYS_VMM_GET_REGS (564): reads a vCPU's register block.
pub fn sys_vmm_get_regs(vcpu_handle: u64, regs_ptr: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        read: true,
        ..CapPermissions::none()
    };
    let vcpu = vcpu_target(vcpu_handle, required)?;
    let regs = vm::get_vcpu_regs(vcpu).ok_or(SyscallError::NotFound)?;
    write_struct(regs_ptr, &regs)?;
    Ok(0)
}

/// SYS_VMM_CREATE_VCPU (570): creates a logical vCPU in a world.
pub fn sys_vmm_create_vcpu(vmm_handle: u64, apic_id: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        write: true,
        ..CapPermissions::none()
    };
    let world = vmm_world(vmm_handle, required)?;
    if apic_id > u32::MAX as u64 {
        return Err(SyscallError::InvalidArgument);
    }
    let vcpu = vm::create_vcpu(world, apic_id as u32).map_err(map_vcpu_error)?;
    match install_handle(ResourceType::Vcpu, vcpu, VCPU_OWNER) {
        Ok(handle) => Ok(handle),
        Err(error) => {
            let _ = vm::destroy_vcpu(vcpu);
            Err(error)
        }
    }
}

/// SYS_VMM_DESTROY_VCPU (571): destroys a logical vCPU.
pub fn sys_vmm_destroy_vcpu(vcpu_handle: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        revoke: true,
        ..VCPU_OWNER
    };
    let vcpu = vcpu_target(vcpu_handle, required)?;
    if !vm::destroy_vcpu(vcpu) {
        return Err(SyscallError::NotFound);
    }
    revoke_handle(vcpu_handle);
    Ok(0)
}

/// SYS_VMM_RUN (565): runs a vCPU until the next "policy" exit and pushes
/// the event onto the world's queue.
pub fn sys_vmm_run(vcpu_handle: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        execute: true,
        write: true,
        ..CapPermissions::none()
    };
    let vcpu = vcpu_target(vcpu_handle, required)?;
    // `RUN` is blocking: the vCPU's kernel task runs the guest until the
    // next policy exit, then the caller resumes.
    vm::request_run(vcpu).map_err(map_run_error)?;
    Ok(0)
}

/// SYS_VMM_INJECT_IRQ (566): schedules the injection of an external
/// interrupt into a vCPU; it will be delivered on the next guest entry.
///
/// `vector` must be a valid vector (0..=255). The injection is deferred:
/// the vector is stored in the vCPU and written to the control block on the
/// next `RUN`.
pub fn sys_vmm_inject_irq(vcpu_handle: u64, vector: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        write: true,
        ..CapPermissions::none()
    };
    let vcpu = vcpu_target(vcpu_handle, required)?;
    if vector > u8::MAX as u64 {
        return Err(SyscallError::InvalidArgument);
    }
    vm::inject_irq(vcpu, vector as u8).map_err(map_vcpu_error)?;
    Ok(0)
}

/// SYS_VMM_EXIT_HANDLER (567): pops an exit event.
///
/// Returns 1 if an event was written, 0 if the queue is empty.
pub fn sys_vmm_exit_handler(vmm_handle: u64, event_ptr: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        read: true,
        ..CapPermissions::none()
    };
    let world = vmm_world(vmm_handle, required)?;
    let event = match vm::pop_exit(world) {
        Ok(event) => event,
        Err(()) => return Ok(0),
    };
    write_struct(event_ptr, &event)?;
    Ok(1)
}

/// SYS_VMM_IRQ_WAIT (568): waits for a vCPU exit event.
///
/// Returns 1 if an event is available, 0 if `timeout_ns` expires first
/// (`timeout_ns = 0` tests immediately).
pub fn sys_vmm_irq_wait(vcpu_handle: u64, timeout_ns: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        read: true,
        ..CapPermissions::none()
    };
    let vcpu = vcpu_target(vcpu_handle, required)?;
    let ready = vm::wait_exit(vcpu, timeout_ns).map_err(map_vcpu_error)?;
    Ok(u64::from(ready))
}

/// SYS_VMM_PAUSE (575): pauses a world.
pub fn sys_vmm_pause(vmm_handle: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        write: true,
        ..CapPermissions::none()
    };
    let world = vmm_world(vmm_handle, required)?;
    vm::pause(world).map_err(map_vm_error)?;
    Ok(0)
}

/// SYS_VMM_RESUME (576): resumes a paused world.
pub fn sys_vmm_resume(vmm_handle: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        write: true,
        ..CapPermissions::none()
    };
    let world = vmm_world(vmm_handle, required)?;
    vm::resume(world).map_err(map_vm_error)?;
    Ok(0)
}

/// SYS_VMM_INJECT_NMI (578): schedules an NMI for the next `RUN`.
pub fn sys_vmm_inject_nmi(vcpu_handle: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        write: true,
        ..CapPermissions::none()
    };
    let vcpu = vcpu_target(vcpu_handle, required)?;
    vm::inject_nmi(vcpu).map_err(map_vcpu_error)?;
    Ok(0)
}

/// SYS_VMM_DEBUG_DUMP (579): logs an engine snapshot.
///
/// Serializes a summary of the worlds and their vCPUs to the kernel output
/// (serial / log), then returns 0. No data is copied to user space: this is a
/// diagnostic tool.
pub fn sys_vmm_debug_dump(_vmm_handle: u64) -> Result<u64, SyscallError> {
    require_control()?;
    crate::s9vm::vm::debug_dump();
    Ok(0)
}

/// SYS_VMM_EXIT_COMPLETE (580): completes an exit emulated by the policy.
///
/// `value` is written to the guest `RAX` and `advance` bytes are added to the
/// guest `RIP` (0 for I/O exits, instruction length for MMIO/EPT exits).
pub fn sys_vmm_exit_complete(
    vcpu_handle: u64,
    value: u64,
    advance: u64,
) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        write: true,
        ..CapPermissions::none()
    };
    let vcpu = vcpu_target(vcpu_handle, required)?;
    if advance > 15 {
        // Longest x86 instruction is 15 bytes.
        return Err(SyscallError::InvalidArgument);
    }
    vm::complete_exit(vcpu, value, advance).map_err(map_vcpu_error)?;
    Ok(0)
}

/// Maximum bytes transferred by one console syscall.
const MAX_CONSOLE_IO: u64 = 64 * 1024;

/// SYS_VMM_CONSOLE_INPUT (581): queues bytes for the guest console.
pub fn sys_vmm_console_input(
    vmm_handle: u64,
    buf_ptr: u64,
    len: u64,
) -> Result<u64, SyscallError> {
    let world = vmm_world(vmm_handle, VMM_OWNER)?;
    if len == 0 || len > MAX_CONSOLE_IO || buf_ptr == 0 {
        return Err(SyscallError::InvalidArgument);
    }
    let mut bytes = alloc::vec![0u8; len as usize];
    let slice = UserSliceRead::new(buf_ptr, len as usize)?;
    if slice.copy_to(&mut bytes) != len as usize {
        return Err(SyscallError::Fault);
    }
    let queued = vm::push_console_input(world, &bytes).map_err(|_| SyscallError::NotFound)?;
    Ok(queued as u64)
}

/// SYS_VMM_CONSOLE_OUTPUT (582): drains console output bytes.
pub fn sys_vmm_console_output(
    vmm_handle: u64,
    buf_ptr: u64,
    len: u64,
) -> Result<u64, SyscallError> {
    let world = vmm_world(vmm_handle, VMM_OWNER)?;
    if len == 0 || len > MAX_CONSOLE_IO || buf_ptr == 0 {
        return Err(SyscallError::InvalidArgument);
    }
    let mut bytes = alloc::vec![0u8; len as usize];
    let count = vm::read_console_output(world, &mut bytes).map_err(|_| SyscallError::NotFound)?;
    if count > 0 {
        let slice = UserSliceWrite::new(buf_ptr, count)?;
        slice.copy_from(&bytes[..count]);
    }
    Ok(count as u64)
}

/// SYS_VMM_BOOT_INFO (583): writes the guest boot-information page.
pub fn sys_vmm_boot_info(vmm_handle: u64, gpa: u64) -> Result<u64, SyscallError> {
    let world = vmm_world(vmm_handle, VMM_OWNER)?;
    vm::write_boot_info(world, gpa).map_err(|error| match error {
        vm::VmError::Unknown => SyscallError::NotFound,
        _ => SyscallError::InvalidArgument,
    })?;
    Ok(0)
}

/// Resolves the scope of a `SYS_VMM_LIST` call.
///
/// Returns `None` for a silo-administrator global listing (`handle == 0`),
/// or `Some(silo_id)` when the caller holds a VMM capability: the listing is
/// then restricted to the worlds owned by that world's silo. This keeps the
/// call capability-gated while allowing a supervisor to enumerate its own
/// worlds without knowing their opaque identifiers.
fn list_scope(vmm_handle: u64) -> Result<Option<u32>, SyscallError> {
    if vmm_handle == 0 {
        require_control()?;
        return Ok(None);
    }
    let required = CapPermissions {
        read: true,
        ..CapPermissions::none()
    };
    let world = vmm_world(vmm_handle, required)?;
    let record = vm::get(world).ok_or(SyscallError::NotFound)?;
    Ok(Some(record.silo_id))
}

/// SYS_VMM_LIST (584): enumerates worlds into a caller buffer.
///
/// Returns the total number of matching worlds. At most `capacity` entries
/// are written, clamped to [`MAX_LIST_ENTRIES`]; the buffer range is
/// overflow-checked before any copy. `capacity == 0` is a count query and
/// accepts a null buffer.
pub fn sys_vmm_list(vmm_handle: u64, entries_ptr: u64, capacity: u64) -> Result<u64, SyscallError> {
    let scope = list_scope(vmm_handle)?;

    let worlds: alloc::vec::Vec<vm::WorldRecord> = {
        let all = vm::list();
        match scope {
            None => all,
            Some(silo_id) => all
                .into_iter()
                .filter(|record| record.silo_id == silo_id)
                .collect(),
        }
    };
    let total = worlds.len();

    if capacity == 0 {
        // Count query: no buffer required, nothing is written.
        return Ok(total as u64);
    }
    if entries_ptr == 0 {
        return Err(SyscallError::Fault);
    }

    let requested = core::cmp::min(capacity, MAX_LIST_ENTRIES as u64) as usize;
    let to_write = core::cmp::min(requested, total);
    let entry_size = core::mem::size_of::<VmmWorldEntry>() as u64;

    for (index, record) in worlds.iter().take(to_write).enumerate() {
        // Bounded and overflow-checked: `index < MAX_LIST_ENTRIES` and
        // `entry_size` is a small constant, but the base pointer is fully
        // user-controlled.
        let offset = (index as u64)
            .checked_mul(entry_size)
            .and_then(|delta| entries_ptr.checked_add(delta))
            .ok_or(SyscallError::InvalidArgument)?;

        let mut entry = VmmWorldEntry {
            abi_version: VMM_ABI_VERSION,
            state: record.state,
            vmm_id: record.id,
            silo_id: record.silo_id,
            vcpu_count: record.vcpu_count,
            mapped_pages: record.mapped_pages,
            ..VmmWorldEntry::default()
        };
        let length = record.name_slice().len().min(VMM_NAME_MAX);
        entry.name[..length].copy_from_slice(&record.name_slice()[..length]);
        entry.name_len = length as u32;
        write_struct(offset, &entry)?;
    }

    Ok(total as u64)
}

/// SYS_VMM_STATS (585): writes the cumulative counters of a world.
///
/// The capability check is the same as `INFO`: read access on the world
/// handle. `exits_pending` is sampled atomically with respect to the event
/// queue lock; the other counters are diagnostics and may be slightly stale.
pub fn sys_vmm_stats(vmm_handle: u64, out_ptr: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        read: true,
        ..CapPermissions::none()
    };
    let world = vmm_world(vmm_handle, required)?;
    let record = vm::get(world).ok_or(SyscallError::NotFound)?;
    let stats = vm::stats(world).ok_or(SyscallError::NotFound)?;
    let exits_pending = vm::exit_count(world).ok_or(SyscallError::NotFound)?;
    let paused = if vm::is_paused(world) { 1 } else { 0 };

    let out = VmmWorldStats {
        abi_version: VMM_ABI_VERSION,
        paused,
        vmm_id: record.id,
        runs: stats.runs,
        policy_exits: stats.policy_exits,
        emulated_exits: stats.emulated_exits,
        emulated_io: stats.emulated_io,
        emulated_mmio: stats.emulated_mmio,
        emulated_msr: stats.emulated_msr,
        injected_interrupts: stats.injected_interrupts,
        windows_armed: stats.windows_armed,
        timer_exits: stats.timer_exits,
        exits_pending: exits_pending as u64,
    };
    write_struct(out_ptr, &out)?;
    Ok(0)
}

/// SYS_VMM_LOAD_IMAGE (586): loads an ELF64 guest image into a world.
///
/// The image bytes are copied out of the caller address space first, so a
/// malformed pointer is rejected before any guest page is mapped. On success
/// the relocated entry point and the loaded span are written to `out_ptr` as a
/// [`VmmImageInfo`]; the caller sets the vCPU registers from it.
pub fn sys_vmm_load_image(
    vmm_handle: u64,
    gpa: u64,
    image_ptr: u64,
    image_len: u64,
    out_ptr: u64,
) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        write: true,
        ..CapPermissions::none()
    };
    let world = vmm_world(vmm_handle, required)?;
    let caps = s9vm::detect().ok_or(SyscallError::NotSupported)?;
    if image_len == 0 || image_len > MAX_IMAGE_BYTES {
        return Err(SyscallError::InvalidArgument);
    }
    if out_ptr == 0 {
        return Err(SyscallError::Fault);
    }
    let slice = UserSliceRead::new(image_ptr, image_len as usize)?;
    let mut image = vec![0u8; image_len as usize];
    if slice.copy_to(&mut image) != image_len as usize {
        return Err(SyscallError::Fault);
    }
    let loaded = vm::load_image(world, &caps, &image, gpa).map_err(map_vm_error)?;
    let info = VmmImageInfo {
        abi_version: VMM_ABI_VERSION,
        entry: loaded.entry,
        image_base: loaded.image_base,
        span_min: loaded.span_min,
        span_max: loaded.span_max,
        ..VmmImageInfo::default()
    };
    write_struct(out_ptr, &info)?;
    Ok(0)
}

/// SYS_VMM_ACPI (587): writes the firmware description tables of a world.
///
/// The tables describe the world's vCPUs and the I/O APIC and are placed at
/// `gpa` (16-byte aligned, conventionally [`vm::ACPI_GPA`]). Returns 0.
pub fn sys_vmm_acpi(vmm_handle: u64, gpa: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        write: true,
        ..CapPermissions::none()
    };
    let world = vmm_world(vmm_handle, required)?;
    let caps = s9vm::detect().ok_or(SyscallError::NotSupported)?;
    vm::write_acpi(world, &caps, gpa).map_err(map_vm_error)?;
    Ok(0)
}

/// SYS_VMM_VCPU_LIST (588): enumerates the vCPUs of a world into a caller
/// buffer.
///
/// `handle == 0` lists every world and requires the silo administrator
/// capability; a non-zero handle restricts the listing to that world and
/// requires read access on the VMM capability. The [`VmmVcpuInfo`] entries are
/// built from [`vm::vcpu_snapshots`] before any user copy, so the engine lock
/// is never held while faulting user memory.
///
/// Returns the total number of matching vCPUs. At most `capacity` entries are
/// written, clamped to [`MAX_VCPU_LIST_ENTRIES`]; the buffer range is
/// overflow-checked before any copy. `capacity == 0` is a count query and
/// accepts a null buffer.
pub fn sys_vmm_vcpu_list(
    vmm_handle: u64,
    entries_ptr: u64,
    capacity: u64,
) -> Result<u64, SyscallError> {
    let (worlds, single) = if vmm_handle == 0 {
        require_control()?;
        (vm::list(), false)
    } else {
        let required = CapPermissions {
            read: true,
            ..CapPermissions::none()
        };
        let world = vmm_world(vmm_handle, required)?;
        let record = vm::get(world).ok_or(SyscallError::NotFound)?;
        (alloc::vec![record], true)
    };

    // Snapshot every vCPU first: the engine lock is released before the user
    // copy, which may fault.
    let mut snapshots: alloc::vec::Vec<(u64, vm::VcpuSnapshot)> = alloc::vec::Vec::new();
    for record in &worlds {
        let Some(vcpus) = vm::vcpu_snapshots(record.id) else {
            if single {
                return Err(SyscallError::NotFound);
            }
            // The world disappeared between the enumeration and the
            // snapshot: a global listing simply skips it.
            continue;
        };
        for vcpu in vcpus {
            snapshots.push((record.id, vcpu));
        }
    }
    let total = snapshots.len();

    if capacity == 0 {
        // Count query: no buffer required, nothing is written.
        return Ok(total as u64);
    }
    if entries_ptr == 0 {
        return Err(SyscallError::Fault);
    }

    let requested = core::cmp::min(capacity, MAX_VCPU_LIST_ENTRIES as u64) as usize;
    let to_write = core::cmp::min(requested, total);
    let entry_size = core::mem::size_of::<VmmVcpuInfo>() as u64;

    for (index, (vmm_id, snapshot)) in snapshots.iter().take(to_write).enumerate() {
        // Bounded and overflow-checked: `index < MAX_VCPU_LIST_ENTRIES` and
        // `entry_size` is a small constant, but the base pointer is fully
        // user-controlled.
        let offset = (index as u64)
            .checked_mul(entry_size)
            .and_then(|delta| entries_ptr.checked_add(delta))
            .ok_or(SyscallError::InvalidArgument)?;

        let mut flags = 0u32;
        if snapshot.hardware_ready {
            flags |= vcpu_flags::HARDWARE_READY;
        }
        if snapshot.executing {
            flags |= vcpu_flags::EXECUTING;
        }
        if snapshot.pending_nmi {
            flags |= vcpu_flags::PENDING_NMI;
        }
        let entry = VmmVcpuInfo {
            abi_version: VMM_ABI_VERSION,
            flags,
            vmm_id: *vmm_id,
            vcpu_id: snapshot.id,
            apic_id: snapshot.apic_id,
            reserved: 0,
        };
        write_struct(offset, &entry)?;
    }

    Ok(total as u64)
}

/// SYS_VMM_VCPU_REGS (589): reads a vCPU's live register block.
///
/// Shares the handle/capability path and the copy helper of
/// [`sys_vmm_get_regs`] (564) instead of duplicating them; the distinct call
/// number keeps the vCPU introspection pair (`VCPU_LIST` / `VCPU_REGS`)
/// append-only.
pub fn sys_vmm_vcpu_regs(vcpu_handle: u64, regs_ptr: u64) -> Result<u64, SyscallError> {
    sys_vmm_get_regs(vcpu_handle, regs_ptr)
}

/// SYS_VMM_INFO (569): snapshot of a world, or global summary if `vmm_id = 0`.
pub fn sys_vmm_info(vmm_handle: u64, out_ptr: u64) -> Result<u64, SyscallError> {
    let mut info = VmmInfo {
        abi_version: strat9_abi::vmm::VMM_ABI_VERSION,
        ..VmmInfo::default()
    };
    let vmm_id = if vmm_handle == 0 {
        require_control()?;
        0
    } else {
        let required = CapPermissions {
            read: true,
            ..CapPermissions::none()
        };
        vmm_world(vmm_handle, required)?
    };
    if vmm_id == 0 {
        // Global engine summary.
        info.state = if s9vm::detected() {
            state::RUNNING
        } else {
            state::STOPPED
        };
        info.vmm_id = 0;
        // The global summary aggregates every world: the vCPU count is the
        // number of vCPUs currently registered, not the number of worlds.
        let mut vcpus = 0u64;
        let mut pages = 0u64;
        for record in vm::list() {
            vcpus = vcpus.saturating_add(u64::from(record.vcpu_count));
            pages = pages.saturating_add(record.mapped_pages);
        }
        info.vcpu_count = vcpus.min(u64::from(u32::MAX)) as u32;
        info.mapped_pages = pages;
        let name = b"s9vm";
        info.name[..name.len()].copy_from_slice(name);
    } else {
        let record = vm::get(vmm_id).ok_or(SyscallError::NotFound)?;
        info.state = record.state;
        info.vmm_id = record.id;
        info.silo_id = record.silo_id;
        info.vcpu_count = record.vcpu_count;
        info.mapped_pages = record.mapped_pages;
        let length = record.name_slice().len();
        info.name[..length].copy_from_slice(record.name_slice());
    }
    write_struct(out_ptr, &info)?;
    Ok(0)
}

/// Builds a vector of worlds for the shell command (diagnostic).
pub fn list_worlds() -> alloc::vec::Vec<vm::WorldRecord> {
    vm::list()
}

/// Builds a `VmmInfo` for a world (diagnostic, without user copy).
pub fn world_info(vmm_id: u64) -> Option<VmmInfo> {
    let record = vm::get(vmm_id)?;
    let mut info = VmmInfo {
        abi_version: strat9_abi::vmm::VMM_ABI_VERSION,
        state: record.state,
        vmm_id: record.id,
        silo_id: record.silo_id,
        vcpu_count: record.vcpu_count,
        mapped_pages: record.mapped_pages,
        ..VmmInfo::default()
    };
    let length = record.name_slice().len();
    info.name[..length].copy_from_slice(record.name_slice());
    Some(info)
}

/// Marks a world as running (used by the selftest and the shell). Returns
/// `false` if the world is unknown.
pub fn mark_running(vmm_id: u64) -> bool {
    vm::set_state(vmm_id, state::RUNNING)
}

/// Marks a world as stopped.
pub fn mark_stopped(vmm_id: u64) -> bool {
    vm::set_state(vmm_id, state::STOPPED)
}
fn map_vm_error(error: VmError) -> SyscallError {
    match error {
        VmError::Unknown => SyscallError::NotFound,
        VmError::Map(MapError::InvalidRange) => SyscallError::InvalidArgument,
        VmError::Map(MapError::Overlap) => SyscallError::InvalidArgument,
        VmError::Map(MapError::QuotaExceeded) => SyscallError::OutOfMemory,
        VmError::Map(MapError::TooManyRegions) => SyscallError::OutOfMemory,
        VmError::Map(MapError::NotMapped) => SyscallError::NotFound,
        VmError::OutOfMemory => SyscallError::OutOfMemory,
        VmError::Translation(_) => SyscallError::NotSupported,
    }
}
fn map_vcpu_error(error: vm::VcpuRegistryError) -> SyscallError {
    match error {
        vm::VcpuRegistryError::WorldUnknown => SyscallError::NotFound,
        vm::VcpuRegistryError::Unknown => SyscallError::NotFound,
        vm::VcpuRegistryError::Limit => SyscallError::OutOfMemory,
        vm::VcpuRegistryError::BadAbiVersion => SyscallError::InvalidArgument,
        vm::VcpuRegistryError::Thread => SyscallError::OutOfMemory,
    }
}
fn map_run_error(error: vm::RunError) -> SyscallError {
    match error {
        vm::RunError::UnknownVcpu => SyscallError::NotFound,
        vm::RunError::NoMemory => SyscallError::Again,
        vm::RunError::InvalidGuestState => SyscallError::InvalidArgument,
        vm::RunError::HardwareNotReady => SyscallError::NotSupported,
        vm::RunError::Hardware(_) => SyscallError::IoError,
        vm::RunError::ExitStorm => SyscallError::Again,
        vm::RunError::Busy => SyscallError::Again,
        vm::RunError::Paused => SyscallError::Again,
    }
}
