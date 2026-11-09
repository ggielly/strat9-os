//! s9vm — handlers for the `SYS_VMM_*` syscalls (ABI block 560–569).
//!
//! P0 scope: management of the world registry (`CREATE`, `DESTROY`,
//! `INFO`). The calls that depend on guest execution (`MAP_MEM`,
//! `SET_REGS`, `RUN`, `INJECT_IRQ`, `EXIT_HANDLER`, `IRQ_WAIT`) returned
//! `ENOSYS`: their implementation will come with the vCPU layer exposed to
//! the user. The purpose of this step is to freeze the ABI and the routing
//! without exposing an incomplete surface.
//!
//! Access control: `CREATE` requires silo administration; the other calls
//! take a **capability handle** returned by `CREATE`
//! (`ResourceType::Vmm`) or `CREATE_VCPU` (`ResourceType::Vcpu`). The handle
//! is opaque to user space; internal identifiers are never accepted
//! directly.

use super::error::SyscallError;
use crate::capability::{
    get_capability_manager, CapId, CapPermissions, ResourceType,
};
use crate::memory::{UserSliceRead, UserSliceWrite};
use crate::process::current_task_clone;
use crate::s9vm::memmap::MapError;
use crate::s9vm::vm::{self, VmError};
use crate::s9vm;
use crate::silo;
use alloc::vec;
use strat9_abi::vmm::{state, VmmInfo, VmmRegs};

/// Maximum size of a structure read from user space.
const MAX_STRUCT: usize = 192;

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
    let capability = get_capability_manager().create_capability(
        resource_type,
        resource as usize,
        permissions,
    );
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
    let record = vm::create(&name[..name_len as usize], silo_id as u32)
        .ok_or(SyscallError::OutOfMemory)?;
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
    vm::map_memory(world, &caps, gpa, len, perms as u32, memtype as u8)
        .map_err(map_vm_error)
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
        info.vcpu_count = vm::count() as u32;
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
