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

//! s9vm — registry of virtual worlds and guest memory.
//!
//! This layer keeps the world registry (opaque identifier, name, owning silo,
//! state) and owns, for each world, its guest memory: pinned frames, GPA map
//! (`GuestMap`) and second-level translation tables (`SecondLevelMemory`).
//!
//! Invariants:
//! - a guest frame is **pinned** for as long as the world lives (never
//!   swapped, never freed);
//! - destruction order frees the translation tables first, then the guest
//!   frames;
//! - no frame allocation is done while holding the registry lock: memory is
//!   taken out of the registry, manipulated, then put back in place.
//!
//! No policy is decided here: access checks are done by the syscall layer
//! (capabilities).

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::memory::frame::{FrameAllocOptions, FramePurpose, PhysFrame};
use crate::process::{kthread, scheduler::ticks, sleep_current_task_ticks, TaskId};
use crate::s9vm::apic::LocalApic;
use crate::s9vm::caps::HwCaps;
use crate::s9vm::exit::ExitClass;
use crate::s9vm::exitqueue::ExitQueue;
use crate::s9vm::guest::{FixedBits, GuestState};
use crate::s9vm::memmap::{perms_from_abi, GuestMap, MapError};
use crate::s9vm::mmu::Perms as MmuPerms;
use crate::s9vm::mmu::PAGE_SIZE;
use crate::s9vm::vcpu::{ExitInfo, SecondLevelMemory, Vcpu, VcpuError};
use crate::sync::{SpinLock, WaitQueue};
use strat9_abi::vmm::{exit_kind, VmmExitEvent, VmmRegs};

/// Maximum number of simultaneous worlds (safety bound).
pub const MAX_WORLDS: usize = 64;
/// Maximum length of a name.
pub const NAME_MAX: usize = 32;
/// Maximum number of vCPUs per world (safety bound, before quotas).
pub const MAX_VCPUS_PER_WORLD: usize = 32;
/// Default guest page quota (1 GiB).
pub const DEFAULT_QUOTA_PAGES: u64 = 262_144;

/// Public record of a world.
#[derive(Debug, Clone, Copy)]
pub struct WorldRecord {
    /// Opaque identifier (never 0).
    pub id: u64,
    /// Name (truncated UTF-8, zero-padded).
    pub name: [u8; NAME_MAX],
    /// Usable length of the name.
    pub name_len: u8,
    /// Owning silo (0 = kernel world).
    pub silo_id: u32,
    /// State (`strat9_abi::vmm::state` constants).
    pub state: u32,
    /// Number of registered vCPUs.
    pub vcpu_count: u32,
    /// Mapped guest pages.
    pub mapped_pages: u64,
}

impl WorldRecord {
    fn new(id: u64, name: &[u8], silo_id: u32) -> Self {
        let mut stored = [0u8; NAME_MAX];
        let length = name.len().min(NAME_MAX);
        stored[..length].copy_from_slice(&name[..length]);
        Self {
            id,
            name: stored,
            name_len: length as u8,
            silo_id,
            state: strat9_abi::vmm::state::CREATED,
            vcpu_count: 0,
            mapped_pages: 0,
        }
    }

    /// Name as a slice of usable bytes.
    pub fn name_slice(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// Guest memory layer errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmError {
    /// Unknown world.
    Unknown,
    /// Invalid reservation (alignment, overlap, quota).
    Map(MapError),
    /// No more frames available.
    OutOfMemory,
    /// Second-level translation error.
    Translation(VcpuError),
}

impl From<MapError> for VmError {
    fn from(value: MapError) -> Self {
        Self::Map(value)
    }
}

impl From<VcpuError> for VmError {
    fn from(value: VcpuError) -> Self {
        Self::Translation(value)
    }
}

/// Allocates a guest RAM frame (zeroed, non-movable, pinned).
fn alloc_guest_frame() -> Option<PhysFrame> {
    crate::sync::with_irqs_disabled(|token| {
        FrameAllocOptions::new()
            .purpose(FramePurpose::KernelData)
            .allocate(token)
            .ok()
    })
}

/// Frees a list of guest frames.
fn free_guest_frames(frames: Vec<PhysFrame>) {
    if frames.is_empty() {
        return;
    }
    crate::sync::with_irqs_disabled(|token| {
        for frame in frames {
            crate::memory::free_frame(token, frame);
        }
    });
}

/// Guest memory of a world.
pub struct WorldMemory {
    second_level: SecondLevelMemory,
    map: GuestMap,
    frames: Vec<PhysFrame>,
}

impl WorldMemory {
    /// Creates empty guest memory.
    pub fn new(quota_pages: u64) -> Result<Self, VmError> {
        Ok(Self {
            second_level: SecondLevelMemory::new()?,
            map: GuestMap::new(quota_pages),
            frames: Vec::new(),
        })
    }

    /// Reserved pages.
    pub fn pages(&self) -> u64 {
        self.map.pages()
    }

    /// Maps a GPA range into guest RAM (frames allocated and pinned).
    ///
    /// `memtype` must be `0` (default write-back); the other types are not yet
    /// supported and are rejected by the caller.
    ///
    /// On failure, every mapping and every frame allocated during the call is
    /// undone: the world's memory stays consistent.
    pub fn map(
        &mut self,
        _caps: &HwCaps,
        gpa: u64,
        len: u64,
        perms_bits: u32,
        memtype: u8,
    ) -> Result<u64, VmError> {
        // 1. Validates the range and reserves the quota before any allocation.
        self.map.reserve(gpa, len, perms_bits, memtype)?;
        let decoded = perms_from_abi(perms_bits);
        let perms = MmuPerms {
            read: decoded.read,
            write: decoded.write,
            execute: decoded.execute,
        };
        let pages = len / PAGE_SIZE;
        let mut allocated: Vec<PhysFrame> = Vec::with_capacity(pages as usize);
        let mut mapped: u64 = 0;
        for index in 0..pages {
            let Some(frame) = alloc_guest_frame() else {
                // Out of memory: undo what has already been done.
                self.rollback(gpa, mapped, allocated);
                self.map.remove(gpa);
                return Err(VmError::OutOfMemory);
            };
            let hpa = frame.start_address.as_u64();
            if let Err(error) = self.second_level.map_4k(gpa + index * PAGE_SIZE, hpa, perms) {
                allocated.push(frame);
                self.rollback(gpa, mapped, allocated);
                self.map.remove(gpa);
                return Err(VmError::Translation(error));
            }
            allocated.push(frame);
            mapped += 1;
        }
        self.frames.extend(allocated);
        Ok(pages)
    }

    /// Undoes `mapped` pages starting at `gpa` and frees the frames.
    fn rollback(&mut self, gpa: u64, mapped: u64, frames: Vec<PhysFrame>) {
        for index in 0..mapped {
            let _ = self.second_level.unmap_4k(gpa + index * PAGE_SIZE);
        }
        free_guest_frames(frames);
    }

    /// Translates a GPA (diagnostic).
    pub fn translate(&self, gpa: u64) -> Option<u64> {
        self.second_level.translate(gpa)
    }

    /// Value of the translation pointer (EPTP) for the control block.
    pub fn second_level_pointer(&self, caps: &HwCaps) -> u64 {
        self.second_level.pointer(caps)
    }

    /// Frees the translation tables, then the guest frames.
    pub fn destroy(mut self) {
        let frames = core::mem::take(&mut self.frames);
        self.map.clear();
        self.second_level.destroy();
        free_guest_frames(frames);
    }
}

/// Registered world: public record + lazy guest memory +
/// logical vCPUs.
struct World {
    record: WorldRecord,
    memory: Option<WorldMemory>,
    vcpus: Vec<VcpuSlot>,
    exits: ExitQueue,
    /// Destruction in progress: any new operation is refused and the vCPU
    /// tasks are stopped before the memory is freed.
    closing: bool,
    /// Paused world: `RUN`s are refused (`Paused`) until resumed.
    paused: bool,
}

/// Logical vCPU: opaque identifier, APIC id and ABI register block.
///
/// The hardware context (control block, host stack, guest state) is created at
/// execution time, not at logical creation time: a world can be configured
/// (memory, vCPUs, registers) before the hardware is activated.
///
/// ADR-4 model: each vCPU is driven by a dedicated **kernel task**
/// ([`VcpuSlot::task`]). The task waits for a `RUN` request, runs the guest
/// until the next policy exit, queues the event, then waits again. The kernel
/// thus guarantees that a guest never runs on the syscall caller's stack.
pub struct VcpuSlot {
    /// Opaque identifier of the vCPU.
    pub id: u64,
    /// Guest APIC identifier.
    pub apic_id: u32,
    /// ABI register block.
    pub regs: VmmRegs,
    /// Hardware context (created on the first `RUN`).
    hardware: Option<Vcpu>,
    /// Guest local APIC (architectural state, MMIO page and x2APIC MSR).
    apic: LocalApic,
    /// External interrupt pending injection at the next `RUN`.
    pending_irq: Option<u8>,
    /// NMI pending injection at the next `RUN`.
    pending_nmi: bool,
    /// Kernel task driving this vCPU (created with the vCPU).
    task: Option<TaskId>,
    /// A `RUN` has been requested and has not been taken into account yet.
    run_requested: bool,
    /// A `RUN` is in flight: a single caller at a time.
    run_in_flight: bool,
    /// The last requested `RUN` is finished.
    run_done: bool,
    /// Result of the last `RUN` (valid when `run_done`).
    run_result: Option<Result<(), RunError>>,
    /// Shutdown requested (vCPU or world destruction).
    shutdown: bool,
    /// The kernel task has finished and its hardware resources are unloaded.
    exited: bool,
    /// Wake-up of the vCPU task on a `RUN` request (or shutdown).
    run_wait: Arc<WaitQueue>,
    /// Wake-up of callers blocked on the end of a `RUN` or on a shutdown.
    done_wait: Arc<WaitQueue>,
}

/// Global world registry.
static WORLDS: SpinLock<BTreeMap<u64, World>> = SpinLock::new(BTreeMap::new());
/// Next identifier (1 = first world; 0 is reserved for the global summary).
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Creates a world. Returns `None` if the registry is full or if the name is
/// empty.
pub fn create(name: &[u8], silo_id: u32) -> Option<WorldRecord> {
    if name.is_empty() || name.len() > NAME_MAX {
        return None;
    }
    let mut worlds = WORLDS.lock();
    if worlds.len() >= MAX_WORLDS {
        return None;
    }
    let mut id = NEXT_ID.fetch_add(1, Ordering::AcqRel);
    while id == 0 || worlds.contains_key(&id) {
        id = NEXT_ID.fetch_add(1, Ordering::AcqRel);
    }
    let record = WorldRecord::new(id, name, silo_id);
    worlds.insert(
        id,
        World {
            record,
            memory: None,
            vcpus: Vec::new(),
            exits: ExitQueue::default(),
            closing: false,
            paused: false,
        },
    );
    Some(record)
}

/// Destroys a world and frees its guest memory.
///
/// The vCPU tasks are stopped and joined **before** the memory is freed: a
/// task still in flight could otherwise dereference the world's second-level
/// tables. A second concurrent call during the close returns `None`.
pub fn destroy(id: u64) -> Option<WorldRecord> {
    // 1. Marks the world closed and wakes all vCPU tasks.
    let mut to_join: Vec<u64> = Vec::new();
    let mut wakers: Vec<Arc<WaitQueue>> = Vec::new();
    {
        let mut worlds = WORLDS.lock();
        let world = worlds.get_mut(&id)?;
        if world.closing {
            return None;
        }
        world.closing = true;
        for slot in world.vcpus.iter_mut() {
            slot.shutdown = true;
            wakers.push(Arc::clone(&slot.run_wait));
            wakers.push(Arc::clone(&slot.done_wait));
            if slot.task.is_some() {
                to_join.push(slot.id);
            }
        }
    }
    for waiter in wakers {
        waiter.wake_all();
    }
    // 2. Waits for the vCPU tasks to exit, without holding the lock.
    for vcpu in to_join {
        wait_vcpu_exited(vcpu);
    }
    // 3. Removes the world and frees the guest memory.
    let world = {
        let mut worlds = WORLDS.lock();
        worlds.remove(&id)?
    };
    if let Some(memory) = world.memory {
        memory.destroy();
    }
    Some(world.record)
}

/// Finds a world and the index of a vCPU in that world.
fn locate_slot(
    worlds: &mut BTreeMap<u64, World>,
    vcpu_id: u64,
) -> Option<(&mut World, usize)> {
    for world in worlds.values_mut() {
        if let Some(index) = world.vcpus.iter().position(|slot| slot.id == vcpu_id) {
            return Some((world, index));
        }
    }
    None
}

/// Waits for a vCPU's kernel task to finish (or for the vCPU to disappear from
/// the registry).
fn wait_vcpu_exited(vcpu_id: u64) {
    loop {
        let waiters = {
            let mut worlds = WORLDS.lock();
            let Some((world, index)) = locate_slot(&mut worlds, vcpu_id) else {
                return;
            };
            let slot = &world.vcpus[index];
            if slot.exited || slot.task.is_none() {
                return;
            }
            Arc::clone(&slot.done_wait)
        };
        waiters.wait_until(|| {
            let mut worlds = WORLDS.lock();
            match locate_slot(&mut worlds, vcpu_id) {
                Some((world, index)) if !world.vcpus[index].exited => None,
                _ => Some(()),
            }
        });
    }
}

/// Removes a vCPU from the registry without waiting for a task.
fn remove_vcpu(vcpu_id: u64) -> bool {
    let mut worlds = WORLDS.lock();
    for world in worlds.values_mut() {
        if let Some(index) = world.vcpus.iter().position(|slot| slot.id == vcpu_id) {
            world.vcpus.remove(index);
            world.record.vcpu_count = world.vcpus.len() as u32;
            return true;
        }
    }
    false
}

/// Creates the registry entry of a vCPU.
fn new_vcpu_slot(id: u64, apic_id: u32) -> VcpuSlot {
    let regs = strat9_abi::vmm::VmmRegs {
        abi_version: strat9_abi::vmm::VMM_ABI_VERSION,
        ..Default::default()
    };
    VcpuSlot {
        id,
        apic_id,
        regs,
        hardware: None,
        apic: LocalApic::new(apic_id),
        pending_irq: None,
        pending_nmi: false,
        task: None,
        run_requested: false,
        run_in_flight: false,
        run_done: false,
        run_result: None,
        shutdown: false,
        exited: false,
        run_wait: Arc::new(WaitQueue::new()),
        done_wait: Arc::new(WaitQueue::new()),
    }
}

/// Returns a record.
pub fn get(id: u64) -> Option<WorldRecord> {
    WORLDS.lock().get(&id).map(|world| world.record)
}

/// Lists the worlds (identifier order).
pub fn list() -> Vec<WorldRecord> {
    WORLDS
        .lock()
        .values()
        .map(|world| world.record)
        .collect()
}

/// Logs an engine snapshot (kernel diagnostic).
pub fn debug_dump() {
    let worlds = list();
    log::info!(
        "[s9vm] debug: {} monde(s), {} CPU actif(s)",
        worlds.len(),
        crate::s9vm::active_cpu_count()
    );
    for world in worlds {
        let name = core::str::from_utf8(world.name_slice()).unwrap_or("<non-utf8>");
        log::info!(
            "[s9vm] debug: world {} name={} silo={} state={} vcpus={} pages={}",
            world.id,
            name,
            world.silo_id,
            world.state,
            world.vcpu_count,
            world.mapped_pages
        );
        let mut worlds = WORLDS.lock();
        if let Some(entry) = worlds.get(&world.id) {
            for slot in &entry.vcpus {
                log::info!(
                    "[s9vm] debug:   vcpu {} apic={} tpr={} irr={} isr={} irq={:?} nmi={} task={:?}",
                    slot.id,
                    slot.apic.apic_id(),
                    slot.apic.tpr(),
                    slot.apic.has_pending(),
                    slot.apic.in_service(),
                    slot.pending_irq,
                    slot.pending_nmi,
                    slot.task
                );
            }
        }
    }
}

/// Number of worlds.
pub fn count() -> usize {
    WORLDS.lock().len()
}

/// Updates a world's state. Returns `false` if the world is unknown.
pub fn set_state(id: u64, state: u32) -> bool {
    let mut worlds = WORLDS.lock();
    match worlds.get_mut(&id) {
        Some(world) => {
            world.record.state = state;
            true
        }
        None => false,
    }
}

/// Updates a world's vCPU count.
pub fn set_vcpu_count(id: u64, count: u32) -> bool {
    let mut worlds = WORLDS.lock();
    match worlds.get_mut(&id) {
        Some(world) => {
            world.record.vcpu_count = count;
            true
        }
        None => false,
    }
}

/// Maps guest memory into a world.
///
/// The memory is taken out of the registry during allocation (never allocate
/// frames under the lock), then put back in place. If the world was destroyed
/// in the meantime, the memory is freed immediately.
pub fn map_memory(
    id: u64,
    caps: &HwCaps,
    gpa: u64,
    len: u64,
    perms_bits: u32,
    memtype: u8,
) -> Result<u64, VmError> {
    // The registry is locked for as short a time as possible: the existing
    // memory is retrieved (or its absence noted), then the lock is released
    // before any frame allocation.
    enum Slot {
        Existing(WorldMemory),
        Empty,
    }
    let slot = {
        let mut worlds = WORLDS.lock();
        let world = worlds.get_mut(&id).ok_or(VmError::Unknown)?;
        match world.memory.take() {
            Some(memory) => Slot::Existing(memory),
            None => Slot::Empty,
        }
    };
    let mut memory = match slot {
        Slot::Existing(memory) => memory,
        Slot::Empty => WorldMemory::new(DEFAULT_QUOTA_PAGES)?,
    };
    let result = memory.map(caps, gpa, len, perms_bits, memtype);
    let mut worlds = WORLDS.lock();
    match worlds.get_mut(&id) {
        Some(world) => {
            if result.is_ok() {
                world.record.mapped_pages = memory.pages();
            }
            world.memory = Some(memory);
            result
        }
        None => {
            drop(worlds);
            memory.destroy();
            Err(VmError::Unknown)
        }
    }
}

/// vCPU layer errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VcpuRegistryError {
    /// Unknown world.
    WorldUnknown,
    /// Unknown vCPU.
    Unknown,
    /// vCPU limit reached for this world.
    Limit,
    /// Incompatible ABI version.
    BadAbiVersion,
    /// The vCPU's kernel task could not be created.
    Thread,
}

/// vCPU execution errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunError {
    /// Unknown vCPU.
    UnknownVcpu,
    /// The world has no mapped guest memory.
    NoMemory,
    /// The supplied guest state is invalid (see `guest::GuestError`).
    InvalidGuestState,
    /// Hardware is not activated on this CPU.
    HardwareNotReady,
    /// Hardware error during execution.
    Hardware(VcpuError),
    /// The limit of consecutive summarized exits is reached (pathological
    /// loop).
    ExitStorm,
    /// A `RUN` is already in flight for this vCPU.
    Busy,
    /// The world is paused.
    Paused,
}

impl From<VcpuError> for RunError {
    fn from(value: VcpuError) -> Self {
        Self::Hardware(value)
    }
}

/// Maximum number of "resumable" exits handled internally before handing
/// control back to policy (protection against an interrupt storm).
const MAX_RESUMED_EXITS: u32 = 64;

/// True if an exit can be resumed immediately by the kernel.
const fn is_resumable(class: ExitClass) -> bool {
    matches!(
        class,
        ExitClass::ExternalInterrupt | ExitClass::InterruptWindow | ExitClass::Apic
    )
}

fn regs_from_guest(guest: &GuestState, base: &VmmRegs) -> VmmRegs {
    VmmRegs {
        abi_version: strat9_abi::vmm::VMM_ABI_VERSION,
        flags: base.flags,
        rax: guest.rax,
        rbx: guest.rbx,
        rcx: guest.rcx,
        rdx: guest.rdx,
        rsi: guest.rsi,
        rdi: guest.rdi,
        rbp: guest.rbp,
        rsp: guest.rsp,
        r8: guest.r8,
        r9: guest.r9,
        r10: guest.r10,
        r11: guest.r11,
        r12: guest.r12,
        r13: guest.r13,
        r14: guest.r14,
        r15: guest.r15,
        rip: guest.rip,
        rflags: guest.rflags,
        cr0: guest.cr0,
        cr3: guest.cr3,
        cr4: guest.cr4,
        efer: guest.efer,
    }
}

fn event_from_exit(exit: &ExitInfo, vcpu_id: u64) -> VmmExitEvent {
    let class = exit.class();
    let mut event = VmmExitEvent {
        abi_version: strat9_abi::vmm::VMM_ABI_VERSION,
        vcpu_id,
        gpa: exit.guest_physical_address,
        flags: 0,
        ..VmmExitEvent::default()
    };
    match class {
        ExitClass::IoPort => {
            let qualification = exit.qualification;
            event.kind = exit_kind::IO_PORT;
            event.port = ((qualification >> 16) & 0xFFFF) as u32;
            event.size = ((qualification & 0x7) + 1) as u32;
            // Bit 3: 0 = OUT, 1 = IN.
            event.flags = ((qualification >> 3) & 1) as u32;
        }
        ExitClass::Halt => {
            event.kind = exit_kind::HALT;
        }
        ExitClass::EptViolation => {
            event.kind = exit_kind::TRANSLATION;
            // Bits 2:0 of the EPT qualification: read/write/execute.
            event.flags = (exit.qualification & 0x7) as u32;
        }
        ExitClass::ExceptionOrNmi => {
            event.kind = exit_kind::EXCEPTION;
            event.flags = exit.interrupt_info;
        }
        ExitClass::PreemptionTimer => {
            event.kind = exit_kind::PREEMPTION_TIMER;
        }
        _ => {
            event.kind = exit_kind::OTHER;
            event.flags = exit.raw_reason;
        }
    }
    event
}

/// Runs a vCPU until the next "policy" exit and queues the corresponding event
/// in the world's queue.
///
/// Exits that are purely hostile to throughput (external interrupt, interrupt
/// window, APIC, preemption timer) are resumed immediately by the kernel; all
/// the others are reported back to policy.
pub fn run_vcpu(vcpu_id: u64, caps: &HwCaps) -> Result<(), RunError> {
    if crate::s9vm::active_cpu_count() == 0 {
        return Err(RunError::HardwareNotReady);
    }
    // 1. Takes the hardware context and the registers out of the registry,
    //    without holding the lock during execution.
    let (world_id, mut hardware, mut regs, pointer, pending_irq, pending_nmi) = {
        let mut worlds = WORLDS.lock();
        let world = vcpu_world_mut(&mut worlds, vcpu_id).ok_or(RunError::UnknownVcpu)?;
        let slot = world
            .vcpus
            .iter_mut()
            .find(|slot| slot.id == vcpu_id)
            .ok_or(RunError::UnknownVcpu)?;
        let memory = world.memory.as_ref().ok_or(RunError::NoMemory)?;
        let pointer = memory.second_level_pointer(caps);
        let hardware = slot.hardware.take();
        let pending_irq = slot.pending_irq.take();
        let pending_nmi = core::mem::replace(&mut slot.pending_nmi, false);
        (world.record.id, hardware, slot.regs, pointer, pending_irq, pending_nmi)
    };
    let mut hardware = match hardware {
        Some(hardware) => hardware,
        None => Vcpu::new(caps, pointer)?,
    };

    // 2. Builds and validates the guest state.
    let mut guest = GuestState::from_abi_regs(&regs);
    let fixed = FixedBits::new(
        caps.cr0_fixed0,
        caps.cr0_fixed1,
        caps.cr4_fixed0,
        caps.cr4_fixed1,
    );
    guest
        .validate(&fixed, caps.unrestricted_guest)
        .map_err(|_| RunError::InvalidGuestState)?;

    // 3. Loads the control block, configures and executes.
    // SAFETY: VT-x is active on this CPU (checked above); the control block
    // and the host stack belong to this vCPU, which is not currently running
    // (context taken out of the registry).
    let mut result = Ok(());
    unsafe {
        let _ = hardware.clear();
        if let Err(error) = hardware.load() {
            result = Err(RunError::Hardware(error));
        } else if let Err(error) = hardware.configure_host() {
            result = Err(RunError::Hardware(error));
        } else if let Err(error) = hardware.configure(caps, &guest) {
            result = Err(RunError::Hardware(error));
        } else if pending_nmi {
            // The NMI takes priority over a pending external interrupt.
            if let Err(error) = hardware.inject_nmi() {
                result = Err(RunError::Hardware(error));
            }
        } else if let Some(vector) = pending_irq {
            // Deferred injection: the "VM-entry interruption information"
            // field is written just before entry; the processor consumes it
            // and resets it on delivery.
            if let Err(error) = hardware.inject_interrupt(vector) {
                result = Err(RunError::Hardware(error));
            }
        }
        if result.is_ok() {
            let mut resumed = 0u32;
            loop {
                match hardware.run() {
                    Ok(exit) => {
                        if is_resumable(exit.class()) && resumed < MAX_RESUMED_EXITS {
                            resumed += 1;
                            continue;
                        }
                        if is_resumable(exit.class()) {
                            result = Err(RunError::ExitStorm);
                        } else {
                            let event = event_from_exit(&exit, vcpu_id);
                            let _ = push_exit(world_id, event);
                        }
                        break;
                    }
                    Err(error) => {
                        result = Err(RunError::Hardware(error));
                        break;
                    }
                }
            }
        }
    }

    // 4. Reloads the registers from the post-execution guest state and puts
    //    the hardware context back into the registry if the world still
    //    exists.
    regs = regs_from_guest(hardware.guest(), &regs);
    let mut worlds = WORLDS.lock();
    if let Some(world) = worlds.get_mut(&world_id) {
        if let Some(slot) = world.vcpus.iter_mut().find(|slot| slot.id == vcpu_id) {
            slot.regs = regs;
            slot.hardware = Some(hardware);
        }
    }
    result
}

/// Queues an event in a world's queue.
pub fn push_exit(world_id: u64, event: VmmExitEvent) -> Result<(), ()> {
    let mut worlds = WORLDS.lock();
    let world = worlds.get_mut(&world_id).ok_or(())?;
    world.exits.push(event).map_err(|_| ())
}

/// Dequeues the next event of a world.
pub fn pop_exit(world_id: u64) -> Result<VmmExitEvent, ()> {
    let mut worlds = WORLDS.lock();
    let world = worlds.get_mut(&world_id).ok_or(())?;
    world.exits.pop().map_err(|_| ())
}

/// Number of pending events for a world.
pub fn exit_count(world_id: u64) -> Option<usize> {
    WORLDS.lock().get(&world_id).map(|world| world.exits.len())
}

/// Next vCPU identifier (global, never 0).
static NEXT_VCPU: AtomicU64 = AtomicU64::new(1);

/// Creates a logical vCPU in a world and the kernel task that drives it.
pub fn create_vcpu(world_id: u64, apic_id: u32) -> Result<u64, VcpuRegistryError> {
    // 1. Registers the vCPU without holding the lock during task creation.
    let id = {
        let mut worlds = WORLDS.lock();
        let world = worlds
            .get_mut(&world_id)
            .ok_or(VcpuRegistryError::WorldUnknown)?;
        if world.closing {
            return Err(VcpuRegistryError::WorldUnknown);
        }
        if world.vcpus.len() >= MAX_VCPUS_PER_WORLD {
            return Err(VcpuRegistryError::Limit);
        }
        let id = NEXT_VCPU.fetch_add(1, Ordering::AcqRel);
        world.vcpus.push(new_vcpu_slot(id, apic_id));
        world.record.vcpu_count = world.vcpus.len() as u32;
        id
    };
    // 2. Creates the vCPU's kernel task (ADR-4 model).
    let task = match kthread::spawn("s9vm-vcpu", move || vcpu_task_main(world_id, id)) {
        Ok(task) => task,
        Err(_) => {
            let _ = remove_vcpu(id);
            return Err(VcpuRegistryError::Thread);
        }
    };
    // 3. Publishes the task identifier if the vCPU still exists.
    {
        let mut worlds = WORLDS.lock();
        if let Some((world, index)) = locate_slot(&mut worlds, id) {
            world.vcpus[index].task = Some(task);
        }
    }
    Ok(id)
}

/// Destroys a logical vCPU. Returns `false` if it is unknown.
///
/// The kernel task is stopped and joined before the entry is removed: the
/// hardware context (control block, host stack, EPT) is never freed during a
/// guest entry.
pub fn destroy_vcpu(vcpu_id: u64) -> bool {
    let (run_wait, done_wait, has_task) = {
        let mut worlds = WORLDS.lock();
        let Some((world, index)) = locate_slot(&mut worlds, vcpu_id) else {
            return false;
        };
        let slot = &mut world.vcpus[index];
        if slot.shutdown {
            return false;
        }
        slot.shutdown = true;
        (
            Arc::clone(&slot.run_wait),
            Arc::clone(&slot.done_wait),
            slot.task.is_some(),
        )
    };
    run_wait.wake_all();
    done_wait.wake_all();
    if has_task {
        wait_vcpu_exited(vcpu_id);
    }
    remove_vcpu(vcpu_id)
}

/// Body of a vCPU's kernel task: waits for `RUN` requests, runs the guest
/// until the next policy exit, publishes the event then waits again.
fn vcpu_task_main(world_id: u64, vcpu_id: u64) {
    let _ = world_id;
    loop {
        // Wake-ups: RUN request or shutdown.
        let run_wait = {
            let mut worlds = WORLDS.lock();
            let Some((world, index)) = locate_slot(&mut worlds, vcpu_id) else {
                return;
            };
            let slot = &world.vcpus[index];
            if slot.shutdown {
                break;
            }
            Arc::clone(&slot.run_wait)
        };
        let run = run_wait.wait_until(|| {
            let mut worlds = WORLDS.lock();
            match locate_slot(&mut worlds, vcpu_id) {
                Some((world, index)) => {
                    let slot = &mut world.vcpus[index];
                    if slot.shutdown {
                        Some(false)
                    } else if slot.run_requested {
                        slot.run_requested = false;
                        Some(true)
                    } else {
                        None
                    }
                }
                None => Some(false),
            }
        });
        if !run {
            break;
        }

        let result = execute_one_run(vcpu_id);

        let done_wait = {
            let mut worlds = WORLDS.lock();
            let Some((world, index)) = locate_slot(&mut worlds, vcpu_id) else {
                return;
            };
            let slot = &mut world.vcpus[index];
            slot.run_done = true;
            slot.run_in_flight = false;
            slot.run_result = Some(result);
            Arc::clone(&slot.done_wait)
        };
        done_wait.wake_all();
    }
    cleanup_vcpu(vcpu_id);
}

/// Executes a `RUN` (at most one guest entry) in the vCPU task.
fn execute_one_run(vcpu_id: u64) -> Result<(), RunError> {
    if crate::s9vm::active_cpu_count() == 0 {
        return Err(RunError::HardwareNotReady);
    }
    let caps = crate::s9vm::detect().ok_or(RunError::HardwareNotReady)?;
    // Host interrupts stay disabled during the guest entry: guest time is
    // bounded by the next exit (P0). VMX preemption (timer) will come with the
    // full preemption model.
    crate::sync::with_irqs_disabled(|_| run_vcpu(vcpu_id, &caps))
}

/// Unloads the hardware context and signals the vCPU task's exit.
fn cleanup_vcpu(vcpu_id: u64) {
    let hardware = {
        let mut worlds = WORLDS.lock();
        match locate_slot(&mut worlds, vcpu_id) {
            Some((world, index)) => world.vcpus[index].hardware.take(),
            None => None,
        }
    };
    if let Some(mut hardware) = hardware {
        if crate::s9vm::active_cpu_count() > 0 {
            // SAFETY: no guest is running on this vCPU anymore.
            unsafe {
                let _ = hardware.clear();
            }
        }
    }
    let done_wait = {
        let mut worlds = WORLDS.lock();
        match locate_slot(&mut worlds, vcpu_id) {
            Some((world, index)) => {
                let slot = &mut world.vcpus[index];
                slot.exited = true;
                Arc::clone(&slot.done_wait)
            }
            None => return,
        }
    };
    done_wait.wake_all();
}

/// Requests execution of a vCPU and **blocks** the caller until the end of
/// that `RUN` (at most one policy exit).
///
/// Only one `RUN` can be in flight per vCPU; a second concurrent call receives
/// [`RunError::Busy`].
pub fn request_run(vcpu_id: u64) -> Result<(), RunError> {
    let (run_wait, done_wait) = {
        let mut worlds = WORLDS.lock();
        let Some((world, index)) = locate_slot(&mut worlds, vcpu_id) else {
            return Err(RunError::UnknownVcpu);
        };
        if world.closing {
            return Err(RunError::UnknownVcpu);
        }
        if world.paused {
            return Err(RunError::Paused);
        }
        let slot = &mut world.vcpus[index];
        if slot.shutdown || slot.task.is_none() {
            return Err(RunError::UnknownVcpu);
        }
        if slot.run_in_flight || slot.run_requested {
            return Err(RunError::Busy);
        }
        slot.run_in_flight = true;
        slot.run_requested = true;
        slot.run_done = false;
        slot.run_result = None;
        (Arc::clone(&slot.run_wait), Arc::clone(&slot.done_wait))
    };
    run_wait.wake_one();
    done_wait
        .wait_until(|| {
            let mut worlds = WORLDS.lock();
            match locate_slot(&mut worlds, vcpu_id) {
                Some((world, index)) => {
                    let slot = &mut world.vcpus[index];
                    if slot.run_done {
                        Some(slot.run_result.take())
                    } else {
                        None
                    }
                }
                None => Some(Some(Err(RunError::UnknownVcpu))),
            }
        })
        .unwrap_or(Err(RunError::UnknownVcpu))
}

/// Waits until at least one exit event is available in the vCPU's world, or
/// until the timeout expires.
///
/// `timeout_ns = 0` tests immediately (no wait). Returns `true` if an event is
/// pending, `false` on timeout.
pub fn wait_exit(vcpu_id: u64, timeout_ns: u64) -> Result<bool, VcpuRegistryError> {
    let world_id = {
        let mut worlds = WORLDS.lock();
        let Some((world, index)) = locate_slot(&mut worlds, vcpu_id) else {
            return Err(VcpuRegistryError::Unknown);
        };
        if world.closing || world.vcpus[index].shutdown {
            return Err(VcpuRegistryError::Unknown);
        }
        world.record.id
    };
    if exit_count(world_id).unwrap_or(0) > 0 {
        return Ok(true);
    }
    if timeout_ns == 0 {
        return Ok(false);
    }
    let budget_ticks = (timeout_ns / crate::arch::timer::NS_PER_TICK).max(1);
    let deadline = ticks().saturating_add(budget_ticks);
    loop {
        if exit_count(world_id).unwrap_or(0) > 0 {
            return Ok(true);
        }
        if ticks() >= deadline {
            return Ok(false);
        }
        sleep_current_task_ticks(1);
    }
}

/// Schedules the injection of an external interrupt into a vCPU.
///
/// The injection is deferred: the vector is remembered and written into the
/// "VM-entry interruption information" field at the next `run_vcpu`. Returns
/// `Unknown` if the vCPU does not exist.
pub fn inject_irq(vcpu_id: u64, vector: u8) -> Result<(), VcpuRegistryError> {
    let mut worlds = WORLDS.lock();
    let world = vcpu_world_mut(&mut worlds, vcpu_id).ok_or(VcpuRegistryError::Unknown)?;
    let slot = world
        .vcpus
        .iter_mut()
        .find(|slot| slot.id == vcpu_id)
        .ok_or(VcpuRegistryError::Unknown)?;
    slot.pending_irq = Some(vector);
    slot.apic.inject(vector);
    Ok(())
}

/// Schedules the injection of an NMI into a vCPU (delivered at the next
/// `RUN`).
pub fn inject_nmi(vcpu_id: u64) -> Result<(), VcpuRegistryError> {
    let mut worlds = WORLDS.lock();
    let world = vcpu_world_mut(&mut worlds, vcpu_id).ok_or(VcpuRegistryError::Unknown)?;
    let slot = world
        .vcpus
        .iter_mut()
        .find(|slot| slot.id == vcpu_id)
        .ok_or(VcpuRegistryError::Unknown)?;
    slot.pending_nmi = true;
    Ok(())
}

/// Pauses a world (`RUN` refused until resumed).
pub fn pause(world_id: u64) -> Result<(), VmError> {
    let mut worlds = WORLDS.lock();
    let world = worlds.get_mut(&world_id).ok_or(VmError::Unknown)?;
    if world.closing {
        return Err(VmError::Unknown);
    }
    world.paused = true;
    world.record.state = strat9_abi::vmm::state::PAUSED;
    Ok(())
}

/// Resumes a paused world.
pub fn resume(world_id: u64) -> Result<(), VmError> {
    let mut worlds = WORLDS.lock();
    let world = worlds.get_mut(&world_id).ok_or(VmError::Unknown)?;
    if world.closing {
        return Err(VmError::Unknown);
    }
    world.paused = false;
    world.record.state = strat9_abi::vmm::state::RUNNING;
    Ok(())
}

/// True if the world is paused.
pub fn is_paused(world_id: u64) -> bool {
    WORLDS
        .lock()
        .get(&world_id)
        .map(|world| world.paused)
        .unwrap_or(false)
}

/// Pending interrupt vector for a vCPU, if any.
pub fn pending_irq(vcpu_id: u64) -> Option<u8> {
    let mut worlds = WORLDS.lock();
    let world = vcpu_world_mut(&mut worlds, vcpu_id)?;
    world
        .vcpus
        .iter()
        .find(|slot| slot.id == vcpu_id)
        .and_then(|slot| slot.pending_irq)
}

/// Finds the world owning a vCPU (excluding closing worlds).
fn vcpu_world_mut(worlds: &mut BTreeMap<u64, World>, vcpu_id: u64) -> Option<&mut World> {
    worlds
        .values_mut()
        .find(|world| !world.closing && world.vcpus.iter().any(|slot| slot.id == vcpu_id))
}

/// Writes a vCPU's register block.
pub fn set_vcpu_regs(vcpu_id: u64, regs: &strat9_abi::vmm::VmmRegs) -> Result<(), VcpuRegistryError> {
    if regs.abi_version != strat9_abi::vmm::VMM_ABI_VERSION {
        return Err(VcpuRegistryError::BadAbiVersion);
    }
    let mut worlds = WORLDS.lock();
    let world = vcpu_world_mut(&mut worlds, vcpu_id).ok_or(VcpuRegistryError::Unknown)?;
    let slot = world
        .vcpus
        .iter_mut()
        .find(|slot| slot.id == vcpu_id)
        .ok_or(VcpuRegistryError::Unknown)?;
    slot.regs = *regs;
    Ok(())
}

/// Reads a vCPU's register block.
pub fn get_vcpu_regs(vcpu_id: u64) -> Option<strat9_abi::vmm::VmmRegs> {
    let worlds = WORLDS.lock();
    for world in worlds.values() {
        if let Some(slot) = world.vcpus.iter().find(|slot| slot.id == vcpu_id) {
            return Some(slot.regs);
        }
    }
    None
}

/// Number of logical vCPUs of a world.
pub fn vcpu_count(world_id: u64) -> Option<u32> {
    WORLDS
        .lock()
        .get(&world_id)
        .map(|world| world.vcpus.len() as u32)
}

/// Diagnostic detail for a world: mapped pages and translation of a GPA.
pub fn debug_translate(id: u64, gpa: u64) -> Option<u64> {
    let memory_ref = {
        let worlds = WORLDS.lock();
        let world = worlds.get(&id)?;
        // A reference cannot be handed out beyond the lock: the translation is
        // copied before it is released.
        world
            .memory
            .as_ref()
            .and_then(|memory| memory.translate(gpa))
    };
    memory_ref
}

/// Frees all entries (tests and kernel shutdown).
pub fn clear() {
    let worlds: BTreeMap<u64, World> = {
        let mut guard = WORLDS.lock();
        core::mem::take(&mut *guard)
    };
    for (_, world) in worlds {
        if let Some(memory) = world.memory {
            memory.destroy();
        }
    }
}

