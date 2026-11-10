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

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::{
    memory::frame::{FrameAllocOptions, FramePurpose, PhysFrame},
    process::{kthread, scheduler::ticks, sleep_current_task_ticks, TaskId},
    s9vm::{
        apic::LocalApic,
        caps::HwCaps,
        emulate::{interrupt_action, InterruptAction},
        exit::ExitClass,
        exitqueue::ExitQueue,
        guest::{FixedBits, GuestState},
        image::{Image, Segment},
        machine::Machine,
        memmap::{perms_from_abi, GuestMap, MapError, MAX_GPA},
        mmu::{Perms as MmuPerms, PAGE_SIZE},
        timing::{ExitLatencyHistogram, WorldTiming, EXIT_LATENCY_BUCKETS},
        vcpu::{ExitInfo, SecondLevelMemory, Vcpu, VcpuError},
    },
    sync::{SpinLock, WaitQueue},
};
use strat9_abi::vmm::{exit_kind, VmmExitEvent, VmmRegs};

/// Maximum number of simultaneous worlds (safety bound).
pub const MAX_WORLDS: usize = 64;
/// Maximum length of a name.
pub const NAME_MAX: usize = 32;
/// Maximum number of vCPUs per world (safety bound, before quotas).
pub const MAX_VCPUS_PER_WORLD: usize = 32;
/// Default guest page quota (1 GiB).
pub const DEFAULT_QUOTA_PAGES: u64 = 262_144;
/// `RFLAGS.IF`: the guest is interruptible.
const RFLAGS_IF: u64 = 1 << 9;
/// Maximum bytes queued for the guest console at once.
pub const MAX_CONSOLE_PENDING: usize = 64 * 1024;
/// Maximum bytes of console output kept for the user side.
pub const MAX_CONSOLE_OUTPUT: usize = 64 * 1024;
/// Maximum frames queued for the guest network device.
pub const MAX_PENDING_FRAMES: usize = 64;
/// Maximum size of one injected network frame.
pub const MAX_FRAME_SIZE: usize = 64 * 1024;
/// Maximum number of guest-transmitted frames buffered for the network
/// front-end.
pub const MAX_NETWORK_OUTPUT_FRAMES: usize = 64;
/// Maximum number of guest-transmitted octets buffered for the network
/// front-end.
pub const MAX_NETWORK_OUTPUT_BYTES: usize = 256 * 1024;

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

/// Cumulative execution counters of a world.
///
/// They are diagnostics only: nothing in the engine depends on them. They are
/// updated by the execution loop and exposed read-only through `/dev/vmm`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorldStats {
    /// `RUN` calls that reached the hardware.
    pub runs: u64,
    /// Exits handed to policy through the event queue.
    pub policy_exits: u64,
    /// Exits replayed in the kernel by the device model.
    pub emulated_exits: u64,
    /// Replayed I/O instructions (PIC ports, POST port).
    pub emulated_io: u64,
    /// Replayed MMIO accesses (APIC and I/O APIC pages).
    pub emulated_mmio: u64,
    /// Replayed MSR accesses (x2APIC window).
    pub emulated_msr: u64,
    /// Interrupts injected into the guest.
    pub injected_interrupts: u64,
    /// Times interrupt-window exiting was armed.
    pub windows_armed: u64,
    /// Guest time slices that expired (preemption timer).
    pub timer_exits: u64,
}

impl WorldStats {
    /// Adds another set of counters to this one.
    pub fn add(&mut self, other: &Self) {
        self.runs += other.runs;
        self.policy_exits += other.policy_exits;
        self.emulated_exits += other.emulated_exits;
        self.emulated_io += other.emulated_io;
        self.emulated_mmio += other.emulated_mmio;
        self.emulated_msr += other.emulated_msr;
        self.injected_interrupts += other.injected_interrupts;
        self.windows_armed += other.windows_armed;
        self.timer_exits += other.timer_exits;
    }
}

/// Number of exit classes tracked by [`WorldTimingSnapshot`].
pub const TIMING_CLASS_COUNT: usize = WorldTiming::class_count();

/// Compact, `Copy` view of a world's cumulative timing aggregates.
///
/// Produced by the read-only `timing()` accessor. Latencies are expressed in
/// time-stamp counter cycles, as measured on the CPU that ran the vCPU; no
/// conversion to nanoseconds is done here, because the time-stamp counter
/// frequency is a property of the host and must be supplied by the reader.
///
/// Semantics:
/// - the histogram is **cumulative** for the lifetime of the world;
/// - `window` and `peak_window` are the counts of the current and peak
///   sliding windows of the global exit-rate meter, one slot per `run_vcpu`
///   invocation (one time slice);
/// - percentiles are conservative upper bounds of logarithmic buckets, never
///   lower than the exact percentile (see the `timing` module).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorldTimingSnapshot {
    /// Number of exits recorded since the world was created.
    pub exits: u64,
    /// Mean latency of every recorded exit, in cycles (0 when `exits == 0`).
    pub mean_cycles: u64,
    /// 95th percentile upper bound of every recorded exit, in cycles.
    pub p95_cycles: u64,
    /// Smallest recorded exit latency, in cycles (0 when `exits == 0`).
    pub min_cycles: u64,
    /// Largest recorded exit latency, in cycles (0 when `exits == 0`).
    pub max_cycles: u64,
    /// Number of in-kernel device-model replays measured.
    pub handler_samples: u64,
    /// Mean device-model replay latency, in cycles (0 when no sample).
    pub handler_mean_cycles: u64,
    /// 95th percentile upper bound of the device-model replay latency.
    pub handler_p95_cycles: u64,
    /// Cumulative number of exits per class, indexed by
    /// [`WorldTiming::class_index`] (always `TIMING_CLASS_COUNT` entries).
    pub per_class: [u64; TIMING_CLASS_COUNT],
    /// Exits recorded in the current sliding window (all classes).
    pub window: u64,
    /// Highest sliding-window value observed (all classes).
    pub peak_window: u64,
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
            if let Err(error) = self
                .second_level
                .map_4k(gpa + index * PAGE_SIZE, hpa, perms)
            {
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

    /// Reserved guest-physical ranges, in address order.
    pub fn regions(&self) -> impl Iterator<Item = &crate::s9vm::memmap::Region> {
        self.map.regions()
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
    /// Guest chipset devices (8259A pair, I/O APIC) and the kernel bridge
    /// that replays their accesses without leaving the kernel.
    machine: Machine,
    /// Cumulative execution counters (diagnostics).
    stats: WorldStats,
    /// Cumulative exit-latency aggregates, per exit class (diagnostics).
    ///
    /// Taken out of the registry while a vCPU of the world runs, with the same
    /// take/put pattern as `stats`, so that the running guest never takes the
    /// registry lock and the exit path never allocates.
    timing: WorldTiming,
    /// Cumulative latency of the in-kernel device-model replay (fast-path
    /// exits), in time-stamp counter cycles. Same lifetime and take/put rules
    /// as `timing`.
    handler_timing: ExitLatencyHistogram,
    /// Console input queued by the user side, delivered at the next `RUN`.
    pending_console_input: Vec<u8>,
    /// Console output produced by the guest, drained by the user side.
    console_output: Vec<u8>,
    /// Frames queued for the guest network device, delivered at the next
    /// `RUN`.
    pending_frames: Vec<Vec<u8>>,
    /// Frames transmitted by the guest, waiting for the network front-end.
    network_output: Vec<Vec<u8>>,
    /// Octets currently queued in `network_output` (bounded).
    network_output_bytes: usize,
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
            machine: Machine::new(),
            stats: WorldStats::default(),
            timing: WorldTiming::default(),
            handler_timing: ExitLatencyHistogram::default(),
            pending_console_input: Vec::new(),
            console_output: Vec::new(),
            pending_frames: Vec::new(),
            network_output: Vec::new(),
            network_output_bytes: 0,
        },
    );
    Some(record)
}

/// Destroys a world and frees its guest memory.
///
/// The vCPU tasks are stopped and joined **before** the memory is freed: a
/// task still in flight could otherwise dereference the world's second-level
/// tables. A second concurrent call during the close returns `None`.
///
/// The timing aggregates (`timing`, `handler_timing`) are plain values owned by
/// the world: they are dropped with it, so no separate reset is needed and no
/// snapshot can outlive the world (the snapshot is `Copy`).
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
fn locate_slot(worlds: &mut BTreeMap<u64, World>, vcpu_id: u64) -> Option<(&mut World, usize)> {
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
    WORLDS.lock().values().map(|world| world.record).collect()
}

/// Logs an engine snapshot (kernel diagnostic).
pub fn debug_dump() {
    let worlds = list();
    log::info!(
        "[s9vm] debug: {} world(s), {} active CPU(s)",
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
            log::info!(
                "[s9vm] debug:   irqchip pic(imr={:#x}, irr={:#x}, isr={:#x}) ioapic(id={})",
                entry.machine.devices().pic.master().mask(),
                entry.machine.devices().pic.master().irr(),
                entry.machine.devices().pic.master().isr(),
                entry.machine.devices().ioapic.apic_id()
            );
            for slot in &entry.vcpus {
                log::info!(
                    "[s9vm] debug:   vcpu {} apic={} tpr={} irr={} isr={} irq={:?} nmi={} task={:?}",
                    slot.id,
                    slot.apic.apic_id(),
                    slot.apic.tpr(),
                    slot.apic.has_pending(),
                    slot.apic.in_service(),
                    slot.apic.pending_vector(),
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

/// A guest image loaded into a world's guest memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadedImage {
    /// Guest-physical entry point, relocated to the load base.
    pub entry: u64,
    /// Guest-physical base address where the image was loaded.
    pub image_base: u64,
    /// Lowest guest-physical address covered by the image (inclusive).
    pub span_min: u64,
    /// Highest guest-physical address covered by the image (exclusive).
    pub span_max: u64,
}

impl LoadedImage {
    /// Number of guest pages in the image span, holes included.
    pub const fn span_pages(&self) -> u64 {
        (self.span_max - self.span_min) / PAGE_SIZE
    }
}

/// Loads an ELF64 guest image into a world's guest memory.
///
/// The image is parsed and validated by [`Image::parse`]; every `PT_LOAD`
/// segment is then mapped through [`map_memory`] with its ELF permissions and
/// default write-back memory type. The file-backed prefix of each segment is
/// copied page by page into the pinned frames (GPA -> HPA -> HHDM) and the
/// remaining bytes (BSS) are zeroed. Nothing is executed: the policy layer
/// decides the initial registers.
///
/// `load_base_gpa` is the guest-physical address of the image base
/// ([`Image::base_vaddr`]) and must be 4 KiB aligned; the image virtual
/// addresses are relocated by the same delta. Loading is not atomic: if a
/// later segment cannot be mapped, the segments already mapped stay in place
/// and the world must be destroyed (the world memory layer has no unmap
/// primitive yet). A malformed image is rejected before any mapping.
pub fn load_image(
    world_id: u64,
    caps: &HwCaps,
    image_bytes: &[u8],
    load_base_gpa: u64,
) -> Result<LoadedImage, VmError> {
    let image = Image::parse(image_bytes).map_err(|error| {
        log::warn!("[s9vm] guest image rejected ({:?})", error);
        VmError::Map(MapError::InvalidRange)
    })?;
    if load_base_gpa % PAGE_SIZE != 0 {
        return Err(VmError::Map(MapError::InvalidRange));
    }
    let (span_min, span_max) = image
        .load_span(load_base_gpa)
        .filter(|(_, end)| *end <= MAX_GPA)
        .ok_or(VmError::Map(MapError::InvalidRange))?;
    let entry = image
        .entry_gpa(load_base_gpa)
        .ok_or(VmError::Map(MapError::InvalidRange))?;
    if !image.entry_is_mapped() {
        log::warn!(
            "[s9vm] guest image entry {:#x} is outside every loadable segment",
            image.entry()
        );
    }

    // 1. Maps the page-aligned footprint of every segment. `map_memory` keeps
    //    the registry lock out of the frame allocation path.
    for segment in image.segments() {
        let gpa = image
            .segment_gpa(load_base_gpa, segment)
            .ok_or(VmError::Map(MapError::InvalidRange))?;
        map_memory(
            world_id,
            caps,
            gpa,
            segment.page_len(),
            segment.perms_bits(),
            0,
        )?;
    }

    // 2. Fills the frames: file-backed bytes, then the zero-filled tail. No
    //    allocation happens here, so the registry lock can be held while the
    //    guest memory is populated.
    {
        let mut worlds = WORLDS.lock();
        let world = worlds.get_mut(&world_id).ok_or(VmError::Unknown)?;
        let memory = world
            .memory
            .as_ref()
            .ok_or(VmError::Map(MapError::NotMapped))?;
        for segment in image.segments() {
            copy_segment(memory, &image, segment, load_base_gpa)?;
        }
    }

    log::info!(
        "[s9vm] image loaded at {:#x}: {} segment(s), {} page(s), entry {:#x}",
        load_base_gpa,
        image.segment_count(),
        image.total_pages(),
        entry
    );
    Ok(LoadedImage {
        entry,
        image_base: load_base_gpa,
        span_min,
        span_max,
    })
}

/// Copies the file-backed bytes of one segment and zeroes its BSS.
fn copy_segment(
    memory: &WorldMemory,
    image: &Image<'_>,
    segment: &Segment,
    load_base_gpa: u64,
) -> Result<(), VmError> {
    let file_bytes = image
        .bytes_for_segment(segment)
        .ok_or(VmError::Map(MapError::NotMapped))?;
    let page_gpa = image
        .segment_gpa(load_base_gpa, segment)
        .ok_or(VmError::Map(MapError::InvalidRange))?;
    let page_start = segment.page_start();
    let file_end_vaddr = segment.vaddr + segment.filesz;
    let end_vaddr = segment.end_vaddr();
    for index in 0..segment.page_count() {
        let page_vaddr = page_start + index * PAGE_SIZE;
        let page_end_vaddr = page_vaddr + PAGE_SIZE;
        let hpa = memory
            .translate(page_gpa + index * PAGE_SIZE)
            .ok_or(VmError::Map(MapError::NotMapped))?;
        let page_virt = crate::memory::phys_to_virt(hpa) as *mut u8;
        // File-backed bytes of this page.
        let copy_start = core::cmp::max(page_vaddr, segment.vaddr);
        let copy_end = core::cmp::min(page_end_vaddr, file_end_vaddr);
        if copy_start < copy_end {
            let length = (copy_end - copy_start) as usize;
            let source_offset = (copy_start - segment.vaddr) as usize;
            let destination_offset = (copy_start - page_vaddr) as usize;
            // SAFETY: the page is owned by this world and mapped by the HHDM;
            // `length` bytes stay inside one page, and `source_offset` stays
            // inside the file-backed slice of the segment.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    file_bytes.as_ptr().add(source_offset),
                    page_virt.add(destination_offset),
                    length,
                );
            }
        }
        // Zero-filled tail (BSS) of this page.
        let zero_start = core::cmp::max(page_vaddr, file_end_vaddr);
        let zero_end = core::cmp::min(page_end_vaddr, end_vaddr);
        if zero_start < zero_end {
            let length = (zero_end - zero_start) as usize;
            let destination_offset = (zero_start - page_vaddr) as usize;
            // SAFETY: same page as above; the zeroed range stays inside it.
            unsafe {
                core::ptr::write_bytes(page_virt.add(destination_offset), 0, length);
            }
        }
    }
    Ok(())
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
///
/// # Timing
///
/// Every guest entry is bracketed by two time-stamp counter reads. The delta is
/// recorded in the world's cumulative timing aggregates, per exit class: the
/// decoded reason for exits that reach policy, the functional class for exits
/// replayed by the kernel. Because the pair spans the guest entry and the exit
/// delivery, the delta measures the entry/exit cost **on the CPU that runs the
/// vCPU** only for single-instruction exits (I/O port, MSR access, second-level
/// violation), where the guest time is negligible; for asynchronous exits
/// (external interrupt, preemption timer, halt) it also contains the guest time
/// slice that preceded the exit, and must not be read as the exit latency.
/// Device-model replay latency is measured separately around the replay.
///
/// The sliding window of the rate meters is advanced once per call: one call is
/// one time slice.
pub fn run_vcpu(vcpu_id: u64, caps: &HwCaps) -> Result<(), RunError> {
    if crate::s9vm::active_cpu_count() == 0 {
        return Err(RunError::HardwareNotReady);
    }
    // 1. Takes the hardware context and the registers out of the registry,
    //    without holding the lock during execution.
    let (
        world_id,
        mut hardware,
        mut regs,
        pointer,
        pending_nmi,
        mut machine,
        mut apic,
        mut stats,
        mut timing,
        mut handler_timing,
        mut pending_console_input,
        mut pending_frames,
        mut console_output,
        mut network_output,
        mut network_output_bytes,
    ) = {
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
        let pending_nmi = core::mem::replace(&mut slot.pending_nmi, false);
        let apic_id = slot.apic_id;
        // The device model and the local APIC stay out of the registry while
        // the guest runs: the exit handler updates them without taking the
        // registry lock, which a running guest must never wait on.
        let machine = core::mem::replace(&mut world.machine, Machine::new());
        let apic = core::mem::replace(&mut slot.apic, LocalApic::new(apic_id));
        let stats = core::mem::replace(&mut world.stats, WorldStats::default());
        // The timing aggregates follow the same take/put pattern as `stats`:
        // the running vCPU updates them without ever taking the registry lock.
        let timing = core::mem::replace(&mut world.timing, WorldTiming::default());
        let handler_timing =
            core::mem::replace(&mut world.handler_timing, ExitLatencyHistogram::default());
        let pending_console_input = core::mem::take(&mut world.pending_console_input);
        let pending_frames = core::mem::take(&mut world.pending_frames);
        let console_output = core::mem::take(&mut world.console_output);
        let network_output = core::mem::take(&mut world.network_output);
        let network_output_bytes = core::mem::replace(&mut world.network_output_bytes, 0);
        (
            world.record.id,
            hardware,
            slot.regs,
            pointer,
            pending_nmi,
            machine,
            apic,
            stats,
            timing,
            handler_timing,
            pending_console_input,
            pending_frames,
            console_output,
            network_output,
            network_output_bytes,
        )
    };
    // One sliding-window slot per invocation: the rate meters measure exits per
    // time slice, and a "slice" is one `run_vcpu` call, whether or not the
    // guest actually entered (hardware setup failures included).
    timing.advance_window();
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
    stats.runs += 1;
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
        }
        if result.is_ok() {
            // Queued console input and network frames entered the world
            // while the vCPU was not running (they cannot be touched during
            // execution): hand them to the device model now, then service the
            // receive queues against the guest memory.
            if !pending_console_input.is_empty() {
                machine
                    .devices_mut()
                    .console
                    .push_input(&pending_console_input);
                pending_console_input.clear();
            }
            if !pending_frames.is_empty() {
                for frame in &pending_frames {
                    machine.push_network_frame(frame);
                }
                pending_frames.clear();
            }
            machine.service_devices(&mut hardware);
            let mut resumed = 0u32;
            // True while interrupt-window exiting is armed in the control
            // block: the guest has a pending vector but interrupts disabled.
            let mut window_armed = false;
            loop {
                // Interrupt delivery. The local APIC is the only source: the
                // highest-priority deliverable vector is injected when the
                // guest is interruptible; otherwise the interrupt window is
                // armed so that the vector is delivered as soon as the guest
                // enables interrupts. The window control is disarmed as soon
                // as it is no longer needed, otherwise the processor would
                // exit after every single instruction in the guest.
                let interruptible = hardware.guest().rflags & RFLAGS_IF != 0;
                let pending = apic.pending_vector();
                match interrupt_action(pending.is_some(), interruptible, window_armed) {
                    InterruptAction::Inject => {
                        if let Some(vector) = pending {
                            if let Err(error) = hardware.inject_interrupt(vector) {
                                result = Err(RunError::Hardware(error));
                                break;
                            }
                            // The vector moves to the in-service register: the
                            // processor delivers it at the next entry.
                            let _ = apic.service();
                            stats.injected_interrupts += 1;
                        }
                        if window_armed {
                            match hardware.set_interrupt_window_exiting(caps, false) {
                                Ok(_) => window_armed = false,
                                Err(error) => {
                                    result = Err(RunError::Hardware(error));
                                    break;
                                }
                            }
                        }
                    }
                    InterruptAction::ArmWindow => {
                        match hardware.set_interrupt_window_exiting(caps, true) {
                            Ok(armed) => {
                                if armed {
                                    stats.windows_armed += 1;
                                }
                                window_armed = armed;
                            }
                            Err(error) => {
                                result = Err(RunError::Hardware(error));
                                break;
                            }
                        }
                    }
                    InterruptAction::DisarmWindow => {
                        match hardware.set_interrupt_window_exiting(caps, false) {
                            Ok(_) => window_armed = false,
                            Err(error) => {
                                result = Err(RunError::Hardware(error));
                                break;
                            }
                        }
                    }
                    InterruptAction::None => {}
                }
                // Bracket the guest entry with two time-stamp counter reads.
                // The delta is the wall-clock time spent between the host and
                // the guest: guest execution plus the hardware entry and exit
                // sequences. See the function documentation for what it means
                // per class.
                let entry_tsc = core::arch::x86_64::_rdtsc();
                let run_result = hardware.run();
                let exit_tsc = core::arch::x86_64::_rdtsc();
                let exit_cycles = exit_tsc.saturating_sub(entry_tsc);
                match run_result {
                    Ok(exit) => {
                        let class = exit.class();
                        // Kernel fast path: accesses to the modeled devices
                        // are replayed in place, so the guest never observes
                        // the exit and policy is not involved.
                        if matches!(
                            class,
                            ExitClass::IoPort | ExitClass::Msr | ExitClass::EptViolation
                        ) {
                            // Replay latency: handler cost only, without the
                            // guest time contained in `exit_cycles`.
                            let handler_tsc = core::arch::x86_64::_rdtsc();
                            let handled = machine.handle(&mut hardware, &mut apic, &exit);
                            let handler_cycles =
                                core::arch::x86_64::_rdtsc().saturating_sub(handler_tsc);
                            match handled {
                                Ok(true) => {
                                    timing.record(class, exit_cycles);
                                    handler_timing.record(handler_cycles);
                                    if resumed >= MAX_RESUMED_EXITS {
                                        result = Err(RunError::ExitStorm);
                                        break;
                                    }
                                    resumed += 1;
                                    stats.emulated_exits += 1;
                                    match class {
                                        ExitClass::IoPort => stats.emulated_io += 1,
                                        ExitClass::EptViolation => stats.emulated_mmio += 1,
                                        ExitClass::Msr => stats.emulated_msr += 1,
                                        _ => {}
                                    }
                                    // Frames transmitted by the guest are
                                    // queued for the network front-end. The
                                    // queue is bounded: a slow consumer loses
                                    // the oldest frames instead of growing
                                    // kernel memory without limit.
                                    let frames = machine.drain_network_frames();
                                    if !frames.is_empty() {
                                        log::info!(
                                            "[s9vm] net: {} octets transmitted",
                                            frames.iter().map(|frame| frame.len()).sum::<usize>()
                                        );
                                        for frame in frames {
                                            if frame.len() > MAX_FRAME_SIZE {
                                                continue;
                                            }
                                            if network_output.len() >= MAX_NETWORK_OUTPUT_FRAMES
                                                || network_output_bytes + frame.len()
                                                    > MAX_NETWORK_OUTPUT_BYTES
                                            {
                                                let dropped = network_output.remove(0);
                                                network_output_bytes = network_output_bytes
                                                    .saturating_sub(dropped.len());
                                            }
                                            network_output_bytes += frame.len();
                                            network_output.push(frame);
                                        }
                                    }
                                    // The console device model collects the
                                    // bytes the guest wrote; the kernel only
                                    // routes them to its own log for now.
                                    let output = machine.drain_console();
                                    if !output.is_empty() {
                                        log::info!(
                                            "[s9vm] console: {}",
                                            core::str::from_utf8(&output)
                                                .unwrap_or("<binary data>")
                                        );
                                        push_console_output(&mut console_output, &output);
                                    }
                                    continue;
                                }
                                Ok(false) | Err(_) => {}
                            }
                        }
                        // Exits that are not replayed by the kernel: the
                        // decoded reason is recorded so that guest entry
                        // failures remain distinguishable from ordinary exits.
                        timing.record_exit(exit.reason, exit_cycles);
                        if is_resumable(class) && resumed < MAX_RESUMED_EXITS {
                            resumed += 1;
                            continue;
                        }
                        if is_resumable(class) {
                            result = Err(RunError::ExitStorm);
                        } else {
                            stats.policy_exits += 1;
                            if class == ExitClass::PreemptionTimer {
                                stats.timer_exits += 1;
                            }
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
        world.machine = machine;
        world.stats = stats;
        world.timing = timing;
        world.handler_timing = handler_timing;
        world.console_output = console_output;
        world.pending_console_input = pending_console_input;
        world.pending_frames = pending_frames;
        world.network_output = network_output;
        world.network_output_bytes = network_output_bytes;
        if let Some(slot) = world.vcpus.iter_mut().find(|slot| slot.id == vcpu_id) {
            slot.regs = regs;
            slot.hardware = Some(hardware);
            slot.apic = apic;
        }
    }
    result
}

/// Appends bytes to the bounded console-output queue of a world.
fn push_console_output(queue: &mut Vec<u8>, bytes: &[u8]) {
    queue.extend_from_slice(bytes);
    if queue.len() > MAX_CONSOLE_OUTPUT {
        let excess = queue.len() - MAX_CONSOLE_OUTPUT;
        queue.drain(..excess);
    }
}

/// Queues console input for a world.
///
/// The bytes are delivered to the guest's receive queue at the next `RUN`;
/// this is the entry point of a console scheme.
pub fn push_console_input(world_id: u64, bytes: &[u8]) -> Result<usize, ()> {
    let mut worlds = WORLDS.lock();
    let world = worlds.get_mut(&world_id).ok_or(())?;
    let room = MAX_CONSOLE_PENDING.saturating_sub(world.pending_console_input.len());
    let count = core::cmp::min(room, bytes.len());
    world
        .pending_console_input
        .extend_from_slice(&bytes[..count]);
    Ok(count)
}

/// Drains console output of a world into `out`.
///
/// Returns the number of bytes copied (0 when nothing is pending).
pub fn read_console_output(world_id: u64, out: &mut [u8]) -> Result<usize, ()> {
    let mut worlds = WORLDS.lock();
    let world = worlds.get_mut(&world_id).ok_or(())?;
    let count = core::cmp::min(out.len(), world.console_output.len());
    out[..count].copy_from_slice(&world.console_output[..count]);
    world.console_output.drain(..count);
    Ok(count)
}

/// Writes the guest boot-information page of a world at `gpa`.
///
/// The page describes the memory ranges reserved for the world and the virtual
/// devices of its machine (MMIO base, I/O APIC line, device-specific value).
/// `gpa` must be page aligned and mapped in the world.
pub fn write_boot_info(world_id: u64, gpa: u64) -> Result<(), VmError> {
    use crate::s9vm::{bootinfo, emulate};
    if gpa % PAGE_SIZE != 0 {
        return Err(VmError::Map(MapError::InvalidRange));
    }
    let mut worlds = WORLDS.lock();
    let world = worlds.get_mut(&world_id).ok_or(VmError::Unknown)?;
    let memory = world
        .memory
        .as_ref()
        .ok_or(VmError::Map(MapError::NotMapped))?;
    let mut info = bootinfo::BootInfo::new();
    for region in memory.regions() {
        info.add_memory(region.gpa, region.len, bootinfo::memory_kind::RAM);
    }
    info.flags = bootinfo::flags::COMPLETE;
    let devices = world.machine.devices();
    if info.add_device(
        bootinfo::device_kind::CONSOLE,
        emulate::CONSOLE_IRQ_LINE as u32,
        emulate::CONSOLE_BASE,
        0,
    ) {
        info.flags |= bootinfo::flags::HAS_CONSOLE;
    }
    if info.add_device(
        bootinfo::device_kind::BLOCK,
        emulate::BLK_IRQ_LINE as u32,
        emulate::BLK_BASE,
        devices.blk.sectors(),
    ) {
        info.flags |= bootinfo::flags::HAS_BLOCK;
    }
    if info.add_device(
        bootinfo::device_kind::NETWORK,
        emulate::NET_IRQ_LINE as u32,
        emulate::NET_BASE,
        0,
    ) {
        info.flags |= bootinfo::flags::HAS_NETWORK;
    }
    let mut page = [0u8; bootinfo::SIZE];
    info.encode(&mut page);
    let hpa = memory
        .translate(gpa)
        .ok_or(VmError::Map(MapError::NotMapped))?;
    // SAFETY: `hpa` belongs to a frame reserved for this world and is mapped by
    // the HHDM; `SIZE` bytes stay inside the page.
    unsafe {
        core::ptr::copy_nonoverlapping(
            page.as_ptr(),
            crate::memory::phys_to_virt(hpa) as *mut u8,
            bootinfo::SIZE,
        );
    }
    Ok(())
}

/// Conventional guest-physical address of the firmware table image.
///
/// ACPI-compatible guests search for the `RSD PTR ` signature on 16-byte
/// boundaries in the extended BIOS data area and in the
/// `0x000E_0000..=0x000F_FFFF` window, so placing the image there makes it
/// discoverable without extending the boot-information page.
pub const ACPI_GPA: u64 = 0x000E_0000;

/// Writes the firmware description tables of a world at `base_gpa`.
///
/// The image is built from the world's vCPU APIC identifiers (one MADT Local
/// APIC entry each) and placed in guest memory. If the range is not mapped
/// yet, it is mapped read-only; if it already belongs to guest RAM (a firmware
/// region mapped by the loader, for instance), the tables are written into the
/// existing pages. `base_gpa` must be 16-byte aligned and the image must stay
/// inside the guest-physical address space.
pub fn write_acpi(world_id: u64, caps: &HwCaps, base_gpa: u64) -> Result<(), VmError> {
    use crate::s9vm::acpi::{AcpiBuilder, IMAGE_ALIGN, MAX_IMAGE_LEN};

    if base_gpa % IMAGE_ALIGN != 0 {
        return Err(VmError::Map(MapError::InvalidRange));
    }
    if base_gpa
        .checked_add(MAX_IMAGE_LEN as u64)
        .map_or(true, |end| end > MAX_GPA)
    {
        return Err(VmError::Map(MapError::InvalidRange));
    }

    // 1. APIC identifiers of the world's vCPUs (the MADT describes them).
    let apic_ids: Vec<u8> = {
        let worlds = WORLDS.lock();
        let world = worlds.get(&world_id).ok_or(VmError::Unknown)?;
        if world.vcpus.is_empty() {
            return Err(VmError::Map(MapError::InvalidRange));
        }
        world.vcpus.iter().map(|slot| slot.apic_id as u8).collect()
    };

    // 2. Builds the image outside the registry lock.
    let builder = AcpiBuilder::new(base_gpa, &apic_ids);
    let layout = builder
        .layout()
        .map_err(|_| VmError::Map(MapError::InvalidRange))?;
    let mut image = alloc::vec![0u8; layout.total_len];
    builder
        .encode(&mut image)
        .map_err(|_| VmError::Map(MapError::InvalidRange))?;
    let len = image.len();
    let page_len = ((len as u64 + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;

    // 3. Maps the window when it is not already backed by guest memory. An
    //    overlap is not an error: the range may already be covered by a larger
    //    reserved region, in which case the copy below simply uses it.
    let already_mapped = {
        let worlds = WORLDS.lock();
        match worlds
            .get(&world_id)
            .and_then(|world| world.memory.as_ref())
        {
            Some(memory) => (0..page_len)
                .step_by(PAGE_SIZE as usize)
                .all(|offset| memory.translate(base_gpa + offset as u64).is_some()),
            None => return Err(VmError::Map(MapError::NotMapped)),
        }
    };
    if !already_mapped {
        if let Err(error) = map_memory(world_id, caps, base_gpa, page_len, 1, 0) {
            if error != VmError::Map(MapError::Overlap) {
                return Err(error);
            }
        }
    }

    // 4. Copies the tables page by page through the HHDM.
    let mut worlds = WORLDS.lock();
    let world = worlds.get_mut(&world_id).ok_or(VmError::Unknown)?;
    let memory = world
        .memory
        .as_ref()
        .ok_or(VmError::Map(MapError::NotMapped))?;
    let mut copied = 0usize;
    while copied < len {
        let page_gpa = base_gpa + ((copied / PAGE_SIZE as usize) * PAGE_SIZE as usize) as u64;
        let page_offset = copied % PAGE_SIZE as usize;
        let count = core::cmp::min(PAGE_SIZE as usize - page_offset, len - copied);
        let hpa = memory
            .translate(page_gpa)
            .ok_or(VmError::Map(MapError::NotMapped))?;
        // SAFETY: the page belongs to this world and is mapped by the HHDM;
        // `page_offset + count <= PAGE_SIZE`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                image[copied..].as_ptr(),
                (crate::memory::phys_to_virt(hpa) as *mut u8).add(page_offset),
                count,
            );
        }
        copied += count;
    }
    drop(worlds);

    log::info!(
        "[s9vm] firmware tables at {:#x}: {} byte(s), {} vCPU(s)",
        base_gpa,
        len,
        apic_ids.len()
    );
    Ok(())
}

/// Peeks at the oldest pending exit event of a world, without consuming it.
///
/// The exit queue is owned by the policy; this accessor only feeds diagnostics
/// (`/dev/vmm/<id>/exits`) and never changes the queue.
pub fn peek_exit(world_id: u64) -> Result<VmmExitEvent, ()> {
    WORLDS
        .lock()
        .get(&world_id)
        .ok_or(())?
        .exits
        .peek()
        .map_err(|_| ())
}

/// Pops one frame transmitted by the guest and queued for the network
/// front-end. Returns `Ok(None)` when the queue is empty.
pub fn read_network_frame(world_id: u64) -> Result<Option<Vec<u8>>, ()> {
    let mut worlds = WORLDS.lock();
    let world = worlds.get_mut(&world_id).ok_or(())?;
    if world.network_output.is_empty() {
        return Ok(None);
    }
    let frame = world.network_output.remove(0);
    world.network_output_bytes = world.network_output_bytes.saturating_sub(frame.len());
    Ok(Some(frame))
}

/// Capacity of the world's block device, in 512-byte sectors.
pub fn disk_sectors(world_id: u64) -> Option<u64> {
    WORLDS
        .lock()
        .get(&world_id)
        .map(|world| world.machine.devices().blk.sectors())
}

/// Reads sectors from the world's block device into `out`.
///
/// Returns the number of bytes copied, clamped to the disk capacity and to the
/// length of `out`.
pub fn read_disk(world_id: u64, sector: u64, out: &mut [u8]) -> Result<usize, ()> {
    let mut worlds = WORLDS.lock();
    let world = worlds.get_mut(&world_id).ok_or(())?;
    let disk = world.machine.devices_mut().blk.disk_mut();
    let offset = sector
        .checked_mul(512)
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or(())?;
    if offset >= disk.len() {
        return Ok(0);
    }
    let count = core::cmp::min(out.len(), disk.len() - offset);
    out[..count].copy_from_slice(&disk[offset..offset + count]);
    Ok(count)
}

/// Writes sectors to the world's block device from `data`.
///
/// Returns the number of bytes written, clamped to the disk capacity and to
/// the length of `data`.
pub fn write_disk(world_id: u64, sector: u64, data: &[u8]) -> Result<usize, ()> {
    let mut worlds = WORLDS.lock();
    let world = worlds.get_mut(&world_id).ok_or(())?;
    let disk = world.machine.devices_mut().blk.disk_mut();
    let offset = sector
        .checked_mul(512)
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or(())?;
    if offset >= disk.len() {
        return Ok(0);
    }
    let count = core::cmp::min(data.len(), disk.len() - offset);
    disk[offset..offset + count].copy_from_slice(&data[..count]);
    Ok(count)
}

/// Diagnostic snapshot of one logical vCPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VcpuSnapshot {
    /// Opaque vCPU identifier.
    pub id: u64,
    /// Guest APIC identifier.
    pub apic_id: u32,
    /// `true` when a hardware context has been created (at least one `RUN`).
    pub hardware_ready: bool,
    /// `true` while a `RUN` request is pending or executing.
    pub executing: bool,
    /// `true` when an NMI is pending delivery.
    pub pending_nmi: bool,
}

/// Diagnostic snapshot of every vCPU of a world.
pub fn vcpu_snapshots(world_id: u64) -> Option<Vec<VcpuSnapshot>> {
    let worlds = WORLDS.lock();
    let world = worlds.get(&world_id)?;
    Some(
        world
            .vcpus
            .iter()
            .map(|slot| VcpuSnapshot {
                id: slot.id,
                apic_id: slot.apic_id,
                hardware_ready: slot.hardware.is_some(),
                executing: slot.run_requested || slot.run_in_flight,
                pending_nmi: slot.pending_nmi,
            })
            .collect(),
    )
}

/// Queues a frame for the network device of a world.
///
/// The frame is handed to the guest's receive queue at the next `RUN`; this is
/// the entry point a network scheme will use.
pub fn push_network_frame(world_id: u64, frame: &[u8]) -> Result<(), ()> {
    let mut worlds = WORLDS.lock();
    let world = worlds.get_mut(&world_id).ok_or(())?;
    if frame.len() > MAX_FRAME_SIZE || world.pending_frames.len() >= MAX_PENDING_FRAMES {
        return Err(());
    }
    world.pending_frames.push(frame.to_vec());
    Ok(())
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

/// Cumulative execution counters of a world.
pub fn stats(world_id: u64) -> Option<WorldStats> {
    WORLDS.lock().get(&world_id).map(|world| world.stats)
}

/// Cumulative execution counters of every world.
pub fn total_stats() -> WorldStats {
    let worlds = WORLDS.lock();
    let mut total = WorldStats::default();
    for world in worlds.values() {
        total.add(&world.stats);
    }
    total
}

/// Upper bound of the bucket that contains the `p`-th sample of the union of
/// every per-class histogram, in cycles.
///
/// The merged distribution is never materialised: the populations are summed
/// bucket by bucket across the classes, which keeps the accessor allocation
/// free. This is the same conservative semantics as
/// `ExitLatencyHistogram::percentile`.
fn merged_percentile(timing: &WorldTiming, p: u8, count: u64) -> u64 {
    if count == 0 {
        return 0;
    }
    let clamped = if p > 100 { 100 } else { p } as u64;
    let scaled = clamped.saturating_mul(count);
    let mut rank = scaled / 100;
    if scaled % 100 != 0 || rank == 0 {
        rank = rank.saturating_add(1);
    }
    let mut cumulative = 0u64;
    for bucket in 0..EXIT_LATENCY_BUCKETS {
        let mut population = 0u64;
        for index in 0..TIMING_CLASS_COUNT {
            if let Some(class) = WorldTiming::class_at(index) {
                population = population.saturating_add(timing.latency(class).bucket_count(bucket));
            }
        }
        cumulative = cumulative.saturating_add(population);
        if cumulative >= rank {
            return ExitLatencyHistogram::bucket_upper_bound(bucket);
        }
    }
    // Defensive: the populations sum to `count`, so the loop always returns.
    0
}

/// Builds a compact snapshot from the two per-world aggregates.
fn timing_snapshot(timing: &WorldTiming, handler: &ExitLatencyHistogram) -> WorldTimingSnapshot {
    let mut snapshot = WorldTimingSnapshot::default();
    let mut sum = 0u64;
    let mut min = u64::MAX;
    let mut max = 0u64;
    for index in 0..TIMING_CLASS_COUNT {
        let Some(class) = WorldTiming::class_at(index) else {
            continue;
        };
        let histogram = timing.latency(class);
        snapshot.per_class[index] = histogram.count();
        snapshot.exits = snapshot.exits.saturating_add(histogram.count());
        sum = sum.saturating_add(histogram.sum());
        if let Some(value) = histogram.min() {
            if value < min {
                min = value;
            }
        }
        if let Some(value) = histogram.max() {
            if value > max {
                max = value;
            }
        }
    }
    if snapshot.exits != 0 {
        snapshot.mean_cycles = sum / snapshot.exits;
        snapshot.min_cycles = min;
        snapshot.max_cycles = max;
        snapshot.p95_cycles = merged_percentile(timing, 95, snapshot.exits);
    }
    snapshot.handler_samples = handler.count();
    snapshot.handler_mean_cycles = handler.mean().unwrap_or(0);
    snapshot.handler_p95_cycles = handler.percentile(95).unwrap_or(0);
    snapshot.window = timing.total_rate().window();
    snapshot.peak_window = timing.total_rate().peak_window();
    snapshot
}

/// Read-only timing snapshot of a world.
///
/// Returns `None` when the world does not exist. The aggregates are taken out
/// of the registry while a vCPU runs (the execution path must never take the
/// registry lock), so a snapshot taken during execution reports the state of
/// the last completed time slice; the in-flight samples are put back when
/// `run_vcpu` returns.
pub fn timing(world_id: u64) -> Option<WorldTimingSnapshot> {
    let worlds = WORLDS.lock();
    let world = worlds.get(&world_id)?;
    Some(timing_snapshot(&world.timing, &world.handler_timing))
}

/// Returns the second-level translation pointer (EPTP) of a world.
///
/// The value is the control-block pointer the hardware uses to walk the guest
/// physical address space; it is the world's real translation table, not a
/// mirror. It stays valid as long as the world exists and its guest memory has
/// not been destroyed, but it must be treated as an opaque, short-lived value:
/// the registry lock is taken only for the lookup, so the caller must already
/// synchronise with world destruction (or copy the value while the world is
/// known to be alive, e.g. during a `RUN`). Returns [`VmError::Unknown`] when
/// the world does not exist and [`VmError::Map`] with
/// [`MapError::NotMapped`] when the world has no guest memory yet.
pub fn second_level_pointer(world_id: u64, caps: &HwCaps) -> Result<u64, VmError> {
    let worlds = WORLDS.lock();
    let world = worlds.get(&world_id).ok_or(VmError::Unknown)?;
    let memory = world
        .memory
        .as_ref()
        .ok_or(VmError::Map(MapError::NotMapped))?;
    Ok(memory.second_level_pointer(caps))
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

/// Completes an exit that the policy emulated: writes the result value to
/// the guest `RAX` and adds `advance` bytes to the guest `RIP`.
///
/// `advance` is 0 for exits that already advanced `RIP` (I/O instructions);
/// it is the instruction length for exits that must be retried or skipped
/// after emulation (EPT violations, MMIO). Only the software register block is
/// updated: the next `RUN` rebuilds the guest state from it.
pub fn complete_exit(vcpu_id: u64, value: u64, advance: u64) -> Result<(), VcpuRegistryError> {
    let mut worlds = WORLDS.lock();
    let world = vcpu_world_mut(&mut worlds, vcpu_id).ok_or(VcpuRegistryError::Unknown)?;
    let slot = world
        .vcpus
        .iter_mut()
        .find(|slot| slot.id == vcpu_id)
        .ok_or(VcpuRegistryError::Unknown)?;
    slot.regs.rax = value;
    slot.regs.rip = slot.regs.rip.wrapping_add(advance);
    Ok(())
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
    // The local APIC is the single delivery path: the vector waits in the IRR
    // until the guest is interruptible (the execution loop injects it and
    // arms the interrupt window when needed).
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

/// Pending deliverable interrupt vector for a vCPU, if any.
pub fn pending_irq(vcpu_id: u64) -> Option<u8> {
    let mut worlds = WORLDS.lock();
    let world = vcpu_world_mut(&mut worlds, vcpu_id)?;
    world
        .vcpus
        .iter()
        .find(|slot| slot.id == vcpu_id)
        .and_then(|slot| slot.apic.pending_vector())
}

/// Finds the world owning a vCPU (excluding closing worlds).
fn vcpu_world_mut(worlds: &mut BTreeMap<u64, World>, vcpu_id: u64) -> Option<&mut World> {
    worlds
        .values_mut()
        .find(|world| !world.closing && world.vcpus.iter().any(|slot| slot.id == vcpu_id))
}

/// Writes a vCPU's register block.
pub fn set_vcpu_regs(
    vcpu_id: u64,
    regs: &strat9_abi::vmm::VmmRegs,
) -> Result<(), VcpuRegistryError> {
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
