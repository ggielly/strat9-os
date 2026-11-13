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

use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::{
    hardware::iommu::{DmaProt, Domain as HardwareIommuDomain, FaultPolicy, MappingKind, Sbdf},
    memory::frame::{FrameAllocOptions, FramePurpose, PhysFrame},
    process::{TaskId, kthread, scheduler::ticks, sleep_current_task_ticks},
    s9vm::{
        apic::LocalApic,
        caps::HwCaps,
        emulate::{InterruptAction, interrupt_action, interrupt_deliverable},
        exit::ExitClass,
        exitqueue::ExitQueue,
        guest::{FixedBits, GuestState},
        image::{Image, Segment},
        iommu::{DeviceId, DomainId, IommuError, IommuModel},
        machine::Machine,
        memmap::{GuestMap, MAX_GPA, MapError, contiguous_2m_aligned, perms_from_abi, plan_map},
        mmu::{PAGE_SIZE, Perms as MmuPerms},
        timing::{EXIT_LATENCY_BUCKETS, ExitLatencyHistogram, WorldTiming},
        vcpu::{ExitInfo, SecondLevelMemory, Vcpu, VcpuError},
        virtio_blk::VirtioBlk,
    },
    sync::{SpinLock, WaitQueue},
};
use strat9_abi::vmm::{
    VMM_DISK_DEFAULT_BYTES, VMM_DISK_MAX_BYTES, VMM_DISK_SECTOR_SIZE, VMM_IOMMU_MAX_MAP_BYTES,
    VmmExitEvent, VmmRegs, exit_kind,
};

/// Maximum number of simultaneous worlds (safety bound).
pub const MAX_WORLDS: usize = 64;
/// Maximum length of a name.
pub const NAME_MAX: usize = 32;
/// Maximum number of vCPUs per world (safety bound, before quotas).
pub const MAX_VCPUS_PER_WORLD: usize = 32;
/// Maximum number of guest modules/initrd ranges per world.
pub const MAX_MODULES_PER_WORLD: usize = 4;
/// Maximum size of one guest module copied through `SYS_VMM_LOAD_MODULE`.
pub const MAX_MODULE_BYTES: usize = 64 * 1024 * 1024;
/// Maximum length of the guest command line stored by `SYS_VMM_SET_CMDLINE`.
pub const CMDLINE_MAX: usize = 256;
/// Maximum bytes covered by one `SYS_VMM_MAP_IOMMU` request (1 GiB).
pub const IOMMU_MAX_MAP_BYTES: u64 = VMM_IOMMU_MAX_MAP_BYTES;
/// Granularity of one IOMMU leaf installed by `SYS_VMM_MAP_IOMMU`.
const IOMMU_PAGE_SIZE: u64 = PAGE_SIZE;
/// Size of a large IOMMU leaf (2 MiB) installed when `REQUIRE_2M` is set.
const IOMMU_LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;
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
    /// # Granularity
    ///
    /// The range is split by [`memmap::plan_map`]: a 2 MiB-aligned middle is
    /// mapped with 2 MiB second-level leaves when the 512 newly allocated
    /// host frames are 2 MiB aligned and physically contiguous, while a
    /// partial head or tail stays on 4 KiB pages. A 2 MiB segment whose frames
    /// are not contiguous (fragmented allocator) falls back to 4 KiB pages for
    /// that segment, so correctness never depends on host contiguity.
    ///
    /// Large leaves reduce second-level table memory and TLB pressure; the
    /// fallback keeps the mapping usable when the allocator cannot provide a
    /// contiguous block.
    ///
    /// On failure, every mapping and every frame allocated during the call is
    /// undone: the world's memory stays consistent. Quota accounting is
    /// unchanged: a 2 MiB leaf still counts as 512 pages.
    pub fn map(
        &mut self,
        _caps: &HwCaps,
        gpa: u64,
        len: u64,
        perms_bits: u32,
        memtype: u8,
    ) -> Result<u64, VmError> {
        // 1. Plan the granularity, then validate and reserve the quota before
        //    allocating anything.
        let plan = plan_map(gpa, len)?;
        self.map.reserve(gpa, len, perms_bits, memtype)?;
        let decoded = perms_from_abi(perms_bits);
        let perms = MmuPerms {
            read: decoded.read,
            write: decoded.write,
            execute: decoded.execute,
        };
        let pages = len / PAGE_SIZE;
        let mut allocated: Vec<PhysFrame> = Vec::with_capacity(pages as usize);
        // Installed mappings, in order: (gpa, len, is_2m_leaf).
        let mut installed: Vec<(u64, u64, bool)> = Vec::new();

        for segment in &plan {
            let frame_count = (segment.len / PAGE_SIZE) as usize;
            let first_frame = allocated.len();
            for _ in 0..frame_count {
                let Some(frame) = alloc_guest_frame() else {
                    self.rollback_mapping(&installed, allocated);
                    self.map.remove(gpa);
                    return Err(VmError::OutOfMemory);
                };
                allocated.push(frame);
            }

            if segment.is_large() {
                let hp_as: Vec<u64> = allocated[first_frame..]
                    .iter()
                    .map(|frame| frame.start_address.as_u64())
                    .collect();
                let base = hp_as.iter().copied().min().unwrap_or(0);
                if contiguous_2m_aligned(base, &hp_as) {
                    match self.second_level.map_2m(segment.gpa, base, perms) {
                        Ok(()) => {
                            installed.push((segment.gpa, segment.len, true));
                            continue;
                        }
                        Err(error) => {
                            self.rollback_mapping(&installed, allocated);
                            self.map.remove(gpa);
                            return Err(VmError::Translation(error));
                        }
                    }
                }
                // Fragmented or unaligned host frames: fall through to 4 KiB
                // pages for this 2 MiB segment.
            }

            for index in 0..frame_count {
                let hpa = allocated[first_frame + index].start_address.as_u64();
                let page_gpa = segment.gpa + index as u64 * PAGE_SIZE;
                match self.second_level.map_4k(page_gpa, hpa, perms) {
                    Ok(()) => installed.push((page_gpa, PAGE_SIZE, false)),
                    Err(error) => {
                        self.rollback_mapping(&installed, allocated);
                        self.map.remove(gpa);
                        return Err(VmError::Translation(error));
                    }
                }
            }
        }

        self.frames.extend(allocated);
        Ok(pages)
    }

    /// Undoes installed mappings and frees every frame of a failed `map`.
    ///
    /// Mappings are torn down in reverse installation order; 2 MiB leaves use
    /// `unmap_2m`, 4 KiB pages use `unmap_4k`. The frame list is then returned
    /// to the allocator exactly once (it is moved in, so no double free is
    /// possible).
    fn rollback_mapping(&mut self, installed: &[(u64, u64, bool)], frames: Vec<PhysFrame>) {
        for &(segment_gpa, segment_len, is_large) in installed.iter().rev() {
            if is_large {
                let _ = self
                    .second_level
                    .root
                    .unmap_2m(&mut self.second_level.tables, segment_gpa);
            } else {
                let page_count = segment_len / PAGE_SIZE;
                for index in 0..page_count {
                    let _ = self.second_level.unmap_4k(segment_gpa + index * PAGE_SIZE);
                }
            }
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
    /// Guest modules/initrd ranges (bounded, insertion order).
    modules: Vec<GuestModule>,
    /// Guest command line (NUL padded; `cmdline_len` is authoritative).
    cmdline: [u8; CMDLINE_MAX],
    /// Number of valid bytes in `cmdline`.
    cmdline_len: usize,
    /// Device translation model of this world (IOMMU).
    ///
    /// The model is pure and owns no frame: it maps device-visible addresses
    /// to host frames already owned by `memory`. It is empty until the first
    /// `SYS_VMM_MAP_IOMMU` call, which lazily allocates the domain.
    iommu: IommuModel,
    /// Address space allocated in `iommu`, if any.
    iommu_domain: Option<DomainId>,
}

/// One guest module/initrd range recorded for the boot-parameter block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestModule {
    /// Guest-physical base address.
    pub base: u64,
    /// Length in bytes.
    pub len: u64,
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
    /// The vCPU task is currently inside `execute_one_run` (guest mode).
    in_guest: bool,
    /// Number of `RUN`s executed by this vCPU task.
    runs: u64,
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
/// Registry type: worlds are **boxed** so that creating or destroying one does
/// not move the (large) World value through the kernel stack. The early
/// bootstrap runs on an 8 KiB stack; a stack-sized move there is a page fault.
type WorldMap = BTreeMap<u64, Box<World>>;

static WORLDS: SpinLock<WorldMap> = SpinLock::new(BTreeMap::new());
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
        Box::new(World {
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
            modules: Vec::new(),
            cmdline: [0u8; CMDLINE_MAX],
            cmdline_len: 0,
            iommu: IommuModel::new(),
            iommu_domain: None,
        }),
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
    destroy_inner(id, None)
}

/// Destroys a world, waiting at most `timeout_ns` for its vCPU tasks.
///
/// Returns `None` when the world does not exist, is already closing, or when a
/// vCPU task did not finish within the budget. In the timeout case the world
/// stays in the registry with `closing` set, so its memory is not freed while a
/// task could still reference it; the caller should treat that as a defect and
/// report it.
pub fn destroy_timeout(id: u64, timeout_ns: u64) -> Option<WorldRecord> {
    destroy_inner(id, Some(timeout_ns))
}

fn destroy_inner(id: u64, timeout_ns: Option<u64>) -> Option<WorldRecord> {
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
        let exited = match timeout_ns {
            Some(timeout_ns) => wait_vcpu_exited_timeout(vcpu, timeout_ns),
            None => {
                wait_vcpu_exited(vcpu);
                true
            }
        };
        if !exited {
            log::warn!(
                "[s9vm] destroy: vCPU task {} did not exit within {} ns; world {} kept closing",
                vcpu,
                timeout_ns.unwrap_or(0),
                id
            );
            return None;
        }
    }
    // 3. Removes the world and frees the guest memory.
    let mut world = {
        let mut worlds = WORLDS.lock();
        worlds.remove(&id)?
    };
    // The IOMMU model owns no frame, but its domains and device bindings must
    // not outlive the world: drop them explicitly before the guest frames.
    // The host VT-d mirror domains are released first (outside the registry
    // lock), which clears their hardware shadow mappings.
    release_host_iommu_domains(id);
    world.iommu.destroy();
    world.iommu_domain = None;
    if let Some(memory) = world.memory.take() {
        memory.destroy();
    }
    Some(world.record)
}

/// Finds a world and the index of a vCPU in that world.
fn locate_slot(worlds: &mut WorldMap, vcpu_id: u64) -> Option<(&mut World, usize)> {
    for world in worlds.values_mut() {
        if let Some(index) = world.vcpus.iter().position(|slot| slot.id == vcpu_id) {
            return Some((world, index));
        }
    }
    None
}

/// Waits at most `timeout_ns` for a vCPU's kernel task to finish.
///
/// Returns `false` on timeout. The world stays in the registry in that case;
/// `destroy_inner` reports the defect instead of freeing memory a task could
/// still reference.
fn wait_vcpu_exited_timeout(vcpu_id: u64, timeout_ns: u64) -> bool {
    let budget_ticks = (timeout_ns / crate::arch::timer::NS_PER_TICK).max(1);
    let deadline = ticks().saturating_add(budget_ticks);
    loop {
        {
            let mut worlds = WORLDS.lock();
            let Some((world, index)) = locate_slot(&mut worlds, vcpu_id) else {
                return true;
            };
            let slot = &world.vcpus[index];
            if slot.exited || slot.task.is_none() {
                return true;
            }
        }
        if ticks() >= deadline {
            return false;
        }
        sleep_current_task_ticks(1);
    }
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
        in_guest: false,
        runs: 0,
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

/// Loads a guest module/initrd blob into a world's guest memory.
///
/// This is the initrd/module companion of [`load_image`]: the bytes are not
/// parsed, they are mapped read/write at `gpa` and copied verbatim. `gpa` must
/// be 4 KiB aligned, the blob must be non-empty and at most
/// [`MAX_MODULE_BYTES`], and at most [`MAX_MODULES_PER_WORLD`] ranges can be
/// recorded per world. The range is recorded for [`write_boot_params`].
///
/// Loading is not atomic: if the module table is full, or if the copy cannot
/// translate a page, the pages already mapped stay in place (the world memory
/// layer has no unmap primitive) and the caller should destroy the world.
pub fn load_module(world_id: u64, caps: &HwCaps, gpa: u64, bytes: &[u8]) -> Result<(), VmError> {
    if gpa % PAGE_SIZE != 0 || bytes.is_empty() || bytes.len() > MAX_MODULE_BYTES {
        return Err(VmError::Map(MapError::InvalidRange));
    }
    let len = bytes.len() as u64;
    if gpa.checked_add(len).is_none_or(|end| end > MAX_GPA) {
        return Err(VmError::Map(MapError::InvalidRange));
    }
    {
        let worlds = WORLDS.lock();
        let world = worlds.get(&world_id).ok_or(VmError::Unknown)?;
        if world.closing || world.modules.len() >= MAX_MODULES_PER_WORLD {
            return Err(VmError::Map(MapError::InvalidRange));
        }
    }
    let page_len = len.div_ceil(PAGE_SIZE) * PAGE_SIZE;
    map_memory(world_id, caps, gpa, page_len, 0b011, 0)?;
    let mut worlds = WORLDS.lock();
    let world = worlds.get_mut(&world_id).ok_or(VmError::Unknown)?;
    if world.closing || world.modules.len() >= MAX_MODULES_PER_WORLD {
        return Err(VmError::Map(MapError::InvalidRange));
    }
    let memory = world
        .memory
        .as_ref()
        .ok_or(VmError::Map(MapError::NotMapped))?;
    let mut offset = 0usize;
    while offset < bytes.len() {
        let page_offset = (offset as u64) & (PAGE_SIZE - 1);
        let chunk = core::cmp::min(bytes.len() - offset, (PAGE_SIZE - page_offset) as usize);
        let hpa = memory
            .translate(gpa + offset as u64)
            .ok_or(VmError::Map(MapError::NotMapped))?;
        // SAFETY: `hpa` belongs to a frame reserved for this world and is
        // mapped through the HHDM; `chunk` stays inside one page.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes[offset..].as_ptr(),
                crate::memory::phys_to_virt(hpa) as *mut u8,
                chunk,
            );
        }
        offset += chunk;
    }
    world.modules.push(GuestModule { base: gpa, len });
    log::info!(
        "[s9vm] module loaded at {:#x}: {} byte(s), {}/{} module(s)",
        gpa,
        len,
        world.modules.len(),
        MAX_MODULES_PER_WORLD
    );
    Ok(())
}

/// Stores the guest kernel command line for a world.
///
/// At most [`CMDLINE_MAX`] bytes are accepted. The buffer is NUL-padded and
/// **not** NUL-terminated: its stored length is authoritative and is returned.
pub fn set_cmdline(world_id: u64, bytes: &[u8]) -> Result<usize, VmError> {
    if bytes.len() > CMDLINE_MAX {
        return Err(VmError::Map(MapError::InvalidRange));
    }
    let mut worlds = WORLDS.lock();
    let world = worlds.get_mut(&world_id).ok_or(VmError::Unknown)?;
    if world.closing {
        return Err(VmError::Unknown);
    }
    world.cmdline = [0u8; CMDLINE_MAX];
    world.cmdline[..bytes.len()].copy_from_slice(bytes);
    world.cmdline_len = bytes.len();
    log::info!("[s9vm] command line stored: {} byte(s)", bytes.len());
    Ok(bytes.len())
}

/// Modules recorded for a world, in insertion order.
pub fn modules(world_id: u64) -> Option<Vec<GuestModule>> {
    WORLDS
        .lock()
        .get(&world_id)
        .map(|world| world.modules.clone())
}

/// Command line recorded for a world, with its authoritative length.
pub fn cmdline(world_id: u64) -> Option<Vec<u8>> {
    WORLDS
        .lock()
        .get(&world_id)
        .map(|world| world.cmdline[..world.cmdline_len].to_vec())
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
    /// The operation did not complete within the caller's budget.
    Timeout,
}

impl From<VcpuError> for RunError {
    fn from(value: VcpuError) -> Self {
        Self::Hardware(value)
    }
}

/// Maximum number of "resumable" exits handled internally before handing
/// control back to policy (protection against an interrupt storm).
const MAX_RESUMED_EXITS: u32 = 64;

/// Consecutive host-interrupt exits tolerated inside one RUN before pin-based
/// external-interrupt exiting is cleared for the rest of the RUN.
///
/// The guest runs with host interrupts disabled, so a pending host interrupt
/// is not delivered while it executes; without this bound every VM entry would
/// exit immediately (the pending interrupt is still pending) and the RUN would
/// livelock until the storm bound trips.
const MAX_HOST_IRQ_EXITS: u32 = 8;

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

/// Names the access type encoded in an EPT-violation qualification.
///
/// Bits 2:0 are read/write/execute; bit 8 tells whether the fault came from a
/// guest-page-table walk (the GPA is then a page-table entry address, not the
/// faulting linear address).
pub(crate) fn ept_access_name(qualification: u64) -> &'static str {
    let access = match qualification & 0x7 {
        0b001 => "read",
        0b010 => "write",
        0b100 => "execute",
        _ => "read/write",
    };
    if qualification & (1 << 8) != 0 {
        "page-table walk"
    } else {
        access
    }
}

fn event_from_exit(exit: &ExitInfo, vcpu_id: u64, guest_rax: u64) -> VmmExitEvent {
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
            // Bit 3: 0 = OUT, 1 = IN. For an OUT the policy needs the data the
            // guest wrote, otherwise every debug-port byte reads as zero.
            let direction_in = (qualification >> 3) & 1 != 0;
            event.flags = u32::from(direction_in);
            if !direction_in {
                let width = u64::from(event.size.min(8));
                let mask = if width == 8 {
                    u64::MAX
                } else {
                    (1u64 << (width * 8)) - 1
                };
                event.value = guest_rax & mask;
            }
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
    // A policy-driven I/O replay must advance the guest RIP itself: the
    // hardware leaves GUEST_RIP at the faulting instruction for port exits.
    event.instruction_length = exit.instruction_length;
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
    // True when this call resumes a vCPU the guest already ran on: the control
    // block then holds the architectural state the guest produced (descriptor
    // tables, segments, MSRs) and it must not be reset by the ABI rebuild.
    let mut resumed = false;
    let mut hardware = match hardware {
        Some(existing) => {
            resumed = existing.entered();
            existing
        }
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
        .map_err(|error| {
            // A rejected state would otherwise only surface as
            // `InvalidGuestState` in the caller: name the failing check and the
            // state fields, so a hardware run is diagnosable from the serial
            // log alone.
            log::warn!(
                "[s9vm] vcpu {}: invalid guest state ({:?}): cr0={:#x} cr3={:#x} cr4={:#x} \
                 efer={:#x} rip={:#x} rsp={:#x} rflags={:#x}",
                vcpu_id,
                error,
                regs.cr0,
                regs.cr3,
                regs.cr4,
                regs.efer,
                regs.rip,
                regs.rsp,
                regs.rflags
            );
            RunError::InvalidGuestState
        })?;

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
        } else if resumed {
            // The guest may have loaded its own GDT/IDT and segments since the
            // previous entry; the processor saved them in the control block on
            // the last exit. Import them before the ABI rebuild writes the boot
            // defaults back: a policy round trip must be transparent for the
            // guest, otherwise the first interrupt after it cannot be
            // delivered (zero IDTR limit → triple fault).
            match hardware.refresh_system_state() {
                Ok(()) => guest.import_system_state(hardware.guest()),
                Err(error) => result = Err(RunError::Hardware(error)),
            }
        }
        if result.is_ok() {
            if let Err(error) = hardware.configure(caps, &guest) {
                result = Err(RunError::Hardware(error));
            }
        }
        if result.is_ok() && pending_nmi {
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
            // Interrupt-window exiting is control-block state and survives a
            // RUN, while `window_armed` below only tracks the current one: a
            // previous RUN that ended on a policy exit can leave the window
            // armed. An interruptible guest would then exit with
            // `InterruptWindow` after every entry and eventually be reported as
            // an exit storm. Start every RUN from a known, disarmed state.
            let _ = hardware.set_interrupt_window_exiting(caps, false);
            // Same reasoning for external-interrupt exiting: the loop may have
            // disabled it after a host-interrupt burst below.
            let _ = hardware.set_external_interrupt_exiting(caps, true);
            let mut resumed = 0u32;
            // Consecutive host-interrupt exits in this RUN. The guest runs with
            // host interrupts disabled, so a pending interrupt is never
            // delivered while the guest executes; past this bound the control
            // is cleared for the rest of the RUN.
            let mut host_irq_burst = 0u32;
            // True while interrupt-window exiting is armed in the control
            // block: the guest has a pending vector but interrupts disabled.
            let mut window_armed = false;
            loop {
                // Interrupt delivery. The local APIC is the only source: the
                // highest-priority deliverable vector is injected when the
                // guest is interruptible; otherwise the interrupt window is
                // armed so that the vector is delivered as soon as the guest
                // becomes ready. The window control is disarmed as soon as it
                // is no longer needed, otherwise the processor would exit
                // after every single instruction in the guest.
                let pending = apic.pending_vector();
                let mut interruptible = hardware.guest().rflags & RFLAGS_IF != 0;
                if interruptible && pending.is_some() {
                    // RFLAGS.IF alone is not enough: blocking by STI or by
                    // MOV SS suppresses VM-entry interruption delivery, and the
                    // vector would be discarded after being taken out of the
                    // APIC. Read the interruptibility state before injecting.
                    match hardware.interruptibility() {
                        Ok(state) => interruptible = interrupt_deliverable(true, state),
                        Err(error) => {
                            result = Err(RunError::Hardware(error));
                            break;
                        }
                    }
                }
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
                // Advances the emulated local APIC timer by the time the guest
                // spent running (one-shot/periodic) and publishes the current
                // time stamp for the TSC-deadline mode. An expiry raises the
                // LVT vector in the APIC; the injection loop below (and at the
                // next iteration) delivers it through the interrupt-window
                // path. The guest TSC offset is zero, so host time stamps are
                // the guest's.
                //
                // APIC timer counts are bus ticks, not TSC cycles: the
                // conversion uses the published host frequency when it is
                // known (0 disables the scaling and keeps the raw-cycle
                // approximation, documented in the timer model).
                let tsc_hz = crate::s9vm::tsc::get()
                    .map(|frequency| frequency.hz())
                    .unwrap_or(0);
                apic.advance_tsc(exit_cycles, tsc_hz);
                apic.set_tsc(exit_tsc);
                // Legacy time base: the 8254 counts down and raises IRQ0, the
                // CMOS RTC advances by whole seconds. Same "advance on exit"
                // model as the local APIC timer, documented in those models.
                machine.advance_time(&mut apic, exit_cycles, tsc_hz);
                match run_result {
                    Ok(exit) => {
                        let class = exit.class();
                        // A triple fault or an entry-state rejection is a
                        // guest crash: policy only receives an `other` event
                        // without the registers, so name the state here. The
                        // guest-physical-address field of such an exit is a
                        // leftover of the previous exit and must not be read.
                        if matches!(class, ExitClass::TripleFault | ExitClass::EntryFailure) {
                            let guest = hardware.guest();
                            log::error!(
                                "[s9vm] vcpu {}: guest {} rip={:#x} rsp={:#x} rflags={:#x} \
                                 cr0={:#x} cr3={:#x} cr4={:#x} efer={:#x} info={:#x}",
                                vcpu_id,
                                if class == ExitClass::TripleFault {
                                    "triple fault"
                                } else {
                                    "entry failure"
                                },
                                guest.rip,
                                guest.rsp,
                                guest.rflags,
                                guest.cr0,
                                guest.cr3,
                                guest.cr4,
                                guest.efer,
                                exit.interrupt_info
                            );
                        }
                        // Kernel fast path: accesses to the modeled devices
                        // are replayed in place, so the guest never observes
                        // the exit and policy is not involved.
                        if matches!(
                            class,
                            ExitClass::IoPort
                                | ExitClass::Msr
                                | ExitClass::EptViolation
                                | ExitClass::Cpuid
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
                                    // An emulated MSR write can change guest
                                    // state fields the control block caches
                                    // (EFER, PAT, FS/GS base, SYSENTER): push
                                    // them back before the next entry.
                                    if class == ExitClass::Msr {
                                        // SAFETY: the control block is loaded
                                        // and the guest is not running (we are
                                        // in the exit handler).
                                        let _ = hardware.sync_msr_state();
                                    }
                                    if resumed >= MAX_RESUMED_EXITS {
                                        log::warn!(
                                            "[s9vm] vcpu {}: exit storm after {} replayed \
                                             exits (class {:?}, rip {:#x}, pending_irq {:?})",
                                            vcpu_id,
                                            resumed,
                                            class,
                                            hardware.guest().rip,
                                            apic.pending_vector()
                                        );
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
                                    // Legacy COM1 output (a kernel that uses the
                                    // 8250 instead of virtio-console): same
                                    // routing, tagged so both are visible.
                                    let serial = machine.drain_serial();
                                    if !serial.is_empty() {
                                        log::info!(
                                            "[s9vm] serial: {}",
                                            core::str::from_utf8(&serial)
                                                .unwrap_or("<binary data>")
                                        );
                                        push_console_output(&mut console_output, &serial);
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
                        // A host interrupt that arrives while the guest runs is
                        // exited but cannot be delivered (host interrupts are
                        // disabled during the RUN). Left alone, the pending
                        // vector makes every entry exit again and the RUN
                        // livelocks. Do not charge those exits to the guest
                        // storm bound: clear external-interrupt exiting after a
                        // short burst so the guest makes progress, and let the
                        // vCPU task service the interrupt when it returns to
                        // the scheduler.
                        if class == ExitClass::ExternalInterrupt {
                            host_irq_burst += 1;
                            if host_irq_burst == MAX_HOST_IRQ_EXITS {
                                let _ = hardware.set_external_interrupt_exiting(caps, false);
                            }
                            continue;
                        }
                        if is_resumable(class) && resumed < MAX_RESUMED_EXITS {
                            resumed += 1;
                            continue;
                        }
                        if is_resumable(class) {
                            log::warn!(
                                "[s9vm] vcpu {}: exit storm after {} resumable exits \
                                 (class {:?}, rip {:#x}, pending_irq {:?})",
                                vcpu_id,
                                resumed,
                                class,
                                hardware.guest().rip,
                                apic.pending_vector()
                            );
                            result = Err(RunError::ExitStorm);
                        } else {
                            stats.policy_exits += 1;
                            if class == ExitClass::PreemptionTimer {
                                stats.timer_exits += 1;
                            }
                            // An EPT violation that reaches policy means the
                            // guest touched a GPA the world does not map and
                            // that no device model claims. Name the address,
                            // the access type and the guest context: without
                            // them the only visible symptom is a replayed
                            // instruction or a later entry failure.
                            if class == ExitClass::EptViolation {
                                log::warn!(
                                    "[s9vm] vcpu {}: EPT violation gpa={:#x} qual={:#x} \
                                     access={} rip={:#x} cr3={:#x} rsp={:#x}",
                                    vcpu_id,
                                    exit.guest_physical_address,
                                    exit.qualification,
                                    ept_access_name(exit.qualification),
                                    hardware.guest().rip,
                                    hardware.guest().cr3,
                                    hardware.guest().rsp
                                );
                            }
                            let event = event_from_exit(&exit, vcpu_id, hardware.guest().rax);
                            let _ = push_exit(world_id, event);
                        }
                        break;
                    }
                    Err(error) => {
                        // A VM-entry failure ("VMfail") carries a hardware
                        // instruction-error code; dump the guest-state fields
                        // too, they are the only way to find the invalid one.
                        if let VcpuError::VmFail(code) = error {
                            log::error!(
                                "[s9vm] vcpu {}: VM entry failed (instruction error {:#x}): {}",
                                vcpu_id,
                                code,
                                hardware.guest_diagnostics()
                            );
                        }
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

/// Errors of [`load_disk`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskError {
    /// The world does not exist (or is being destroyed).
    Unknown,
    /// Empty or non-sector-multiple image length.
    InvalidLength,
    /// Image larger than [`VMM_DISK_MAX_BYTES`].
    TooLarge,
}

/// Replaces the contents of a world's block device with a disk image.
///
/// `bytes` must be a non-empty multiple of [`VMM_DISK_SECTOR_SIZE`] and at
/// most [`VMM_DISK_MAX_BYTES`]. The image is copied from sector 0, the device
/// is **never shrunk**, and the capacity after the call is at least
/// `max(current, VMM_DISK_DEFAULT_BYTES, image length)`. Bytes past the image
/// are zero, so a shorter image fully replaces the previous content; when the
/// device has to grow it is rebuilt zeroed (read-only mode preserved), which
/// resets its virtio transport state. Meant to be called before the guest
/// boots. Returns the resulting capacity in 512-byte sectors.
pub fn load_disk(world_id: u64, bytes: &[u8]) -> Result<u64, DiskError> {
    if bytes.is_empty() || bytes.len() as u64 % VMM_DISK_SECTOR_SIZE != 0 {
        return Err(DiskError::InvalidLength);
    }
    if bytes.len() as u64 > VMM_DISK_MAX_BYTES {
        return Err(DiskError::TooLarge);
    }
    let mut worlds = WORLDS.lock();
    let world = worlds.get_mut(&world_id).ok_or(DiskError::Unknown)?;
    if world.closing {
        return Err(DiskError::Unknown);
    }
    let blk = &mut world.machine.devices_mut().blk;
    let current = blk.sectors() * VMM_DISK_SECTOR_SIZE;
    // Grow-only: never shrink, and leave at least the documented default
    // capacity so a small image still yields a stable 256-sector device.
    let target = current.max(VMM_DISK_DEFAULT_BYTES).max(bytes.len() as u64);
    if target == current {
        // In-place replacement keeps the virtio transport state.
        let disk = blk.disk_mut();
        disk.fill(0);
        disk[..bytes.len()].copy_from_slice(bytes);
    } else {
        // Growth rebuilds the device zeroed; preserve the access mode.
        let read_only = blk.read_only();
        let mut fresh = if read_only {
            VirtioBlk::new_read_only(target as usize)
        } else {
            VirtioBlk::new(target as usize)
        };
        fresh.disk_mut()[..bytes.len()].copy_from_slice(bytes);
        *blk = fresh;
    }
    Ok(target / VMM_DISK_SECTOR_SIZE)
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
    /// `true` while the vCPU task is inside guest execution (VM entry/exits).
    pub in_guest: bool,
    /// Number of `RUN`s completed by this vCPU task.
    pub runs: u64,
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
                in_guest: slot.in_guest,
                runs: slot.runs,
                pending_nmi: slot.pending_nmi,
            })
            .collect(),
    )
}

/// Writes the guest boot-parameter block at `gpa`.
///
/// The 1024-byte block (`s9vm::bootparams`) is the hand-off structure a real
/// operating-system guest expects: a physical memory map derived from the
/// world's mapped regions, the ACPI RSDP address, the console device and the
/// boot flags. `gpa` must be page aligned and already mapped in the world; the
/// block is copied through the HHDM like the boot-information page.
///
/// Region classification: write-back RAM that does not overlap a device window
/// is `USABLE`; anything mapped with a non-default memory type or overlapping
/// the console/block/network/APIC windows is `MMIO`; the firmware window
/// (`ACPI_GPA..ACPI_GPA + acpi::MAX_IMAGE_LEN`) is `ACPI_RECLAIMABLE`. Adjacent
/// ranges of the same kind are merged; if more than the block capacity remain,
/// the map is truncated (logged) rather than refusing to boot the guest.
pub fn write_boot_params(world_id: u64, gpa: u64) -> Result<(), VmError> {
    use crate::s9vm::{acpi, bootparams, emulate};

    if gpa % PAGE_SIZE != 0 {
        return Err(VmError::Map(MapError::InvalidRange));
    }
    let acpi_end = ACPI_GPA.saturating_add(acpi::MAX_IMAGE_LEN as u64);
    let mut worlds = WORLDS.lock();
    let world = worlds.get_mut(&world_id).ok_or(VmError::Unknown)?;
    let memory = world
        .memory
        .as_ref()
        .ok_or(VmError::Map(MapError::NotMapped))?;

    let mut params = bootparams::BootParams::new();
    params.set_rsdp(ACPI_GPA);
    params.set_console(emulate::CONSOLE_BASE, emulate::CONSOLE_IRQ_LINE as u32);
    params
        .set_flags(
            bootparams::flags::CONSOLE_PRESENT
                | bootparams::flags::BLOCK_PRESENT
                | bootparams::flags::NETWORK_PRESENT,
        )
        .map_err(|_| VmError::Map(MapError::InvalidRange))?;

    // Initrd/module ranges and the command line are authoritative in the
    // world registry: `SYS_VMM_LOAD_MODULE` and `SYS_VMM_SET_CMDLINE` fill
    // them before this block is written.
    for module in &world.modules {
        params
            .add_module(module.base, module.len)
            .map_err(|_| VmError::Map(MapError::InvalidRange))?;
    }
    params
        .set_cmdline(&world.cmdline[..world.cmdline_len])
        .map_err(|_| VmError::Map(MapError::InvalidRange))?;

    // Builds the map from the world's own reservations, merging neighbours of
    // the same kind so that a fragmented map still fits in the fixed block.
    let mut pending: Option<(u64, u64, u32)> = None;
    let mut truncated = false;
    for region in memory.regions() {
        let kind = classify_region(region, acpi_end);
        match pending {
            Some((base, len, current)) if current == kind && base + len == region.gpa => {
                pending = Some((base, len + region.len, current));
            }
            Some((base, len, current)) => {
                if params.add_memory(base, len, current).is_err() {
                    truncated = true;
                }
                pending = Some((region.gpa, region.len, kind));
            }
            None => pending = Some((region.gpa, region.len, kind)),
        }
    }
    if let Some((base, len, kind)) = pending {
        if params.add_memory(base, len, kind).is_err() {
            truncated = true;
        }
    }

    let mut page = [0u8; bootparams::SIZE];
    params.encode(&mut page);
    let hpa = memory
        .translate(gpa)
        .ok_or(VmError::Map(MapError::NotMapped))?;
    // SAFETY: `hpa` belongs to a frame reserved for this world, is mapped by
    // the HHDM, and `SIZE` bytes stay inside one 4 KiB page.
    unsafe {
        core::ptr::copy_nonoverlapping(
            page.as_ptr(),
            crate::memory::phys_to_virt(hpa) as *mut u8,
            bootparams::SIZE,
        );
    }
    // Read the device flags back from guest memory: a guest that reports a
    // device as "not advertised" can then be distinguished from a wrong
    // boot-parameter block on the writer side.
    let mut flags_readback = [0u8; 4];
    unsafe {
        core::ptr::copy_nonoverlapping(
            (crate::memory::phys_to_virt(hpa) as *const u8).add(bootparams::OFF_FLAGS),
            flags_readback.as_mut_ptr(),
            flags_readback.len(),
        );
    }
    let flags_readback = u32::from_le_bytes(flags_readback);
    drop(worlds);
    if truncated {
        log::warn!(
            "[s9vm] boot params at {:#x}: memory map truncated to {} entries",
            gpa,
            bootparams::MAX_MEMORY_ENTRIES
        );
    }
    log::info!(
        "[s9vm] boot params at {:#x}: flags {:#x} (readback {:#x}), {} memory range(s), \
         {} module(s), cmdline {} byte(s), rsdp {:#x}",
        gpa,
        params.flags(),
        flags_readback,
        params.memory_count(),
        params.module_count(),
        params.cmdline_len(),
        ACPI_GPA
    );
    Ok(())
}

/// Classifies one world region for the guest boot-parameter memory map.
fn classify_region(region: &crate::s9vm::memmap::Region, acpi_end: u64) -> u32 {
    use crate::s9vm::{bootparams::memory_kind, emulate};

    let end = region.end();
    fn overlaps(start: u64, end: u64, other: u64, other_end: u64) -> bool {
        start < other_end && other < end
    }
    // Device windows and MMIO-typed mappings are not ordinary RAM.
    let device = [
        (emulate::APIC_BASE, emulate::APIC_BASE + 0x1000),
        (emulate::IOAPIC_BASE, emulate::IOAPIC_BASE + 0x1000),
        (emulate::CONSOLE_BASE, emulate::CONSOLE_BASE + 0x1000),
        (emulate::BLK_BASE, emulate::BLK_BASE + 0x1000),
        (emulate::NET_BASE, emulate::NET_BASE + 0x1000),
    ];
    if region.memtype != 0
        || device
            .iter()
            .any(|(start, end_device)| overlaps(region.gpa, end, *start, *end_device))
    {
        return memory_kind::MMIO;
    }
    // The firmware table image is reclaimable once the guest has parsed it.
    if overlaps(region.gpa, end, ACPI_GPA, acpi_end) {
        return memory_kind::ACPI_RECLAIMABLE;
    }
    memory_kind::USABLE
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
/// The value is the pointer the control block uses to walk the guest physical
/// address space; it is the world's real translation table, not a mirror. It
/// stays valid as long as the world exists and its guest memory has not been
/// destroyed (the tables are freed by `destroy`), so the caller must not cache
/// it beyond the world's lifetime. The registry lock is taken briefly for the
/// lookup and never across guest execution.
///
/// Returns [`VmError::Unknown`] when the world does not exist, and
/// [`VmError::Map`] with [`MapError::NotMapped`] when the world has no guest
/// memory yet.
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

// ============================================================================
// Device translation (IOMMU)
// ============================================================================

/// Validates the shape of an IOMMU map/unmap request.
fn validate_iommu_range(iova: u64, len: u64, require_2m: bool) -> Result<(), IommuError> {
    if len == 0
        || len > IOMMU_MAX_MAP_BYTES
        || len % IOMMU_PAGE_SIZE != 0
        || iova % IOMMU_PAGE_SIZE != 0
    {
        return Err(IommuError::InvalidRange);
    }
    if iova.checked_add(len).map_or(true, |end| end > MAX_GPA) {
        return Err(IommuError::InvalidRange);
    }
    if require_2m && (iova % IOMMU_LARGE_PAGE_SIZE != 0 || len % IOMMU_LARGE_PAGE_SIZE != 0) {
        return Err(IommuError::InvalidRange);
    }
    Ok(())
}

/// Returns the IOMMU domain of a world, allocating it on first use.
///
/// One domain per world: every device assigned to the world shares the same
/// address space, so a mapping installed for one device is visible to the
/// others (the device set is trusted to be co-operating; isolation is between
/// worlds, not inside one).
fn iommu_domain(world: &mut World) -> Result<DomainId, IommuError> {
    if world.closing {
        return Err(IommuError::UnknownDomain);
    }
    match world.iommu_domain {
        Some(domain) => Ok(domain),
        None => {
            let domain = world.iommu.create_domain()?;
            world.iommu_domain = Some(domain);
            Ok(domain)
        }
    }
}

// ----------------------------------------------------------------------------
// Host VT-d mirroring (best effort, software model stays authoritative)
// ----------------------------------------------------------------------------

/// One host-side mirror segment, collected while the registry lock is held.
///
/// The collection is bounded by the model quota (`MAX_ENTRIES_PER_DOMAIN`), so
/// the vector cannot grow without bound.
struct HostIommuSegment {
    iova: u64,
    phys: u64,
    len: u64,
    kind: MappingKind,
}

/// Host IOMMU domains, one per `(world, PCI function)`.
///
/// The registry lock and this lock are **never** held together: the table is
/// only used to find or park an `Arc`, and the hardware IOMMU layer (which has
/// its own locks) is called after it has been released.
static IOMMU_HOST_DOMAINS: SpinLock<BTreeMap<(u64, u32), Arc<HardwareIommuDomain>>> =
    SpinLock::new(BTreeMap::new());

/// One-shot note when the host backend is not ready (feature disabled, no
/// DMAR, or activation not validated). The software model keeps working.
static IOMMU_BACKEND_NOTED: AtomicBool = AtomicBool::new(false);

/// Records (once) that host mirroring is disabled.
fn note_iommu_backend_unavailable() {
    if !IOMMU_BACKEND_NOTED.swap(true, Ordering::Relaxed) {
        log::info!(
            "[s9vm] iommu: host VT-d backend not ready; host mirroring disabled, \
             software model only"
        );
    }
}

/// True when the authoritative host backend is ready for mirroring.
fn iommu_host_ready() -> bool {
    crate::arch::iommu::backend().is_ready()
}

/// Translates the model permissions into VT-d DMA rights.
///
/// `Perms::read`/`write` describe what the **device** may do with the mapped
/// memory: read becomes `DmaProt::READ`, write becomes `DmaProt::WRITE`.
/// Execute has no meaning for a DMA translation and is ignored. A mapping with
/// neither read nor write (execute-only) becomes `DmaProt::NONE`; the hardware
/// leaf is installed but the device cannot access it.
fn iommu_dma_prot(perms: MmuPerms) -> DmaProt {
    let mut bits = 0u8;
    if perms.read {
        bits |= DmaProt::READ.bits();
    }
    if perms.write {
        bits |= DmaProt::WRITE.bits();
    }
    match DmaProt::from_bits(bits) {
        Some(prot) => prot,
        None => DmaProt::NONE,
    }
}

/// Returns (creating it on first use) the host VT-d domain of one PCI
/// function assigned to a world.
///
/// Each successful acquisition takes one logical reference on the hardware
/// domain; it is released by [`release_host_iommu_domains`] at world teardown.
fn host_iommu_domain(world_id: u64, sbdf: Sbdf) -> Option<Arc<HardwareIommuDomain>> {
    let key = (world_id, sbdf.to_u32());
    if let Some(domain) = IOMMU_HOST_DOMAINS.lock().get(&key) {
        return Some(Arc::clone(domain));
    }
    let domain = match crate::hardware::iommu::domain_for_owned(sbdf, None, FaultPolicy::Log) {
        Ok(domain) => domain,
        Err(error) => {
            log::warn!(
                "[s9vm] iommu: host domain for world={} {} unavailable: {:?}",
                world_id,
                sbdf,
                error
            );
            return None;
        }
    };
    let mut map = IOMMU_HOST_DOMAINS.lock();
    if let Some(existing) = map.get(&key) {
        let existing = Arc::clone(existing);
        drop(map);
        // Another request created the domain first: drop our extra logical
        // reference and use the registered one.
        let _ = crate::hardware::iommu::release_domain(&domain);
        return Some(existing);
    }
    map.insert(key, Arc::clone(&domain));
    Some(domain)
}

/// Mirrors model segments into the host VT-d backend.
///
/// Called **without** the world registry lock. Best effort: a missing/not-ready
/// backend disables mirroring with a one-time log; a hardware failure is
/// logged with the world, device, IOVA and keeps the software model semantics
/// (the syscall still succeeds).
fn mirror_host_map(world_id: u64, device: u32, segments: &[HostIommuSegment], perms: MmuPerms) {
    if segments.is_empty() {
        return;
    }
    if !iommu_host_ready() {
        note_iommu_backend_unavailable();
        return;
    }
    let sbdf = Sbdf::from_u32(device);
    let Some(domain) = host_iommu_domain(world_id, sbdf) else {
        return;
    };
    let prot = iommu_dma_prot(perms);
    let backend = crate::arch::iommu::backend();
    // One hardware mapping per model leaf: the granularity must stay exactly
    // aligned with the software model so a later (possibly partial) unmap can
    // never leave a wider hardware mapping installed than the model allows.
    for segment in segments {
        match domain.map_kind(segment.iova, segment.phys, segment.len, prot, segment.kind) {
            Ok(()) => {}
            Err(crate::hardware::iommu::IommuError::BackendNotReady) => {
                note_iommu_backend_unavailable();
                return;
            }
            Err(error) => log::warn!(
                "[s9vm] iommu: host map failed world={} device={} iova={:#x} \
                 len={:#x} kind={:?}: {:?}",
                world_id,
                sbdf,
                segment.iova,
                segment.len,
                segment.kind,
                error
            ),
        }
    }
    // One invalidation for the whole batch (the per-leaf backend calls may
    // already flush when translation is active).
    backend.invalidate_domain(domain.id());
}

/// Removes a range from the host mirror of one device.
///
/// Called **without** the world registry lock; best effort like
/// [`mirror_host_map`]. When no host domain exists for the pair the call is a
/// no-op (the mirror was never installed or the backend was not ready).
fn mirror_host_unmap(world_id: u64, device: u32, iova: u64, len: u64) {
    if !iommu_host_ready() {
        return;
    }
    let sbdf = Sbdf::from_u32(device);
    let key = (world_id, sbdf.to_u32());
    let domain = match IOMMU_HOST_DOMAINS.lock().get(&key) {
        Some(domain) => Arc::clone(domain),
        None => return,
    };
    let backend = crate::arch::iommu::backend();
    match domain.unmap(iova, len) {
        Ok(_pages) => backend.invalidate_domain(domain.id()),
        Err(crate::hardware::iommu::IommuError::NotMapped) => {
            // The mirror may be partial after an earlier best-effort failure;
            // the software model remains authoritative.
            log::debug!(
                "[s9vm] iommu: host unmap found no mirror world={} device={} \
                 iova={:#x} len={:#x}",
                world_id,
                sbdf,
                iova,
                len
            );
        }
        Err(error) => log::warn!(
            "[s9vm] iommu: host unmap failed world={} device={} iova={:#x} \
             len={:#x}: {:?}",
            world_id,
            sbdf,
            iova,
            len,
            error
        ),
    }
}

/// Releases every host VT-d domain owned by a world.
///
/// Called from `destroy_inner` after the world has been removed from the
/// registry and **without** the registry lock. The domains are torn down first
/// (their mappings are cleared and unmapped from the hardware shadow tables),
/// then their logical reference is dropped.
fn release_host_iommu_domains(world_id: u64) {
    let domains: Vec<Arc<HardwareIommuDomain>> = {
        let mut map = IOMMU_HOST_DOMAINS.lock();
        let keys: Vec<(u64, u32)> = map
            .keys()
            .filter(|(world, _)| *world == world_id)
            .copied()
            .collect();
        keys.into_iter()
            .filter_map(|key| map.remove(&key))
            .collect()
    };
    for domain in domains {
        if !crate::hardware::iommu::release_domain(&domain) {
            // A lingering logical reference would keep the hardware domain
            // alive: force the teardown rather than leaking a translation
            // domain for a destroyed world.
            log::warn!(
                "[s9vm] iommu: world {} host domain {} still referenced; \
                 forcing teardown",
                world_id,
                domain.id().raw()
            );
            let _ = crate::hardware::iommu::teardown(domain.id());
        }
    }
}

/// Maps an IOVA range of a world to the host frames backing its guest memory.
///
/// Contract:
/// - `iova`/`len` are 4 KiB aligned and `len <= IOMMU_MAX_MAP_BYTES`; with
///   `require_2m` both are 2 MiB aligned and every 2 MiB block must be backed
///   by a physically contiguous, 2 MiB-aligned host range.
/// - Every IOVA page must be backed by the world's guest memory
///   (`WorldMemory::translate`); an unmapped GPA returns
///   [`IommuError::NotMapped`] and nothing is installed.
/// - The device is bound to the world domain (idempotent when already bound).
/// - All-or-nothing: on any error the leaves installed by this call are
///   removed before returning.
///
/// When the host VT-d backend is ready (`arch::iommu::backend().is_ready()`),
/// the same leaves are mirrored into the host shadow tables **after** the
/// registry lock is released: one `hardware::iommu::Domain` per
/// `(world, PCI function)`, `map_kind` with 4 KiB / 2 MiB matching the model
/// leaf and `DmaProt` derived from `perms`, followed by a domain invalidation.
/// The mirror is best effort: a missing/not-ready backend disables it with a
/// one-time log, and a hardware failure is logged with world/device/IOVA while
/// the software model (authoritative) and the syscall result are unchanged.
/// Mappings created before the backend becomes ready are not retroactively
/// mirrored.
///
/// Returns the number of 4 KiB pages covered. The host physical addresses are
/// never returned to the caller.
pub fn iommu_map(
    world_id: u64,
    iova: u64,
    len: u64,
    perms: MmuPerms,
    require_2m: bool,
    device: u32,
) -> Result<u64, IommuError> {
    validate_iommu_range(iova, len, require_2m)?;
    let pages = len / IOMMU_PAGE_SIZE;
    // Host mirror segments are collected under the registry lock (the model
    // quota bounds their number) and installed after it is released, so the
    // hardware IOMMU layer is never called with the registry lock held.
    let mirror_capacity =
        core::cmp::min(pages, crate::s9vm::iommu::MAX_ENTRIES_PER_DOMAIN as u64) as usize;
    let mut mirror: Vec<HostIommuSegment> = Vec::with_capacity(mirror_capacity);
    {
        let mut worlds = WORLDS.lock();
        let world = worlds.get_mut(&world_id).ok_or(IommuError::UnknownDomain)?;
        let domain = iommu_domain(world)?;
        let memory = world.memory.as_ref().ok_or(IommuError::NotMapped)?;

        if require_2m {
            let leaves = len / IOMMU_LARGE_PAGE_SIZE;
            let mut done = 0u64;
            for leaf in 0..leaves {
                let base = iova + leaf * IOMMU_LARGE_PAGE_SIZE;
                let hpa = match memory.translate(base) {
                    Some(hpa) => hpa,
                    None => {
                        if done > 0 {
                            let _ =
                                world
                                    .iommu
                                    .unmap_2m(domain, iova, done * IOMMU_LARGE_PAGE_SIZE);
                        }
                        return Err(IommuError::NotMapped);
                    }
                };
                if hpa % IOMMU_LARGE_PAGE_SIZE != 0 {
                    if done > 0 {
                        let _ = world
                            .iommu
                            .unmap_2m(domain, iova, done * IOMMU_LARGE_PAGE_SIZE);
                    }
                    return Err(IommuError::InvalidRange);
                }
                // A 2 MiB leaf needs a physically contiguous block: verify
                // every 4 KiB page of the block maps to the expected
                // contiguous HPA.
                let block_pages = IOMMU_LARGE_PAGE_SIZE / IOMMU_PAGE_SIZE;
                for sub in 1..block_pages {
                    let gpa = base + sub * IOMMU_PAGE_SIZE;
                    if memory.translate(gpa) != Some(hpa + sub * IOMMU_PAGE_SIZE) {
                        if done > 0 {
                            let _ =
                                world
                                    .iommu
                                    .unmap_2m(domain, iova, done * IOMMU_LARGE_PAGE_SIZE);
                        }
                        return Err(IommuError::NotMapped);
                    }
                }
                if let Err(error) =
                    world
                        .iommu
                        .map_2m(domain, base, hpa, IOMMU_LARGE_PAGE_SIZE, perms)
                {
                    if done > 0 {
                        let _ = world
                            .iommu
                            .unmap_2m(domain, iova, done * IOMMU_LARGE_PAGE_SIZE);
                    }
                    return Err(error);
                }
                mirror.push(HostIommuSegment {
                    iova: base,
                    phys: hpa,
                    len: IOMMU_LARGE_PAGE_SIZE,
                    kind: MappingKind::Page2M,
                });
                done += 1;
            }
        } else {
            let mut done = 0u64;
            for page in 0..pages {
                let gpa = iova + page * IOMMU_PAGE_SIZE;
                let hpa = match memory.translate(gpa) {
                    Some(hpa) => hpa,
                    None => {
                        if done > 0 {
                            let _ = world.iommu.unmap(domain, iova, done * IOMMU_PAGE_SIZE);
                        }
                        return Err(IommuError::NotMapped);
                    }
                };
                if let Err(error) = world.iommu.map(domain, gpa, hpa, IOMMU_PAGE_SIZE, perms) {
                    if done > 0 {
                        let _ = world.iommu.unmap(domain, iova, done * IOMMU_PAGE_SIZE);
                    }
                    return Err(error);
                }
                mirror.push(HostIommuSegment {
                    iova: gpa,
                    phys: hpa,
                    len: IOMMU_PAGE_SIZE,
                    kind: MappingKind::Page4K,
                });
                done += 1;
            }
        }

        // Bind the device to the world domain. Binding twice to the same
        // domain is idempotent; any other failure rolls the mapping back.
        match world.iommu.bind_device(domain, DeviceId(device)) {
            Ok(()) | Err(IommuError::AlreadyBound) => {}
            Err(error) => {
                if require_2m {
                    let _ = world.iommu.unmap_2m(domain, iova, len);
                } else {
                    let _ = world.iommu.unmap(domain, iova, len);
                }
                return Err(error);
            }
        }
    }
    // Registry lock released: mirror into the host VT-d backend, best effort.
    mirror_host_map(world_id, device, &mirror, perms);
    Ok(pages)
}

/// Removes an IOVA range of a world from its device translation domain.
///
/// The range must have been installed by [`iommu_map`] with the same leaf
/// size. When the domain becomes empty the device is unbound. Returns the
/// number of 4 KiB pages removed.
///
/// The software model is updated under the registry lock; the host VT-d
/// mirror is removed afterwards, without the lock, best effort.
pub fn iommu_unmap(
    world_id: u64,
    iova: u64,
    len: u64,
    require_2m: bool,
    device: u32,
) -> Result<u64, IommuError> {
    validate_iommu_range(iova, len, require_2m)?;
    let pages = {
        let mut worlds = WORLDS.lock();
        let world = worlds.get_mut(&world_id).ok_or(IommuError::UnknownDomain)?;
        if world.closing {
            return Err(IommuError::UnknownDomain);
        }
        let domain = world.iommu_domain.ok_or(IommuError::NotMapped)?;
        let pages = if require_2m {
            world.iommu.unmap_2m(domain, iova, len)?
        } else {
            world.iommu.unmap(domain, iova, len)?
        };
        if world.iommu.mapped_entries(domain) == Some(0) {
            let _ = world.iommu.unbind_device(DeviceId(device));
        }
        pages
    };
    mirror_host_unmap(world_id, device, iova, len);
    Ok(pages)
}

/// Translates one device-visible address of a world.
///
/// This is a **kernel-side** diagnostic/device-model accessor: the host
/// physical address is never exposed through the syscall ABI.
pub fn iommu_translate(world_id: u64, iova: u64) -> Option<u64> {
    let mut worlds = WORLDS.lock();
    let world = worlds.get_mut(&world_id)?;
    if world.closing {
        return None;
    }
    let domain = world.iommu_domain?;
    world.iommu.translate(domain, iova)
}

/// Number of leaves installed in the device translation domain of a world.
pub fn iommu_mapped_entries(world_id: u64) -> Option<usize> {
    let worlds = WORLDS.lock();
    let world = worlds.get(&world_id)?;
    world.iommu.mapped_entries(world.iommu_domain?)
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
    //
    // Diagnostics: this path can be called from any task context (including a
    // userspace syscall), and a silently dropped kernel task used to be
    // indistinguishable from a hang. The three log lines below tell an operator
    // exactly where a stuck `SYS_VMM_CREATE_VCPU` stopped.
    log::info!("[s9vm] create_vcpu {}: spawning the vCPU kernel task", id);
    let task = match kthread::spawn("s9vm-vcpu", move || vcpu_task_main(world_id, id)) {
        Ok(task) => task,
        Err(_) => {
            log::warn!("[s9vm] create_vcpu {}: kernel task spawn failed", id);
            let _ = remove_vcpu(id);
            return Err(VcpuRegistryError::Thread);
        }
    };
    log::info!(
        "[s9vm] create_vcpu {}: kernel task {} spawned",
        id,
        task.as_u64()
    );
    // 3. Publishes the task identifier if the vCPU still exists.
    {
        let mut worlds = WORLDS.lock();
        if let Some((world, index)) = locate_slot(&mut worlds, id) {
            world.vcpus[index].task = Some(task);
        }
    }
    log::info!("[s9vm] create_vcpu {}: registered", id);
    Ok(id)
}

/// Registers a logical vCPU **without** spawning a kernel task.
///
/// The slot exists in the registry (so `write_acpi` can describe it, its
/// register block can be read and `destroy` has nothing to join), but
/// `request_run` is refused: there is no task to wake. Callers that use it
/// drive the vCPU with a direct `Vcpu` loop, which keeps the in-kernel
/// selftests independent from the scheduler.
pub fn create_vcpu_detached(world_id: u64, apic_id: u32) -> Result<u64, VcpuRegistryError> {
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

        {
            let mut worlds = WORLDS.lock();
            if let Some((world, index)) = locate_slot(&mut worlds, vcpu_id) {
                world.vcpus[index].in_guest = true;
            }
        }
        let result = execute_one_run(vcpu_id);
        // Diagnostics: one line per RUN tells an operator whether the vCPU
        // task executed at all (a missing line means the task never ran; an
        // error here is the reason the guest stopped).
        match &result {
            Ok(()) => log::info!("[s9vm] vcpu task {}: run executed", vcpu_id),
            Err(RunError::NoMemory) => log::info!(
                "[s9vm] vcpu task {}: run skipped (the world has no guest memory)",
                vcpu_id
            ),
            Err(error) => log::warn!("[s9vm] vcpu task {}: run failed ({:?})", vcpu_id, error),
        }

        let done_wait = {
            let mut worlds = WORLDS.lock();
            let Some((world, index)) = locate_slot(&mut worlds, vcpu_id) else {
                return;
            };
            let slot = &mut world.vcpus[index];
            slot.in_guest = false;
            slot.runs = slot.runs.saturating_add(1);
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
    // VT-x activation is **per CPU**: the vCPU kernel task can be scheduled on
    // a CPU that has never executed `VMXON` (activation at boot only enables
    // the boot CPU). Running a guest there would execute VMX instructions
    // without a VMXON root and fault the kernel, so the task activates the
    // current CPU first (the activation is idempotent and cheap once done).
    // `VMXON` expects interrupts disabled.
    let activated =
        crate::s9vm::activation_region(crate::arch::x86_64::percpu::current_cpu_index()).is_some();
    if !activated {
        let result = crate::sync::with_irqs_disabled(|_| crate::s9vm::activate_current_cpu());
        if result.is_err() {
            log::warn!(
                "[s9vm] vcpu task: cannot activate VT-x on cpu {}",
                crate::arch::x86_64::percpu::current_cpu_index()
            );
            return Err(RunError::HardwareNotReady);
        }
    }
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

/// Posts a `RUN` request without waiting for the vCPU task.
///
/// The request is marked in the slot, the vCPU kernel task is woken, and the
/// call returns immediately. The caller must collect completion with
/// [`wait_run_complete`] (or observe the exit queue). Only one `RUN` may be in
/// flight per vCPU; a second request before completion returns
/// [`RunError::Busy`].
///
/// This is the kernel-internal primitive used by the SMP selftest to queue two
/// vCPUs back-to-back and measure real overlap; it has no ABI/syscall surface.
pub fn request_run_async(vcpu_id: u64) -> Result<(), RunError> {
    let run_wait = {
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
        Arc::clone(&slot.run_wait)
    };
    run_wait.wake_one();
    Ok(())
}

/// Waits, at most `timeout_ns`, for a previously posted `RUN` to complete.
///
/// Returns the result published by the vCPU task (`Ok` or a `RunError`), or
/// [`RunError::Timeout`] when the task did not finish within the budget. The
/// timed-out request stays in flight; the caller must not post another `RUN`
/// until it completes.
pub fn wait_run_complete(vcpu_id: u64, timeout_ns: u64) -> Result<(), RunError> {
    let budget_ticks = (timeout_ns / crate::arch::timer::NS_PER_TICK).max(1);
    let deadline = ticks().saturating_add(budget_ticks);
    loop {
        {
            let mut worlds = WORLDS.lock();
            match locate_slot(&mut worlds, vcpu_id) {
                Some((world, index)) => {
                    let slot = &mut world.vcpus[index];
                    if slot.run_done {
                        return slot.run_result.take().unwrap_or(Ok(()));
                    }
                }
                None => return Err(RunError::UnknownVcpu),
            }
        }
        if ticks() >= deadline {
            return Err(RunError::Timeout);
        }
        sleep_current_task_ticks(1);
    }
}

/// Diagnostic state of the last `RUN` of a vCPU.
///
/// Returns `(done, in_flight, result)`. The result is `Some` as soon as the
/// vCPU task published the outcome of the run, so a caller that observes a
/// missing exit can distinguish "the run failed" from "the task never ran":
/// without it the only visible symptom is a timeout.
pub fn run_completion(vcpu_id: u64) -> Option<(bool, bool, Option<Result<(), RunError>>)> {
    let mut worlds = WORLDS.lock();
    let (world, index) = locate_slot(&mut worlds, vcpu_id)?;
    let slot = &world.vcpus[index];
    Some((slot.run_done, slot.run_in_flight, slot.run_result))
}

/// Requests execution of a vCPU and **blocks** the caller until the end of
/// that `RUN` (at most one policy exit).
///
/// Only one `RUN` can be in flight per vCPU; a second concurrent call receives
/// [`RunError::Busy`].
pub fn request_run(vcpu_id: u64) -> Result<(), RunError> {
    request_run_inner(vcpu_id, None)
}

/// Requests execution of a vCPU and waits at most `timeout_ns` for the end of
/// that `RUN`.
///
/// Returns [`RunError::Timeout`] if the vCPU task did not complete the request
/// within the budget. The request stays queued (`run_in_flight`), so a late
/// completion still clears the slot; the caller must treat the timeout as a
/// defect and must not issue another `RUN` before it completes.
pub fn request_run_timeout(vcpu_id: u64, timeout_ns: u64) -> Result<(), RunError> {
    request_run_async(vcpu_id)?;
    wait_run_complete(vcpu_id, timeout_ns)
}

fn request_run_inner(vcpu_id: u64, timeout_ns: Option<u64>) -> Result<(), RunError> {
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

    if let Some(timeout_ns) = timeout_ns {
        let budget_ticks = (timeout_ns / crate::arch::timer::NS_PER_TICK).max(1);
        let deadline = ticks().saturating_add(budget_ticks);
        loop {
            {
                let mut worlds = WORLDS.lock();
                match locate_slot(&mut worlds, vcpu_id) {
                    Some((world, index)) => {
                        let slot = &mut world.vcpus[index];
                        if slot.run_done {
                            return slot.run_result.take().unwrap_or(Ok(()));
                        }
                    }
                    None => return Err(RunError::UnknownVcpu),
                }
            }
            if ticks() >= deadline {
                return Err(RunError::Timeout);
            }
            sleep_current_task_ticks(1);
        }
    }

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
fn vcpu_world_mut(worlds: &mut WorldMap, vcpu_id: u64) -> Option<&mut World> {
    worlds
        .values_mut()
        .find(|world| !world.closing && world.vcpus.iter().any(|slot| slot.id == vcpu_id))
        .map(Box::as_mut)
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

/// Sets the guest CPU description (CPUID policy) of a world.
///
/// The policy belongs to the world, not to a vCPU: the device model and the
/// CPUID replay live in the world's `Machine`, so every vCPU of the world
/// observes the same CPU. Returns `false` when the world does not exist.
pub fn set_cpuid_policy(world_id: u64, policy: crate::s9vm::cpuid::CpuidPolicy) -> bool {
    let mut worlds = WORLDS.lock();
    match worlds.get_mut(&world_id) {
        Some(world) => {
            world.machine.set_cpuid_policy(policy);
            true
        }
        None => false,
    }
}

/// Current guest CPU description (CPUID policy) of a world.
pub fn cpuid_policy(world_id: u64) -> Option<crate::s9vm::cpuid::CpuidPolicy> {
    WORLDS
        .lock()
        .get(&world_id)
        .map(|world| world.machine.cpuid_policy())
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
    let worlds: WorldMap = {
        let mut guard = WORLDS.lock();
        core::mem::take(&mut *guard)
    };
    for (_, world) in worlds {
        if let Some(memory) = world.memory {
            memory.destroy();
        }
    }
}
