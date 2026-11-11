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

//! Per-CPU data (x86_64)
//!
//! Minimal per-CPU tracking for SMP bring-up. This keeps CPU identity,
//! online state, and per-CPU kernel stack top pointers.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// Maximum number of CPUs supported for now.
pub const MAX_CPUS: usize = 32;

/// Offsets used by the SYSCALL entry (must match `PerCpuArch` layout).
/// Note: cpu_index is at offset 0 (8 bytes).
pub const USER_RSP_OFFSET: usize = 8;
pub const KERNEL_RSP_OFFSET: usize = 16;
pub const PREEMPT_COUNT_OFFSET: usize = 24;

/// Minimal per-CPU block accessed from assembly via GS base.
///
/// **Layout invariant** (`#[repr(C)]`):
/// - `cpu_index`    at offset  0 (8 bytes) : read by assembly as `gs:[0]`
/// - `user_rsp`     at offset  8 (8 bytes)
/// - `kernel_rsp`   at offset 16 (8 bytes)
/// - `preempt_count` at offset 24 (4 bytes) : touched by `inc`/`dec`/`mov`
///   through `gs:[24]`, so a single GS-relative instruction always hits the
///   executing CPU's own counter even if an IRQ migrates the task between two
///   Rust statements.
///
/// `AtomicU64` is `#[repr(C, align(8))]` and has the same size/alignment as
/// `u64`, so the offsets declared in `USER_RSP_OFFSET`/`KERNEL_RSP_OFFSET` are
/// preserved. The inline assembly in `current_cpu_index()` reads the raw 8
/// bytes from `gs:[0]`, which are the inner `u64` of `AtomicU64`.
#[repr(C)]
pub struct PerCpuArch {
    /// CPU index for this block. Written once during init via `AtomicU64::store`
    /// (no raw-pointer cast needed), then only ever read. `AtomicU64` provides
    /// proper `UnsafeCell` interior mutability so reads through `&PerCpuArch`
    /// are not UB even though the field was written after the struct was placed
    /// in a `static`.
    pub cpu_index: AtomicU64, // offset 0 : read by assembly: `mov rax, gs:[0]`
    pub user_rsp: AtomicU64,   // offset 8
    pub kernel_rsp: AtomicU64, // offset 16
    /// Preemption-disable depth counter (offset 24).
    ///
    /// Lives in the arch block so it is reachable GS-relative: `inc`/`dec`
    /// through `gs:[PREEMPT_COUNT_OFFSET]` are atomic with respect to task
    /// migration (the segment base is re-read for the executing CPU).
    pub preempt_count: AtomicU32, // offset 24
}

const _: () = assert!(core::mem::offset_of!(PerCpuArch, user_rsp) == USER_RSP_OFFSET);
const _: () = assert!(core::mem::offset_of!(PerCpuArch, kernel_rsp) == KERNEL_RSP_OFFSET);
const _: () = assert!(
    core::mem::offset_of!(PerCpuArch, preempt_count) == PREEMPT_COUNT_OFFSET
);

/// Per-CPU state.
#[repr(C)]
pub struct PerCpu {
    pub arch: PerCpuArch,
    present: AtomicBool,
    online: AtomicBool,
    apic_id: AtomicU32,
    kernel_stack_top: AtomicU64,
    tlb_ready: AtomicBool,
    /// Fast signal-pending hint for the current CPU.
    ///
    /// Set by `send_signal` when a signal targets the task currently running
    /// on this CPU. Checked by the syscall dispatcher to avoid the expensive
    /// `current_task_clone()` + scheduler lock when no signal is pending.
    ///
    /// AtomicU32 (not AtomicBool) for better cache-line performance.
    ///
    /// NOTE TODO : the extra bits are reserved for future fast-pending flags.
    pub signal_pending: AtomicU32,
}

impl PerCpu {
    /// Creates a new instance.
    pub const fn new() -> Self {
        Self {
            arch: PerCpuArch {
                cpu_index: AtomicU64::new(0),
                user_rsp: AtomicU64::new(0),
                kernel_rsp: AtomicU64::new(0),
                preempt_count: AtomicU32::new(0),
            },
            present: AtomicBool::new(false),
            online: AtomicBool::new(false),
            apic_id: AtomicU32::new(0),
            kernel_stack_top: AtomicU64::new(0),
            tlb_ready: AtomicBool::new(false),
            signal_pending: AtomicU32::new(0),
        }
    }

    /// Performs the apic id operation.
    pub fn apic_id(&self) -> u32 {
        self.apic_id.load(Ordering::Acquire)
    }

    /// Performs the online operation.
    pub fn online(&self) -> bool {
        self.online.load(Ordering::Acquire)
    }
}

static CPU_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Bitmask of CPU indices that are currently online (MAX_CPUS = 32 bits).
///
/// Indices are assigned in MADT order at registration time, *before* an AP is
/// known to have booted, so the set of online indices can be sparse. Consumers
/// must iterate this mask instead of assuming `0..cpu_count()` is all online.
static ONLINE_MASK: AtomicU64 = AtomicU64::new(0);
static PERCPU: [PerCpu; MAX_CPUS] = [const { PerCpu::new() }; MAX_CPUS];

/// Set to `true` once the BSP has called `init_gs_base`.
///
/// Used by `current_cpu_index()` to skip the serialising `rdmsr` null-guard
/// on every hot-path call once GS is permanently initialised.
///
/// **Invariant**: APs always call `init_gs_base` *before* the first call to
/// `current_cpu_index()` on that AP (see `smp_main` in `smp.rs`).  Once
/// `BSP_GS_INITIALIZED` is true, any CPU that could possibly call
/// `current_cpu_index()` must already have a valid GS base, so the direct
/// `gs:[0]` read on the fast path is safe.
static BSP_GS_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the boot CPU (BSP) entry.
pub fn init_boot_cpu(apic_id: u32) -> usize {
    let cpu = &PERCPU[0];
    cpu.present.store(true, Ordering::Release);
    cpu.online.store(true, Ordering::Release);
    cpu.apic_id.store(apic_id, Ordering::Release);
    // AtomicU64::store through shared ref : no unsafe needed, UnsafeCell provides
    // interior mutability so this write is well-defined.
    cpu.arch.cpu_index.store(0, Ordering::Release);
    cpu.tlb_ready.store(false, Ordering::Release);
    CPU_COUNT.store(1, Ordering::Release);
    // BSP is always online; publish via the handshake mask as well.
    ONLINE_MASK.fetch_or(1, Ordering::SeqCst);
    0
}

/// Register a new CPU by APIC ID, returning its CPU index.
pub fn register_cpu(apic_id: u32) -> Option<usize> {
    for (idx, cpu) in PERCPU.iter().enumerate() {
        if cpu
            .present
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            cpu.online.store(false, Ordering::Release);
            cpu.apic_id.store(apic_id, Ordering::Release);
            cpu.arch.cpu_index.store(idx as u64, Ordering::Release);
            cpu.tlb_ready.store(false, Ordering::Release);
            CPU_COUNT.fetch_add(1, Ordering::AcqRel);
            return Some(idx);
        }
    }
    None
}

/// Mark a CPU as online by APIC ID.
///
/// Publication uses a `SeqCst` OR on `ONLINE_MASK` so it forms a handshake with
/// the BSP's `SeqCst` boot-window close: the BSP either observes this CPU as
/// online, or this CPU observes the closed window and revokes its own bit.
pub fn mark_online_by_apic(apic_id: u32) -> Option<usize> {
    for (idx, cpu) in PERCPU.iter().enumerate() {
        if cpu.present.load(Ordering::Acquire) && cpu.apic_id.load(Ordering::Acquire) == apic_id {
            cpu.online.store(true, Ordering::Release);
            cpu.tlb_ready.store(false, Ordering::Release);
            // Re-confirm index in arch block (no-op if already set, safe to repeat).
            cpu.arch.cpu_index.store(idx as u64, Ordering::Release);
            ONLINE_MASK.fetch_or(1u64 << idx, Ordering::SeqCst);
            return Some(idx);
        }
    }
    None
}

/// Returns `true` iff CPU `index` is present and currently published online.
pub fn is_online(index: usize) -> bool {
    if index >= MAX_CPUS {
        return false;
    }
    if !PERCPU[index].present.load(Ordering::Acquire) {
        return false;
    }
    ONLINE_MASK.load(Ordering::Acquire) & (1u64 << index) != 0
}

/// Number of currently online CPUs (popcount of the online mask).
pub fn online_count() -> usize {
    ONLINE_MASK.load(Ordering::Acquire).count_ones() as usize
}

/// Revoke the online bit for `index` (used by an AP that lost the boot race).
pub fn clear_online(index: usize) {
    if index >= MAX_CPUS {
        return;
    }
    ONLINE_MASK.fetch_and(!(1u64 << index), Ordering::SeqCst);
    PERCPU[index].online.store(false, Ordering::Release);
}

/// Fill `out` with online CPU indices in ascending order; returns the count.
///
/// Indices are sparse: callers must not assume the first `count` slots of
/// `0..cpu_count()` are the online ones.
pub fn online_cpu_indices(out: &mut [usize]) -> usize {
    let mask = ONLINE_MASK.load(Ordering::Acquire);
    let mut count = 0;
    for idx in 0..MAX_CPUS {
        if mask & (1u64 << idx) != 0 && is_online(idx) {
            if count == out.len() {
                break;
            }
            out[count] = idx;
            count += 1;
        }
    }
    count
}

/// Set the per-CPU kernel stack top for the given CPU index.
pub fn set_kernel_stack_top(index: usize, rsp: u64) {
    if let Some(cpu) = PERCPU.get(index) {
        cpu.kernel_stack_top.store(rsp, Ordering::Release);
    }
}

/// Get the per-CPU kernel stack top for the given CPU index.
pub fn kernel_stack_top(index: usize) -> Option<u64> {
    PERCPU
        .get(index)
        .map(|cpu| cpu.kernel_stack_top.load(Ordering::Acquire))
}

/// Set the per-CPU SYSCALL kernel RSP (used by syscall entry).
pub fn set_kernel_rsp_for_cpu(index: usize, rsp: u64) {
    if let Some(cpu) = PERCPU.get(index) {
        cpu.arch.kernel_rsp.store(rsp, Ordering::Release);
    }
}

/// Set the per-CPU SYSCALL kernel RSP for the current CPU.
pub fn set_kernel_rsp_current(rsp: u64) {
    let cpu_index = current_cpu_index();
    set_kernel_rsp_for_cpu(cpu_index, rsp);
}

/// Initialize GS base for this CPU to point at its per-CPU block.
///
/// Sets `IA32_GS_BASE` (0xC000_0101, current GS base) to
/// `&PERCPU[cpu_index].arch` for kernel execution, and initializes
/// `IA32_KERNEL_GS_BASE` (0xC000_0102) to 0 as the initial user GS base.
///
/// For the BSP (cpu_index == 0) this also sets `BSP_GS_INITIALIZED`, enabling
/// the fast (non-serialising) path in `current_cpu_index()`.
///
/// **Ordering for APs**: in `smp_main`, `init_gs_base` is called before the
/// first `current_cpu_index()` can execute on that AP, so it is safe to take
/// the fast path on the AP after the BSP flag is visible.
pub fn init_gs_base(cpu_index: usize) {
    let base = &PERCPU[cpu_index].arch as *const PerCpuArch as u64;
    // IA32_GS_BASE = 0xC000_0101, IA32_KERNEL_GS_BASE = 0xC000_0102.
    // Keep GS_BASE on kernel per-CPU for Ring 0; seed KERNEL_GS_BASE with 0
    // so the first Ring 0->3 transition can restore a non-kernel user GS.
    crate::arch::x86_64::wrmsr(0xC000_0101, base);
    crate::arch::x86_64::wrmsr(0xC000_0102, 0);

    if cpu_index == 0 {
        // Release ordering: all prior init writes must be visible before any
        // CPU sees the flag and takes the fast path in current_cpu_index().
        BSP_GS_INITIALIZED.store(true, Ordering::Release);
    }
}

/// Find a CPU index by APIC ID.
pub fn cpu_index_by_apic(apic_id: u32) -> Option<usize> {
    for (idx, cpu) in PERCPU.iter().enumerate() {
        if cpu.present.load(Ordering::Acquire) && cpu.apic_id.load(Ordering::Acquire) == apic_id {
            return Some(idx);
        }
    }
    None
}

/// Get the total number of CPUs that have been registered.
pub fn cpu_count() -> usize {
    CPU_COUNT.load(Ordering::Acquire)
}

/// Get the total number of CPUs (public alias for OSTD compatibility).
pub fn get_cpu_count() -> usize {
    cpu_count()
}

// ========== Preemption helpers ==========

/// Increment the preemption-disable depth for the current CPU.
/// When depth > 0, the scheduler will not preempt this CPU.
///
/// The counter lives at `gs:[PREEMPT_COUNT_OFFSET]`, so the increment is a
/// single GS-relative instruction: an IRQ arriving just before it cannot make
/// the task migrate and bump *another* CPU's counter (the segment base is
/// resolved for whichever task/CPU actually executes the `inc`).
///
/// Early boot is a no-op: before `init_gs_base` the GS base is 0, so the
/// instruction would fault. APs call `init_gs_base` before any preempt op.
#[inline]
pub fn preempt_disable() {
    if !BSP_GS_INITIALIZED.load(Ordering::Acquire) {
        return;
    }
    // SAFETY: GS base points at `PERCPU[current].arch` (offset 24 is the
    // preempt_count field, guaranteed by the layout asserts above). Prereq
    // `BSP_GS_INITIALIZED` => every CPU running kernel code has GS set.
    // `inc` on a GS-relative u32 is atomic wrt task migration.
    unsafe {
        core::arch::asm!(
            "inc dword ptr gs:[{off}]",
            off = const PREEMPT_COUNT_OFFSET,
            options(nostack),
        );
    }
}

/// Decrement the preemption-disable depth for the current CPU.
/// Must be paired with exactly one prior call to `preempt_disable`.
///
/// The decrement is a single `lock xadd` on `gs:[PREEMPT_COUNT_OFFSET]`, which
/// atomically returns the old value and subtracts one: an IRQ cannot migrate
/// the task between the read and the write, so the counter always belongs to
/// the CPU that actually executes the instruction.
///
/// Underflow guard: if the counter is already 0 (mismatched call), the
/// decrement is skipped and a warning is emitted rather than letting u32 wrap
/// to u32::MAX and disabling the scheduler permanently.
///
/// When the depth reaches 0, a reschedule that was requested while preemption
/// was disabled is serviced immediately via `maybe_preempt()`; otherwise the
/// request would sit pending until the next timer tick.
#[inline]
pub fn preempt_enable() {
    if !BSP_GS_INITIALIZED.load(Ordering::Acquire) {
        return;
    }
    // Single atomic read-modify-write: `lock xadd` returns the old value in
    // `prev` and subtracts one in the same uninterruptible operation, so an
    // IRQ cannot migrate the task between the read and the write.
    let mut prev: u32 = u32::MAX; // -1
    // SAFETY: see `preempt_disable`; the field is a plain u32 in the arch
    // block and the GS base is valid on this CPU.
    unsafe {
        core::arch::asm!(
            "lock xadd dword ptr gs:[{off}], {p:e}",
            p = inout(reg) prev,
            off = const PREEMPT_COUNT_OFFSET,
            options(nostack),
        );
    }
    if prev == 0 {
        // Mismatched preempt_enable : undo the wrap (u32::MAX -> 0) and log.
        unsafe {
            core::arch::asm!(
                "inc dword ptr gs:[{off}]",
                off = const PREEMPT_COUNT_OFFSET,
                options(nostack),
            );
        }
        log::warn!(
            "preempt_enable: underflow on CPU {} (mismatched call)",
            current_cpu_index()
        );
        return;
    }
    let next = prev - 1;
    if next == 0 {
        // Leaving the critical section with no nested guards left: honour any
        // reschedule requested while preemption was disabled. `maybe_preempt`
        // re-checks `is_preemptible()` (now true) and takes the scheduler lock
        // with `try_lock_no_irqsave`, so this cannot deadlock or recurse.
        crate::process::scheduler::maybe_preempt();
    }
}

/// Returns `true` if preemption is currently allowed on this CPU
/// (preempt_count == 0).
#[inline]
pub fn is_preemptible() -> bool {
    let idx = current_cpu_index();
    if PERCPU[idx].arch.cpu_index.load(Ordering::Relaxed) as usize != idx {
        return true; // Early boot: no scheduler active, preemption is allowed.
    }
    PERCPU[idx].arch.preempt_count.load(Ordering::Relaxed) == 0
}

/// Get the APIC ID for a given CPU index, or `None` if not present.
pub fn apic_id_by_cpu_index(index: usize) -> Option<u32> {
    PERCPU
        .get(index)
        .filter(|cpu| cpu.present.load(Ordering::Acquire))
        .map(|cpu| cpu.apic_id.load(Ordering::Acquire))
}

/// Resolve current CPU index via a GS-relative load from offset 0.
///
/// **Hot path** (after `init_gs_base` has run on the BSP): a single
/// non-serialising `mov rax, gs:[0]` : no MSR, no pipeline stall.
///
/// **Slow/early-boot path** (before `init_gs_base` is called the first time):
/// reads `IA32_GS_BASE` via `rdmsr` as a null-guard; if the GS base is 0
/// (hardware reset value, before our `wrmsr`) the function returns 0 (BSP
/// slot) without touching GS.  Once the BSP calls `init_gs_base`, the slow
/// path is never taken again.
///
/// **Corrupt-GS defence**: the returned index is clamped to [0, MAX_CPUS-1]
/// so a bogus GS value can never produce an out-of-bounds array access.
///
/// **Invariant for APs**: `smp_main` always calls `init_gs_base` before the
/// first `current_cpu_index()` on each AP, so the hot path is safe for APs.
#[inline]
pub fn current_cpu_index() -> usize {
    // SAFETY:
    // Hot path : `gs:[0]` reads `PerCpuArch::cpu_index` (AtomicU64, repr(C),
    // offset 0).  Valid because `BSP_GS_INITIALIZED` is only set after the BSP's
    // GS base has been written, and APs always write their GS base before
    // executing any code that calls this function.
    //
    // Slow path : `rdmsr` is a privileged Ring-0 instruction, always valid here.
    // The derference of `gs_base` is guarded by the != 0 check.
    unsafe {
        if BSP_GS_INITIALIZED.load(Ordering::Acquire) {
            // Fast path: GS is valid on every CPU that can run kernel code now.
            let idx: u64;
            core::arch::asm!(
                "mov {idx}, gs:[0]",
                idx = out(reg) idx,
                options(nostack, preserves_flags, readonly),
            );
            return (idx as usize).min(MAX_CPUS - 1);
        }

        // Slow path: early boot : GS not yet set on any CPU.
        // `rdmsr` reads IA32_GS_BASE (0xC000_0101) as a null-guard.
        let lo: u32;
        let hi: u32;
        core::arch::asm!(
            "rdmsr",
            in("ecx")  0xC000_0101u32,
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags),
        );
        let gs_base = (lo as u64) | ((hi as u64) << 32);
        if gs_base == 0 {
            return 0; // GS not yet initialised : early boot, return BSP slot.
        }

        // GS is set but BSP_GS_INITIALIZED wasn't yet visible (narrow race
        // between wrmsr and the store; take the GS-relative read here too).
        let idx: u64;
        core::arch::asm!(
            "mov {idx}, gs:[0]",
            idx = out(reg) idx,
            options(nostack, preserves_flags, readonly),
        );
        (idx as usize).min(MAX_CPUS - 1)
    }
}

/// Alias for current_cpu_index.
#[inline]
pub fn current_cpu_index_fast() -> usize {
    current_cpu_index()
}

/// Resolve current CPU index from GS base (compatibility).
pub fn cpu_index_from_gs() -> Option<usize> {
    Some(current_cpu_index())
}

/// Access the per-CPU array (read-only).
pub fn percpu() -> &'static [PerCpu; MAX_CPUS] {
    &PERCPU
}

/// Mark current CPU as ready to handle TLB shootdown IPIs.
///
/// Ordering matters: publish readiness with `Release`, then a `SeqCst` fence,
/// then flush the local TLB. Any page-table modification made before
/// readiness was published is guaranteed visible and flushed before the CPU
/// can acknowledge a shootdown.
pub fn mark_tlb_ready_current() {
    let idx = current_cpu_index();
    PERCPU[idx].tlb_ready.store(true, Ordering::Release);
    core::sync::atomic::fence(Ordering::SeqCst);
    crate::arch::x86_64::tlb::flush_local_all();
}

/// Returns true iff CPU `index` is online and ready for TLB shootdown.
pub fn tlb_ready(index: usize) -> bool {
    PERCPU
        .get(index)
        .map(|cpu| {
            cpu.present.load(Ordering::Acquire)
                && cpu.online.load(Ordering::Acquire)
                && cpu.tlb_ready.load(Ordering::Acquire)
        })
        .unwrap_or(false)
}

// ========== Fast signal-pending hint ==========

/// Set the `signal_pending` flag for the current CPU.
///
/// Called by `send_signal` when a signal targets the task running on this CPU.
/// The syscall dispatcher checks this flag to avoid the expensive scheduler
/// lock when no signal is pending.
#[inline]
pub fn set_signal_pending_current() {
    let idx = current_cpu_index();
    PERCPU[idx].signal_pending.store(1, Ordering::Release);
}

/// Test and clear the `signal_pending` flag for the current CPU.
///
/// Returns `true` if a signal was marked pending since the last check.
/// This is a one-shot check : the flag is cleared atomically.
#[inline]
pub fn test_and_clear_signal_pending_current() -> bool {
    let idx = current_cpu_index();
    PERCPU[idx].signal_pending.swap(0, Ordering::AcqRel) != 0
}
