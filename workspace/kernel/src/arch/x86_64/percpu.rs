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

/// Minimal per-CPU block accessed from assembly via GS base.
///
/// **Layout invariant** (`#[repr(C)]`):
/// - `cpu_index` at offset  0 (8 bytes) : read by assembly as `gs:[0]`
/// - `user_rsp`  at offset  8 (8 bytes)
/// - `kernel_rsp` at offset 16 (8 bytes)
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
}

const _: () = assert!(core::mem::offset_of!(PerCpuArch, user_rsp) == USER_RSP_OFFSET);
const _: () = assert!(core::mem::offset_of!(PerCpuArch, kernel_rsp) == KERNEL_RSP_OFFSET);

/// Per-CPU state.
#[repr(C)]
pub struct PerCpu {
    pub arch: PerCpuArch,
    present: AtomicBool,
    online: AtomicBool,
    apic_id: AtomicU32,
    kernel_stack_top: AtomicU64,
    tlb_ready: AtomicBool,
    /// Preemption-disable depth counter.
    /// When > 0, `maybe_preempt()` and `yield_task()` are no-ops on this CPU.
    pub preempt_count: AtomicU32,
}

impl PerCpu {
    /// Creates a new instance.
    pub const fn new() -> Self {
        Self {
            arch: PerCpuArch {
                cpu_index: AtomicU64::new(0),
                user_rsp: AtomicU64::new(0),
                kernel_rsp: AtomicU64::new(0),
            },
            present: AtomicBool::new(false),
            online: AtomicBool::new(false),
            apic_id: AtomicU32::new(0),
            kernel_stack_top: AtomicU64::new(0),
            tlb_ready: AtomicBool::new(false),
            preempt_count: AtomicU32::new(0),
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
pub fn mark_online_by_apic(apic_id: u32) -> Option<usize> {
    for (idx, cpu) in PERCPU.iter().enumerate() {
        if cpu.present.load(Ordering::Acquire) && cpu.apic_id.load(Ordering::Acquire) == apic_id {
            cpu.online.store(true, Ordering::Release);
            cpu.tlb_ready.store(false, Ordering::Release);
            // Re-confirm index in arch block (no-op if already set, safe to repeat).
            cpu.arch.cpu_index.store(idx as u64, Ordering::Release);
            return Some(idx);
        }
    }
    None
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
/// Safe to call from any Ring-0 context **after** `init_gs_base` has run on
/// this CPU.  If called before GS is initialised (early boot), `current_cpu_index`
/// returns 0, which is always the BSP slot.  On the BSP itself that is correct;
/// on an AP before its GS base is set the call is a no-op because the AP's
/// scheduler is not yet running : incrementing slot 0 would be wrong, so we
/// verify the GS index matches the slot we are about to touch.
#[inline]
pub fn preempt_disable() {
    let idx = current_cpu_index();
    // SAFETY: idx is clamped to [0, MAX_CPUS-1] by current_cpu_index().
    // Additional guard: if GS is not yet set on this CPU, cpu_index will be
    // the BSP's slot (0).  Skip if the slot's stored cpu_index disagrees with
    // idx : that means GS isn't set here yet.
    if PERCPU[idx].arch.cpu_index.load(Ordering::Relaxed) as usize == idx {
        PERCPU[idx].preempt_count.fetch_add(1, Ordering::Relaxed);
    }
}

/// Decrement the preemption-disable depth for the current CPU.
/// Must be paired with exactly one prior call to `preempt_disable`.
///
/// Includes an underflow guard: if the counter is already 0 (mismatched call),
/// the decrement is skipped and a warning is emitted rather than letting u32
/// wrap to u32::MAX and disabling the scheduler permanently.
#[inline]
pub fn preempt_enable() {
    let idx = current_cpu_index();
    if PERCPU[idx].arch.cpu_index.load(Ordering::Relaxed) as usize == idx {
        // Load first: prevent wrapping from 0 to u32::MAX.
        let prev = PERCPU[idx].preempt_count.load(Ordering::Relaxed);
        if prev > 0 {
            PERCPU[idx].preempt_count.fetch_sub(1, Ordering::Relaxed);
        } else {
            // Mismatched preempt_enable : log and leave count at 0.
            log::warn!("preempt_enable: underflow on CPU {} (mismatched call)", idx);
        }
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
    PERCPU[idx].preempt_count.load(Ordering::Relaxed) == 0
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
pub fn mark_tlb_ready_current() {
    let idx = current_cpu_index();
    PERCPU[idx].tlb_ready.store(true, Ordering::Release);
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
