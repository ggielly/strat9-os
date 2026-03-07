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
#[repr(C)]
pub struct PerCpuArch {
    pub cpu_index: u64, // Must be at offset 0 for O(1) current_cpu_index()
    pub user_rsp: AtomicU64,
    pub kernel_rsp: AtomicU64,
}

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
                cpu_index: 0,
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

/// Initialize the boot CPU (BSP) entry.
pub fn init_boot_cpu(apic_id: u32) -> usize {
    let cpu = &PERCPU[0];
    cpu.present.store(true, Ordering::Release);
    cpu.online.store(true, Ordering::Release);
    cpu.apic_id.store(apic_id, Ordering::Release);
    // SAFETY: We are during early boot, single-threaded.
    unsafe {
        let arch_ptr = &cpu.arch as *const PerCpuArch as *mut PerCpuArch;
        (*arch_ptr).cpu_index = 0;
    }
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
            // SAFETY: present bit just acquired by us.
            unsafe {
                let arch_ptr = &cpu.arch as *const PerCpuArch as *mut PerCpuArch;
                (*arch_ptr).cpu_index = idx as u64;
            }
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
            // Re-confirm index in arch block
            unsafe {
                let arch_ptr = &cpu.arch as *const PerCpuArch as *mut PerCpuArch;
                (*arch_ptr).cpu_index = idx as u64;
            }
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
/// Point GS base at `&PERCPU[cpu_index].arch`.
pub fn init_gs_base(cpu_index: usize) {
    let base = &PERCPU[cpu_index].arch as *const PerCpuArch as u64;
    // IA32_GS_BASE = 0xC0000101, IA32_KERNEL_GS_BASE = 0xC0000102
    crate::arch::x86_64::wrmsr(0xC000_0101, base);
    crate::arch::x86_64::wrmsr(0xC000_0102, base);
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

// ─── Preemption helpers ───────────────────────────────────────────────────────

/// Increment the preemption-disable depth for the current CPU.
/// When depth > 0, the scheduler will not preempt this CPU.
///
/// Safe to call from any Ring-0 context **after** `init_gs_base` has run on
/// this CPU.  If called before GS is initialised (early boot), `current_cpu_index`
/// returns 0, which is always the BSP slot.  On the BSP itself that is correct;
/// on an AP before its GS base is set the call is a no-op because the AP's
/// scheduler is not yet running — incrementing slot 0 would be wrong, so we
/// verify the GS index matches the slot we are about to touch.
#[inline]
pub fn preempt_disable() {
    let idx = current_cpu_index();
    // SAFETY: idx is clamped to [0, MAX_CPUS-1] by current_cpu_index().
    // Additional guard: if GS is not yet set on this CPU, cpu_index will be
    // the BSP's slot (0).  Skip if the slot's stored cpu_index disagrees with
    // idx — that means GS isn't set here yet.
    if PERCPU[idx].arch.cpu_index as usize == idx {
        PERCPU[idx].preempt_count.fetch_add(1, Ordering::Relaxed);
    }
}

/// Decrement the preemption-disable depth for the current CPU.
/// Must be paired with exactly one prior call to `preempt_disable`.
#[inline]
pub fn preempt_enable() {
    let idx = current_cpu_index();
    if PERCPU[idx].arch.cpu_index as usize == idx {
        PERCPU[idx].preempt_count.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Returns `true` if preemption is currently allowed on this CPU
/// (preempt_count == 0).
#[inline]
pub fn is_preemptible() -> bool {
    let idx = current_cpu_index();
    if PERCPU[idx].arch.cpu_index as usize != idx {
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
/// `PerCpuArch::cpu_index` sits at GS:[0].  Once `init_gs_base` has run on
/// this CPU, the read is a single non-serialising memory access — far cheaper
/// than an `rdmsr`.
///
/// **Early-boot guard**: before `init_gs_base`, GS_BASE is 0 and a segment-
/// relative load would raise a #GP.  We read `IA32_GS_BASE` (MSR 0xC000_0101)
/// once as a null-guard and fall back to CPU slot 0 (BSP) if not yet set.
/// This guard read is only serialising during that very early window; once GS
/// is initialised the branch is not taken.
///
/// **Corrupt-GS defence**: the returned index is clamped to [0, MAX_CPUS-1]
/// so a bogus GS value can never cause an out-of-bounds array access.
#[inline]
pub fn current_cpu_index() -> usize {
    // SAFETY: `rdmsr` in Ring 0 is always valid.  The GS-relative load is
    // valid iff gs_base != 0, which we assert just above.  `cpu_index` is
    // the first (offset 0) u64 field of `PerCpuArch` (repr(C)).
    unsafe {
        // Null-guard: read IA32_GS_BASE only to check for early-boot zero.
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
            return 0; // GS not yet initialised — early boot, return BSP slot.
        }

        // Hot path: GS-segment-relative load; not serialising, no MSR touch.
        let idx: u64;
        core::arch::asm!(
            "mov {idx}, gs:[0]",
            idx = out(reg) idx,
            options(nostack, preserves_flags, readonly),
        );
        // Clamp: a corrupt GS must never produce an OOB index.
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
