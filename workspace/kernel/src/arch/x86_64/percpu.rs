//! Per-CPU data (x86_64)
//!
//! Minimal per-CPU tracking for SMP bring-up. This keeps CPU identity,
//! online state, and per-CPU kernel stack top pointers.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// Maximum number of CPUs supported for now.
pub const MAX_CPUS: usize = 32;

/// Offsets used by the SYSCALL entry (must match `PerCpuArch` layout).
pub const USER_RSP_OFFSET: usize = 0;
pub const KERNEL_RSP_OFFSET: usize = 8;

/// Minimal per-CPU block accessed from assembly via GS base.
#[repr(C)]
pub struct PerCpuArch {
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
    cpu_index: AtomicU32,
    kernel_stack_top: AtomicU64,
    /// Preemption-disable depth counter.
    /// When > 0, `maybe_preempt()` and `yield_task()` are no-ops on this CPU.
    pub preempt_count: AtomicU32,
}

impl PerCpu {
    pub const fn new() -> Self {
        Self {
            arch: PerCpuArch {
                user_rsp: AtomicU64::new(0),
                kernel_rsp: AtomicU64::new(0),
            },
            present: AtomicBool::new(false),
            online: AtomicBool::new(false),
            apic_id: AtomicU32::new(0),
            cpu_index: AtomicU32::new(0),
            kernel_stack_top: AtomicU64::new(0),
            preempt_count: AtomicU32::new(0),
        }
    }

    pub fn apic_id(&self) -> u32 {
        self.apic_id.load(Ordering::Acquire)
    }

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
    cpu.cpu_index.store(0, Ordering::Release);
    CPU_COUNT.store(1, Ordering::Release);
    0
}

/// Register a new CPU by APIC ID, returning its CPU index.
pub fn register_cpu(apic_id: u32) -> Option<usize> {
    for (idx, cpu) in PERCPU.iter().enumerate() {
        if !cpu.present.load(Ordering::Acquire) {
            cpu.present.store(true, Ordering::Release);
            cpu.online.store(false, Ordering::Release);
            cpu.apic_id.store(apic_id, Ordering::Release);
            cpu.cpu_index.store(idx as u32, Ordering::Release);
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
    PERCPU.get(index)
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
    let apic_id = crate::arch::x86_64::apic::lapic_id();
    let cpu_index = cpu_index_by_apic(apic_id).unwrap_or(0);
    set_kernel_rsp_for_cpu(cpu_index, rsp);
}

/// Initialize GS base for this CPU to point at its per-CPU block.
pub fn init_gs_base(cpu_index: usize) {
    let base = &PERCPU[cpu_index] as *const PerCpu as u64;
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

// ─── Preemption helpers ───────────────────────────────────────────────────────

/// Increment the preemption-disable depth for the current CPU.
/// When depth > 0, the scheduler will not preempt this CPU.
#[inline]
pub fn preempt_disable() {
    let idx = current_cpu_index_fast();
    PERCPU[idx].preempt_count.fetch_add(1, Ordering::Relaxed);
}

/// Decrement the preemption-disable depth for the current CPU.
/// Must be paired with exactly one prior call to `preempt_disable`.
#[inline]
pub fn preempt_enable() {
    let idx = current_cpu_index_fast();
    PERCPU[idx].preempt_count.fetch_sub(1, Ordering::Relaxed);
}

/// Returns `true` if preemption is currently allowed on this CPU
/// (preempt_count == 0).
#[inline]
pub fn is_preemptible() -> bool {
    let idx = current_cpu_index_fast();
    PERCPU[idx].preempt_count.load(Ordering::Relaxed) == 0
}

/// Get the APIC ID for a given CPU index, or `None` if not present.
pub fn apic_id_by_cpu_index(index: usize) -> Option<u32> {
    PERCPU
        .get(index)
        .filter(|cpu| cpu.present.load(Ordering::Acquire))
        .map(|cpu| cpu.apic_id.load(Ordering::Acquire))
}

/// Fast current-CPU index lookup via APIC ID (CPUID instruction).
/// Returns 0 if APIC is not yet initialized.
#[inline]
fn current_cpu_index_fast() -> usize {
    let apic_id = crate::arch::x86_64::apic::lapic_id();
    cpu_index_by_apic(apic_id).unwrap_or(0)
}

/// Access the per-CPU array (read-only).
pub fn percpu() -> &'static [PerCpu; MAX_CPUS] {
    &PERCPU
}
