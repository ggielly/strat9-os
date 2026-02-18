//! Task State Segment (TSS) for Strat9-OS
//!
//! The TSS is required for:
//! - Interrupt Stack Table (IST) entries for safe exception handling
//! - Ring 3 -> Ring 0 stack switching (privilege_stack_table[0] = rsp0)

use core::{
    mem::MaybeUninit,
    sync::atomic::{AtomicBool, Ordering},
};
use x86_64::{structures::tss::TaskStateSegment, VirtAddr};

/// IST index used for the double fault handler
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

/// IST stack size (20 KB)
const IST_STACK_SIZE: usize = 4096 * 5;

/// Static IST stacks for double fault handler (per-CPU)
static mut IST_STACKS: [[u8; IST_STACK_SIZE]; crate::arch::x86_64::percpu::MAX_CPUS] =
    [[0; IST_STACK_SIZE]; crate::arch::x86_64::percpu::MAX_CPUS];

/// Per-CPU TSS storage
static mut TSS: [MaybeUninit<TaskStateSegment>; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { MaybeUninit::uninit() }; crate::arch::x86_64::percpu::MAX_CPUS];

static TSS_INIT: [AtomicBool; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; crate::arch::x86_64::percpu::MAX_CPUS];

/// Initialize the TSS with IST entries
///
/// Must be called before `gdt::init()` since the GDT references the TSS.
pub fn init() {
    init_cpu(0);
}

/// Initialize the TSS for a given CPU index.
pub fn init_cpu(cpu_index: usize) {
    // SAFETY: Called during init (BSP) or AP bring-up before interrupts are enabled on that CPU.
    unsafe {
        let stack_ptr = &raw const IST_STACKS[cpu_index] as *const u8;
        let stack_end = VirtAddr::from_ptr(stack_ptr) + IST_STACK_SIZE as u64;
        let mut tss = TaskStateSegment::new();
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = stack_end;

        TSS[cpu_index].write(tss);
        TSS_INIT[cpu_index].store(true, Ordering::Release);

        let ist_addr = VirtAddr::from_ptr(stack_ptr);
        log::info!(
            "TSS[CPU{}] initialized: IST[{}] stack @ {:#x}..{:#x} ({} KB)",
            cpu_index,
            DOUBLE_FAULT_IST_INDEX,
            ist_addr.as_u64(),
            ist_addr.as_u64() + IST_STACK_SIZE as u64,
            IST_STACK_SIZE / 1024,
        );
    }
}

/// Get a reference to the TSS for a given CPU index (for GDT descriptor creation).
pub fn tss_for(cpu_index: usize) -> &'static TaskStateSegment {
    if !TSS_INIT[cpu_index].load(Ordering::Acquire) {
        panic!("TSS for CPU{} not initialized", cpu_index);
    }
    // SAFETY: TSS was initialized in init_cpu and lives for 'static.
    unsafe { &*TSS[cpu_index].as_ptr() }
}

/// Update TSS.rsp0 — the kernel stack pointer used when transitioning
/// from Ring 3 to Ring 0 on interrupt/syscall.
///
/// Called on every context switch to point to the new task's kernel stack top.
pub fn set_kernel_stack(stack_top: VirtAddr) {
    let apic_id = super::apic::lapic_id();
    let cpu_index = crate::arch::x86_64::percpu::cpu_index_by_apic(apic_id).unwrap_or(0);
    set_kernel_stack_for(cpu_index, stack_top);
}

/// Update TSS.rsp0 for a specific CPU index.
pub fn set_kernel_stack_for(cpu_index: usize, stack_top: VirtAddr) {
    // SAFETY: privilege_stack_table[0] is a VirtAddr (u64), writes are atomic on x86_64.
    // Called with interrupts disabled or from the scheduler with lock held.
    if !TSS_INIT[cpu_index].load(Ordering::Acquire) {
        return;
    }
    unsafe {
        let tss = &raw mut *TSS[cpu_index].as_mut_ptr();
        (*tss).privilege_stack_table[0] = stack_top;
    }
}
