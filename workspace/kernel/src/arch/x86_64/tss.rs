//! Task State Segment (TSS) for Strat9-OS
//!
//! The TSS is required for:
//! - Interrupt Stack Table (IST) entries for safe exception handling
//! - Ring 3 -> Ring 0 stack switching (privilege_stack_table[0] = rsp0)

use core::{
    mem::MaybeUninit,
    panic::Location,
    sync::atomic::{AtomicBool, Ordering},
};
use x86_64::{structures::tss::TaskStateSegment, VirtAddr};

#[repr(C, packed)]
struct DescriptorTableRegister {
    limit: u16,
    base: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct LoadedTssInfo {
    pub tr_selector: u16,
    pub tss_base: u64,
    pub rsp0: u64,
}

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
    // Bounds check: prevent OOB access into static arrays before any unsafe.
    assert!(
        cpu_index < crate::arch::x86_64::percpu::MAX_CPUS,
        "TSS init_cpu: cpu_index {} >= MAX_CPUS {}",
        cpu_index,
        crate::arch::x86_64::percpu::MAX_CPUS,
    );
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
    assert!(
        cpu_index < crate::arch::x86_64::percpu::MAX_CPUS,
        "tss_for: cpu_index {} >= MAX_CPUS",
        cpu_index,
    );
    if !TSS_INIT[cpu_index].load(Ordering::Acquire) {
        panic!("TSS for CPU{} not initialized", cpu_index);
    }
    // SAFETY: TSS was initialized in init_cpu and lives for 'static.
    unsafe { &*TSS[cpu_index].as_ptr() }
}

/// Return TSS.rsp0 for a specific CPU, if its TSS is initialized.
pub fn kernel_stack_for(cpu_index: usize) -> Option<VirtAddr> {
    if cpu_index >= crate::arch::x86_64::percpu::MAX_CPUS {
        return None;
    }
    if !TSS_INIT[cpu_index].load(Ordering::Acquire) {
        return None;
    }
    // SAFETY: The TSS for this CPU is initialized and lives for the whole kernel lifetime.
    unsafe {
        let tss = &*TSS[cpu_index].as_ptr();
        Some(tss.privilege_stack_table[0])
    }
}

/// Read the TSS currently loaded in TR by decoding the live GDT entry.
pub fn loaded_tss_info() -> Option<LoadedTssInfo> {
    let mut gdtr = DescriptorTableRegister { limit: 0, base: 0 };
    let tr_selector: u16;
    // SAFETY: `sgdt`/`str` are privileged register reads with no side effect.
    unsafe {
        core::arch::asm!(
            "sgdt [{}]",
            in(reg) &mut gdtr,
            options(nostack, preserves_flags),
        );
        core::arch::asm!(
            "str {0:x}",
            out(reg) tr_selector,
            options(nostack, nomem, preserves_flags),
        );
    }

    if tr_selector == 0 {
        return None;
    }

    let entry_offset = (tr_selector & !0x7) as usize;
    if entry_offset + 16 > gdtr.limit as usize + 1 {
        return None;
    }

    // SAFETY: The GDTR base/limit were read from the CPU and bounds-checked above.
    let (low, high) = unsafe {
        let entry_ptr = (gdtr.base + entry_offset as u64) as *const u64;
        (
            core::ptr::read_unaligned(entry_ptr),
            core::ptr::read_unaligned(entry_ptr.add(1)),
        )
    };

    let base_low =
        ((low >> 16) & 0xFFFF) | (((low >> 32) & 0xFF) << 16) | (((low >> 56) & 0xFF) << 24);
    let tss_base = base_low | (high << 32);
    if tss_base == 0 {
        return None;
    }

    // SAFETY: The live TSS base comes from the CPU's TSS descriptor.
    let rsp0 = unsafe {
        let tss = &*(tss_base as *const TaskStateSegment);
        tss.privilege_stack_table[0].as_u64()
    };

    Some(LoadedTssInfo {
        tr_selector,
        tss_base,
        rsp0,
    })
}

/// Update TSS.rsp0 — the kernel stack pointer used when transitioning
/// from Ring 3 to Ring 0 on interrupt/syscall.
///
/// Called on every context switch to point to the new task's kernel stack top.
#[track_caller]
pub fn set_kernel_stack(stack_top: VirtAddr) {
    let cpu_index = crate::arch::x86_64::percpu::current_cpu_index();
    set_kernel_stack_for(cpu_index, stack_top);
}

/// Update TSS.rsp0 for a specific CPU index.
#[track_caller]
pub fn set_kernel_stack_for(cpu_index: usize, stack_top: VirtAddr) {
    if cpu_index >= crate::arch::x86_64::percpu::MAX_CPUS {
        log::warn!("set_kernel_stack_for: cpu_index {} out of range", cpu_index);
        return;
    }
    // SAFETY: privilege_stack_table[0] is a VirtAddr (u64), writes are atomic on x86_64.
    // Called with interrupts disabled or from the scheduler with lock held.
    if !TSS_INIT[cpu_index].load(Ordering::Acquire) {
        return;
    }
    let caller = Location::caller();
    unsafe {
        let tss = &raw mut *TSS[cpu_index].as_mut_ptr();
        let old_stack_top = (*tss).privilege_stack_table[0];
        (*tss).privilege_stack_table[0] = stack_top;
        crate::e9_println!(
            "[tss-set] cpu={} old={:#x} new={:#x} caller={}:{}",
            cpu_index,
            old_stack_top.as_u64(),
            stack_top.as_u64(),
            caller.file(),
            caller.line()
        );
    }
}
