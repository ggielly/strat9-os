//! Global Descriptor Table (GDT) for Strat9-OS
//!
//! Sets up the GDT with kernel code/data segments, user segments for SYSRET,
//! and a TSS descriptor. The TSS must be initialized before this module.
//!
//! ## Segment layout (SYSRET-compatible)
//!
//! ```text
//! Index 0: Null
//! Index 1: Kernel Code 64-bit  (CS=0x08)     ← SYSCALL loads CS from STAR[47:32]
//! Index 2: Kernel Data          (SS=0x10)     ← SYSCALL loads SS
//! Index 3: User Code 32-bit    (dummy, 0x18)  ← STAR[63:48] base
//! Index 4: User Data            (0x20)        ← SYSRETQ: SS = base+8 | RPL3 = 0x23
//! Index 5: User Code 64-bit    (0x28)        ← SYSRETQ: CS = base+16 | RPL3 = 0x2B
//! Index 6-7: TSS (16-byte descriptor)
//! ```
//!
//! STAR MSR: `[47:32]=0x08` (kernel CS), `[63:48]=0x18` (index 3).
//! SYSRETQ: CS = 0x18+16 = 0x28 | RPL3 = 0x2B, SS = 0x18+8 = 0x20 | RPL3 = 0x23.

use core::{
    mem::MaybeUninit,
    sync::atomic::{AtomicBool, Ordering},
};
use x86_64::{
    instructions::{
        segmentation::{Segment, CS, DS, SS},
        tables::load_tss,
    },
    structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector},
};

/// GDT storage — per CPU
static mut GDT: [MaybeUninit<GlobalDescriptorTable>; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { MaybeUninit::uninit() }; crate::arch::x86_64::percpu::MAX_CPUS];

/// Cached segment selectors after GDT is loaded (per CPU)
static mut SELECTORS: [MaybeUninit<Selectors>; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { MaybeUninit::uninit() }; crate::arch::x86_64::percpu::MAX_CPUS];
static SELECTORS_INIT: [AtomicBool; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; crate::arch::x86_64::percpu::MAX_CPUS];

#[derive(Copy, Clone)]
struct Selectors {
    kernel_code: SegmentSelector,
    kernel_data: SegmentSelector,
    #[allow(dead_code)]
    user_code32: SegmentSelector,
    user_data: SegmentSelector,
    user_code64: SegmentSelector,
    #[allow(dead_code)]
    tss: SegmentSelector,
}

/// Initialize the GDT with kernel segments, user segments, and TSS.
///
/// **Prerequisite**: `tss::init()` must be called first.
///
/// The segment ordering is critical for SYSRET to work correctly.
/// SYSRET expects: STAR[63:48] points to a base where base+0 = user_code32,
/// base+8 = user_data, base+16 = user_code64.
pub fn init() {
    init_cpu(0);
}

/// Initialize the GDT for a given CPU index.
pub fn init_cpu(cpu_index: usize) {
    // SAFETY: Called during init (BSP) or AP bring-up before interrupts are enabled on that CPU.
    unsafe {
        let gdt = &mut *GDT[cpu_index].as_mut_ptr();
        *gdt = GlobalDescriptorTable::new();

        // Index 1: Kernel Code 64-bit (0x08)
        let kernel_code = gdt.append(Descriptor::kernel_code_segment());
        // Index 2: Kernel Data (0x10)
        let kernel_data = gdt.append(Descriptor::kernel_data_segment());

        // Index 3: User Code 32-bit dummy (0x18)
        // SYSRET requires this slot to exist. We create a 32-bit code segment
        // with DPL=3 that is never actually used for execution.
        // Descriptor bits: Present | DPL=3 | Code segment | Readable | 32-bit
        let user_code32_bits: u64 = (1 << 47)       // Present
            | (3 << 45)                               // DPL = 3
            | (1 << 44)                               // S = 1 (code/data)
            | (1 << 43)                               // Executable
            | (1 << 41)                               // Readable
            | (1 << 54); // D = 1 (32-bit default)
        let user_code32 = gdt.append(Descriptor::UserSegment(user_code32_bits));

        // Index 4: User Data (0x20)
        let user_data = gdt.append(Descriptor::user_data_segment());
        // Index 5: User Code 64-bit (0x28)
        let user_code64 = gdt.append(Descriptor::user_code_segment());

        // Index 6-7: TSS (16-byte descriptor)
        let tss_sel = gdt.append(Descriptor::tss_segment(super::tss::tss_for(cpu_index)));

        gdt.load_unsafe();

        // Reload segment registers with new selectors
        CS::set_reg(kernel_code);
        DS::set_reg(kernel_data);
        SS::set_reg(kernel_data);

        // Load TSS into task register
        load_tss(tss_sel);

        SELECTORS[cpu_index].write(Selectors {
            kernel_code,
            kernel_data,
            user_code32,
            user_data,
            user_code64,
            tss: tss_sel,
        });
        SELECTORS_INIT[cpu_index].store(true, Ordering::Release);

        log::info!(
            "GDT[CPU{}] loaded: CS={:#x} DS/SS={:#x} user32={:#x} user_data={:#x} user64={:#x} TSS={:#x}",
            cpu_index,
            kernel_code.0,
            kernel_data.0,
            user_code32.0,
            user_data.0,
            user_code64.0,
            tss_sel.0,
        );
    }
}

/// Get the kernel code segment selector
pub fn kernel_code_selector() -> SegmentSelector {
    selectors_for(current_cpu_index()).kernel_code
}

/// Get the kernel data segment selector
pub fn kernel_data_selector() -> SegmentSelector {
    selectors_for(current_cpu_index()).kernel_data
}

/// Get the user code 64-bit segment selector (with RPL=3)
pub fn user_code_selector() -> SegmentSelector {
    let sel = selectors_for(current_cpu_index()).user_code64;
    SegmentSelector(sel.0 | 3) // Set RPL=3
}

/// Get the user data segment selector (with RPL=3)
pub fn user_data_selector() -> SegmentSelector {
    let sel = selectors_for(current_cpu_index()).user_data;
    SegmentSelector(sel.0 | 3) // Set RPL=3
}

/// Get the raw STAR MSR value for SYSCALL/SYSRET.
///
/// STAR[47:32] = kernel CS selector (for SYSCALL entry)
/// STAR[63:48] = user code 32 selector base (for SYSRET calculation)
pub fn star_msr_value() -> u64 {
    let sels = selectors_for(current_cpu_index());
    let kernel_cs = sels.kernel_code.0 as u64;
    let user_base = sels.user_code32.0 as u64; // 0x18 (without RPL)
    (kernel_cs << 32) | (user_base << 48)
}

fn selectors_for(cpu_index: usize) -> Selectors {
    if !SELECTORS_INIT[cpu_index].load(Ordering::Acquire) {
        panic!("GDT selectors for CPU{} not initialized", cpu_index);
    }
    // SAFETY: Initialized in init_cpu and stored for 'static lifetime.
    unsafe { *SELECTORS[cpu_index].as_ptr() }
}

fn current_cpu_index() -> usize {
    let apic_id = super::apic::lapic_id();
    crate::arch::x86_64::percpu::cpu_index_by_apic(apic_id).unwrap_or(0)
}
