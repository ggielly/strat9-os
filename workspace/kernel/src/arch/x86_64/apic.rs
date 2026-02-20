//! Local APIC (Advanced Programmable Interrupt Controller) driver
//!
//! Provides MMIO-based access to the Local APIC registers.
//! The Local APIC base address is discovered via ACPI MADT and
//! accessed through the HHDM (Higher Half Direct Map).

use crate::memory;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Whether the Local APIC has been initialized
static APIC_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Virtual base address of the Local APIC MMIO registers
static APIC_BASE_VIRT: AtomicU64 = AtomicU64::new(0);

// ===== Local APIC Register Offsets =====

/// Local APIC ID Register
const REG_ID: u32 = 0x020;
/// Local APIC Version Register
#[allow(dead_code)]
const REG_VERSION: u32 = 0x030;
/// Task Priority Register
const REG_TPR: u32 = 0x080;
/// End of Interrupt Register
const REG_EOI: u32 = 0x0B0;
/// Spurious Interrupt Vector Register
const REG_SPURIOUS: u32 = 0x0F0;
/// Error Status Register
pub const REG_ESR: u32 = 0x280;
/// Interrupt Command Register (low)
pub const REG_ICR_LOW: u32 = 0x300;
/// Interrupt Command Register (high)
pub const REG_ICR_HIGH: u32 = 0x310;
/// LVT Timer Register
pub const REG_LVT_TIMER: u32 = 0x320;
/// Timer Initial Count Register
pub const REG_TIMER_INIT: u32 = 0x380;
/// Timer Current Count Register
pub const REG_TIMER_CURRENT: u32 = 0x390;
/// Timer Divide Configuration Register
pub const REG_TIMER_DIVIDE: u32 = 0x3E0;

// ===== LVT Timer Modes =====

/// LVT Timer: periodic mode (bit 17)
pub const LVT_TIMER_PERIODIC: u32 = 1 << 17;
/// LVT Timer: masked (bit 16)
#[allow(dead_code)]
pub const LVT_TIMER_MASKED: u32 = 1 << 16;

/// MSR address for APIC base
const IA32_APIC_BASE_MSR: u32 = 0x1B;
/// APIC global enable bit in IA32_APIC_BASE MSR
const APIC_BASE_ENABLE: u64 = 1 << 11;

/// Spurious interrupt vector number
const SPURIOUS_VECTOR: u8 = 0xFF;

/// Vector used for cross-CPU reschedule IPIs.
pub const IPI_RESCHED_VECTOR: u8 = 0xE0;

/// Vector used for TLB shootdown IPIs.
pub const IPI_TLB_SHOOTDOWN_VECTOR: u8 = 0xF0;

/// Check if APIC is present via CPUID
pub fn is_present() -> bool {
    let (_eax, _ebx, _ecx, edx) = super::cpuid(1, 0);
    // CPUID.01H:EDX bit 9 = APIC
    edx & (1 << 9) != 0
}

/// Get the Local APIC ID from CPUID
pub fn lapic_id() -> u32 {
    let (_eax, ebx, _ecx, _edx) = super::cpuid(1, 0);
    // CPUID.01H:EBX[31:24] = initial APIC ID
    (ebx >> 24) & 0xFF
}

/// Check if the Local APIC has been initialized
pub fn is_initialized() -> bool {
    APIC_INITIALIZED.load(Ordering::Relaxed)
}

/// Read a Local APIC register
///
/// # Safety
/// APIC must be initialized (base address valid and mapped).
pub unsafe fn read_reg(offset: u32) -> u32 {
    let addr = APIC_BASE_VIRT.load(Ordering::Relaxed) + offset as u64;
    // SAFETY: APIC MMIO is mapped via HHDM, volatile read required for MMIO
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Write a Local APIC register
///
/// # Safety
/// APIC must be initialized (base address valid and mapped).
pub unsafe fn write_reg(offset: u32, value: u32) {
    let addr = APIC_BASE_VIRT.load(Ordering::Relaxed) + offset as u64;
    // SAFETY: APIC MMIO is mapped via HHDM, volatile write required for MMIO
    unsafe { core::ptr::write_volatile(addr as *mut u32, value) }
}

/// Initialize the Local APIC.
///
/// `madt_lapic_addr` is the LAPIC base physical address from the MADT.
/// We use the MSR value as authoritative but log if it differs from MADT.
pub fn init(madt_lapic_addr: u32) {
    // Read the APIC base MSR to get the actual physical address
    let apic_base_msr = super::rdmsr(IA32_APIC_BASE_MSR);
    let apic_phys = apic_base_msr & 0xFFFF_F000; // Mask to get 4K-aligned base

    if apic_phys != madt_lapic_addr as u64 {
        log::warn!(
            "LAPIC: MSR base 0x{:X} differs from MADT 0x{:X}, using MSR",
            apic_phys,
            madt_lapic_addr
        );
    }

    // Enable the APIC globally via MSR if not already enabled
    if apic_base_msr & APIC_BASE_ENABLE == 0 {
        super::wrmsr(IA32_APIC_BASE_MSR, apic_base_msr | APIC_BASE_ENABLE);
    }

    // Convert physical base to virtual via HHDM
    let apic_virt = memory::phys_to_virt(apic_phys);
    APIC_BASE_VIRT.store(apic_virt, Ordering::Relaxed);

    // SAFETY: APIC base is now set and mapped via HHDM
    unsafe {
        // Clear the Error Status Register (write twice per Intel SDM)
        write_reg(REG_ESR, 0);
        write_reg(REG_ESR, 0);

        // Set Task Priority Register to 0 (accept all interrupts)
        write_reg(REG_TPR, 0);

        // Enable the APIC: set bit 8 (APIC Software Enable) + spurious vector
        write_reg(REG_SPURIOUS, 0x100 | SPURIOUS_VECTOR as u32);
    }

    APIC_INITIALIZED.store(true, Ordering::Relaxed);

    // SAFETY: APIC is initialized
    let id = unsafe { read_reg(REG_ID) >> 24 };
    log::info!(
        "LAPIC: initialized at phys=0x{:X} virt=0x{:X} (ID={})",
        apic_phys,
        apic_virt,
        id
    );
}

/// Initialize per-core Local APIC state on Application Processors.
///
/// This assumes the APIC base is already mapped and `APIC_BASE_VIRT`
/// has been set by the BSP during `init()`.
pub fn init_ap() {
    if !APIC_INITIALIZED.load(Ordering::Relaxed) {
        log::warn!("LAPIC: init_ap called before init");
        return;
    }

    // SAFETY: APIC base is mapped via HHDM and APIC is enabled.
    unsafe {
        // Clear ESR (twice per SDM)
        write_reg(REG_ESR, 0);
        write_reg(REG_ESR, 0);
        // Accept all interrupts
        write_reg(REG_TPR, 0);
        // Software enable APIC + spurious vector
        write_reg(REG_SPURIOUS, 0x100 | SPURIOUS_VECTOR as u32);
    }
}

/// Send End-of-Interrupt to the Local APIC
#[inline]
pub fn eoi() {
    // SAFETY: APIC is initialized when this is called from interrupt handlers
    unsafe {
        write_reg(REG_EOI, 0);
    }
}

/// Send a "reschedule now" IPI to the CPU identified by `target_apic_id`.
///
/// Uses Fixed delivery mode (vector `IPI_RESCHED_VECTOR`), physical destination.
/// This is fire-and-forget — no delivery status wait is needed for reschedule
/// IPIs because a missed IPI only delays preemption by at most one timer tick.
///
/// # Safety
/// APIC must be initialized (`APIC_INITIALIZED == true`).
pub fn send_resched_ipi(target_apic_id: u32) {
    // SAFETY: APIC base is valid and mapped; ICR MMIO is 32-bit aligned.
    unsafe {
        // Clear ESR before sending (Intel SDM §10.12.7).
        write_reg(REG_ESR, 0);
        // Set destination APIC ID in ICR high word.
        write_reg(REG_ICR_HIGH, target_apic_id << 24);
        // ICR low: bits[7:0] = vector, bits[10:8] = 000 (Fixed delivery),
        //          bit 11 = 0 (Physical destination), bit 14 = 1 (Assert level),
        //          bits[15] = 0 (Edge trigger).
        // Writing ICR low triggers the IPI.
        write_reg(REG_ICR_LOW, IPI_RESCHED_VECTOR as u32 | (1 << 14));
    }
}
