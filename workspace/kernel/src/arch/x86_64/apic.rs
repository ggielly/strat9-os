//! Local APIC (Advanced Programmable Interrupt Controller) driver
//!
//! Provides MMIO-based access to the Local APIC registers.
//! The Local APIC base address is discovered via ACPI MADT and
//! accessed through the HHDM (Higher Half Direct Map).

use crate::memory;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// Whether the Local APIC has been initialized
static APIC_INITIALIZED: AtomicBool = AtomicBool::new(false);
/// Whether x2APIC mode is active.
static APIC_X2_MODE: AtomicBool = AtomicBool::new(false);

/// Virtual base address of the Local APIC MMIO registers
static APIC_BASE_VIRT: AtomicU64 = AtomicU64::new(0);

/// Physical base address of the Local APIC MMIO registers (used by address-space init)
static APIC_BASE_PHYS: AtomicU64 = AtomicU64::new(0);
/// Per-CPU shadow of xAPIC-compatible ICR high writes (destination field).
static ICR_HIGH_SHADOW: [AtomicU32; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { AtomicU32::new(0) }; crate::arch::x86_64::percpu::MAX_CPUS];

/// Return the physical base address of the LAPIC MMIO region, or 0 if not yet initialized.
pub fn lapic_phys() -> u64 {
    APIC_BASE_PHYS.load(Ordering::Relaxed)
}

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
/// Dedicated Local APIC timer interrupt vector (aligned with Theseus-style setup).
pub const LVT_TIMER_VECTOR: u8 = 0xD2;

/// MSR address for APIC base
const IA32_APIC_BASE_MSR: u32 = 0x1B;
/// IA32_APIC_BASE physical base address mask (up to MAXPHYADDR 52 bits).
const APIC_BASE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
/// APIC global enable bit in IA32_APIC_BASE MSR
const APIC_BASE_ENABLE: u64 = 1 << 11;
/// x2APIC enable bit in IA32_APIC_BASE MSR
const APIC_BASE_EXTD: u64 = 1 << 10;

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

/// Check if x2APIC is supported via CPUID
pub fn is_x2apic_supported() -> bool {
    let (_eax, _ebx, ecx, _edx) = super::cpuid(1, 0);
    // CPUID.01H:ECX bit 21 = x2APIC
    ecx & (1 << 21) != 0
}

/// Get the current Local APIC ID.
///
/// When APIC is initialized, read the LAPIC ID register (authoritative at runtime).
/// Before APIC init, fall back to CPUID initial APIC ID.
pub fn lapic_id() -> u32 {
    if APIC_INITIALIZED.load(Ordering::Relaxed) {
        // SAFETY: guarded by APIC_INITIALIZED.
        let raw = unsafe { read_reg(REG_ID) };
        if APIC_X2_MODE.load(Ordering::Relaxed) {
            return raw;
        }
        return raw >> 24;
    }

    let (_eax, ebx, _ecx, _edx) = super::cpuid(1, 0);
    (ebx >> 24) & 0xFF
}

/// Check if the Local APIC has been initialized
pub fn is_initialized() -> bool {
    APIC_INITIALIZED.load(Ordering::Relaxed)
}

/// Returns true when Local APIC is running in x2APIC mode.
pub fn is_x2apic_enabled() -> bool {
    APIC_X2_MODE.load(Ordering::Relaxed)
}

#[inline]
fn x2apic_msr_for_reg(offset: u32) -> Option<u32> {
    match offset {
        REG_ID => Some(0x802),
        REG_VERSION => Some(0x803),
        REG_TPR => Some(0x808),
        REG_EOI => Some(0x80B),
        REG_SPURIOUS => Some(0x80F),
        REG_ESR => Some(0x828),
        REG_LVT_TIMER => Some(0x832),
        REG_TIMER_INIT => Some(0x838),
        REG_TIMER_CURRENT => Some(0x839),
        REG_TIMER_DIVIDE => Some(0x83E),
        _ => None,
    }
}

#[inline]
fn current_cpu_slot() -> usize {
    let idx = crate::arch::x86_64::percpu::current_cpu_index();
    if idx < crate::arch::x86_64::percpu::MAX_CPUS {
        idx
    } else {
        0
    }
}

/// Read a Local APIC register
///
/// # Safety
/// APIC must be initialized (base address valid and mapped).
pub unsafe fn read_reg(offset: u32) -> u32 {
    if APIC_X2_MODE.load(Ordering::Relaxed) {
        return match offset {
            REG_ICR_LOW => super::rdmsr(0x830) as u32,
            REG_ICR_HIGH => ((super::rdmsr(0x830) >> 32) as u32) << 24,
            _ => {
                let Some(msr) = x2apic_msr_for_reg(offset) else {
                    return 0;
                };
                super::rdmsr(msr) as u32
            }
        };
    }

    let addr = APIC_BASE_VIRT.load(Ordering::Relaxed) + offset as u64;
    // SAFETY: APIC MMIO is mapped via HHDM, volatile read required for MMIO
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Write a Local APIC register
///
/// # Safety
/// APIC must be initialized (base address valid and mapped).
pub unsafe fn write_reg(offset: u32, value: u32) {
    if APIC_X2_MODE.load(Ordering::Relaxed) {
        match offset {
            REG_ICR_HIGH => {
                let cpu = current_cpu_slot();
                // xAPIC callers write destination as apic_id << 24 in ICR high.
                // Keep this compatibility and decode to a raw x2APIC destination id.
                let dest = if value & 0x00FF_FFFF == 0 {
                    value >> 24
                } else {
                    value
                };
                ICR_HIGH_SHADOW[cpu].store(dest, Ordering::Relaxed);
            }
            REG_ICR_LOW => {
                let cpu = current_cpu_slot();
                let dest = ICR_HIGH_SHADOW[cpu].load(Ordering::Relaxed) as u64;
                super::wrmsr(0x830, (dest << 32) | value as u64);
            }
            _ => {
                if let Some(msr) = x2apic_msr_for_reg(offset) {
                    super::wrmsr(msr, value as u64);
                }
            }
        }
        return;
    }

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
    let apic_phys = apic_base_msr & APIC_BASE_ADDR_MASK;

    if apic_phys != madt_lapic_addr as u64 {
        log::warn!(
            "LAPIC: MSR base 0x{:X} differs from MADT 0x{:X}, using MSR",
            apic_phys,
            madt_lapic_addr
        );
    }

    let mut target_msr = apic_base_msr | APIC_BASE_ENABLE;
    let use_x2apic = is_x2apic_supported();
    if use_x2apic {
        target_msr |= APIC_BASE_EXTD;
    }
    if target_msr != apic_base_msr {
        super::wrmsr(IA32_APIC_BASE_MSR, target_msr);
    }
    APIC_X2_MODE.store(use_x2apic, Ordering::Relaxed);

    // Convert physical base to virtual via HHDM
    let apic_virt = memory::phys_to_virt(apic_phys);
    APIC_BASE_VIRT.store(apic_virt, Ordering::Relaxed);
    APIC_BASE_PHYS.store(apic_phys, Ordering::Relaxed);

    // Diagnostic: log HHDM and computed addresses so we can detect HHDM=0 issues.
    crate::serial_println!(
        "[apic] init: hhdm={:#x} lapic_phys={:#x} lapic_virt={:#x}",
        memory::hhdm_offset(),
        apic_phys,
        apic_virt
    );
    if apic_virt == apic_phys {
        crate::serial_println!(
            "[apic] WARN: lapic_virt == lapic_phys (HHDM offset is 0!) \
             The LAPIC MMIO is identity-mapped at a low address. \
             Kernel MMIO entries will be propagated to user page tables."
        );
    }

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

    let id = lapic_id();
    log::info!(
        "LAPIC: initialized at phys=0x{:X} virt=0x{:X} (ID={}, mode={})",
        apic_phys,
        apic_virt,
        id,
        if use_x2apic { "x2APIC" } else { "xAPIC" }
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

/// Send an IPI with a pre-built ICR low value to a specific APIC destination.
///
/// `icr_low` must contain delivery mode/vector/flags in xAPIC layout.
pub fn send_ipi_raw(target_apic_id: u32, icr_low: u32) {
    unsafe {
        write_reg(REG_ESR, 0);
        if APIC_X2_MODE.load(Ordering::Relaxed) {
            super::wrmsr(0x830, ((target_apic_id as u64) << 32) | icr_low as u64);
        } else {
            write_reg(REG_ICR_HIGH, target_apic_id << 24);
            write_reg(REG_ICR_LOW, icr_low);
        }
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
    send_ipi_raw(target_apic_id, IPI_RESCHED_VECTOR as u32 | (1 << 14));
}
