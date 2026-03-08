//! x2APIC (Extended xAPIC) driver
//!
//! Provides MSR-based access to x2APIC registers instead of MMIO.
//! x2APIC extends the APIC ID to 32 bits and uses MSRs for all register access.

use crate::arch::x86_64::{rdmsr, wrmsr};

/// MSR addresses for x2APIC registers
const IA32_X2APIC_APICID: u32 = 0x802;
const IA32_X2APIC_VERSION: u32 = 0x803;
const IA32_X2APIC_TPR: u32 = 0x808;
const IA32_X2APIC_EOI: u32 = 0x80B;
const IA32_X2APIC_SIVR: u32 = 0x80F;
const IA32_X2APIC_ESR: u32 = 0x828;
const IA32_X2APIC_ICR: u32 = 0x830;
const IA32_X2APIC_LVT_TIMER: u32 = 0x832;
const IA32_X2APIC_TIMER_INIT: u32 = 0x838;
const IA32_X2APIC_TIMER_CURRENT: u32 = 0x839;
const IA32_X2APIC_TIMER_DIV: u32 = 0x83E;

/// x2APIC driver implementation
pub struct X2Apic {
    _private: (),
}

impl X2Apic {
    /// Create a new x2APIC instance if the feature is available
    pub fn new() -> Option<Self> {
        if !Self::is_supported() {
            return None;
        }
        Some(Self { _private: () })
    }

    /// Check if x2APIC is supported via CPUID
    pub fn is_supported() -> bool {
        let (_eax, _ebx, ecx, _edx) = super::cpuid(1, 0);
        ecx & (1 << 21) != 0
    }

    /// Enable x2APIC mode
    pub fn enable(&self) {
        const X2APIC_ENABLE_BITS: u64 = (1 << 10) | (1 << 11); // EXTD + EN bits

        // SAFETY: Safe to enable x2APIC if CPUID indicates support
        unsafe {
            // Enable x2APIC and xAPIC globally
            let mut base = super::rdmsr(0x1B); // IA32_APIC_BASE
            if base & X2APIC_ENABLE_BITS != X2APIC_ENABLE_BITS {
                base |= X2APIC_ENABLE_BITS;
                super::wrmsr(0x1B, base);
            }

            // Configure Spurious Vector Register
            let svr: u64 = (1 << 8) | 0xFF; // Enable APIC + spurious vector 0xFF
            wrmsr(IA32_X2APIC_SIVR, svr);
        }
    }

    /// Get the x2APIC ID
    pub fn id(&self) -> u32 {
        // SAFETY: Safe to read APIC ID register
        unsafe { rdmsr(IA32_X2APIC_APICID) as u32 }
    }

    /// Get the x2APIC version
    pub fn version(&self) -> u32 {
        // SAFETY: Safe to read version register
        unsafe { rdmsr(IA32_X2APIC_VERSION) as u32 }
    }

    /// Send End-of-Interrupt
    pub fn eoi(&self) {
        // SAFETY: Safe to write EOI register
        unsafe { wrmsr(IA32_X2APIC_EOI, 0) };
    }

    /// Send an Inter-Processor Interrupt
    pub fn send_ipi(&self, target_id: u32, vector: u8) {
        // SAFETY: Safe to write ICR registers
        unsafe {
            // Clear error status
            wrmsr(IA32_X2APIC_ESR, 0);

            // Set ICR: vector in bits 0-7, delivery mode in bits 8-10
            let icr_low = vector as u64 | (0 << 8); // Fixed delivery mode
            wrmsr(IA32_X2APIC_ICR, icr_low);
        }
    }

    /// Configure the local APIC timer
    pub fn configure_timer(&self, initial_count: u64, vector: u8, periodic: bool) {
        // SAFETY: Safe to configure timer registers
        unsafe {
            // Set timer initial count
            wrmsr(IA32_X2APIC_TIMER_INIT, initial_count);

            // Configure LVT Timer register
            let mut lvt = vector as u64;
            if periodic {
                lvt |= 1 << 17; // Periodic mode
            }
            wrmsr(IA32_X2APIC_LVT_TIMER, lvt);
        }
    }
}
