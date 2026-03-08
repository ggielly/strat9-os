//! x2APIC (Extended xAPIC) driver
//!
//! Provides MSR-based access to x2APIC registers instead of MMIO.
//! x2APIC extends the APIC ID to 32 bits and uses MSRs for all register access.

use crate::arch::x86_64::{rdmsr, wrmsr};

const IA32_APIC_BASE_MSR: u32 = 0x1B;
const APIC_BASE_EN: u64 = 1 << 11;
const APIC_BASE_EXTD: u64 = 1 << 10;

const IA32_X2APIC_APICID: u32 = 0x802;
const IA32_X2APIC_VERSION: u32 = 0x803;
const IA32_X2APIC_EOI: u32 = 0x80B;
const IA32_X2APIC_SIVR: u32 = 0x80F;
const IA32_X2APIC_ESR: u32 = 0x828;
const IA32_X2APIC_ICR: u32 = 0x830;
const IA32_X2APIC_LVT_TIMER: u32 = 0x832;
const IA32_X2APIC_TIMER_INIT: u32 = 0x838;
const IA32_X2APIC_TIMER_DIV: u32 = 0x83E;

pub struct X2Apic {
    _private: (),
}

impl X2Apic {
    pub fn new() -> Option<Self> {
        if !Self::is_supported() {
            return None;
        }
        // SAFETY: rdmsr is a privileged Ring-0 instruction, valid here.
        let base = unsafe { rdmsr(IA32_APIC_BASE_MSR) };
        if base & (APIC_BASE_EN | APIC_BASE_EXTD) == (APIC_BASE_EN | APIC_BASE_EXTD) {
            Some(Self { _private: () })
        } else {
            None
        }
    }

    pub fn is_supported() -> bool {
        let (_eax, _ebx, ecx, _edx) = super::cpuid(1, 0);
        ecx & (1 << 21) != 0
    }

    pub fn enable(&self) {
        // SAFETY: wrmsr/rdmsr are Ring-0 privileged instructions, valid here.
        unsafe {
            let base = rdmsr(IA32_APIC_BASE_MSR);
            let already_extd = base & APIC_BASE_EXTD != 0;

            if !already_extd {
                if base & APIC_BASE_EN == 0 {
                    wrmsr(IA32_APIC_BASE_MSR, base | APIC_BASE_EN);
                }
                wrmsr(IA32_APIC_BASE_MSR, base | APIC_BASE_EN | APIC_BASE_EXTD);
            }

            let base_after = rdmsr(IA32_APIC_BASE_MSR);
            if base_after & (APIC_BASE_EN | APIC_BASE_EXTD) != (APIC_BASE_EN | APIC_BASE_EXTD) {
                return;
            }

            let svr: u64 = (1 << 8) | 0xFF;
            wrmsr(IA32_X2APIC_SIVR, svr);
        }
    }

    pub fn id(&self) -> u32 {
        // SAFETY: x2APIC MSR reads are valid after enable().
        unsafe { rdmsr(IA32_X2APIC_APICID) as u32 }
    }

    pub fn version(&self) -> u32 {
        // SAFETY: x2APIC MSR reads are valid after enable().
        unsafe { rdmsr(IA32_X2APIC_VERSION) as u32 }
    }

    pub fn eoi(&self) {
        // SAFETY: x2APIC MSR writes are valid after enable().
        unsafe { wrmsr(IA32_X2APIC_EOI, 0) };
    }

    pub fn send_ipi(&self, target_id: u32, vector: u8) {
        // SAFETY: x2APIC ICR write is valid after enable(). ICR is a single
        // 64-bit MSR write in x2APIC: bits[63:32]=destination, bits[31:0]=command.
        unsafe {
            wrmsr(IA32_X2APIC_ESR, 0);
            let icr = ((target_id as u64) << 32)
                | (vector as u64)
                | (1 << 14);
            wrmsr(IA32_X2APIC_ICR, icr);
        }
    }

    pub fn configure_timer(&self, initial_count: u32, vector: u8, periodic: bool) {
        // SAFETY: x2APIC timer MSR writes are valid after enable().
        unsafe {
            let mut lvt = vector as u64;
            if periodic {
                lvt |= 1 << 17;
            }
            wrmsr(IA32_X2APIC_LVT_TIMER, lvt);
            wrmsr(IA32_X2APIC_TIMER_INIT, initial_count as u64);
        }
    }
}
