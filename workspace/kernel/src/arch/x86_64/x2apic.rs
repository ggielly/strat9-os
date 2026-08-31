//! x2APIC (Extended xAPIC) driver
//!
//! Provides MSR-based access to x2APIC registers instead of MMIO.
//! x2APIC extends the APIC ID to 32 bits and uses MSRs for all register access.
//!
//! Key differences from xAPIC:
//! - All registers accessed via MSRs (no MMIO).
//! - ICR writes are atomic single MSR writes (no delivery status polling needed).
//! - APIC ID is 32 bits (not just 8).
//! - ESR is write-1-to-clear (write 0 to ack, read for errors).

use crate::arch::x86_64::{rdmsr, wrmsr};

// IA32_APIC_BASE MSR
const IA32_APIC_BASE_MSR: u32 = 0x1B;
const APIC_BASE_EN: u64 = 1 << 11;
const APIC_BASE_EXTD: u64 = 1 << 10;

// x2APIC register MSR addresses
const IA32_X2APIC_APICID: u32 = 0x802;
const IA32_X2APIC_VERSION: u32 = 0x803;
const IA32_X2APIC_EOI: u32 = 0x80B;
const IA32_X2APIC_SIVR: u32 = 0x80F;
const IA32_X2APIC_ESR: u32 = 0x828;
const IA32_X2APIC_ICR: u32 = 0x830;
const IA32_X2APIC_LVT_TIMER: u32 = 0x832;
const IA32_X2APIC_TIMER_INIT: u32 = 0x838;
const IA32_X2APIC_TIMER_DIV: u32 = 0x83E;

// ICR field constants (Intel SDM Vol. 3A, Table 10-1)
//
// ICR low 32 bits:
//   [0:7]   Vector
//   [8:10]  Delivery Mode
//   [11]    Destination Mode (0=physical, 1=logical)
//   [12]    Delivery Status (read-only in x2APIC — write is ignored)
//   [13]    Reserved
//   [14]    Level (0=de-assert, 1=assert — only meaningful for INIT/ExtINT)
//   [15]    Trigger Mode (0=edge, 1=level)
//   [16:17] Reserved
//   [18:19] Destination Shorthand
//   [20:31] Reserved
//
// ICR high 32 bits:
//   [32:63] Destination Field (x2APIC: full 32-bit APIC ID)

const DELIVERY_FIXED: u64 = 0b000 << 8;
const DELIVERY_INIT: u64 = 0b101 << 8;
const DELIVERY_STARTUP: u64 = 0b110 << 8;
const DELIVERY_SIPI: u64 = 0b110 << 8; // STARTUP and SIPI share mode 110

const TRIGGER_EDGE: u64 = 0 << 15;
const TRIGGER_LEVEL: u64 = 1 << 15;

const LEVEL_ASSERT: u64 = 1 << 14;
const LEVEL_DEASSERT: u64 = 0 << 14;

const DEST_PHYSICAL: u64 = 0 << 11;
const DEST_SHORTHAND_NONE: u64 = 0b00 << 18;

/// Timer divide configuration values (IA32_X2APIC_TIMER_DIV, MSR 0x83E).
///
/// The timer frequency is the bus clock (or core crystal clock) divided by
/// the value encoded here.  After reset the register is 0 (= divide by 2).
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerDivide {
    /// Divide by 2 (reset default).
    Div2 = 0b000,
    /// Divide by 4.
    Div4 = 0b001,
    /// Divide by 8.
    Div8 = 0b010,
    /// Divide by 16.
    Div16 = 0b011,
    /// Divide by 32.
    Div32 = 0b100,
    /// Divide by 64.
    Div64 = 0b101,
    /// Divide by 128.
    Div128 = 0b110,
    /// Divide by 1.
    Div1 = 0b111,
}

pub struct X2Apic {
    _private: (),
}

impl X2Apic {
    pub fn new() -> Option<Self> {
        if !Self::is_supported() {
            return None;
        }
        let base = rdmsr(IA32_APIC_BASE_MSR);
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

    /// Enable x2APIC mode on this CPU.
    ///
    /// Performs the two-step enable sequence:
    /// 1. Ensure APIC global enable (EN=1) in IA32_APIC_BASE.
    /// 2. Set x2APIC enable (EXTD=1).
    ///
    /// Writes the Spurious Interrupt Vector Register to finalize.
    ///
    /// Returns `Err` if the CPU refuses to enter x2APIC mode (e.g. BIOS
    /// locked the APIC base, or the CPU doesn't actually support x2APIC).
    pub fn enable(&self) -> Result<(), &'static str> {
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
            return Err("failed to enter x2APIC mode");
        }

        // SVR: APIC software enable (bit 8) + spurious vector 0xFF.
        let svr: u64 = (1 << 8) | 0xFF;
        wrmsr(IA32_X2APIC_SIVR, svr);
        Ok(())
    }

    /// Read and clear the Error Status Register.
    ///
    /// After a send_ipi() the ESR should be read to detect delivery errors
    /// (illegal vector, accept error, etc.).  Writes-1-to-clear, so we write 0
    /// then read to snapshot.
    pub fn read_and_clear_esr(&self) -> u32 {
        wrmsr(IA32_X2APIC_ESR, 0);
        rdmsr(IA32_X2APIC_ESR) as u32
    }

    pub fn id(&self) -> u32 {
        rdmsr(IA32_X2APIC_APICID) as u32
    }

    pub fn version(&self) -> u32 {
        rdmsr(IA32_X2APIC_VERSION) as u32
    }

    pub fn eoi(&self) {
        wrmsr(IA32_X2APIC_EOI, 0);
    }

    /// Send an IPI to a specific x2APIC destination.
    ///
    /// Uses Fixed delivery mode, physical destination, edge-triggered,
    /// no shorthand.  This is the common-case IPI (reschedule, TLB shootdown, etc.).
    pub fn send_ipi(&self, target_id: u32, vector: u8) {
        // Clear ESR before sending (Intel SDM requirement).
        wrmsr(IA32_X2APIC_ESR, 0);

        let icr = ((target_id as u64) << 32)
            | DEST_SHORTHAND_NONE
            | TRIGGER_EDGE
            | LEVEL_ASSERT
            | DEST_PHYSICAL
            | DELIVERY_FIXED
            | (vector as u64);

        wrmsr(IA32_X2APIC_ICR, icr);
    }

    /// Send an INIT IPI to a specific x2APIC destination.
    ///
    /// INIT IPIs use Delivery Mode = 101 (INIT).  In x2APIC mode the Level
    /// bit is not meaningful for INIT delivery, but is set to 1 (assert) by
    /// convention to match xAPIC-compatible INIT sequences.
    pub fn send_init_ipi(&self, target_id: u32) {
        wrmsr(IA32_X2APIC_ESR, 0);

        let icr = ((target_id as u64) << 32)
            | DEST_SHORTHAND_NONE
            | TRIGGER_EDGE
            | LEVEL_ASSERT
            | DEST_PHYSICAL
            | DELIVERY_INIT;

        wrmsr(IA32_X2APIC_ICR, icr);
    }

    /// Send a STARTUP IPI (SIPI) to a specific x2APIC destination.
    ///
    /// `start_page` is the start-up vector (page frame number of the real-mode
    /// entry point, e.g. 0x08 for physical 0x0800).  The CPU begins execution
    /// at `start_page << 12` in real mode after receiving SIPI.
    pub fn send_startup_ipi(&self, target_id: u32, start_page: u8) {
        wrmsr(IA32_X2APIC_ESR, 0);

        let icr = ((target_id as u64) << 32)
            | DEST_SHORTHAND_NONE
            | TRIGGER_EDGE
            | DEST_PHYSICAL
            | DELIVERY_STARTUP
            | (start_page as u64);

        wrmsr(IA32_X2APIC_ICR, icr);
    }

    // ── LVT Timer ──────────────────────────────────────────────────────

    /// Configure the LVT timer.
    ///
    /// Programs the divide configuration, LVT entry, and initial count in the
    /// correct order (SDM requires: DIV → LVT → INIT_COUNT).
    pub fn configure_timer(&self, initial_count: u32, vector: u8, periodic: bool, divide: TimerDivide) {
        let mut lvt = vector as u64;
        if periodic {
            lvt |= 1 << 17;
        }
        wrmsr(IA32_X2APIC_TIMER_DIV, divide as u64);
        wrmsr(IA32_X2APIC_LVT_TIMER, lvt);
        wrmsr(IA32_X2APIC_TIMER_INIT, initial_count as u64);
    }

    /// Mask the LVT timer (set mask bit = 1 → timer interrupt suppressed).
    pub fn mask_timer(&self) {
        let lvt = rdmsr(IA32_X2APIC_LVT_TIMER);
        wrmsr(IA32_X2APIC_LVT_TIMER, lvt | (1 << 16));
    }

    /// Unmask the LVT timer (clear mask bit = 0 → timer interrupt delivered).
    pub fn unmask_timer(&self) {
        let lvt = rdmsr(IA32_X2APIC_LVT_TIMER);
        wrmsr(IA32_X2APIC_LVT_TIMER, lvt & !(1 << 16));
    }
}
