//! s9vm — pure model of the guest local APIC (xAPIC / x2APIC).
//!
//! This module models the minimal architectural state of a local APIC: MMIO
//! registers (4 KiB page), x2APIC registers (MSRs), IRR/ISR, priority (TPR/PPR),
//! EOI and IPI. It **touches no hardware**: the kernel layer reads/writes
//! the registers to emulate guest accesses and decide injections.
//!
//! The encodings come from the Intel documentation (SDM vol. 3A, chapter
//! "Advanced Programmable Interrupt Controller"). No constant specific to
//! a particular hypervisor is used.
//!
//! ## Injection policy
//!
//! The model is deliberately kept separate from the control block's interrupt
//! windows: it answers "which interrupt is deliverable?" via
//! [`LocalApic::pending_vector`], and the caller decides when (RFLAGS.IF,
//! interrupt window, etc.). Architectural priority is honored:
//! the smallest priority class strictly greater than the PPR, then the
//! smallest vector of that class.

/// Size of the local APIC MMIO page.
pub const PAGE_SIZE: usize = 0x1000;

/// Offsets of the xAPIC MMIO registers.
pub mod reg {
    pub const ID: usize = 0x020;
    pub const VERSION: usize = 0x030;
    pub const TPR: usize = 0x080;
    pub const PPR: usize = 0x0A0;
    pub const EOI: usize = 0x0B0;
    pub const LDR: usize = 0x0D0;
    pub const DFR: usize = 0x0E0;
    pub const SVR: usize = 0x0F0;
    pub const ISR: usize = 0x100;
    pub const TMR: usize = 0x180;
    pub const IRR: usize = 0x200;
    pub const ESR: usize = 0x280;
    pub const ICR_LOW: usize = 0x300;
    pub const ICR_HIGH: usize = 0x310;
    pub const LVT_TIMER: usize = 0x320;
    pub const LVT_THERMAL: usize = 0x330;
    pub const LVT_PERF: usize = 0x340;
    pub const LVT_LINT0: usize = 0x350;
    pub const LVT_LINT1: usize = 0x360;
    pub const LVT_ERROR: usize = 0x370;
    pub const INITIAL_COUNT: usize = 0x380;
    pub const CURRENT_COUNT: usize = 0x390;
    pub const DIVIDE_CONFIG: usize = 0x3E0;
    pub const SELF_IPI: usize = 0x3F0;
}

/// x2APIC registers exposed by `RDMSR`/`WRMSR`.
pub mod x2apic {
    pub const ID: u32 = 0x802;
    pub const VERSION: u32 = 0x803;
    pub const TPR: u32 = 0x808;
    pub const PPR: u32 = 0x80A;
    pub const EOI: u32 = 0x80B;
    pub const LDR: u32 = 0x80D;
    pub const DFR: u32 = 0x80E;
    pub const SVR: u32 = 0x80F;
    pub const ISR: u32 = 0x810;
    pub const IRR: u32 = 0x820;
    pub const ESR: u32 = 0x828;
    pub const ICR: u32 = 0x830;
    pub const LVT_TIMER: u32 = 0x832;
    pub const INITIAL_COUNT: u32 = 0x838;
    pub const CURRENT_COUNT: u32 = 0x839;
    pub const DIVIDE_CONFIG: u32 = 0x83E;
    pub const SELF_IPI: u32 = 0x83F;
}

/// Advertised hardware version (integrated xAPIC family, 6 LVTs).
pub const VERSION_VALUE: u32 = 0x0005_0014;
/// Spurious register: enabled, vector 0xFF.
pub const SVR_DEFAULT: u32 = 0x0000_01FF;
/// Vector of the spurious register.
pub const SPURIOUS_VECTOR: u8 = 0xFF;
/// Enable bit of the spurious register.
pub const SVR_ENABLE: u32 = 1 << 8;

/// Delivery mode in the ICR register (bits 10:8).
pub mod delivery {
    pub const FIXED: u32 = 0;
    pub const LOWEST: u32 = 1;
    pub const SMI: u32 = 2;
    pub const NMI: u32 = 4;
    pub const INIT: u32 = 5;
    pub const STARTUP: u32 = 6;
}

/// Shorthand destination in the ICR register (bits 19:18).
pub mod shorthand {
    pub const NO_SHORTHAND: u32 = 0;
    pub const SELF: u32 = 1;
    pub const ALL_INCLUDING_SELF: u32 = 2;
    pub const ALL_EXCLUDING_SELF: u32 = 3;
}

/// Complete state of a guest local APIC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalApic {
    /// APIC identifier (ID register, 8 significant bits in field 31:24).
    id: u32,
    /// Task priority (TPR), bits 7:0 significant.
    tpr: u8,
    /// Spurious register (SVR).
    svr: u32,
    /// Error status register.
    esr: u32,
    /// In-Service registers (8 x 32 bits = 256 vectors).
    isr: [u32; 8],
    /// In-Request registers (8 x 32 bits = 256 vectors).
    irr: [u32; 8],
    /// LVT: timer, thermal, perf, LINT0, LINT1, error.
    lvt: [u32; 6],
    /// ICR low/high.
    icr_low: u32,
    icr_high: u32,
    /// Initial and current timer count.
    initial_count: u32,
    current_count: u32,
    /// Timer divider.
    divide_config: u32,
}

impl LocalApic {
    /// Creates a local APIC for `apic_id`, LVTs masked, SVR enabled.
    pub const fn new(apic_id: u32) -> Self {
        Self {
            id: (apic_id & 0xFF) << 24,
            tpr: 0,
            svr: SVR_DEFAULT,
            esr: 0,
            isr: [0; 8],
            irr: [0; 8],
            lvt: [0x0001_0000; 6],
            icr_low: 0,
            icr_high: 0,
            initial_count: 0,
            current_count: 0,
            divide_config: 0,
        }
    }

    /// APIC identifier (8-bit value, not shifted).
    pub const fn apic_id(&self) -> u32 {
        self.id >> 24
    }

    /// Current task priority.
    pub const fn tpr(&self) -> u8 {
        self.tpr
    }

    /// Processor priority (TPR and ISR combined), on 8 bits.
    pub fn ppr(&self) -> u8 {
        let mut ppr = self.tpr;
        for index in (0..8).rev() {
            if self.isr[index] != 0 {
                // The PPR is a class priority: the low nibble of the
                // highest in-service vector is ignored.
                ppr = ppr.max(highest_vector(index, self.isr[index]) & 0xF0);
                break;
            }
        }
        ppr
    }

    /// True if the spurious register enables interrupts.
    pub const fn enabled(&self) -> bool {
        self.svr & SVR_ENABLE != 0
    }

    /// True if at least one vector is pending.
    pub fn has_pending(&self) -> bool {
        self.irr.iter().any(|word| *word != 0)
    }

    /// Injects a vector into the IRR (idempotent).
    pub fn inject(&mut self, vector: u8) {
        self.irr[(vector as usize) >> 5] |= 1 << (vector & 31);
    }

    /// Highest-priority deliverable vector, without modifying the state.
    pub fn pending_vector(&self) -> Option<u8> {
        if !self.enabled() {
            return None;
        }
        let ppr = self.ppr();
        let ppr_class = priority_class(u32::from(ppr));
        let mut best: Option<u8> = None;
        for index in 0..8u8 {
            let mut word = self.irr[index as usize];
            while word != 0 {
                let bit = word.trailing_zeros() as u8;
                let vector = index * 32 + bit;
                word &= word - 1;
                if vector < 16 {
                    continue;
                }
                let class = priority_class(u32::from(vector));
                // Priority strictly greater than the PPR: the class must be
                // greater (vectors of the same class are blocked,
                // as required by the architecture).
                if class > ppr_class {
                    best = Some(match best {
                        Some(current) => current.min(vector),
                        None => vector,
                    });
                }
            }
        }
        best
    }

    /// Moves the deliverable vector from the IRR to the ISR and returns it.
    pub fn service(&mut self) -> Option<u8> {
        let vector = self.pending_vector()?;
        self.irr[(vector as usize) >> 5] &= !(1 << (vector & 31));
        self.isr[(vector as usize) >> 5] |= 1 << (vector & 31);
        Some(vector)
    }

    /// Records an EOI: removes the highest-priority vector from the ISR.
    pub fn eoi(&mut self) {
        for index in (0..8).rev() {
            let word = self.isr[index];
            if word != 0 {
                let bit = 31 - word.leading_zeros() as usize;
                self.isr[index] &= !(1u32 << bit);
                return;
            }
        }
    }

    /// True if a vector is in service.
    pub fn in_service(&self) -> bool {
        self.isr.iter().any(|word| *word != 0)
    }

    /// Reads an MMIO register (address relative to the APIC page).
    ///
    /// Unimplemented offsets return 0 (guest access tolerated).
    pub fn mmio_read(&self, offset: usize) -> u32 {
        if let Some(index) = isr_index(offset, reg::ISR) {
            return self.isr[index];
        }
        if let Some(index) = isr_index(offset, reg::IRR) {
            return self.irr[index];
        }
        match offset {
            reg::ID => self.id,
            reg::VERSION => VERSION_VALUE,
            reg::TPR => u32::from(self.tpr),
            reg::PPR => u32::from(self.ppr()),
            reg::SVR => self.svr,
            reg::ESR => self.esr,
            reg::ICR_LOW => self.icr_low,
            reg::ICR_HIGH => self.icr_high,
            reg::INITIAL_COUNT => self.initial_count,
            reg::CURRENT_COUNT => self.current_count,
            reg::DIVIDE_CONFIG => self.divide_config,
            reg::LVT_TIMER => self.lvt[0],
            reg::LVT_THERMAL => self.lvt[1],
            reg::LVT_PERF => self.lvt[2],
            reg::LVT_LINT0 => self.lvt[3],
            reg::LVT_LINT1 => self.lvt[4],
            reg::LVT_ERROR => self.lvt[5],
            _ => 0,
        }
    }

    /// Writes an MMIO register. Unimplemented offsets are ignored.
    pub fn mmio_write(&mut self, offset: usize, value: u32) {
        match offset {
            reg::TPR => self.tpr = (value & 0xFF) as u8,
            reg::EOI => self.eoi(),
            reg::SVR => self.svr = value & 0x0000_01FF,
            reg::ESR => self.esr = value,
            reg::ICR_LOW => self.write_icr_low(value),
            reg::ICR_HIGH => self.icr_high = value & 0xFF00_0000,
            reg::INITIAL_COUNT => {
                self.initial_count = value;
                self.current_count = value;
            }
            reg::DIVIDE_CONFIG => self.divide_config = value & 0xB,
            reg::LVT_TIMER => self.lvt[0] = value,
            reg::LVT_THERMAL => self.lvt[1] = value,
            reg::LVT_PERF => self.lvt[2] = value,
            reg::LVT_LINT0 => self.lvt[3] = value,
            reg::LVT_LINT1 => self.lvt[4] = value,
            reg::LVT_ERROR => self.lvt[5] = value,
            reg::SELF_IPI => self.inject((value & 0xFF) as u8),
            _ => {}
        }
    }

    /// Handles an ICR-low write: fixed IPI to self or NMI.
    fn write_icr_low(&mut self, value: u32) {
        self.icr_low = value;
        let delivery_mode = (value >> 8) & 0x7;
        let destination = (value >> 18) & 0x3;
        let vector = (value & 0xFF) as u8;
        match (delivery_mode, destination) {
            (delivery::FIXED, shorthand::SELF) | (delivery::LOWEST, shorthand::SELF) => {
                self.inject(vector);
            }
            (delivery::NMI, _) | (delivery::INIT, _) | (delivery::STARTUP, _) => {
                // Handled outside the APIC (dedicated injection / reset): we
                // accept the write so that the guest can continue.
            }
            _ => {
                // External destination not modeled in P1 (a single guest CPU).
            }
        }
    }

    /// Reads an x2APIC MSR. Returns `None` outside the `0x800..=0x8FF` range.
    pub fn x2apic_read(&self, msr: u32) -> Option<u64> {
        if let Some(index) = isr_msr_index(msr, x2apic::ISR) {
            return Some(u64::from(self.isr[index]));
        }
        if let Some(index) = isr_msr_index(msr, x2apic::IRR) {
            return Some(u64::from(self.irr[index]));
        }
        let value: u64 = match msr {
            x2apic::ID => u64::from(self.id),
            x2apic::VERSION => u64::from(VERSION_VALUE),
            x2apic::TPR => u64::from(self.tpr),
            x2apic::PPR => u64::from(self.ppr()),
            x2apic::EOI => 0,
            x2apic::LDR => (u64::from(self.apic_id()) << 24) | 0x01_0000,
            x2apic::DFR => 0x0000_00FF,
            x2apic::SVR => u64::from(self.svr),
            x2apic::ESR => u64::from(self.esr),
            x2apic::ICR => ((self.icr_high as u64) << 32) | u64::from(self.icr_low),
            x2apic::LVT_TIMER => u64::from(self.lvt[0]),
            x2apic::INITIAL_COUNT => u64::from(self.initial_count),
            x2apic::CURRENT_COUNT => u64::from(self.current_count),
            x2apic::DIVIDE_CONFIG => u64::from(self.divide_config),
            _ => return None,
        };
        Some(value)
    }

    /// Writes an x2APIC MSR. Returns `false` if the MSR is not modeled.
    pub fn x2apic_write(&mut self, msr: u32, value: u64) -> bool {
        match msr {
            x2apic::TPR => self.tpr = (value & 0xFF) as u8,
            x2apic::EOI => self.eoi(),
            x2apic::SVR => self.svr = (value as u32) & 0x0000_01FF,
            x2apic::ESR => self.esr = value as u32,
            x2apic::ICR => {
                self.icr_high = (value >> 32) as u32;
                self.write_icr_low(value as u32);
            }
            x2apic::LVT_TIMER => self.lvt[0] = value as u32,
            x2apic::INITIAL_COUNT => {
                self.initial_count = value as u32;
                self.current_count = value as u32;
            }
            x2apic::DIVIDE_CONFIG => self.divide_config = (value as u32) & 0xB,
            x2apic::SELF_IPI => self.inject((value & 0xFF) as u8),
            _ => return false,
        }
        true
    }
}

/// Highest vector of an ISR/IRR word (`index` = word 0..7).
fn highest_vector(index: usize, word: u32) -> u8 {
    (index as u8) * 32 + (31 - word.leading_zeros() as u8)
}

/// Index of an ISR/IRR register in MMIO (16-byte stride, 8 registers).
fn isr_index(offset: usize, base: usize) -> Option<usize> {
    if offset < base || offset >= base + 8 * 16 {
        return None;
    }
    let delta = offset - base;
    if delta % 16 != 0 {
        return None;
    }
    Some(delta / 16)
}

/// Index of an ISR/IRR register in x2APIC (8 consecutive MSRs).
fn isr_msr_index(msr: u32, base: u32) -> Option<usize> {
    if msr < base || msr >= base + 8 {
        return None;
    }
    Some((msr - base) as usize)
}

/// Priority class of a vector (bits 7:4).
pub const fn priority_class(vector: u32) -> u8 {
    ((vector >> 4) & 0xF) as u8
}
