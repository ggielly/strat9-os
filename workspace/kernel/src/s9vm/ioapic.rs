//! s9vm — pure model of the guest I/O APIC.
//!
//! A PC-compatible guest discovers an I/O APIC through ACPI and drives it
//! through two MMIO registers: `IOREGSEL` (offset `0x00`) selects an indirect
//! register, `IOWIN` (offset `0x10`) reads or writes it. The redirection table
//! maps 24 input pins to vectors, delivery modes and destinations.
//!
//! This module only holds architectural state; it touches no hardware. The
//! kernel calls [`IoApic::mmio_read`] / [`IoApic::mmio_write`] when it emulates
//! the guest's I/O APIC page, and the routing layer later uses
//! [`IoApic::entry`] to decide which vector and destination a pin produces.

/// MMIO offset of the indirect register selector.
pub const REG_SELECT: usize = 0x00;
/// MMIO offset of the indirect register window.
pub const REG_WINDOW: usize = 0x10;
/// Number of redirection pins of the modelled I/O APIC.
pub const PIN_COUNT: usize = 24;
/// Version register value: version 0x11, 24 redirection entries.
pub const VERSION: u32 = 0x0017_0011;
/// First indirect register index of the redirection table.
pub const REDIRECTION_BASE: u32 = 0x10;

/// One 64-bit redirection table entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RedirectionEntry {
    raw: u64,
}

impl RedirectionEntry {
    /// Raw 64-bit value.
    pub const fn raw(self) -> u64 {
        self.raw
    }

    /// Builds an entry from its raw value (reserved bits are kept as written
    /// so a read-back matches what the guest wrote).
    pub const fn from_raw(raw: u64) -> Self {
        Self { raw }
    }

    /// Interrupt vector (bits 7:0).
    pub const fn vector(self) -> u8 {
        (self.raw & 0xFF) as u8
    }

    /// Delivery mode (bits 10:8): 0 fixed, 1 lowest priority, 2 SMI, 4 NMI,
    /// 5 INIT, 6 startup.
    pub const fn delivery_mode(self) -> u8 {
        ((self.raw >> 8) & 0x7) as u8
    }

    /// Destination mode (bit 11): 0 physical, 1 logical.
    pub const fn logical_destination(self) -> bool {
        self.raw & (1 << 11) != 0
    }

    /// Polarity (bit 13): 0 active high, 1 active low.
    pub const fn active_low(self) -> bool {
        self.raw & (1 << 13) != 0
    }

    /// Trigger mode (bit 15): 0 edge, 1 level.
    pub const fn level_triggered(self) -> bool {
        self.raw & (1 << 15) != 0
    }

    /// Mask (bit 16).
    pub const fn masked(self) -> bool {
        self.raw & (1 << 16) != 0
    }

    /// Destination APIC id (bits 63:56).
    pub const fn destination(self) -> u8 {
        (self.raw >> 56) as u8
    }
}

/// Complete state of one I/O APIC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoApic {
    /// 8-bit APIC id (register 0x00, bits 27:24).
    id: u8,
    /// Currently selected indirect register.
    select: u32,
    /// Redirection table.
    redirection: [RedirectionEntry; PIN_COUNT],
}

impl IoApic {
    /// Creates an I/O APIC with every pin masked (reset state).
    pub const fn new(apic_id: u8) -> Self {
        Self {
            id: apic_id,
            select: 0,
            redirection: [RedirectionEntry { raw: 1 << 16 }; PIN_COUNT],
        }
    }

    /// APIC id of this I/O APIC.
    pub const fn apic_id(&self) -> u8 {
        self.id
    }

    /// Currently selected indirect register.
    pub const fn selected(&self) -> u32 {
        self.select
    }

    /// Redirection entry for `pin` (masked pins included).
    pub const fn entry(&self, pin: usize) -> Option<RedirectionEntry> {
        if pin < PIN_COUNT {
            Some(self.redirection[pin])
        } else {
            None
        }
    }

    /// Programs `pin` with a vector; the entry stays masked if `masked`.
    pub fn set_pin(&mut self, pin: usize, vector: u8, masked: bool) {
        if pin < PIN_COUNT {
            let mut raw = self.redirection[pin].raw & !0x1_FFFF;
            raw |= u64::from(vector);
            if masked {
                raw |= 1 << 16;
            }
            self.redirection[pin] = RedirectionEntry { raw };
        }
    }

    /// Vector programmed for `pin`, if the pin is unmasked and delivers a
    /// fixed-mode interrupt.
    pub fn vector_for_pin(&self, pin: usize) -> Option<u8> {
        let entry = self.entry(pin)?;
        if entry.masked() || entry.delivery_mode() != 0 {
            None
        } else {
            Some(entry.vector())
        }
    }

    /// Reads one indirect register value (used by `IOWIN` reads).
    fn register_value(&self, index: u32) -> u32 {
        match index {
            0x00 => u32::from(self.id) << 24,
            0x01 => VERSION,
            0x02 => 0, // arbitration register, unused with one I/O APIC
            index if (REDIRECTION_BASE..REDIRECTION_BASE + 2 * PIN_COUNT as u32).contains(&index) => {
                let offset = index - REDIRECTION_BASE;
                let pin = (offset / 2) as usize;
                let raw = self.redirection[pin].raw;
                if offset % 2 == 0 {
                    raw as u32
                } else {
                    (raw >> 32) as u32
                }
            }
            _ => 0,
        }
    }

    /// Writes one indirect register value (used by `IOWIN` writes).
    fn write_register(&mut self, index: u32, value: u32) {
        match index {
            0x00 => self.id = ((value >> 24) & 0xFF) as u8,
            index if (REDIRECTION_BASE..REDIRECTION_BASE + 2 * PIN_COUNT as u32).contains(&index) => {
                let offset = index - REDIRECTION_BASE;
                let pin = (offset / 2) as usize;
                let mut raw = self.redirection[pin].raw;
                if offset % 2 == 0 {
                    raw = (raw & 0xFFFF_FFFF_0000_0000) | u64::from(value);
                } else {
                    raw = (raw & 0x0000_0000_FFFF_FFFF) | (u64::from(value) << 32);
                }
                self.redirection[pin] = RedirectionEntry { raw };
            }
            _ => {
                // Version and arbitration registers are read-only.
            }
        }
    }

    /// Reads a 32-bit MMIO register of the I/O APIC page.
    ///
    /// Only `IOREGSEL` and `IOWIN` are meaningful; other offsets return 0 so a
    /// guest access never faults.
    pub fn mmio_read(&self, offset: usize) -> u32 {
        match offset {
            REG_SELECT => self.select,
            REG_WINDOW => self.register_value(self.select),
            _ => 0,
        }
    }

    /// Writes a 32-bit MMIO register of the I/O APIC page.
    pub fn mmio_write(&mut self, offset: usize, value: u32) {
        match offset {
            REG_SELECT => self.select = value & 0xFF,
            REG_WINDOW => self.write_register(self.select, value),
            _ => {}
        }
    }
}

impl Default for IoApic {
    fn default() -> Self {
        Self::new(0)
    }
}
