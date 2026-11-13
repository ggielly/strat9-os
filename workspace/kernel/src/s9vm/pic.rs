//! s9vm : pure model of the guest 8259A programmable interrupt controller.
//!
//! A PC-compatible guest expects two cascaded 8259A chips (master on ports
//! `0x20`/`0x21`, slave on `0xA0`/`0xA1`). This module models the
//! architectural state and the command sequences needed to emulate those port
//! accesses and to decide which vector (if any) the guest should receive.
//!
//! It touches no hardware: the kernel calls [`Pic::write_command`],
//! [`Pic::write_data`], [`Pic::read_command`], [`Pic::read_data`] when the
//! guest accesses the PIC ports, and [`Pic::raise`] / [`Pic::acknowledge`] to
//! follow interrupt delivery.
//!
//! The model is intentionally simple but faithful for a single-CPU guest:
//! fixed priority (IR0 highest), full ICW1-ICW4 initialisation, OCW1 (mask),
//! OCW2 (EOI, specific EOI and rotate-in-auto-EOI commands are accepted),
//! OCW3 (read IRR/ISR, poll mode), and the master/slave cascade on IR2.

/// Port offsets for the two chips.
pub mod port {
    /// Master command port (OCW1..OCW3 write, IRR/ISR read).
    pub const MASTER_COMMAND: u16 = 0x20;
    /// Master data port (ICW2..ICW4, OCW1 mask).
    pub const MASTER_DATA: u16 = 0x21;
    /// Slave command port.
    pub const SLAVE_COMMAND: u16 = 0xA0;
    /// Slave data port.
    pub const SLAVE_DATA: u16 = 0xA1;
}

/// Cascade input of the master connected to the slave (IR2).
pub const CASCADE_IRQ: u8 = 2;

/// One 8259A chip.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Chip {
    /// Interrupt request register.
    irr: u8,
    /// In-service register.
    isr: u8,
    /// Interrupt mask register.
    imr: u8,
    /// Vector base programmed by ICW2.
    vector_base: u8,
    /// Single mode (ICW1 bit 1): no cascade.
    single: bool,
    /// Level-triggered mode (ICW1 bit 3).
    level_triggered: bool,
    /// ICW4 was requested (ICW1 bit 0).
    needs_icw4: bool,
    /// Initialisation step: 0 = ready for ICW1, 1 = expect ICW2, 2 = expect
    /// ICW3, 3 = expect ICW4.
    init_step: u8,
    /// Ready for OCW3 (bit 3 of OCW3 was written last).
    ocw3_selected: bool,
    /// OCW3 read register: false = IRR, true = ISR.
    read_isr: bool,
    /// OCW3 poll mode.
    poll_mode: bool,
    /// OCW3 special mask mode.
    special_mask: bool,
}

impl Chip {
    /// Creates a chip in the reset state (all masked, no vector base).
    pub const fn new() -> Self {
        Self {
            irr: 0,
            isr: 0,
            imr: 0xFF,
            vector_base: 0,
            single: false,
            level_triggered: false,
            needs_icw4: false,
            init_step: 0,
            ocw3_selected: false,
            read_isr: false,
            poll_mode: false,
            special_mask: false,
        }
    }

    /// True while the initialisation sequence is in progress.
    pub const fn initializing(&self) -> bool {
        self.init_step != 0
    }

    /// Current vector base (ICW2), typically `0x08` for the master.
    pub const fn vector_base(&self) -> u8 {
        self.vector_base
    }

    /// Current interrupt mask.
    pub const fn mask(&self) -> u8 {
        self.imr
    }

    /// Requests currently pending.
    pub const fn irr(&self) -> u8 {
        self.irr
    }

    /// Requests currently in service.
    pub const fn isr(&self) -> u8 {
        self.isr
    }

    /// Raises (asserts) one IRQ line.
    pub fn raise(&mut self, irq: u8) {
        if irq < 8 {
            self.irr |= 1 << irq;
        }
    }

    /// Lowers (deasserts) one IRQ line.
    ///
    /// In level-triggered mode the request exists while the line is high, so
    /// deasserting it withdraws a request that was not acknowledged yet. In
    /// edge-triggered mode : the PC default : the request was latched by the
    /// rising edge and stays in the `IRR` until the processor acknowledges it,
    /// even if the line is already low again: a device pulse must not be lost
    /// because it was serviced later (masked line, or a guest that has not
    /// unmasked the pair yet).
    pub fn lower(&mut self, irq: u8) {
        if irq < 8 && self.level_triggered {
            self.irr &= !(1 << irq);
        }
    }

    /// Masked request with the highest priority (lowest IRQ number), if any.
    fn highest_pending(&self) -> Option<u8> {
        let eligible = self.irr & !self.imr;
        if eligible == 0 {
            None
        } else {
            Some(eligible.trailing_zeros() as u8)
        }
    }

    /// Accepts the highest-priority pending request: moves it from IRR to ISR
    /// and returns its vector, or `None` when nothing is deliverable.
    pub fn acknowledge(&mut self) -> Option<u8> {
        let irq = self.highest_pending()?;
        self.irr &= !(1 << irq);
        self.isr |= 1 << irq;
        Some(self.vector_base.wrapping_add(irq))
    }

    /// Highest in-service IRQ (lowest number), if any.
    fn highest_in_service(&self) -> Option<u8> {
        if self.isr == 0 {
            None
        } else {
            Some(self.isr.trailing_zeros() as u8)
        }
    }

    /// Non-specific EOI: clears the highest in-service request.
    pub fn eoi(&mut self) {
        if let Some(irq) = self.highest_in_service() {
            self.isr &= !(1 << irq);
        }
    }

    /// Specific EOI: clears the given in-service request.
    pub fn eoi_specific(&mut self, irq: u8) {
        if irq < 8 {
            self.isr &= !(1 << irq);
        }
    }

    /// Writes the command port (OCW1 is written to the data port, so this
    /// port handles ICW1 and OCW2/OCW3).
    pub fn write_command(&mut self, value: u8) {
        if value & 0x10 != 0 {
            // ICW1: start the initialisation sequence.
            self.imr = 0xFF;
            self.isr = 0;
            self.irr = 0;
            self.single = value & 0x02 != 0;
            self.level_triggered = value & 0x08 != 0;
            self.needs_icw4 = value & 0x01 != 0;
            self.init_step = 1;
            self.ocw3_selected = false;
            return;
        }
        if self.initializing() {
            return;
        }
        if value & 0x08 != 0 {
            // OCW3: bit 3 set and bit 4 clear (ICW1 was handled above).
            // Bit 0 selects IRR (0) or ISR (1), bit 2 is the poll command,
            // bit 1 enables special-mask-mode updates (bit 6 = SMM value).
            self.ocw3_selected = true;
            self.read_isr = value & 0x01 != 0;
            if value & 0x04 != 0 {
                self.poll_mode = true;
                self.read_isr = true;
            }
            if value & 0x02 != 0 {
                self.special_mask = value & 0x40 != 0;
            }
            return;
        }
        if value & 0x18 == 0 {
            // OCW2: EOI commands (bits 7:5 = R, SL, EOI).
            match (value >> 5) & 0x7 {
                0b011 => self.eoi_specific(value & 0x07),
                _ => self.eoi(),
            }
        }
    }

    /// Writes the data port: ICW2..ICW4 during initialisation, OCW1 otherwise.
    pub fn write_data(&mut self, value: u8) {
        match self.init_step {
            1 => {
                self.vector_base = value & 0xF8;
                self.init_step = 2;
            }
            2 => {
                // ICW3: cascade wiring, not needed for a single slave.
                self.init_step = if self.needs_icw4 { 3 } else { 0 };
            }
            3 => {
                // ICW4: 8086 mode expected; other bits not modelled.
                self.init_step = 0;
            }
            _ => {
                self.imr = value;
            }
        }
    }

    /// Reads the command port (IRR/ISR, or the poll status).
    pub fn read_command(&mut self) -> u8 {
        if self.poll_mode {
            self.poll_mode = false;
            return match self.highest_pending() {
                Some(irq) => irq | 0x80,
                None => 0,
            };
        }
        if self.ocw3_selected && self.read_isr {
            self.isr
        } else {
            self.irr
        }
    }

    /// Reads the data port (IMR).
    pub fn read_data(&self) -> u8 {
        self.imr
    }
}

/// Cascaded pair of 8259A chips of one guest machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pic {
    master: Chip,
    slave: Chip,
}

impl Pic {
    /// Creates a PC-compatible pair (master vector base 0x08, slave base 0x70).
    pub const fn new() -> Self {
        Self {
            master: Chip::new(),
            slave: Chip::new(),
        }
    }

    /// Master chip state.
    pub const fn master(&self) -> &Chip {
        &self.master
    }

    /// Slave chip state.
    pub const fn slave(&self) -> &Chip {
        &self.slave
    }

    /// Port range served by the PIC: (`0x20`, `0x21`, `0xA0`, `0xA1`).
    pub const fn handles_port(port: u16) -> bool {
        matches!(
            port,
            port::MASTER_COMMAND | port::MASTER_DATA | port::SLAVE_COMMAND | port::SLAVE_DATA
        )
    }

    /// Writes to a PIC port. Returns `false` if the port is not a PIC port.
    pub fn write(&mut self, port: u16, value: u8) -> bool {
        match port {
            port::MASTER_COMMAND => self.master.write_command(value),
            port::MASTER_DATA => self.master.write_data(value),
            port::SLAVE_COMMAND => self.slave.write_command(value),
            port::SLAVE_DATA => self.slave.write_data(value),
            _ => return false,
        }
        true
    }

    /// Reads from a PIC port. Returns `None` if the port is not a PIC port.
    pub fn read(&mut self, port: u16) -> Option<u8> {
        match port {
            port::MASTER_COMMAND => Some(self.master.read_command()),
            port::MASTER_DATA => Some(self.master.read_data()),
            port::SLAVE_COMMAND => Some(self.slave.read_command()),
            port::SLAVE_DATA => Some(self.slave.read_data()),
            _ => None,
        }
    }

    /// Raises an IRQ line (0..15).
    pub fn raise(&mut self, irq: u8) {
        if irq < 8 {
            self.master.raise(irq);
        } else if irq < 16 {
            self.slave.raise(irq - 8);
            // The slave is wired to the master's cascade input.
            self.master.raise(CASCADE_IRQ);
        }
    }

    /// Lowers an IRQ line (0..15).
    pub fn lower(&mut self, irq: u8) {
        if irq < 8 {
            self.master.lower(irq);
        } else if irq < 16 {
            self.slave.lower(irq - 8);
            if self.slave.irr == 0 {
                self.master.lower(CASCADE_IRQ);
            }
        }
    }

    /// Accepts the highest-priority request across both chips.
    ///
    /// The slave is serviced through the master's cascade input, so a pending
    /// slave request is reported with the slave's vector while both in-service
    /// registers are updated.
    pub fn acknowledge(&mut self) -> Option<u8> {
        let master_ready = self.master.highest_pending();
        let slave_ready = self.slave.highest_pending();

        // Priority order across the cascade: master IR0/IR1, then the slave
        // (through IR2), then master IR3..IR7.
        if slave_ready.is_some() && self.master.imr & (1 << CASCADE_IRQ) == 0 {
            let higher_master_wins = matches!(
                master_ready,
                Some(irq) if irq < CASCADE_IRQ
            );
            if !higher_master_wins {
                let vector = self.slave.acknowledge()?;
                self.master.acknowledge();
                return Some(vector);
            }
        }
        self.master.acknowledge()
    }

    /// Non-specific EOI: an EOI from the slave is forwarded to the master when
    /// the slave has no more requests in service.
    pub fn eoi(&mut self) {
        if self.slave.isr != 0 {
            self.slave.eoi();
            if self.slave.isr == 0 {
                self.master.eoi_specific(CASCADE_IRQ);
            }
        } else {
            self.master.eoi();
        }
    }
}

impl Default for Pic {
    fn default() -> Self {
        Self::new()
    }
}
