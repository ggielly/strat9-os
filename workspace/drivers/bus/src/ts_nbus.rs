use crate::{BusChild, BusDriver, BusError, PowerState};
use alloc::{string::String, vec::Vec};

const TS_NBUS_DIRECTION_IN: bool = false;
const TS_NBUS_DIRECTION_OUT: bool = true;
const TS_NBUS_WRITE_ADR: bool = false;
const TS_NBUS_WRITE_VAL: bool = true;

const MAX_POLL_RDY: u32 = 10000;

const COMPATIBLE: &[&str] = &["technologic,ts-nbus"];

/// A single memory-mapped GPIO line of the FPGA GPIO controller that
/// backs the NBUS bit-banging protocol.
///
/// # Register layout
///
/// The controller is expected to expose two 32-bit registers relative to
/// `base`:
///
/// - `base + 0x00`: **data** register, bit `offset` drives/reflects the line;
/// - `base + 0x04`: **direction** register, bit `offset` set = output,
///   cleared = input.
///
/// All accesses are volatile read-modify-write so concurrent lines of the
/// same controller are preserved.
///
/// An unconfigured pin (`base == 0`) reports [`Self::is_configured`] ==
/// false; transactions that need it are rejected instead of silently
/// doing nothing.
pub struct GpioPin {
    /// Physical base address of the GPIO controller register block.
    pub base: usize,
    /// Bit index of this line within the controller's 32-bit registers.
    pub offset: u32,
    /// When true, logical high/low are inverted relative to the electrical level.
    pub active_low: bool,
}

impl GpioPin {
    /// Offset of the data (set/clear via read-modify-write) register.
    pub const DATA_REG_OFFSET: usize = 0x00;
    /// Offset of the direction register (bit set = output).
    pub const DIR_REG_OFFSET: usize = 0x04;

    /// Returns true when this pin points at a real controller (`base != 0`).
    pub fn is_configured(&self) -> bool {
        self.base != 0 && self.offset < 32
    }

    /// Reads the data register.
    fn read_data(&self) -> u32 {
        // SAFETY: callers guarantee `base` is the mapped base of a GPIO
        // controller register block and `DATA_REG_OFFSET + 4` stays within it.
        unsafe { core::ptr::read_volatile((self.base + Self::DATA_REG_OFFSET) as *const u32) }
    }

    /// Writes the data register.
    fn write_data(&self, val: u32) {
        // SAFETY: see `read_data`.
        unsafe { core::ptr::write_volatile((self.base + Self::DATA_REG_OFFSET) as *mut u32, val) }
    }

    /// Sets or clears bit `offset` of a register via volatile read-modify-write.
    fn rmw_bit(&self, reg_offset: usize, set: bool) {
        let addr = (self.base + reg_offset) as *const u32;
        // SAFETY: see `read_data`; read-modify-write keeps sibling lines intact.
        let mut val = unsafe { core::ptr::read_volatile(addr) };
        let mask = 1u32 << self.offset;
        if set {
            val |= mask;
        } else {
            val &= !mask;
        }
        // SAFETY: same mapping, write back the updated word.
        unsafe { core::ptr::write_volatile(addr as *mut u32, val) };
    }

    /// Drives the line to its logical-high level.
    pub fn set_high(&self) {
        let bit = !self.active_low;
        self.rmw_bit(Self::DATA_REG_OFFSET, bit);
    }

    /// Drives the line to its logical-low level.
    pub fn set_low(&self) {
        let bit = self.active_low;
        self.rmw_bit(Self::DATA_REG_OFFSET, bit);
    }

    /// Samples the current logical level of the line.
    pub fn get_value(&self) -> bool {
        let raw = self.read_data() & (1u32 << self.offset) != 0;
        raw != self.active_low
    }

    /// Configures the line as input (direction bit cleared).
    pub fn set_direction_input(&self) {
        self.rmw_bit(Self::DIR_REG_OFFSET, false);
    }

    /// Configures the line as output (direction bit set).
    pub fn set_direction_output(&self) {
        self.rmw_bit(Self::DIR_REG_OFFSET, true);
    }
}

pub struct TsNbus {
    data_pins: [Option<GpioPin>; 8],
    csn: Option<GpioPin>,
    txrx: Option<GpioPin>,
    strobe: Option<GpioPin>,
    ale: Option<GpioPin>,
    rdy: Option<GpioPin>,
    power_state: PowerState,
    children: Vec<BusChild>,
}

/// Control line of the NBUS protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NbusControlPin {
    /// Chip select.
    Csn,
    /// TX/RX direction selector.
    TxRx,
    /// Strobe.
    Strobe,
    /// Address latch enable.
    Ale,
    /// Ready (input).
    Rdy,
}

impl TsNbus {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            data_pins: [const { None }; 8],
            csn: None,
            txrx: None,
            strobe: None,
            ale: None,
            rdy: None,
            power_state: PowerState::Off,
            children: Vec::new(),
        }
    }

    /// Wires one of the 8 data lines (`index` 0..8) to a GPIO pin.
    /// Returns [`BusError::InvalidArgument`] when `index >= 8`.
    pub fn set_data_pin(&mut self, index: usize, pin: GpioPin) -> Result<(), BusError> {
        if index >= 8 {
            return Err(BusError::InvalidArgument);
        }
        self.data_pins[index] = Some(pin);
        Ok(())
    }

    /// Wires a control line to a GPIO pin.
    pub fn set_control_pin(&mut self, which: NbusControlPin, pin: GpioPin) {
        let slot = match which {
            NbusControlPin::Csn => &mut self.csn,
            NbusControlPin::TxRx => &mut self.txrx,
            NbusControlPin::Strobe => &mut self.strobe,
            NbusControlPin::Ale => &mut self.ale,
            NbusControlPin::Rdy => &mut self.rdy,
        };
        *slot = Some(pin);
    }

    /// Verifies that every pin required by the bit-banging protocol is
    /// configured, so transactions fail loudly instead of silently no-op'ing.
    fn validate_pins(&self) -> Result<(), BusError> {
        for (i, p) in self.data_pins.iter().enumerate() {
            match p {
                Some(p) if p.is_configured() => {}
                _ => return Err(BusError::InvalidArgument),
            }
        }
        for p in [&self.csn, &self.txrx, &self.strobe, &self.ale, &self.rdy] {
            match p {
                Some(p) if p.is_configured() => {}
                _ => return Err(BusError::InvalidArgument),
            }
        }
        Ok(())
    }

    /// Sets data direction.
    fn set_data_direction(&self, output: bool) {
        for p in self.data_pins.iter().flatten() {
            if output {
                p.set_direction_output();
            } else {
                p.set_direction_input();
            }
        }
    }

    /// Writes byte.
    fn write_byte(&self, val: u8) {
        for i in 0..8 {
            if let Some(ref p) = self.data_pins[i] {
                if (val >> i) & 1 != 0 {
                    p.set_high();
                } else {
                    p.set_low();
                }
            }
        }
    }

    /// Reads byte.
    fn read_byte(&self) -> u8 {
        let mut val = 0u8;
        for i in 0..8 {
            if let Some(ref p) = self.data_pins[i]
                && p.get_value()
            {
                val |= 1 << i;
            }
        }
        val
    }

    /// Starts transaction.
    fn start_transaction(&self) {
        if let Some(ref s) = self.strobe {
            s.set_high();
        }
    }

    /// Performs the end transaction operation.
    fn end_transaction(&self) {
        if let Some(ref s) = self.strobe {
            s.set_low();
        }
    }

    /// Performs the wait rdy operation.
    fn wait_rdy(&self) -> Result<(), BusError> {
        for _ in 0..MAX_POLL_RDY {
            if let Some(ref r) = self.rdy
                && r.get_value()
            {
                return Ok(());
            }
        }
        Err(BusError::Timeout)
    }

    /// Performs the reset bus operation.
    fn reset_bus(&self) {
        self.write_byte(0);
        if let Some(ref c) = self.csn {
            c.set_low();
        }
        if let Some(ref s) = self.strobe {
            s.set_low();
        }
        if let Some(ref a) = self.ale {
            a.set_low();
        }
    }

    /// Performs the bus read operation.
    pub fn bus_read(&self, address: u16) -> Result<u16, BusError> {
        self.set_data_direction(true);
        if let Some(ref t) = self.txrx {
            t.set_low();
        }
        if let Some(ref a) = self.ale {
            a.set_high();
        }

        self.write_byte((address >> 8) as u8);
        self.start_transaction();
        self.end_transaction();

        self.write_byte(address as u8);
        self.start_transaction();
        self.end_transaction();

        if let Some(ref a) = self.ale {
            a.set_low();
        }
        self.set_data_direction(false);

        if let Some(ref c) = self.csn {
            c.set_high();
        }
        self.start_transaction();
        self.wait_rdy()?;
        let msb = self.read_byte();
        self.end_transaction();

        self.start_transaction();
        self.wait_rdy()?;
        let lsb = self.read_byte();
        self.end_transaction();

        if let Some(ref c) = self.csn {
            c.set_low();
        }

        Ok(((msb as u16) << 8) | (lsb as u16))
    }

    /// Performs the bus write operation.
    pub fn bus_write(&self, address: u16, value: u16) -> Result<(), BusError> {
        self.set_data_direction(true);
        if let Some(ref t) = self.txrx {
            t.set_high();
        }
        if let Some(ref a) = self.ale {
            a.set_high();
        }

        self.write_byte((address >> 8) as u8);
        self.start_transaction();
        self.end_transaction();

        self.write_byte(address as u8);
        self.start_transaction();
        self.end_transaction();

        if let Some(ref a) = self.ale {
            a.set_low();
        }
        if let Some(ref c) = self.csn {
            c.set_high();
        }

        self.write_byte((value >> 8) as u8);
        self.start_transaction();
        self.wait_rdy()?;
        self.end_transaction();

        self.write_byte(value as u8);
        self.start_transaction();
        self.wait_rdy()?;
        self.end_transaction();

        if let Some(ref c) = self.csn {
            c.set_low();
        }

        Ok(())
    }

    /// Performs the add child operation.
    pub fn add_child(&mut self, child: BusChild) {
        self.children.push(child);
    }
}

impl BusDriver for TsNbus {
    /// Performs the name operation.
    fn name(&self) -> &str {
        "ts-nbus"
    }

    /// Performs the compatible operation.
    fn compatible(&self) -> &[&str] {
        COMPATIBLE
    }

    /// Requires explicit GPIO pin configuration; no auto-detect.
    fn probe(&self) -> bool {
        false
    }

    /// Performs the init operation.
    fn init(&mut self, _base: usize) -> Result<(), BusError> {
        self.validate_pins()?;
        self.reset_bus();
        self.power_state = PowerState::On;
        Ok(())
    }

    /// Performs the shutdown operation.
    fn shutdown(&mut self) -> Result<(), BusError> {
        self.reset_bus();
        self.power_state = PowerState::Off;
        Ok(())
    }

    /// Reads reg.
    fn read_reg(&self, offset: usize) -> Result<u32, BusError> {
        // bus_read indexes a u16 register space: reject out-of-range
        // offsets instead of silently truncating to the low 16 bits.
        let off = u16::try_from(offset).map_err(|_| BusError::InvalidAddress)?;
        let val = self.bus_read(off)?;
        Ok(val as u32)
    }

    /// Writes reg.
    fn write_reg(&mut self, offset: usize, value: u32) -> Result<(), BusError> {
        let off = u16::try_from(offset).map_err(|_| BusError::InvalidAddress)?;
        self.bus_write(off, value as u16)
    }

    /// Performs the children operation.
    fn children(&self) -> Vec<BusChild> {
        self.children.clone()
    }
}
