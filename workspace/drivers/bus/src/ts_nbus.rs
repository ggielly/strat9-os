use alloc::{string::String, vec::Vec};
use crate::{BusChild, BusDriver, BusError, PowerState};

const TS_NBUS_DIRECTION_IN: bool = false;
const TS_NBUS_DIRECTION_OUT: bool = true;
const TS_NBUS_WRITE_ADR: bool = false;
const TS_NBUS_WRITE_VAL: bool = true;

const MAX_POLL_RDY: u32 = 10000;

const COMPATIBLE: &[&str] = &["technologic,ts-nbus"];

pub struct GpioPin {
    pub base: usize,
    pub offset: u32,
    pub active_low: bool,
}

impl GpioPin {
    pub fn set_high(&self) { /* MMIO GPIO set */ }
    pub fn set_low(&self) { /* MMIO GPIO clear */ }
    pub fn get_value(&self) -> bool { false }
    pub fn set_direction_input(&self) { /* configure as input */ }
    pub fn set_direction_output(&self) { /* configure as output */ }
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

impl TsNbus {
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

    fn set_data_direction(&self, output: bool) {
        for pin in &self.data_pins {
            if let Some(p) = pin {
                if output {
                    p.set_direction_output();
                } else {
                    p.set_direction_input();
                }
            }
        }
    }

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

    fn read_byte(&self) -> u8 {
        let mut val = 0u8;
        for i in 0..8 {
            if let Some(ref p) = self.data_pins[i] {
                if p.get_value() {
                    val |= 1 << i;
                }
            }
        }
        val
    }

    fn start_transaction(&self) {
        if let Some(ref s) = self.strobe {
            s.set_high();
        }
    }

    fn end_transaction(&self) {
        if let Some(ref s) = self.strobe {
            s.set_low();
        }
    }

    fn wait_rdy(&self) -> Result<(), BusError> {
        for _ in 0..MAX_POLL_RDY {
            if let Some(ref r) = self.rdy {
                if r.get_value() {
                    return Ok(());
                }
            }
        }
        Err(BusError::Timeout)
    }

    fn reset_bus(&self) {
        self.write_byte(0);
        if let Some(ref c) = self.csn { c.set_low(); }
        if let Some(ref s) = self.strobe { s.set_low(); }
        if let Some(ref a) = self.ale { a.set_low(); }
    }

    pub fn bus_read(&self, address: u16) -> Result<u16, BusError> {
        self.set_data_direction(true);
        if let Some(ref t) = self.txrx { t.set_low(); }
        if let Some(ref a) = self.ale { a.set_high(); }

        self.write_byte((address >> 8) as u8);
        self.start_transaction();
        self.end_transaction();

        self.write_byte(address as u8);
        self.start_transaction();
        self.end_transaction();

        if let Some(ref a) = self.ale { a.set_low(); }
        self.set_data_direction(false);

        if let Some(ref c) = self.csn { c.set_high(); }
        self.start_transaction();
        self.wait_rdy()?;
        let msb = self.read_byte();
        self.end_transaction();

        self.start_transaction();
        self.wait_rdy()?;
        let lsb = self.read_byte();
        self.end_transaction();

        if let Some(ref c) = self.csn { c.set_low(); }

        Ok(((msb as u16) << 8) | (lsb as u16))
    }

    pub fn bus_write(&self, address: u16, value: u16) -> Result<(), BusError> {
        self.set_data_direction(true);
        if let Some(ref t) = self.txrx { t.set_high(); }
        if let Some(ref a) = self.ale { a.set_high(); }

        self.write_byte((address >> 8) as u8);
        self.start_transaction();
        self.end_transaction();

        self.write_byte(address as u8);
        self.start_transaction();
        self.end_transaction();

        if let Some(ref a) = self.ale { a.set_low(); }
        if let Some(ref c) = self.csn { c.set_high(); }

        self.write_byte((value >> 8) as u8);
        self.start_transaction();
        self.wait_rdy()?;
        self.end_transaction();

        self.write_byte(value as u8);
        self.start_transaction();
        self.wait_rdy()?;
        self.end_transaction();

        if let Some(ref c) = self.csn { c.set_low(); }

        Ok(())
    }

    pub fn add_child(&mut self, child: BusChild) {
        self.children.push(child);
    }
}

impl BusDriver for TsNbus {
    fn name(&self) -> &str { "ts-nbus" }

    fn compatible(&self) -> &[&str] { COMPATIBLE }

    fn init(&mut self, _base: usize) -> Result<(), BusError> {
        self.reset_bus();
        self.power_state = PowerState::On;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), BusError> {
        self.reset_bus();
        self.power_state = PowerState::Off;
        Ok(())
    }

    fn read_reg(&self, offset: usize) -> Result<u32, BusError> {
        let val = self.bus_read(offset as u16)?;
        Ok(val as u32)
    }

    fn write_reg(&mut self, offset: usize, value: u32) -> Result<(), BusError> {
        self.bus_write(offset as u16, value as u16)
    }

    fn children(&self) -> Vec<BusChild> {
        self.children.clone()
    }
}
