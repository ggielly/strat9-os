use alloc::{string::String, vec::Vec};
use crate::{BusChild, BusDriver, BusError, PowerState};
use crate::mmio::MmioRegion;

const COMPATIBLE: &[&str] = &[
    "simple-pm-bus",
    "simple-bus",
    "simple-mfd",
    "isa",
    "arm,amba-bus",
];

pub struct SimplePmBus {
    regs: MmioRegion,
    power_state: PowerState,
    children: Vec<BusChild>,
    num_clocks: u32,
}

impl SimplePmBus {
    pub fn new() -> Self {
        Self {
            regs: MmioRegion::new(),
            power_state: PowerState::Off,
            children: Vec::new(),
            num_clocks: 0,
        }
    }

    pub fn set_num_clocks(&mut self, n: u32) {
        self.num_clocks = n;
    }

    pub fn add_child(&mut self, child: BusChild) {
        self.children.push(child);
    }
}

impl BusDriver for SimplePmBus {
    fn name(&self) -> &str { "simple-pm-bus" }

    fn compatible(&self) -> &[&str] { COMPATIBLE }

    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x1000);
        self.power_state = PowerState::On;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), BusError> {
        self.power_state = PowerState::Off;
        Ok(())
    }

    fn suspend(&mut self) -> Result<(), BusError> {
        self.power_state = PowerState::Suspended;
        Ok(())
    }

    fn resume(&mut self) -> Result<(), BusError> {
        self.power_state = PowerState::On;
        Ok(())
    }

    fn read_reg(&self, offset: usize) -> Result<u32, BusError> {
        if !self.regs.is_valid() {
            return Err(BusError::InitFailed);
        }
        Ok(self.regs.read32(offset))
    }

    fn write_reg(&mut self, offset: usize, value: u32) -> Result<(), BusError> {
        if !self.regs.is_valid() {
            return Err(BusError::InitFailed);
        }
        self.regs.write32(offset, value);
        Ok(())
    }

    fn children(&self) -> Vec<BusChild> {
        self.children.clone()
    }
}
