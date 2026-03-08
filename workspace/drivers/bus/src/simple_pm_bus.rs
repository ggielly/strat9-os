use crate::{BusChild, BusDriver, BusError, PowerState, mmio::MmioRegion};
use alloc::{string::String, vec::Vec};

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
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            regs: MmioRegion::new(),
            power_state: PowerState::Off,
            children: Vec::new(),
            num_clocks: 0,
        }
    }

    /// Sets num clocks.
    pub fn set_num_clocks(&mut self, n: u32) {
        self.num_clocks = n;
    }

    /// Performs the add child operation.
    pub fn add_child(&mut self, child: BusChild) {
        self.children.push(child);
    }
}

impl BusDriver for SimplePmBus {
    /// Performs the name operation.
    fn name(&self) -> &str {
        "simple-pm-bus"
    }

    /// Performs the compatible operation.
    fn compatible(&self) -> &[&str] {
        COMPATIBLE
    }

    /// Performs the init operation.
    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x1000);
        self.power_state = PowerState::On;
        Ok(())
    }

    /// Performs the shutdown operation.
    fn shutdown(&mut self) -> Result<(), BusError> {
        self.power_state = PowerState::Off;
        Ok(())
    }

    /// Performs the suspend operation.
    fn suspend(&mut self) -> Result<(), BusError> {
        self.power_state = PowerState::Suspended;
        Ok(())
    }

    /// Performs the resume operation.
    fn resume(&mut self) -> Result<(), BusError> {
        self.power_state = PowerState::On;
        Ok(())
    }

    /// Reads reg.
    fn read_reg(&self, offset: usize) -> Result<u32, BusError> {
        if !self.regs.is_valid() {
            return Err(BusError::InitFailed);
        }
        Ok(self.regs.read32(offset))
    }

    /// Writes reg.
    fn write_reg(&mut self, offset: usize, value: u32) -> Result<(), BusError> {
        if !self.regs.is_valid() {
            return Err(BusError::InitFailed);
        }
        self.regs.write32(offset, value);
        Ok(())
    }

    /// Performs the children operation.
    fn children(&self) -> Vec<BusChild> {
        self.children.clone()
    }
}
