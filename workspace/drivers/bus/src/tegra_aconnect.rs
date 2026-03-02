use alloc::{string::String, vec::Vec};
use crate::{BusChild, BusDriver, BusError, PowerState};
use crate::mmio::MmioRegion;

const COMPATIBLE: &[&str] = &["nvidia,tegra210-aconnect"];

pub struct TegraAconnect {
    regs: MmioRegion,
    power_state: PowerState,
    children: Vec<BusChild>,
    ape_clk_enabled: bool,
    apb2ape_clk_enabled: bool,
}

impl TegraAconnect {
    pub fn new() -> Self {
        Self {
            regs: MmioRegion::new(),
            power_state: PowerState::Off,
            children: Vec::new(),
            ape_clk_enabled: false,
            apb2ape_clk_enabled: false,
        }
    }

    pub fn add_child(&mut self, child: BusChild) {
        self.children.push(child);
    }

    pub fn enable_clocks(&mut self) -> Result<(), BusError> {
        self.ape_clk_enabled = true;
        self.apb2ape_clk_enabled = true;
        Ok(())
    }

    pub fn disable_clocks(&mut self) {
        self.ape_clk_enabled = false;
        self.apb2ape_clk_enabled = false;
    }
}

impl BusDriver for TegraAconnect {
    fn name(&self) -> &str { "tegra-aconnect" }

    fn compatible(&self) -> &[&str] { COMPATIBLE }

    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x1000);
        self.enable_clocks()?;
        self.power_state = PowerState::On;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), BusError> {
        self.disable_clocks();
        self.power_state = PowerState::Off;
        Ok(())
    }

    fn suspend(&mut self) -> Result<(), BusError> {
        self.disable_clocks();
        self.power_state = PowerState::Suspended;
        Ok(())
    }

    fn resume(&mut self) -> Result<(), BusError> {
        self.enable_clocks()?;
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
