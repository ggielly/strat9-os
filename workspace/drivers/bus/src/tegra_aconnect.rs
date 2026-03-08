use crate::{BusChild, BusDriver, BusError, PowerState, mmio::MmioRegion};
use alloc::{string::String, vec::Vec};

const COMPATIBLE: &[&str] = &["nvidia,tegra210-aconnect"];

pub struct TegraAconnect {
    regs: MmioRegion,
    power_state: PowerState,
    children: Vec<BusChild>,
    ape_clk_enabled: bool,
    apb2ape_clk_enabled: bool,
}

impl TegraAconnect {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            regs: MmioRegion::new(),
            power_state: PowerState::Off,
            children: Vec::new(),
            ape_clk_enabled: false,
            apb2ape_clk_enabled: false,
        }
    }

    /// Performs the add child operation.
    pub fn add_child(&mut self, child: BusChild) {
        self.children.push(child);
    }

    /// Enables clocks.
    pub fn enable_clocks(&mut self) -> Result<(), BusError> {
        self.ape_clk_enabled = true;
        self.apb2ape_clk_enabled = true;
        Ok(())
    }

    /// Disables clocks.
    pub fn disable_clocks(&mut self) {
        self.ape_clk_enabled = false;
        self.apb2ape_clk_enabled = false;
    }
}

impl BusDriver for TegraAconnect {
    /// Performs the name operation.
    fn name(&self) -> &str {
        "tegra-aconnect"
    }

    /// Performs the compatible operation.
    fn compatible(&self) -> &[&str] {
        COMPATIBLE
    }

    /// Performs the init operation.
    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x1000);
        self.enable_clocks()?;
        self.power_state = PowerState::On;
        Ok(())
    }

    /// Performs the shutdown operation.
    fn shutdown(&mut self) -> Result<(), BusError> {
        self.disable_clocks();
        self.power_state = PowerState::Off;
        Ok(())
    }

    /// Performs the suspend operation.
    fn suspend(&mut self) -> Result<(), BusError> {
        self.disable_clocks();
        self.power_state = PowerState::Suspended;
        Ok(())
    }

    /// Performs the resume operation.
    fn resume(&mut self) -> Result<(), BusError> {
        self.enable_clocks()?;
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
