use alloc::{string::String, vec::Vec};
use crate::{BusChild, BusDriver, BusError, PowerState};
use crate::mmio::MmioRegion;

const COMPATIBLE: &[&str] = &["allwinner,sun50i-a64-de2"];

pub struct Sun50iDe2 {
    regs: MmioRegion,
    power_state: PowerState,
    sram_claimed: bool,
    children: Vec<BusChild>,
}

impl Sun50iDe2 {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            regs: MmioRegion::new(),
            power_state: PowerState::Off,
            sram_claimed: false,
            children: Vec::new(),
        }
    }

    /// Performs the claim sram operation.
    pub fn claim_sram(&mut self) -> Result<(), BusError> {
        self.sram_claimed = true;
        Ok(())
    }

    /// Performs the release sram operation.
    pub fn release_sram(&mut self) {
        self.sram_claimed = false;
    }

    /// Performs the add child operation.
    pub fn add_child(&mut self, child: BusChild) {
        self.children.push(child);
    }
}

impl BusDriver for Sun50iDe2 {
    /// Performs the name operation.
    fn name(&self) -> &str { "sun50i-de2" }

    /// Performs the compatible operation.
    fn compatible(&self) -> &[&str] { COMPATIBLE }

    /// Performs the init operation.
    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x1000);
        self.claim_sram()?;
        self.power_state = PowerState::On;
        Ok(())
    }

    /// Performs the shutdown operation.
    fn shutdown(&mut self) -> Result<(), BusError> {
        self.release_sram();
        self.power_state = PowerState::Off;
        Ok(())
    }

    /// Reads reg.
    fn read_reg(&self, offset: usize) -> Result<u32, BusError> {
        if !self.regs.is_valid() { return Err(BusError::InitFailed); }
        Ok(self.regs.read32(offset))
    }

    /// Writes reg.
    fn write_reg(&mut self, offset: usize, value: u32) -> Result<(), BusError> {
        if !self.regs.is_valid() { return Err(BusError::InitFailed); }
        self.regs.write32(offset, value);
        Ok(())
    }

    /// Performs the children operation.
    fn children(&self) -> Vec<BusChild> {
        self.children.clone()
    }
}
