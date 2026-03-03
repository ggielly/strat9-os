use alloc::{string::String, vec::Vec};
use crate::{BusChild, BusDriver, BusError, PowerState};
use crate::mmio::MmioRegion;

const OCP2SCP_TIMING: usize = 0x18;
const SYNC2_MASK: u32 = 0xF;
const SYNC2_SAFE_VALUE: u32 = 0x6;

const COMPATIBLE: &[&str] = &[
    "ti,omap-ocp2scp",
    "ti,am437x-ocp2scp",
];

pub struct OmapOcp2Scp {
    regs: MmioRegion,
    power_state: PowerState,
    is_am437x: bool,
    children: Vec<BusChild>,
}

impl OmapOcp2Scp {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            regs: MmioRegion::new(),
            power_state: PowerState::Off,
            is_am437x: false,
            children: Vec::new(),
        }
    }

    /// Sets am437x.
    pub fn set_am437x(&mut self, am437x: bool) {
        self.is_am437x = am437x;
    }

    /// Performs the add child operation.
    pub fn add_child(&mut self, child: BusChild) {
        self.children.push(child);
    }

    /// Performs the configure timing operation.
    fn configure_timing(&self) {
        if self.is_am437x || !self.regs.is_valid() {
            return;
        }
        let mut reg = self.regs.read32(OCP2SCP_TIMING);
        reg &= !SYNC2_MASK;
        reg |= SYNC2_SAFE_VALUE;
        self.regs.write32(OCP2SCP_TIMING, reg);
    }
}

impl BusDriver for OmapOcp2Scp {
    /// Performs the name operation.
    fn name(&self) -> &str { "omap-ocp2scp" }

    /// Performs the compatible operation.
    fn compatible(&self) -> &[&str] { COMPATIBLE }

    /// Performs the init operation.
    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x20);
        self.configure_timing();
        self.power_state = PowerState::On;
        Ok(())
    }

    /// Performs the shutdown operation.
    fn shutdown(&mut self) -> Result<(), BusError> {
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
