use alloc::{string::String, vec::Vec};
use crate::{BusChild, BusDriver, BusError, PowerState};
use crate::mmio::MmioRegion;

const IMX_AIPSTZ_MPR0: usize = 0x00;

const COMPATIBLE: &[&str] = &["fsl,imx8mp-aipstz"];

pub struct AipstzConfig {
    pub mpr0: u32,
}

pub const IMX8MP_DEFAULT_CFG: AipstzConfig = AipstzConfig {
    mpr0: 0x7777_7777,
};

pub struct ImxAipstz {
    regs: MmioRegion,
    config: AipstzConfig,
    power_state: PowerState,
    children: Vec<BusChild>,
}

impl ImxAipstz {
    pub fn new(config: AipstzConfig) -> Self {
        Self {
            regs: MmioRegion::new(),
            config,
            power_state: PowerState::Off,
            children: Vec::new(),
        }
    }

    fn apply_config(&self) {
        if !self.regs.is_valid() { return; }
        self.regs.write32(IMX_AIPSTZ_MPR0, self.config.mpr0);
    }

    pub fn add_child(&mut self, child: BusChild) {
        self.children.push(child);
    }
}

impl BusDriver for ImxAipstz {
    fn name(&self) -> &str { "imx-aipstz" }

    fn compatible(&self) -> &[&str] { COMPATIBLE }

    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x100);
        self.apply_config();
        self.power_state = PowerState::On;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), BusError> {
        self.power_state = PowerState::Off;
        Ok(())
    }

    fn resume(&mut self) -> Result<(), BusError> {
        self.apply_config();
        self.power_state = PowerState::On;
        Ok(())
    }

    fn read_reg(&self, offset: usize) -> Result<u32, BusError> {
        if !self.regs.is_valid() { return Err(BusError::InitFailed); }
        Ok(self.regs.read32(offset))
    }

    fn write_reg(&mut self, offset: usize, value: u32) -> Result<(), BusError> {
        if !self.regs.is_valid() { return Err(BusError::InitFailed); }
        self.regs.write32(offset, value);
        Ok(())
    }

    fn children(&self) -> Vec<BusChild> {
        self.children.clone()
    }
}
