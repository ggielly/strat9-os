use alloc::{string::String, vec::Vec};
use crate::{BusChild, BusDriver, BusError, PowerState};
use crate::mmio::MmioRegion;

const TEGRA_GMI_CONFIG: usize = 0x00;
const TEGRA_GMI_TIMING0: usize = 0x10;
const TEGRA_GMI_TIMING1: usize = 0x14;

const CONFIG_GO: u32 = 1 << 31;
const BUS_WIDTH_32BIT: u32 = 1 << 30;
const MUX_MODE: u32 = 1 << 28;
const RDY_BEFORE_DATA: u32 = 1 << 24;
const RDY_ACTIVE_HIGH: u32 = 1 << 23;
const ADV_ACTIVE_HIGH: u32 = 1 << 22;
const OE_ACTIVE_HIGH: u32 = 1 << 21;
const CS_ACTIVE_HIGH: u32 = 1 << 20;

const MAX_CHIP_SELECT: u32 = 8;

const COMPATIBLE: &[&str] = &[
    "nvidia,tegra20-gmi",
    "nvidia,tegra30-gmi",
];

fn cs_select(x: u32) -> u32 { (x & 0x7) << 4 }
fn muxed_width(x: u32) -> u32 { (x & 0xF) << 12 }
fn hold_width(x: u32) -> u32 { (x & 0xF) << 8 }
fn adv_width(x: u32) -> u32 { (x & 0xF) << 4 }
fn ce_width(x: u32) -> u32 { x & 0xF }
fn we_width(x: u32) -> u32 { (x & 0xFF) << 16 }
fn oe_width(x: u32) -> u32 { (x & 0xFF) << 8 }
fn wait_width(x: u32) -> u32 { x & 0xFF }

pub struct GmiConfig {
    pub bus_width_32: bool,
    pub mux_mode: bool,
    pub rdy_before_data: bool,
    pub rdy_active_high: bool,
    pub adv_active_high: bool,
    pub oe_active_high: bool,
    pub cs_active_high: bool,
    pub chip_select: u32,
}

pub struct GmiTiming {
    pub muxed_width: u32,
    pub hold_width: u32,
    pub adv_width: u32,
    pub ce_width: u32,
    pub we_width: u32,
    pub oe_width: u32,
    pub wait_width: u32,
}

pub struct TegraGmi {
    regs: MmioRegion,
    power_state: PowerState,
    snor_config: u32,
    snor_timing0: u32,
    snor_timing1: u32,
}

impl TegraGmi {
    pub fn new() -> Self {
        Self {
            regs: MmioRegion::new(),
            power_state: PowerState::Off,
            snor_config: 0,
            snor_timing0: 0,
            snor_timing1: 0,
        }
    }

    pub fn configure(&mut self, cfg: &GmiConfig, timing: &GmiTiming) {
        let mut config = 0u32;
        if cfg.bus_width_32 { config |= BUS_WIDTH_32BIT; }
        if cfg.mux_mode { config |= MUX_MODE; }
        if cfg.rdy_before_data { config |= RDY_BEFORE_DATA; }
        if cfg.rdy_active_high { config |= RDY_ACTIVE_HIGH; }
        if cfg.adv_active_high { config |= ADV_ACTIVE_HIGH; }
        if cfg.oe_active_high { config |= OE_ACTIVE_HIGH; }
        if cfg.cs_active_high { config |= CS_ACTIVE_HIGH; }
        if cfg.chip_select < MAX_CHIP_SELECT {
            config |= cs_select(cfg.chip_select);
        }
        self.snor_config = config;

        self.snor_timing0 = muxed_width(timing.muxed_width)
            | hold_width(timing.hold_width)
            | adv_width(timing.adv_width)
            | ce_width(timing.ce_width);

        self.snor_timing1 = we_width(timing.we_width)
            | oe_width(timing.oe_width)
            | wait_width(timing.wait_width);
    }

    pub fn apply_config(&self) {
        if !self.regs.is_valid() { return; }
        self.regs.write32(TEGRA_GMI_TIMING0, self.snor_timing0);
        self.regs.write32(TEGRA_GMI_TIMING1, self.snor_timing1);
        self.regs.write32(TEGRA_GMI_CONFIG, self.snor_config | CONFIG_GO);
    }
}

impl BusDriver for TegraGmi {
    fn name(&self) -> &str { "tegra-gmi" }

    fn compatible(&self) -> &[&str] { COMPATIBLE }

    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x20);
        self.apply_config();
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
        self.apply_config();
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
}
