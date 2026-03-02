use alloc::{string::String, vec::Vec};
use crate::{BusChild, BusDriver, BusError, PowerState};
use crate::mmio::MmioRegion;

const IXP4XX_EXP_CS_EN: u32 = 1 << 31;
const IXP456_EXP_PAR_EN: u32 = 1 << 30;
const IXP4XX_EXP_T1_MASK: u32 = 0x3 << 28;
const IXP4XX_EXP_T1_SHIFT: u32 = 28;
const IXP4XX_EXP_T2_MASK: u32 = 0x3 << 26;
const IXP4XX_EXP_T2_SHIFT: u32 = 26;
const IXP4XX_EXP_T3_MASK: u32 = 0xF << 22;
const IXP4XX_EXP_T3_SHIFT: u32 = 22;
const IXP4XX_EXP_T4_MASK: u32 = 0x3 << 20;
const IXP4XX_EXP_T4_SHIFT: u32 = 20;
const IXP4XX_EXP_T5_MASK: u32 = 0xF << 16;
const IXP4XX_EXP_T5_SHIFT: u32 = 16;
const IXP4XX_EXP_CYC_TYPE_MASK: u32 = 0x3 << 14;
const IXP4XX_EXP_CYC_TYPE_SHIFT: u32 = 14;
const IXP4XX_EXP_SIZE_MASK: u32 = 0xF << 10;
const IXP4XX_EXP_SIZE_SHIFT: u32 = 10;
const IXP4XX_EXP_BYTE_RD16: u32 = 1 << 6;
const IXP4XX_EXP_HRDY_POL: u32 = 1 << 5;
const IXP4XX_EXP_MUX_EN: u32 = 1 << 4;
const IXP4XX_EXP_SPLT_EN: u32 = 1 << 3;
const IXP4XX_EXP_WR_EN: u32 = 1 << 1;
const IXP4XX_EXP_BYTE_EN: u32 = 1 << 0;

const IXP4XX_EXP_CNFG0: usize = 0x20;
const IXP4XX_EXP_CNFG0_MEM_MAP: u32 = 1 << 31;

const BOOT_BASE: u64 = 0x0000_0000;
const NORMAL_BASE: u64 = 0x5000_0000;
const CS_STRIDE: u64 = 0x0100_0000;
const MAX_CS: usize = 8;

const COMPATIBLE: &[&str] = &[
    "intel,ixp42x-expansion-bus-controller",
    "intel,ixp43x-expansion-bus-controller",
    "intel,ixp45x-expansion-bus-controller",
    "intel,ixp46x-expansion-bus-controller",
];

pub struct CsTimingConfig {
    pub t1: u32,
    pub t2: u32,
    pub t3: u32,
    pub t4: u32,
    pub t5: u32,
    pub cycle_type: u32,
    pub byte_rd16: bool,
    pub mux_en: bool,
    pub splt_en: bool,
    pub wr_en: bool,
    pub byte_en: bool,
    pub hrdy_pol: bool,
}

pub struct IntelIxp4xxEb {
    regs: MmioRegion,
    bus_base: u64,
    num_cs: usize,
    is_42x: bool,
    is_43x: bool,
    power_state: PowerState,
    children: Vec<BusChild>,
}

impl IntelIxp4xxEb {
    pub fn new() -> Self {
        Self {
            regs: MmioRegion::new(),
            bus_base: NORMAL_BASE,
            num_cs: MAX_CS,
            is_42x: false,
            is_43x: false,
            power_state: PowerState::Off,
            children: Vec::new(),
        }
    }

    pub fn set_variant(&mut self, is_42x: bool, is_43x: bool) {
        self.is_42x = is_42x;
        self.is_43x = is_43x;
        if is_43x { self.num_cs = 4; }
    }

    fn detect_bus_base(&mut self) {
        let cnfg0 = self.regs.read32(IXP4XX_EXP_CNFG0);
        self.bus_base = if cnfg0 & IXP4XX_EXP_CNFG0_MEM_MAP != 0 {
            NORMAL_BASE
        } else {
            BOOT_BASE
        };
    }

    pub fn configure_cs(&self, cs: usize, config: &CsTimingConfig) -> Result<(), BusError> {
        if cs >= self.num_cs {
            return Err(BusError::InvalidArgument);
        }

        let offset = cs * 4;
        let mut val = IXP4XX_EXP_CS_EN;

        val |= (config.t1 << IXP4XX_EXP_T1_SHIFT) & IXP4XX_EXP_T1_MASK;
        val |= (config.t2 << IXP4XX_EXP_T2_SHIFT) & IXP4XX_EXP_T2_MASK;
        val |= (config.t3 << IXP4XX_EXP_T3_SHIFT) & IXP4XX_EXP_T3_MASK;
        val |= (config.t4 << IXP4XX_EXP_T4_SHIFT) & IXP4XX_EXP_T4_MASK;
        val |= (config.t5 << IXP4XX_EXP_T5_SHIFT) & IXP4XX_EXP_T5_MASK;
        val |= (config.cycle_type << IXP4XX_EXP_CYC_TYPE_SHIFT) & IXP4XX_EXP_CYC_TYPE_MASK;

        if config.byte_rd16 { val |= IXP4XX_EXP_BYTE_RD16; }
        if config.mux_en { val |= IXP4XX_EXP_MUX_EN; }
        if config.splt_en { val |= IXP4XX_EXP_SPLT_EN; }
        if config.wr_en { val |= IXP4XX_EXP_WR_EN; }
        if config.byte_en { val |= IXP4XX_EXP_BYTE_EN; }
        if config.hrdy_pol && self.is_42x { val |= IXP4XX_EXP_HRDY_POL; }

        self.regs.write32(offset, val);
        Ok(())
    }

    pub fn cs_base_addr(&self, cs: usize) -> u64 {
        self.bus_base + (cs as u64) * CS_STRIDE
    }

    pub fn add_child(&mut self, child: BusChild) {
        self.children.push(child);
    }
}

impl BusDriver for IntelIxp4xxEb {
    fn name(&self) -> &str { "intel-ixp4xx-eb" }

    fn compatible(&self) -> &[&str] { COMPATIBLE }

    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x30);
        self.detect_bus_base();
        self.power_state = PowerState::On;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), BusError> {
        self.power_state = PowerState::Off;
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
