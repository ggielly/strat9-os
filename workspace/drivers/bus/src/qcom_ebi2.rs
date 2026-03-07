use crate::{BusChild, BusDriver, BusError, PowerState, mmio::MmioRegion};
use alloc::{string::String, vec::Vec};

const EBI2_XMEM_CFG: usize = 0x0000;
const EBI2_XMEM_CS0_SLOW_CFG: usize = 0x0008;
const EBI2_XMEM_CS1_SLOW_CFG: usize = 0x000C;
const EBI2_XMEM_CS2_SLOW_CFG: usize = 0x0010;
const EBI2_XMEM_CS3_SLOW_CFG: usize = 0x0014;
const EBI2_XMEM_CS4_SLOW_CFG: usize = 0x0018;
const EBI2_XMEM_CS5_SLOW_CFG: usize = 0x001C;
const EBI2_XMEM_CS0_FAST_CFG: usize = 0x0028;
const EBI2_XMEM_CS1_FAST_CFG: usize = 0x002C;
const EBI2_XMEM_CS2_FAST_CFG: usize = 0x0030;
const EBI2_XMEM_CS3_FAST_CFG: usize = 0x0034;
const EBI2_XMEM_CS4_FAST_CFG: usize = 0x0038;
const EBI2_XMEM_CS5_FAST_CFG: usize = 0x003C;

const CS0_ENABLE: u32 = 0x03;
const CS1_ENABLE: u32 = 0x0C;
const CS2_ENABLE: u32 = 0x10;
const CS3_ENABLE: u32 = 0x20;
const CS4_ENABLE: u32 = 0x180;
const CS5_ENABLE: u32 = 0x600;

const SLOW_RECOVERY_SHIFT: u32 = 28;
const SLOW_WR_HOLD_SHIFT: u32 = 24;
const SLOW_WR_DELTA_SHIFT: u32 = 16;
const SLOW_RD_DELTA_SHIFT: u32 = 8;
const SLOW_WR_WAIT_SHIFT: u32 = 4;
const SLOW_RD_WAIT_SHIFT: u32 = 0;

const FAST_RD_HOLD_SHIFT: u32 = 24;
const FAST_ADV_OE_RECOVERY_SHIFT: u32 = 16;
const FAST_ADDR_HOLD_ENA: u32 = 1 << 5;

const NUM_CS: usize = 6;

const CS_ENABLE_MASKS: [u32; NUM_CS] = [
    CS0_ENABLE, CS1_ENABLE, CS2_ENABLE, CS3_ENABLE, CS4_ENABLE, CS5_ENABLE,
];
const CS_SLOW_OFFSETS: [usize; NUM_CS] = [
    EBI2_XMEM_CS0_SLOW_CFG,
    EBI2_XMEM_CS1_SLOW_CFG,
    EBI2_XMEM_CS2_SLOW_CFG,
    EBI2_XMEM_CS3_SLOW_CFG,
    EBI2_XMEM_CS4_SLOW_CFG,
    EBI2_XMEM_CS5_SLOW_CFG,
];
const CS_FAST_OFFSETS: [usize; NUM_CS] = [
    EBI2_XMEM_CS0_FAST_CFG,
    EBI2_XMEM_CS1_FAST_CFG,
    EBI2_XMEM_CS2_FAST_CFG,
    EBI2_XMEM_CS3_FAST_CFG,
    EBI2_XMEM_CS4_FAST_CFG,
    EBI2_XMEM_CS5_FAST_CFG,
];

const COMPATIBLE: &[&str] = &["qcom,msm8660-ebi2", "qcom,apq8060-ebi2"];

pub struct Ebi2CsConfig {
    pub recovery_cycles: u32,
    pub wr_hold_cycles: u32,
    pub wr_delta_cycles: u32,
    pub rd_delta_cycles: u32,
    pub wr_wait_cycles: u32,
    pub rd_wait_cycles: u32,
    pub rd_hold_cycles: u32,
    pub adv_oe_recovery: u32,
    pub addr_hold_ena: bool,
}

impl Ebi2CsConfig {
    /// Converts this to slow reg.
    pub fn to_slow_reg(&self) -> u32 {
        (self.recovery_cycles << SLOW_RECOVERY_SHIFT)
            | (self.wr_hold_cycles << SLOW_WR_HOLD_SHIFT)
            | (self.wr_delta_cycles << SLOW_WR_DELTA_SHIFT)
            | (self.rd_delta_cycles << SLOW_RD_DELTA_SHIFT)
            | (self.wr_wait_cycles << SLOW_WR_WAIT_SHIFT)
            | (self.rd_wait_cycles << SLOW_RD_WAIT_SHIFT)
    }

    /// Converts this to fast reg.
    pub fn to_fast_reg(&self) -> u32 {
        let mut val = (self.rd_hold_cycles << FAST_RD_HOLD_SHIFT)
            | (self.adv_oe_recovery << FAST_ADV_OE_RECOVERY_SHIFT);
        if self.addr_hold_ena {
            val |= FAST_ADDR_HOLD_ENA;
        }
        val
    }
}

pub struct QcomEbi2 {
    regs: MmioRegion,
    cs_configs: [Option<Ebi2CsConfig>; NUM_CS],
    power_state: PowerState,
    children: Vec<BusChild>,
}

impl QcomEbi2 {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            regs: MmioRegion::new(),
            cs_configs: [const { None }; NUM_CS],
            power_state: PowerState::Off,
            children: Vec::new(),
        }
    }

    /// Performs the configure cs operation.
    pub fn configure_cs(&mut self, cs: usize, config: Ebi2CsConfig) {
        if cs < NUM_CS {
            self.cs_configs[cs] = Some(config);
        }
    }

    /// Performs the apply config operation.
    fn apply_config(&self) {
        self.regs.write32(EBI2_XMEM_CFG, 0);

        for cs in 0..NUM_CS {
            if let Some(ref cfg) = self.cs_configs[cs] {
                let mut xmem = self.regs.read32(EBI2_XMEM_CFG);
                xmem |= CS_ENABLE_MASKS[cs];
                self.regs.write32(EBI2_XMEM_CFG, xmem);

                self.regs.write32(CS_SLOW_OFFSETS[cs], cfg.to_slow_reg());
                self.regs.write32(CS_FAST_OFFSETS[cs], cfg.to_fast_reg());
            }
        }
    }

    /// Performs the add child operation.
    pub fn add_child(&mut self, child: BusChild) {
        self.children.push(child);
    }
}

impl BusDriver for QcomEbi2 {
    /// Performs the name operation.
    fn name(&self) -> &str {
        "qcom-ebi2"
    }

    /// Performs the compatible operation.
    fn compatible(&self) -> &[&str] {
        COMPATIBLE
    }

    /// Performs the init operation.
    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x100);
        self.apply_config();
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
