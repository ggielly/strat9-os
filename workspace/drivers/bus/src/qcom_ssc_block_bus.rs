use crate::{BusChild, BusDriver, BusError, PowerState, mmio::MmioRegion};
use alloc::{string::String, vec::Vec};

const AXI_HALTREQ_REG: usize = 0x0;
const AXI_HALTACK_REG: usize = 0x4;
const AXI_IDLE_REG: usize = 0x8;

const SSCAON_CONFIG0_CLAMP_EN_OVRD: u32 = 1 << 4;
const SSCAON_CONFIG0_CLAMP_EN_OVRD_VAL: u32 = 1 << 5;
const SSCAON_CONFIG1_CFG: u32 = 1 << 31;

const MAX_HALT_WAIT: u32 = 10000;

const COMPATIBLE: &[&str] = &["qcom,ssc-block-bus"];

pub struct QcomSscBlockBus {
    halt_regs: MmioRegion,
    config0_regs: MmioRegion,
    config1_regs: MmioRegion,
    power_state: PowerState,
    children: Vec<BusChild>,
}

impl QcomSscBlockBus {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            halt_regs: MmioRegion::new(),
            config0_regs: MmioRegion::new(),
            config1_regs: MmioRegion::new(),
            power_state: PowerState::Off,
            children: Vec::new(),
        }
    }

    /// Initializes halt regs.
    pub fn init_halt_regs(&mut self, base: usize) {
        self.halt_regs.init(base, 0x10);
    }

    /// Initializes config regs.
    pub fn init_config_regs(&mut self, config0_base: usize, config1_base: usize) {
        self.config0_regs.init(config0_base, 0x10);
        self.config1_regs.init(config1_base, 0x10);
    }

    /// Ensures every MMIO region (halt, config0, config1) has been mapped
    /// by platform code before any register access.
    ///
    /// Accessing an unmapped [`MmioRegion`] would trip its internal
    /// assertions (kernel panic); failing early with
    /// [`BusError::InitFailed`] turns a hard crash into a clean
    /// driver-registration failure instead.
    fn ensure_mapped(&self) -> Result<(), BusError> {
        if self.halt_regs.is_valid() && self.config0_regs.is_valid() && self.config1_regs.is_valid()
        {
            Ok(())
        } else {
            Err(BusError::InitFailed)
        }
    }

    /// Performs the bus init operation.
    fn bus_init(&self) -> Result<(), BusError> {
        self.ensure_mapped()?;

        self.config0_regs
            .clear_bits32(0, SSCAON_CONFIG0_CLAMP_EN_OVRD_VAL);
        self.config0_regs
            .set_bits32(0, SSCAON_CONFIG0_CLAMP_EN_OVRD);
        self.config1_regs.clear_bits32(0, SSCAON_CONFIG1_CFG);

        self.halt_regs.write32(AXI_HALTREQ_REG, 0);

        for _ in 0..MAX_HALT_WAIT {
            let idle = self.halt_regs.read32(AXI_IDLE_REG);
            if idle != 0 {
                return Ok(());
            }
        }

        // The AXI bus never reached idle: report it instead of silently
        // claiming success.
        Err(BusError::Timeout)
    }

    /// Performs the bus deinit operation.
    ///
    /// The safety clamps are always applied, even when the halt handshake
    /// times out; the timeout is reported through the returned error.
    fn bus_deinit(&self) -> Result<(), BusError> {
        self.ensure_mapped()?;

        self.halt_regs.write32(AXI_HALTREQ_REG, 1);

        let mut halted = false;
        for _ in 0..MAX_HALT_WAIT {
            let ack = self.halt_regs.read32(AXI_HALTACK_REG);
            if ack != 0 {
                halted = true;
                break;
            }
        }

        self.config0_regs
            .set_bits32(0, SSCAON_CONFIG0_CLAMP_EN_OVRD_VAL);
        self.config1_regs.set_bits32(0, SSCAON_CONFIG1_CFG);

        if halted {
            Ok(())
        } else {
            Err(BusError::Timeout)
        }
    }

    /// Performs the add child operation.
    pub fn add_child(&mut self, child: BusChild) {
        self.children.push(child);
    }
}

impl BusDriver for QcomSscBlockBus {
    /// Performs the name operation.
    fn name(&self) -> &str {
        "qcom-ssc-block-bus"
    }

    /// Performs the compatible operation.
    fn compatible(&self) -> &[&str] {
        COMPATIBLE
    }

    /// Performs the init operation.
    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.halt_regs.init(base, 0x10);
        self.bus_init()?;
        self.power_state = PowerState::On;
        Ok(())
    }

    /// Performs the shutdown operation.
    fn shutdown(&mut self) -> Result<(), BusError> {
        let res = self.bus_deinit();
        self.power_state = PowerState::Off;
        res
    }

    /// Reads reg.
    fn read_reg(&self, offset: usize) -> Result<u32, BusError> {
        if !self.halt_regs.is_valid() {
            return Err(BusError::InitFailed);
        }
        Ok(self.halt_regs.read32(offset))
    }

    /// Writes reg.
    fn write_reg(&mut self, offset: usize, value: u32) -> Result<(), BusError> {
        if !self.halt_regs.is_valid() {
            return Err(BusError::InitFailed);
        }
        self.halt_regs.write32(offset, value);
        Ok(())
    }

    /// Performs the children operation.
    fn children(&self) -> Vec<BusChild> {
        self.children.clone()
    }
}
