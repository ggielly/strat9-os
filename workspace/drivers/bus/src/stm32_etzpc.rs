use alloc::{string::String, vec::Vec};
use crate::{BusChild, BusDriver, BusError, PowerState};
use crate::mmio::MmioRegion;
use crate::stm32_firewall::{FirewallController, FirewallType};

const ETZPC_DECPROT: usize = 0x10;
const ETZPC_HWCFGR: usize = 0x3F0;

const ETZPC_PROT_A7NS: u32 = 0x3;

const HWCFGR_NUM_TZMA_MASK: u32 = 0xFF;
const HWCFGR_NUM_PER_SEC_MASK: u32 = 0xFF00;
const HWCFGR_NUM_PER_SEC_SHIFT: u32 = 8;
const HWCFGR_NUM_AHB_SEC_MASK: u32 = 0xFF0000;
const HWCFGR_NUM_AHB_SEC_SHIFT: u32 = 16;

const COMPATIBLE: &[&str] = &["st,stm32-etzpc"];

pub struct Stm32Etzpc {
    regs: MmioRegion,
    num_per: u32,
    num_master: u32,
    power_state: PowerState,
    children: Vec<BusChild>,
}

impl Stm32Etzpc {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            regs: MmioRegion::new(),
            num_per: 0,
            num_master: 0,
            power_state: PowerState::Off,
            children: Vec::new(),
        }
    }

    /// Reads hwcfg.
    fn read_hwcfg(&mut self) {
        let hwcfg = self.regs.read32(ETZPC_HWCFGR);
        self.num_per = (hwcfg & HWCFGR_NUM_PER_SEC_MASK) >> HWCFGR_NUM_PER_SEC_SHIFT;
        self.num_master = (hwcfg & HWCFGR_NUM_AHB_SEC_MASK) >> HWCFGR_NUM_AHB_SEC_SHIFT;
    }

    /// Reads decprot.
    fn read_decprot(&self, id: u32) -> u32 {
        let reg_idx = id / 16;
        let bit_offset = (id % 16) * 2;
        let val = self.regs.read32(ETZPC_DECPROT + (reg_idx as usize) * 4);
        (val >> bit_offset) & 0x3
    }

    /// Performs the add child operation.
    pub fn add_child(&mut self, child: BusChild) {
        self.children.push(child);
    }
}

impl FirewallController for Stm32Etzpc {
    /// Performs the name operation.
    fn name(&self) -> &str { "stm32-etzpc" }

    /// Performs the firewall type operation.
    fn firewall_type(&self) -> FirewallType { FirewallType::Peripheral }

    /// Performs the max entries operation.
    fn max_entries(&self) -> u32 { self.num_per + self.num_master }

    /// Performs the grant access operation.
    fn grant_access(&self, firewall_id: u32) -> Result<(), BusError> {
        if firewall_id >= self.num_per + self.num_master {
            return Err(BusError::InvalidArgument);
        }

        let decprot = self.read_decprot(firewall_id);
        if decprot != ETZPC_PROT_A7NS {
            return Err(BusError::PermissionDenied);
        }

        Ok(())
    }

    /// Performs the release access operation.
    fn release_access(&self, _firewall_id: u32) -> Result<(), BusError> {
        Ok(())
    }
}

impl BusDriver for Stm32Etzpc {
    /// Performs the name operation.
    fn name(&self) -> &str { "stm32-etzpc" }

    /// Performs the compatible operation.
    fn compatible(&self) -> &[&str] { COMPATIBLE }

    /// Performs the init operation.
    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x400);
        self.read_hwcfg();
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
