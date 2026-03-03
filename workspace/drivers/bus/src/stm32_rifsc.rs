use alloc::{string::String, vec::Vec};
use crate::{BusChild, BusDriver, BusError, PowerState};
use crate::mmio::MmioRegion;
use crate::stm32_firewall::{FirewallController, FirewallType};

const RIFSC_RISC_SECCFGR0: usize = 0x10;
const RIFSC_RISC_PRIVCFGR0: usize = 0x30;
const RIFSC_RISC_PER0_CIDCFGR: usize = 0x100;
const RIFSC_RISC_PER0_SEMCR: usize = 0x104;
const RIFSC_RISC_HWCFGR2: usize = 0xFEC;

const CIDCFGR_STRIDE: usize = 0x08;
const CIDCFGR_CFEN: u32 = 1 << 0;
const CIDCFGR_SEMEN: u32 = 1 << 1;
const CIDCFGR_SEMWL_MASK: u32 = 0xFF << 16;
const CIDCFGR_SCID_MASK: u32 = 0x7 << 4;
const CIDCFGR_SCID_SHIFT: u32 = 4;

const SEMCR_MUTEX: u32 = 1 << 0;

const HWCFGR2_CONF1_MASK: u32 = 0xFFFF;
const HWCFGR2_CONF2_MASK: u32 = 0xFF << 16;
const HWCFGR2_CONF2_SHIFT: u32 = 16;
const HWCFGR2_CONF3_MASK: u32 = 0xFF << 24;
const HWCFGR2_CONF3_SHIFT: u32 = 24;

const EXPECTED_CID: u32 = 1;

const COMPATIBLE: &[&str] = &[
    "st,stm32mp25-rifsc",
    "st,stm32mp21-rifsc",
];

pub struct Stm32Rifsc {
    regs: MmioRegion,
    nb_risup: u32,
    nb_rimu: u32,
    nb_risal: u32,
    power_state: PowerState,
    children: Vec<BusChild>,
}

impl Stm32Rifsc {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            regs: MmioRegion::new(),
            nb_risup: 0,
            nb_rimu: 0,
            nb_risal: 0,
            power_state: PowerState::Off,
            children: Vec::new(),
        }
    }

    /// Reads hwcfg.
    fn read_hwcfg(&mut self) {
        let hwcfg = self.regs.read32(RIFSC_RISC_HWCFGR2);
        self.nb_risup = hwcfg & HWCFGR2_CONF1_MASK;
        self.nb_rimu = (hwcfg & HWCFGR2_CONF2_MASK) >> HWCFGR2_CONF2_SHIFT;
        self.nb_risal = (hwcfg & HWCFGR2_CONF3_MASK) >> HWCFGR2_CONF3_SHIFT;
    }

    /// Returns whether secure.
    fn is_secure(&self, id: u32) -> bool {
        let reg_idx = id / 32;
        let bit = id % 32;
        let val = self.regs.read32(RIFSC_RISC_SECCFGR0 + (reg_idx as usize) * 4);
        (val & (1 << bit)) != 0
    }

    /// Returns whether privileged.
    fn is_privileged(&self, id: u32) -> bool {
        let reg_idx = id / 32;
        let bit = id % 32;
        let val = self.regs.read32(RIFSC_RISC_PRIVCFGR0 + (reg_idx as usize) * 4);
        (val & (1 << bit)) != 0
    }

    /// Performs the cidcfgr offset operation.
    fn cidcfgr_offset(id: u32) -> usize {
        RIFSC_RISC_PER0_CIDCFGR + (id as usize) * CIDCFGR_STRIDE
    }

    /// Performs the semcr offset operation.
    fn semcr_offset(id: u32) -> usize {
        RIFSC_RISC_PER0_SEMCR + (id as usize) * CIDCFGR_STRIDE
    }

    /// Performs the acquire semaphore operation.
    fn acquire_semaphore(&self, id: u32) -> Result<(), BusError> {
        let offset = Self::semcr_offset(id);
        self.regs.write32(offset, SEMCR_MUTEX);
        let val = self.regs.read32(offset);
        if val & SEMCR_MUTEX != 0 {
            Ok(())
        } else {
            Err(BusError::PermissionDenied)
        }
    }

    /// Performs the release semaphore operation.
    fn release_semaphore(&self, id: u32) {
        let offset = Self::semcr_offset(id);
        self.regs.write32(offset, 0);
    }

    /// Performs the add child operation.
    pub fn add_child(&mut self, child: BusChild) {
        self.children.push(child);
    }
}

impl FirewallController for Stm32Rifsc {
    /// Performs the name operation.
    fn name(&self) -> &str { "stm32-rifsc" }

    /// Performs the firewall type operation.
    fn firewall_type(&self) -> FirewallType { FirewallType::Peripheral }

    /// Performs the max entries operation.
    fn max_entries(&self) -> u32 { self.nb_risup }

    /// Performs the grant access operation.
    fn grant_access(&self, firewall_id: u32) -> Result<(), BusError> {
        if firewall_id >= self.nb_risup {
            return Err(BusError::InvalidArgument);
        }

        if self.is_secure(firewall_id) {
            return Err(BusError::PermissionDenied);
        }

        let cidcfgr = self.regs.read32(Self::cidcfgr_offset(firewall_id));

        if cidcfgr & CIDCFGR_CFEN != 0 {
            let scid = (cidcfgr & CIDCFGR_SCID_MASK) >> CIDCFGR_SCID_SHIFT;

            if cidcfgr & CIDCFGR_SEMEN != 0 {
                let semwl = (cidcfgr & CIDCFGR_SEMWL_MASK) >> 16;
                if semwl & (1 << EXPECTED_CID) == 0 {
                    return Err(BusError::PermissionDenied);
                }
                return self.acquire_semaphore(firewall_id);
            }

            if scid != EXPECTED_CID {
                return Err(BusError::PermissionDenied);
            }
        }

        Ok(())
    }

    /// Performs the release access operation.
    fn release_access(&self, firewall_id: u32) -> Result<(), BusError> {
        if firewall_id >= self.nb_risup {
            return Err(BusError::InvalidArgument);
        }

        let cidcfgr = self.regs.read32(Self::cidcfgr_offset(firewall_id));
        if cidcfgr & CIDCFGR_CFEN != 0 && cidcfgr & CIDCFGR_SEMEN != 0 {
            self.release_semaphore(firewall_id);
        }

        Ok(())
    }
}

impl BusDriver for Stm32Rifsc {
    /// Performs the name operation.
    fn name(&self) -> &str { "stm32-rifsc" }

    /// Performs the compatible operation.
    fn compatible(&self) -> &[&str] { COMPATIBLE }

    /// Performs the init operation.
    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x1000);
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
