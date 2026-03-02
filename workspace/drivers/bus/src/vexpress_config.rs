use alloc::{string::String, vec::Vec};
use crate::{BusChild, BusDriver, BusError, PowerState};
use crate::mmio::MmioRegion;

const SYS_MISC: usize = 0x00;
const SYS_MISC_MASTERSITE: u32 = 1 << 14;

const SYS_PROCID0: usize = 0x24;
const SYS_PROCID1: usize = 0x28;
const SYS_HBI_MASK: u32 = 0xFFF;

const SYS_CFGDATA: usize = 0x40;
const SYS_CFGCTRL: usize = 0x44;
const SYS_CFGCTRL_START: u32 = 1 << 31;
const SYS_CFGCTRL_WRITE: u32 = 1 << 30;
const SYS_CFGSTAT: usize = 0x48;
const SYS_CFGSTAT_ERR: u32 = 1 << 1;
const SYS_CFGSTAT_COMPLETE: u32 = 1 << 0;

const SITE_MB: u32 = 0;
const SITE_DB1: u32 = 1;
const SITE_DB2: u32 = 2;
const SITE_MASTER: u32 = 0xF;

const MAX_POLL_TRIES: u32 = 100;

const COMPATIBLE: &[&str] = &["vexpress-syscfg"];

fn cfg_ctrl_dcc(n: u32) -> u32 { (n & 0xF) << 26 }
fn cfg_ctrl_func(n: u32) -> u32 { (n & 0x3F) << 20 }
fn cfg_ctrl_site(n: u32) -> u32 { (n & 0x3) << 16 }
fn cfg_ctrl_position(n: u32) -> u32 { (n & 0xF) << 12 }
fn cfg_ctrl_device(n: u32) -> u32 { n & 0xFFF }

pub struct VexpressConfig {
    regs: MmioRegion,
    master_site: u32,
    power_state: PowerState,
}

impl VexpressConfig {
    pub fn new() -> Self {
        Self {
            regs: MmioRegion::new(),
            master_site: SITE_MASTER,
            power_state: PowerState::Off,
        }
    }

    fn detect_master_site(&mut self) {
        let misc = self.regs.read32(SYS_MISC);
        self.master_site = if misc & SYS_MISC_MASTERSITE != 0 {
            SITE_DB2
        } else {
            SITE_DB1
        };
    }

    pub fn read_procid(&self, site: u32) -> u32 {
        let offset = if site == SITE_DB1 { SYS_PROCID0 } else { SYS_PROCID1 };
        self.regs.read32(offset)
    }

    pub fn hbi(&self) -> u32 {
        let id = self.read_procid(self.master_site);
        id & SYS_HBI_MASK
    }

    pub fn config_read(&self, site: u32, position: u32, dcc: u32,
                       function: u32, device: u32) -> Result<u32, BusError> {
        let command = self.regs.read32(SYS_CFGCTRL);
        if command & SYS_CFGCTRL_START != 0 {
            return Err(BusError::Timeout);
        }

        let real_site = if site == SITE_MASTER { self.master_site } else { site };

        let cmd = SYS_CFGCTRL_START
            | cfg_ctrl_dcc(dcc)
            | cfg_ctrl_site(real_site)
            | cfg_ctrl_position(position)
            | cfg_ctrl_func(function)
            | cfg_ctrl_device(device);

        self.regs.write32(SYS_CFGDATA, 0xDEAD_BEEF);
        self.regs.write32(SYS_CFGSTAT, 0);
        self.regs.write32(SYS_CFGCTRL, cmd);
        crate::mmio::memory_barrier();

        for _ in 0..MAX_POLL_TRIES {
            let status = self.regs.read32(SYS_CFGSTAT);
            if status & SYS_CFGSTAT_ERR != 0 {
                return Err(BusError::IoError);
            }
            if status & SYS_CFGSTAT_COMPLETE != 0 {
                return Ok(self.regs.read32(SYS_CFGDATA));
            }
        }

        Err(BusError::Timeout)
    }

    pub fn config_write(&self, site: u32, position: u32, dcc: u32,
                        function: u32, device: u32, data: u32) -> Result<(), BusError> {
        let command = self.regs.read32(SYS_CFGCTRL);
        if command & SYS_CFGCTRL_START != 0 {
            return Err(BusError::Timeout);
        }

        let real_site = if site == SITE_MASTER { self.master_site } else { site };

        let cmd = SYS_CFGCTRL_START
            | SYS_CFGCTRL_WRITE
            | cfg_ctrl_dcc(dcc)
            | cfg_ctrl_site(real_site)
            | cfg_ctrl_position(position)
            | cfg_ctrl_func(function)
            | cfg_ctrl_device(device);

        self.regs.write32(SYS_CFGDATA, data);
        self.regs.write32(SYS_CFGSTAT, 0);
        self.regs.write32(SYS_CFGCTRL, cmd);
        crate::mmio::memory_barrier();

        for _ in 0..MAX_POLL_TRIES {
            let status = self.regs.read32(SYS_CFGSTAT);
            if status & SYS_CFGSTAT_ERR != 0 {
                return Err(BusError::IoError);
            }
            if status & SYS_CFGSTAT_COMPLETE != 0 {
                return Ok(());
            }
        }

        Err(BusError::Timeout)
    }
}

impl BusDriver for VexpressConfig {
    fn name(&self) -> &str { "vexpress-config" }

    fn compatible(&self) -> &[&str] { COMPATIBLE }

    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x100);
        self.detect_master_site();
        self.power_state = PowerState::On;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), BusError> {
        self.power_state = PowerState::Off;
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
