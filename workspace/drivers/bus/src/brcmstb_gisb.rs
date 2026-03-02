use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use crate::{BusChild, BusDriver, BusError, PowerState};
use crate::mmio::MmioRegion;

const ARB_ERR_CAP_CLEAR: u32 = 0x0001;
const ARB_ERR_CAP_STATUS_TIMEOUT: u32 = 1 << 12;
const ARB_ERR_CAP_STATUS_TEA: u32 = 1 << 11;
const ARB_ERR_CAP_STATUS_WRITE: u32 = 1 << 1;
const ARB_ERR_CAP_STATUS_VALID: u32 = 1 << 0;

const ARB_BP_CAP_CLEAR: u32 = 1 << 0;
const ARB_BP_CAP_STATUS_WRITE: u32 = 1 << 1;
const ARB_BP_CAP_STATUS_VALID: u32 = 1 << 0;

const COMPATIBLE: &[&str] = &[
    "brcm,bcm7038-gisb-arb",
    "brcm,bcm7278-gisb-arb",
    "brcm,bcm7400-gisb-arb",
    "brcm,bcm74165-gisb-arb",
    "brcm,bcm7435-gisb-arb",
    "brcm,bcm7445-gisb-arb",
];

#[derive(Clone, Copy)]
pub struct GisbOffsets {
    pub arb_timer: usize,
    pub arb_bp_cap_clr: usize,
    pub arb_bp_cap_addr: usize,
    pub arb_bp_cap_status: usize,
    pub arb_bp_cap_master: Option<usize>,
    pub arb_err_cap_clr: usize,
    pub arb_err_cap_addr: usize,
    pub arb_err_cap_status: usize,
    pub arb_err_cap_master: Option<usize>,
    pub arb_err_cap_hi_addr: Option<usize>,
}

pub const BCM7038_OFFSETS: GisbOffsets = GisbOffsets {
    arb_timer: 0x00C, arb_bp_cap_clr: 0x014, arb_bp_cap_addr: 0x0B8,
    arb_bp_cap_status: 0x0C0, arb_bp_cap_master: None,
    arb_err_cap_clr: 0x0C4, arb_err_cap_addr: 0x0C8,
    arb_err_cap_status: 0x0D0, arb_err_cap_master: None, arb_err_cap_hi_addr: None,
};

pub const BCM7445_OFFSETS: GisbOffsets = GisbOffsets {
    arb_timer: 0x008, arb_bp_cap_clr: 0x010, arb_bp_cap_addr: 0x1D8,
    arb_bp_cap_status: 0x1E0, arb_bp_cap_master: Some(0x1E4),
    arb_err_cap_clr: 0x7E4, arb_err_cap_addr: 0x7EC,
    arb_err_cap_status: 0x7F4, arb_err_cap_master: Some(0x7F8), arb_err_cap_hi_addr: Some(0x7E8),
};

pub const BCM7278_OFFSETS: GisbOffsets = GisbOffsets {
    arb_timer: 0x008, arb_bp_cap_clr: 0x01C, arb_bp_cap_addr: 0x220,
    arb_bp_cap_status: 0x230, arb_bp_cap_master: Some(0x234),
    arb_err_cap_clr: 0x7F8, arb_err_cap_addr: 0x7E0,
    arb_err_cap_status: 0x7F0, arb_err_cap_master: Some(0x7F4), arb_err_cap_hi_addr: None,
};

pub struct GisbErrorInfo {
    pub address: u64,
    pub master: Option<u32>,
    pub is_write: bool,
    pub is_timeout: bool,
    pub is_tea: bool,
}

pub struct BrcmstbGisb {
    regs: MmioRegion,
    offsets: GisbOffsets,
    error_count: AtomicU64,
    big_endian: bool,
    saved_timeout: u32,
    master_names: Vec<String>,
    power_state: PowerState,
}

impl BrcmstbGisb {
    pub fn new(offsets: GisbOffsets) -> Self {
        Self {
            regs: MmioRegion::new(),
            offsets,
            error_count: AtomicU64::new(0),
            big_endian: false,
            saved_timeout: 0,
            master_names: Vec::new(),
            power_state: PowerState::Off,
        }
    }

    pub fn set_big_endian(&mut self, big_endian: bool) {
        self.big_endian = big_endian;
    }

    pub fn add_master_name(&mut self, name: String) {
        self.master_names.push(name);
    }

    fn read_gisb(&self, offset: usize) -> u32 {
        let val = self.regs.read32(offset);
        if self.big_endian { val.swap_bytes() } else { val }
    }

    fn write_gisb(&self, offset: usize, val: u32) {
        let val = if self.big_endian { val.swap_bytes() } else { val };
        self.regs.write32(offset, val);
    }

    pub fn get_timeout(&self) -> u32 {
        self.read_gisb(self.offsets.arb_timer)
    }

    pub fn set_timeout(&self, val: u32) {
        self.write_gisb(self.offsets.arb_timer, val);
    }

    pub fn handle_timeout_irq(&self) -> Option<GisbErrorInfo> {
        let status = self.read_gisb(self.offsets.arb_err_cap_status);
        if status & ARB_ERR_CAP_STATUS_VALID == 0 {
            return None;
        }

        let addr_lo = self.read_gisb(self.offsets.arb_err_cap_addr);
        let addr_hi = self.offsets.arb_err_cap_hi_addr
            .map(|off| self.read_gisb(off))
            .unwrap_or(0);
        let master = self.offsets.arb_err_cap_master
            .map(|off| self.read_gisb(off));

        let info = GisbErrorInfo {
            address: ((addr_hi as u64) << 32) | (addr_lo as u64),
            master,
            is_write: (status & ARB_ERR_CAP_STATUS_WRITE) != 0,
            is_timeout: (status & ARB_ERR_CAP_STATUS_TIMEOUT) != 0,
            is_tea: (status & ARB_ERR_CAP_STATUS_TEA) != 0,
        };

        self.write_gisb(self.offsets.arb_err_cap_clr, ARB_ERR_CAP_CLEAR);

        Some(info)
    }

    pub fn handle_bp_irq(&self) -> Option<GisbErrorInfo> {
        let status = self.read_gisb(self.offsets.arb_bp_cap_status);
        if status & ARB_BP_CAP_STATUS_VALID == 0 {
            return None;
        }

        let addr = self.read_gisb(self.offsets.arb_bp_cap_addr);
        let master = self.offsets.arb_bp_cap_master
            .map(|off| self.read_gisb(off));

        let info = GisbErrorInfo {
            address: addr as u64,
            master,
            is_write: (status & ARB_BP_CAP_STATUS_WRITE) != 0,
            is_timeout: false,
            is_tea: false,
        };

        self.write_gisb(self.offsets.arb_bp_cap_clr, ARB_BP_CAP_CLEAR);

        Some(info)
    }
}

impl BusDriver for BrcmstbGisb {
    fn name(&self) -> &str { "brcmstb-gisb" }

    fn compatible(&self) -> &[&str] { COMPATIBLE }

    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x800);
        self.power_state = PowerState::On;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), BusError> {
        self.power_state = PowerState::Off;
        Ok(())
    }

    fn suspend(&mut self) -> Result<(), BusError> {
        self.saved_timeout = self.get_timeout();
        self.power_state = PowerState::Suspended;
        Ok(())
    }

    fn resume(&mut self) -> Result<(), BusError> {
        self.set_timeout(self.saved_timeout);
        self.power_state = PowerState::On;
        Ok(())
    }

    fn read_reg(&self, offset: usize) -> Result<u32, BusError> {
        if !self.regs.is_valid() { return Err(BusError::InitFailed); }
        Ok(self.read_gisb(offset))
    }

    fn write_reg(&mut self, offset: usize, value: u32) -> Result<(), BusError> {
        if !self.regs.is_valid() { return Err(BusError::InitFailed); }
        self.write_gisb(offset, value);
        Ok(())
    }

    fn error_count(&self) -> u64 {
        self.error_count.load(Ordering::Relaxed)
    }

    fn handle_irq(&mut self) -> bool {
        let timeout = self.handle_timeout_irq();
        let bp = self.handle_bp_irq();
        if timeout.is_some() || bp.is_some() {
            self.error_count.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
}
