use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use crate::{BusChild, BusDriver, BusError, PowerState};
use crate::mmio::MmioRegion;

const L3_TARG_STDERRLOG_MAIN: usize = 0x48;
const L3_TARG_STDERRLOG_HDR: usize = 0x4C;
const L3_TARG_STDERRLOG_MSTADDR: usize = 0x50;
const L3_TARG_STDERRLOG_INFO: usize = 0x58;
const L3_TARG_STDERRLOG_SLVOFSLSB: usize = 0x5C;
const L3_TARG_STDERRLOG_CINFO_INFO: usize = 0x64;
const L3_TARG_STDERRLOG_CINFO_MSTADDR: usize = 0x68;
const L3_TARG_STDERRLOG_CINFO_OPCODE: usize = 0x6C;

const L3_FLAGMUX_REGERR0: usize = 0x0C;
const L3_FLAGMUX_MASK0: usize = 0x08;

const CLEAR_STDERR_LOG: u32 = 1 << 31;
const CUSTOM_ERROR: u32 = 0x2;
const STANDARD_ERROR: u32 = 0x0;

const MAX_L3_MODULES: usize = 3;

const COMPATIBLE: &[&str] = &[
    "ti,omap4-l3-noc",
    "ti,omap5-l3-noc",
    "ti,dra7-l3-noc",
    "ti,am4372-l3-noc",
];

pub struct L3TargetData {
    pub offset: u32,
    pub name: &'static str,
}

pub struct L3FlagmuxData {
    pub offset: u32,
    pub targets: &'static [L3TargetData],
    pub mask_app_bits: u32,
    pub mask_dbg_bits: u32,
}

pub struct L3MasterData {
    pub id: u32,
    pub name: &'static str,
}

pub struct OmapL3Noc {
    modules: [MmioRegion; MAX_L3_MODULES],
    num_modules: usize,
    error_count: AtomicU64,
    power_state: PowerState,
    saved_mask_app: [u32; MAX_L3_MODULES],
    saved_mask_dbg: [u32; MAX_L3_MODULES],
}

impl OmapL3Noc {
    pub fn new() -> Self {
        Self {
            modules: [MmioRegion::new(), MmioRegion::new(), MmioRegion::new()],
            num_modules: 0,
            error_count: AtomicU64::new(0),
            power_state: PowerState::Off,
            saved_mask_app: [0; MAX_L3_MODULES],
            saved_mask_dbg: [0; MAX_L3_MODULES],
        }
    }

    pub fn init_module(&mut self, index: usize, base: usize, size: usize) {
        if index < MAX_L3_MODULES {
            self.modules[index].init(base, size);
            if index >= self.num_modules {
                self.num_modules = index + 1;
            }
        }
    }

    pub fn handle_target_error(&self, module: usize, target_offset: usize) -> Result<ErrorInfo, BusError> {
        if module >= self.num_modules || !self.modules[module].is_valid() {
            return Err(BusError::InvalidArgument);
        }

        let base_offset = target_offset;
        let main = self.modules[module].read32(base_offset + L3_TARG_STDERRLOG_MAIN);
        let hdr = self.modules[module].read32(base_offset + L3_TARG_STDERRLOG_HDR);
        let mstaddr = self.modules[module].read32(base_offset + L3_TARG_STDERRLOG_MSTADDR);

        let err_type = if (hdr & 0xFF) == CUSTOM_ERROR {
            ErrorType::Custom
        } else {
            ErrorType::Standard
        };

        let info = match err_type {
            ErrorType::Standard => {
                let slave_addr = self.modules[module].read32(base_offset + L3_TARG_STDERRLOG_SLVOFSLSB);
                ErrorInfo {
                    err_type,
                    master_addr: mstaddr,
                    slave_addr,
                    header: hdr,
                    main_reg: main,
                }
            }
            ErrorType::Custom => {
                let cinfo = self.modules[module].read32(base_offset + L3_TARG_STDERRLOG_CINFO_INFO);
                ErrorInfo {
                    err_type,
                    master_addr: mstaddr,
                    slave_addr: cinfo,
                    header: hdr,
                    main_reg: main,
                }
            }
        };

        self.modules[module].write32(base_offset + L3_TARG_STDERRLOG_MAIN, CLEAR_STDERR_LOG);

        Ok(info)
    }

    pub fn read_flagmux(&self, module: usize, inttype: usize) -> u32 {
        if module >= self.num_modules || !self.modules[module].is_valid() {
            return 0;
        }
        self.modules[module].read32(L3_FLAGMUX_REGERR0 + (inttype << 3))
    }

    pub fn mask_target(&self, module: usize, target_bit: u32, inttype: usize) {
        if module >= self.num_modules || !self.modules[module].is_valid() {
            return;
        }
        let mask_offset = L3_FLAGMUX_MASK0 + (inttype << 3);
        self.modules[module].set_bits32(mask_offset, 1 << target_bit);
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ErrorType {
    Standard,
    Custom,
}

#[derive(Debug, Clone)]
pub struct ErrorInfo {
    pub err_type: ErrorType,
    pub master_addr: u32,
    pub slave_addr: u32,
    pub header: u32,
    pub main_reg: u32,
}

impl BusDriver for OmapL3Noc {
    fn name(&self) -> &str { "omap-l3-noc" }

    fn compatible(&self) -> &[&str] { COMPATIBLE }

    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.init_module(0, base, 0x1000);
        self.power_state = PowerState::On;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), BusError> {
        self.power_state = PowerState::Off;
        Ok(())
    }

    fn suspend(&mut self) -> Result<(), BusError> {
        for i in 0..self.num_modules {
            if self.modules[i].is_valid() {
                self.saved_mask_app[i] = self.modules[i].read32(L3_FLAGMUX_MASK0);
                self.saved_mask_dbg[i] = self.modules[i].read32(L3_FLAGMUX_MASK0 + 8);
            }
        }
        self.power_state = PowerState::Suspended;
        Ok(())
    }

    fn resume(&mut self) -> Result<(), BusError> {
        for i in 0..self.num_modules {
            if self.modules[i].is_valid() {
                self.modules[i].write32(L3_FLAGMUX_MASK0, self.saved_mask_app[i]);
                self.modules[i].write32(L3_FLAGMUX_MASK0 + 8, self.saved_mask_dbg[i]);
            }
        }
        self.power_state = PowerState::On;
        Ok(())
    }

    fn read_reg(&self, offset: usize) -> Result<u32, BusError> {
        if self.num_modules == 0 || !self.modules[0].is_valid() {
            return Err(BusError::InitFailed);
        }
        Ok(self.modules[0].read32(offset))
    }

    fn write_reg(&mut self, offset: usize, value: u32) -> Result<(), BusError> {
        if self.num_modules == 0 || !self.modules[0].is_valid() {
            return Err(BusError::InitFailed);
        }
        self.modules[0].write32(offset, value);
        Ok(())
    }

    fn error_count(&self) -> u64 {
        self.error_count.load(Ordering::Relaxed)
    }

    fn handle_irq(&mut self) -> bool {
        self.error_count.fetch_add(1, Ordering::Relaxed);
        true
    }
}
