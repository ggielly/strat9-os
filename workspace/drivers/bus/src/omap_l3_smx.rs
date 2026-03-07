use crate::{BusChild, BusDriver, BusError, PowerState, mmio::MmioRegion};
use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

const L3_AGENT_CONTROL: usize = 0x020;
const L3_AGENT_STATUS: usize = 0x028;
const L3_ERROR_LOG: usize = 0x058;
const L3_ERROR_LOG_ADDR: usize = 0x060;
const L3_SI_FLAG_STATUS_0: usize = 0x510;
const L3_SI_FLAG_STATUS_1: usize = 0x530;

const L3_AGENT_STATUS_CLEAR_IA: u32 = 0x1000_0000;
const L3_AGENT_STATUS_CLEAR_TA: u32 = 0x0100_0000;

const L3_ERROR_LOG_MULTI: u32 = 1 << 31;
const L3_ERROR_LOG_SECONDARY: u32 = 1 << 30;
const L3_ERROR_LOG_CODE_MASK: u32 = 0x0F00_0000;
const L3_ERROR_LOG_CODE_SHIFT: u32 = 24;
const L3_ERROR_LOG_INITID_MASK: u32 = 0x0000_FF00;
const L3_ERROR_LOG_INITID_SHIFT: u32 = 8;
const L3_ERROR_LOG_CMD_MASK: u32 = 0x0000_0007;

const COMPATIBLE: &[&str] = &["ti,omap3-l3-smx"];

const L3_ERROR_CODES: &[&str] = &[
    "no error",
    "unsupported command",
    "address hole",
    "protection violation",
    "in-band error",
    "request timeout (not accepted)",
    "request timeout (no response)",
];

const L3_APP_BASES: &[usize] = &[
    0x1400, 0x1800, 0x1C00, 0x4400, 0x4000, 0x5800, 0x5400, 0x4C00, 0x5000, 0x3000,
];

const L3_DEBUG_BASES: &[usize] = &[0x1400, 0x5C00, 0x1800];

pub struct Omap3L3ErrorInfo {
    pub code: u32,
    pub initiator: u32,
    pub cmd: u32,
    pub address: u32,
    pub is_multi: bool,
    pub is_secondary: bool,
}

impl Omap3L3ErrorInfo {
    /// Performs the code str operation.
    pub fn code_str(&self) -> &'static str {
        L3_ERROR_CODES.get(self.code as usize).unwrap_or(&"unknown")
    }
}

pub struct OmapL3Smx {
    regs: MmioRegion,
    error_count: AtomicU64,
    power_state: PowerState,
}

impl OmapL3Smx {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            regs: MmioRegion::new(),
            error_count: AtomicU64::new(0),
            power_state: PowerState::Off,
        }
    }

    /// Reads error at.
    pub fn read_error_at(&self, base_offset: usize) -> Omap3L3ErrorInfo {
        let err_log = self.regs.read32(base_offset + L3_ERROR_LOG);
        let address = self.regs.read32(base_offset + L3_ERROR_LOG_ADDR);

        let code = (err_log & L3_ERROR_LOG_CODE_MASK) >> L3_ERROR_LOG_CODE_SHIFT;
        let initiator = (err_log & L3_ERROR_LOG_INITID_MASK) >> L3_ERROR_LOG_INITID_SHIFT;
        let cmd = err_log & L3_ERROR_LOG_CMD_MASK;

        Omap3L3ErrorInfo {
            code,
            initiator,
            cmd,
            address,
            is_multi: (err_log & L3_ERROR_LOG_MULTI) != 0,
            is_secondary: (err_log & L3_ERROR_LOG_SECONDARY) != 0,
        }
    }

    /// Performs the clear error at operation.
    pub fn clear_error_at(&self, base_offset: usize) {
        self.regs.write32(
            base_offset + L3_AGENT_STATUS,
            L3_AGENT_STATUS_CLEAR_IA | L3_AGENT_STATUS_CLEAR_TA,
        );
        self.regs.write32(base_offset + L3_ERROR_LOG, 0);
    }

    /// Reads flag status.
    pub fn read_flag_status(&self, irq_type: usize) -> u32 {
        let offset = if irq_type == 0 {
            L3_SI_FLAG_STATUS_0
        } else {
            L3_SI_FLAG_STATUS_1
        };
        self.regs.read32(offset)
    }

    /// Handles error irq.
    pub fn handle_error_irq(&mut self, irq_type: usize) -> Option<Omap3L3ErrorInfo> {
        let status = self.read_flag_status(irq_type);
        if status == 0 {
            return None;
        }

        let source = status.trailing_zeros() as usize;
        let bases = if irq_type == 0 {
            L3_APP_BASES
        } else {
            L3_DEBUG_BASES
        };

        if source >= bases.len() {
            return None;
        }

        let base = bases[source];
        let info = self.read_error_at(base);
        self.clear_error_at(base);
        self.error_count.fetch_add(1, Ordering::Relaxed);
        Some(info)
    }
}

impl BusDriver for OmapL3Smx {
    /// Performs the name operation.
    fn name(&self) -> &str {
        "omap-l3-smx"
    }

    /// Performs the compatible operation.
    fn compatible(&self) -> &[&str] {
        COMPATIBLE
    }

    /// Performs the init operation.
    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x10000);
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

    /// Performs the error count operation.
    fn error_count(&self) -> u64 {
        self.error_count.load(Ordering::Relaxed)
    }

    /// Handles irq.
    fn handle_irq(&mut self) -> bool {
        let app = self.handle_error_irq(0);
        let dbg = self.handle_error_irq(1);
        app.is_some() || dbg.is_some()
    }
}
