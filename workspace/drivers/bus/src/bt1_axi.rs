use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use crate::{BusChild, BusDriver, BusError, PowerState};
use crate::mmio::MmioRegion;

const BT1_AXI_WERRL: usize = 0x110;
const BT1_AXI_WERRH: usize = 0x114;
const BT1_AXI_WERRH_TYPE: u32 = 1 << 23;
const BT1_AXI_WERRH_ADDR_SHIFT: u32 = 24;
const BT1_AXI_WERRH_ADDR_MASK: u32 = 0xFF00_0000;

const COMPATIBLE: &[&str] = &["baikal,bt1-axi"];

pub struct Bt1Axi {
    qos_regs: MmioRegion,
    sys_regs: MmioRegion,
    error_count: AtomicU64,
    power_state: PowerState,
}

impl Bt1Axi {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            qos_regs: MmioRegion::new(),
            sys_regs: MmioRegion::new(),
            error_count: AtomicU64::new(0),
            power_state: PowerState::Off,
        }
    }

    /// Initializes sys regs.
    pub fn init_sys_regs(&mut self, base: usize, size: usize) {
        self.sys_regs.init(base, size);
    }

    /// Reads error info.
    pub fn read_error_info(&self) -> Option<AxiErrorInfo> {
        if !self.sys_regs.is_valid() {
            return None;
        }
        let low = self.sys_regs.read32(BT1_AXI_WERRL);
        let high = self.sys_regs.read32(BT1_AXI_WERRH);

        let is_no_slave = (high & BT1_AXI_WERRH_TYPE) != 0;
        let addr_high = (high & BT1_AXI_WERRH_ADDR_MASK) >> BT1_AXI_WERRH_ADDR_SHIFT;

        Some(AxiErrorInfo {
            address_low: low,
            address_high: addr_high,
            is_no_slave,
        })
    }
}

pub struct AxiErrorInfo {
    pub address_low: u32,
    pub address_high: u32,
    pub is_no_slave: bool,
}

impl AxiErrorInfo {
    /// Performs the full address operation.
    pub fn full_address(&self) -> u64 {
        ((self.address_high as u64) << 32) | (self.address_low as u64)
    }

    /// Performs the error type str operation.
    pub fn error_type_str(&self) -> &'static str {
        if self.is_no_slave { "no slave" } else { "slave protocol error" }
    }
}

impl BusDriver for Bt1Axi {
    /// Performs the name operation.
    fn name(&self) -> &str { "bt1-axi" }

    /// Performs the compatible operation.
    fn compatible(&self) -> &[&str] { COMPATIBLE }

    /// Performs the init operation.
    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.qos_regs.init(base, 0x200);
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
        if !self.qos_regs.is_valid() {
            return Err(BusError::InitFailed);
        }
        Ok(self.qos_regs.read32(offset))
    }

    /// Writes reg.
    fn write_reg(&mut self, offset: usize, value: u32) -> Result<(), BusError> {
        if !self.qos_regs.is_valid() {
            return Err(BusError::InitFailed);
        }
        self.qos_regs.write32(offset, value);
        Ok(())
    }

    /// Performs the error count operation.
    fn error_count(&self) -> u64 {
        self.error_count.load(Ordering::Relaxed)
    }

    /// Handles irq.
    fn handle_irq(&mut self) -> bool {
        if let Some(_info) = self.read_error_info() {
            self.error_count.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        false
    }
}
