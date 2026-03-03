use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use crate::{BusChild, BusDriver, BusError, PowerState};
use crate::mmio::MmioRegion;

const APB_EHB_ISR: usize = 0x00;
const APB_EHB_ISR_PENDING: u32 = 1 << 0;
const APB_EHB_ISR_MASK: u32 = 1 << 1;
const APB_EHB_ADDR: usize = 0x04;
const APB_EHB_TIMEOUT: usize = 0x08;

const APB_EHB_TIMEOUT_MIN: u32 = 0x0000_03FF;
const APB_EHB_TIMEOUT_MAX: u32 = 0xFFFF_FFFF;

const COMPATIBLE: &[&str] = &["baikal,bt1-apb"];

pub struct Bt1Apb {
    regs: MmioRegion,
    nodev_regs: MmioRegion,
    error_count: AtomicU64,
    clock_rate: u64,
    power_state: PowerState,
}

impl Bt1Apb {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            regs: MmioRegion::new(),
            nodev_regs: MmioRegion::new(),
            error_count: AtomicU64::new(0),
            clock_rate: 0,
            power_state: PowerState::Off,
        }
    }

    /// Initializes nodev region.
    pub fn init_nodev_region(&mut self, base: usize, size: usize) {
        self.nodev_regs.init(base, size);
    }

    /// Sets clock rate.
    pub fn set_clock_rate(&mut self, rate: u64) {
        self.clock_rate = rate;
    }

    /// Performs the timeout cycles to us operation.
    pub fn timeout_cycles_to_us(&self, n: u32) -> u64 {
        if self.clock_rate == 0 {
            return 0;
        }
        (n as u64) * 1_000_000 / self.clock_rate
    }

    /// Performs the timeout us to cycles operation.
    pub fn timeout_us_to_cycles(&self, timeout_us: u64) -> u32 {
        if self.clock_rate == 0 {
            return APB_EHB_TIMEOUT_MIN;
        }
        let n = timeout_us * self.clock_rate / 1_000_000;
        (n as u32).clamp(APB_EHB_TIMEOUT_MIN, APB_EHB_TIMEOUT_MAX)
    }

    /// Returns timeout us.
    pub fn get_timeout_us(&self) -> u64 {
        let n = self.regs.read32(APB_EHB_TIMEOUT);
        self.timeout_cycles_to_us(n)
    }

    /// Sets timeout us.
    pub fn set_timeout_us(&self, timeout_us: u64) {
        let n = self.timeout_us_to_cycles(timeout_us);
        self.regs.write32(APB_EHB_TIMEOUT, n);
    }

    /// Reads fault address.
    pub fn read_fault_address(&self) -> u32 {
        self.regs.read32(APB_EHB_ADDR)
    }

    /// Enables irq.
    pub fn enable_irq(&self) {
        self.regs.modify32(
            APB_EHB_ISR,
            APB_EHB_ISR_PENDING | APB_EHB_ISR_MASK,
            APB_EHB_ISR_MASK,
        );
    }

    /// Disables irq.
    pub fn disable_irq(&self) {
        self.regs.clear_bits32(APB_EHB_ISR, APB_EHB_ISR_MASK);
    }

    /// Performs the clear pending operation.
    pub fn clear_pending(&self) {
        self.regs.clear_bits32(APB_EHB_ISR, APB_EHB_ISR_PENDING);
    }
}

impl BusDriver for Bt1Apb {
    /// Performs the name operation.
    fn name(&self) -> &str { "bt1-apb" }

    /// Performs the compatible operation.
    fn compatible(&self) -> &[&str] { COMPATIBLE }

    /// Performs the init operation.
    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x10);
        self.enable_irq();
        self.power_state = PowerState::On;
        Ok(())
    }

    /// Performs the shutdown operation.
    fn shutdown(&mut self) -> Result<(), BusError> {
        self.disable_irq();
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
        let isr = self.regs.read32(APB_EHB_ISR);
        if isr & APB_EHB_ISR_PENDING == 0 {
            return false;
        }
        let _addr = self.read_fault_address();
        self.error_count.fetch_add(1, Ordering::Relaxed);
        self.clear_pending();
        true
    }
}
