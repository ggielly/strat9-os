use crate::{BusChild, BusDriver, BusError, PowerState, mmio::MmioRegion};
use alloc::{string::String, vec::Vec};

const UNIPHIER_SBC_BASE: usize = 0x100;
const UNIPHIER_SBC_CTRL0: usize = 0x200;
const UNIPHIER_SBC_STRIDE: usize = 0x10;
const UNIPHIER_SBC_NR_BANKS: usize = 8;

const UNIPHIER_SBC_BASE_BE: u32 = 1 << 0;
const UNIPHIER_SBC_BASE_DUMMY: u32 = 0xFFFF_FFFF;

const MIN_BANK_SIZE: u32 = 128 * 1024;

const COMPATIBLE: &[&str] = &["socionext,uniphier-system-bus"];

#[derive(Clone, Copy)]
pub struct BankConfig {
    pub base: u32,
    pub end: u32,
}

impl BankConfig {
    /// Performs the empty operation.
    pub const fn empty() -> Self {
        Self { base: 0, end: 0 }
    }

    /// Returns whether valid.
    pub fn is_valid(&self) -> bool {
        self.end > self.base
    }

    /// Performs the size operation.
    pub fn size(&self) -> u32 {
        self.end - self.base
    }
}

pub struct UniphierSystemBus {
    regs: MmioRegion,
    banks: [BankConfig; UNIPHIER_SBC_NR_BANKS],
    boot_swap: bool,
    power_state: PowerState,
    children: Vec<BusChild>,
}

impl UniphierSystemBus {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            regs: MmioRegion::new(),
            banks: [BankConfig::empty(); UNIPHIER_SBC_NR_BANKS],
            boot_swap: false,
            power_state: PowerState::Off,
            children: Vec::new(),
        }
    }

    /// Sets bank.
    pub fn set_bank(&mut self, index: usize, base: u32, end: u32) {
        if index < UNIPHIER_SBC_NR_BANKS {
            let aligned_base = base & !((MIN_BANK_SIZE) - 1);
            let aligned_end = (end + MIN_BANK_SIZE - 1) & !((MIN_BANK_SIZE) - 1);
            self.banks[index] = BankConfig {
                base: aligned_base,
                end: aligned_end,
            };
        }
    }

    /// Performs the check boot swap operation.
    pub fn check_boot_swap(&mut self) {
        let bank0_base = self.regs.read32(UNIPHIER_SBC_BASE);
        self.boot_swap = (bank0_base & UNIPHIER_SBC_BASE_BE) != 0;
        if self.boot_swap {
            let tmp = self.banks[0];
            self.banks[0] = self.banks[1];
            self.banks[1] = tmp;
        }
    }

    /// Performs the apply bank config operation.
    fn apply_bank_config(&self) {
        for i in 0..UNIPHIER_SBC_NR_BANKS {
            let offset = UNIPHIER_SBC_BASE + i * UNIPHIER_SBC_STRIDE;

            if !self.banks[i].is_valid() {
                let dummy_val = if i < 2 { UNIPHIER_SBC_BASE_DUMMY } else { 0 };
                self.regs.write32(offset, dummy_val);
                continue;
            }

            let bank = &self.banks[i];
            let mask = !(bank.size() - 1);
            let reg_val =
                (bank.base & 0xFFFE_0000) | (((!mask) >> 16) & 0xFFFE) | UNIPHIER_SBC_BASE_BE;

            self.regs.write32(offset, reg_val);
        }
    }

    /// Performs the add child operation.
    pub fn add_child(&mut self, child: BusChild) {
        self.children.push(child);
    }
}

impl BusDriver for UniphierSystemBus {
    /// Performs the name operation.
    fn name(&self) -> &str {
        "uniphier-system-bus"
    }

    /// Performs the compatible operation.
    fn compatible(&self) -> &[&str] {
        COMPATIBLE
    }

    /// Performs the init operation.
    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x400);
        self.check_boot_swap();
        self.apply_bank_config();
        self.power_state = PowerState::On;
        Ok(())
    }

    /// Performs the shutdown operation.
    fn shutdown(&mut self) -> Result<(), BusError> {
        self.power_state = PowerState::Off;
        Ok(())
    }

    /// Performs the resume operation.
    fn resume(&mut self) -> Result<(), BusError> {
        self.apply_bank_config();
        self.power_state = PowerState::On;
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
