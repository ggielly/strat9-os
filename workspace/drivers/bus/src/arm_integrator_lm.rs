use alloc::{string::String, vec::Vec};
use crate::{BusChild, BusDriver, BusError, PowerState};
use crate::mmio::MmioRegion;

const INTEGRATOR_SC_DEC_OFFSET: usize = 0x10;
const INTEGRATOR_AP_EXP_BASE: u64 = 0xC000_0000;
const INTEGRATOR_AP_EXP_STRIDE: u64 = 0x1000_0000;
const NUM_SLOTS: usize = 4;

const COMPATIBLE: &[&str] = &["arm,integrator-ap-lm"];

pub struct ArmIntegratorLm {
    syscon_regs: MmioRegion,
    slots_present: [bool; NUM_SLOTS],
    power_state: PowerState,
}

impl ArmIntegratorLm {
    pub fn new() -> Self {
        Self {
            syscon_regs: MmioRegion::new(),
            slots_present: [false; NUM_SLOTS],
            power_state: PowerState::Off,
        }
    }

    fn detect_modules(&mut self) {
        if !self.syscon_regs.is_valid() { return; }
        let val = self.syscon_regs.read32(INTEGRATOR_SC_DEC_OFFSET);
        for i in 0..NUM_SLOTS {
            self.slots_present[i] = (val & (1 << (4 + i))) != 0;
        }
    }

    pub fn slot_base(slot: usize) -> u64 {
        INTEGRATOR_AP_EXP_BASE + (slot as u64) * INTEGRATOR_AP_EXP_STRIDE
    }

    pub fn is_slot_present(&self, slot: usize) -> bool {
        slot < NUM_SLOTS && self.slots_present[slot]
    }
}

impl BusDriver for ArmIntegratorLm {
    fn name(&self) -> &str { "arm-integrator-lm" }

    fn compatible(&self) -> &[&str] { COMPATIBLE }

    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.syscon_regs.init(base, 0x100);
        self.detect_modules();
        self.power_state = PowerState::On;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), BusError> {
        self.power_state = PowerState::Off;
        Ok(())
    }

    fn read_reg(&self, offset: usize) -> Result<u32, BusError> {
        if !self.syscon_regs.is_valid() {
            return Err(BusError::InitFailed);
        }
        Ok(self.syscon_regs.read32(offset))
    }

    fn write_reg(&mut self, offset: usize, value: u32) -> Result<(), BusError> {
        if !self.syscon_regs.is_valid() {
            return Err(BusError::InitFailed);
        }
        self.syscon_regs.write32(offset, value);
        Ok(())
    }

    fn children(&self) -> Vec<BusChild> {
        let mut children = Vec::new();
        for i in 0..NUM_SLOTS {
            if self.slots_present[i] {
                children.push(BusChild {
                    name: alloc::format!("lm{}", i),
                    base_addr: Self::slot_base(i),
                    size: INTEGRATOR_AP_EXP_STRIDE,
                });
            }
        }
        children
    }
}
