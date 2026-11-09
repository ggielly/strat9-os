/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

use crate::{BusChild, BusDriver, BusError, PowerState, mmio::MmioRegion};
use alloc::{string::String, vec::Vec};

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
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            syscon_regs: MmioRegion::new(),
            slots_present: [false; NUM_SLOTS],
            power_state: PowerState::Off,
        }
    }

    /// Performs the detect modules operation.
    fn detect_modules(&mut self) {
        if !self.syscon_regs.is_valid() {
            return;
        }
        let val = self.syscon_regs.read32(INTEGRATOR_SC_DEC_OFFSET);
        for i in 0..NUM_SLOTS {
            self.slots_present[i] = (val & (1 << (4 + i))) != 0;
        }
    }

    /// Performs the slot base operation.
    pub fn slot_base(slot: usize) -> u64 {
        INTEGRATOR_AP_EXP_BASE + (slot as u64) * INTEGRATOR_AP_EXP_STRIDE
    }

    /// Returns whether slot present.
    pub fn is_slot_present(&self, slot: usize) -> bool {
        slot < NUM_SLOTS && self.slots_present[slot]
    }
}

impl BusDriver for ArmIntegratorLm {
    /// Performs the name operation.
    fn name(&self) -> &str {
        "arm-integrator-lm"
    }

    /// Performs the compatible operation.
    fn compatible(&self) -> &[&str] {
        COMPATIBLE
    }

    /// Performs the init operation.
    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.syscon_regs.init(base, 0x100);
        self.detect_modules();
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
        if !self.syscon_regs.is_valid() {
            return Err(BusError::InitFailed);
        }
        self.syscon_regs.check_user_offset(offset)?;
        Ok(self.syscon_regs.read32(offset))
    }

    /// Writes reg.
    fn write_reg(&mut self, offset: usize, value: u32) -> Result<(), BusError> {
        if !self.syscon_regs.is_valid() {
            return Err(BusError::InitFailed);
        }
        self.syscon_regs.check_user_offset(offset)?;
        self.syscon_regs.write32(offset, value);
        Ok(())
    }

    /// Performs the children operation.
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
