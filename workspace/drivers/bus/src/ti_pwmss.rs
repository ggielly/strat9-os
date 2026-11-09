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

const COMPATIBLE: &[&str] = &["ti,am33xx-pwmss"];

pub struct TiPwmss {
    regs: MmioRegion,
    power_state: PowerState,
    children: Vec<BusChild>,
}

impl TiPwmss {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            regs: MmioRegion::new(),
            power_state: PowerState::Off,
            children: Vec::new(),
        }
    }

    /// Performs the add child operation.
    pub fn add_child(&mut self, child: BusChild) {
        self.children.push(child);
    }
}

impl BusDriver for TiPwmss {
    /// Performs the name operation.
    fn name(&self) -> &str {
        "ti-pwmss"
    }

    /// Performs the compatible operation.
    fn compatible(&self) -> &[&str] {
        COMPATIBLE
    }

    /// Performs the init operation.
    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x1000);
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
        self.regs.check_user_offset(offset)?;
        Ok(self.regs.read32(offset))
    }

    /// Writes reg.
    fn write_reg(&mut self, offset: usize, value: u32) -> Result<(), BusError> {
        if !self.regs.is_valid() {
            return Err(BusError::InitFailed);
        }
        self.regs.check_user_offset(offset)?;
        self.regs.write32(offset, value);
        Ok(())
    }

    /// Performs the children operation.
    fn children(&self) -> Vec<BusChild> {
        self.children.clone()
    }
}
