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

const IMX_AIPSTZ_MPR0: usize = 0x00;

const COMPATIBLE: &[&str] = &["fsl,imx8mp-aipstz"];

pub struct AipstzConfig {
    pub mpr0: u32,
}

pub const IMX8MP_DEFAULT_CFG: AipstzConfig = AipstzConfig { mpr0: 0x7777_7777 };

pub struct ImxAipstz {
    regs: MmioRegion,
    config: AipstzConfig,
    power_state: PowerState,
    children: Vec<BusChild>,
}

impl ImxAipstz {
    /// Creates a new instance.
    pub fn new(config: AipstzConfig) -> Self {
        Self {
            regs: MmioRegion::new(),
            config,
            power_state: PowerState::Off,
            children: Vec::new(),
        }
    }

    /// Performs the apply config operation.
    fn apply_config(&self) {
        if !self.regs.is_valid() {
            return;
        }
        self.regs.write32(IMX_AIPSTZ_MPR0, self.config.mpr0);
    }

    /// Performs the add child operation.
    pub fn add_child(&mut self, child: BusChild) {
        self.children.push(child);
    }
}

impl BusDriver for ImxAipstz {
    /// Performs the name operation.
    fn name(&self) -> &str {
        "imx-aipstz"
    }

    /// Performs the compatible operation.
    fn compatible(&self) -> &[&str] {
        COMPATIBLE
    }

    /// Performs the init operation.
    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x100);
        self.apply_config();
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
        self.apply_config();
        self.power_state = PowerState::On;
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
