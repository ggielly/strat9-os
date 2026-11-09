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

const OCP2SCP_TIMING: usize = 0x18;
const SYNC2_MASK: u32 = 0xF;
const SYNC2_SAFE_VALUE: u32 = 0x6;

const COMPATIBLE: &[&str] = &["ti,omap-ocp2scp", "ti,am437x-ocp2scp"];

pub struct OmapOcp2Scp {
    regs: MmioRegion,
    power_state: PowerState,
    is_am437x: bool,
    children: Vec<BusChild>,
}

impl OmapOcp2Scp {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            regs: MmioRegion::new(),
            power_state: PowerState::Off,
            is_am437x: false,
            children: Vec::new(),
        }
    }

    /// Sets am437x.
    pub fn set_am437x(&mut self, am437x: bool) {
        self.is_am437x = am437x;
    }

    /// Performs the add child operation.
    pub fn add_child(&mut self, child: BusChild) {
        self.children.push(child);
    }

    /// Performs the configure timing operation.
    fn configure_timing(&self) {
        if self.is_am437x || !self.regs.is_valid() {
            return;
        }
        let mut reg = self.regs.read32(OCP2SCP_TIMING);
        reg &= !SYNC2_MASK;
        reg |= SYNC2_SAFE_VALUE;
        self.regs.write32(OCP2SCP_TIMING, reg);
    }
}

impl BusDriver for OmapOcp2Scp {
    /// Performs the name operation.
    fn name(&self) -> &str {
        "omap-ocp2scp"
    }

    /// Performs the compatible operation.
    fn compatible(&self) -> &[&str] {
        COMPATIBLE
    }

    /// Performs the init operation.
    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x20);
        self.configure_timing();
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
