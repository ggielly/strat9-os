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

use crate::BusError;
use alloc::{string::String, vec::Vec};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallType {
    Peripheral,
    Memory,
    NoType,
}

pub struct FirewallEntry {
    pub firewall_id: u32,
    pub extra_args: [u32; 4],
    pub extra_args_count: usize,
}

pub trait FirewallController: Send + Sync {
    /// Performs the name operation.
    fn name(&self) -> &str;
    /// Performs the firewall type operation.
    fn firewall_type(&self) -> FirewallType;
    /// Performs the max entries operation.
    fn max_entries(&self) -> u32;
    /// Performs the grant access operation.
    fn grant_access(&self, firewall_id: u32) -> Result<(), BusError>;
    /// Performs the release access operation.
    fn release_access(&self, firewall_id: u32) -> Result<(), BusError>;
    /// Performs the grant memory range operation.
    fn grant_memory_range(&self, _start: u64, _size: u64) -> Result<(), BusError> {
        Err(BusError::NotSupported)
    }
}
