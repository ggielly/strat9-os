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

//! Pure conversion of physical boot modules into initfs registration arguments.
use strat9_abi::boot::{ModuleEntry, MAX_BOOT_MODULES};

pub struct InitfsModule<'a> {
    pub name: &'a str,
    pub virtual_base: u64,
    pub len: usize,
}

impl<'a> InitfsModule<'a> {
    /// Numeric validation only. The boot path must keep the payload reserved and
    /// mapped for the lifetime of the VFS file before anyone dereferences it.
    pub fn from_physical(entry: &'a ModuleEntry, hhdm: u64) -> Result<Self, &'static str> {
        let name = entry.checked_name()?;
        if entry.base == 0 || entry.size > isize::MAX as u64 {
            return Err("invalid module payload extent");
        }
        entry
            .base
            .checked_add(entry.size)
            .ok_or("module physical range overflow")?;
        let virtual_base = hhdm
            .checked_add(entry.base)
            .ok_or("module HHDM address overflow")?;
        let last = virtual_base
            .checked_add(entry.size.saturating_sub(1))
            .ok_or("module virtual range overflow")?;
        // This boot path uses four-level x86-64 paging. Reject ranges through
        // the noncanonical hole as well as already-converted physical inputs.
        if !canonical(virtual_base) || !canonical(last) || (virtual_base >> 47) != (last >> 47) {
            return Err("module virtual range is not canonical");
        }
        Ok(Self {
            name,
            virtual_base,
            len: entry.size as usize,
        })
    }
}

pub fn validate_modules(entries: &[ModuleEntry], hhdm: u64) -> Result<(), &'static str> {
    if entries.len() > MAX_BOOT_MODULES {
        return Err("too many initfs modules");
    }
    for (index, entry) in entries.iter().enumerate() {
        let view = InitfsModule::from_physical(entry, hhdm)?;
        for previous in &entries[..index] {
            if previous.checked_name()?.eq_ignore_ascii_case(view.name) {
                return Err("duplicate initfs module name");
            }
        }
    }
    Ok(())
}

fn canonical(address: u64) -> bool {
    address < (1 << 47) || address >= 0xFFFF_8000_0000_0000
}
