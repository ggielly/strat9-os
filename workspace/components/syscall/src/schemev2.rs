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

#[derive(Debug, Clone, Copy)]
#[repr(C)]
/// Fixed-size ABI representation of a registered scheme.
pub struct SchemeV2 {
    pub name: [u8; 256],
    pub id: u32,
    pub flags: u32,
}

impl SchemeV2 {
    /// Create a scheme descriptor from name, id and flags.
    pub fn new(name: &str, id: u32, flags: u32) -> Self {
        let mut scheme = Self {
            name: [0; 256],
            id,
            flags,
        };

        let name_bytes = name.as_bytes();
        let len = core::cmp::min(name_bytes.len(), 255);
        scheme.name[..len].copy_from_slice(&name_bytes[..len]);

        scheme
    }

    /// Return the scheme name up to the first NUL byte.
    pub fn name(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(256);
        core::str::from_utf8(&self.name[..len]).unwrap_or("<invalid>")
    }
}
