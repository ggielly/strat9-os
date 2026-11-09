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

//! Domain-specific syscall wrappers for the EXT4 strate.

pub use strat9_syscall::{
    call,
    error::{self, Error},
};

pub type Result<T> = error::Result<T>;

/// Implements volume read.
pub fn volume_read(handle: u64, sector: u64, buf: &mut [u8], sector_count: u64) -> Result<usize> {
    call::volume_read(
        handle as usize,
        sector as usize,
        buf.as_mut_ptr() as usize,
        sector_count as usize,
    )
}

/// Implements volume write.
pub fn volume_write(handle: u64, sector: u64, buf: &[u8], sector_count: u64) -> Result<usize> {
    call::volume_write(
        handle as usize,
        sector as usize,
        buf.as_ptr() as usize,
        sector_count as usize,
    )
}

/// Implements volume info.
pub fn volume_info(handle: u64) -> Result<u64> {
    call::volume_info(handle as usize).map(|v| v as u64)
}

/// Implements debug log.
pub fn debug_log(msg: &str) {
    let _ = call::debug_log(msg.as_bytes());
}

/// Implements exit.
pub fn exit(code: usize) -> ! {
    call::exit(code)
}
