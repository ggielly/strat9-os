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

#![no_std]

extern crate alloc;

pub mod syscalls;

pub use strat9_syscall::data::IpcMessage;

pub const OPCODE_OPEN: u32 = 0x01;
pub const OPCODE_READ: u32 = 0x02;
pub const OPCODE_WRITE: u32 = 0x03;
pub const OPCODE_CLOSE: u32 = 0x04;
pub const OPCODE_BULK_SETUP: u32 = 0x09;
pub const OPCODE_BULK_TEARDOWN: u32 = 0x0A;
