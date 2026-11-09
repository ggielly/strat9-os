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

pub const ABI_VERSION_MAJOR: u16 = 0;
pub const ABI_VERSION_MINOR: u16 = 1;

/// Packed return format for `SYS_ABI_VERSION`: `(major << 16) | minor`.
pub const ABI_VERSION_PACKED: u32 = ((ABI_VERSION_MAJOR as u32) << 16) | (ABI_VERSION_MINOR as u32);

pub mod boot;
pub mod data;
pub mod errno;
pub mod flag;
pub mod ip;
pub mod ipc;
pub mod ipc_codec;
pub mod ipc_payload;
pub mod iommu;
pub mod net;
pub mod syscall;
pub mod vmm;
