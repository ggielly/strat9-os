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

//! DMA (Direct Memory Access) safety abstractions.
//!
//! Provides `DmaBuffer` for pinning physical memory during DMA transfers
//! and `DmaDirection` for compile-time direction enforcement.
//!
//! Inspired by Asterinas OSTD `ostd/src/mm/dma/`.

pub mod bounce;
pub mod buffer;
pub mod direction;
pub mod mapper;

pub use bounce::DmaBounce;
pub use buffer::{DmaBuffer, DmaConstraint, DmaError};
pub use direction::{DmaBidirectional, DmaDirection, DmaFromDevice, DmaToDevice};
pub use mapper::DmaMapper;
