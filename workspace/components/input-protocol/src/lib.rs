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

//! Canonical normalized input protocol of strat9-os (A.5).
//!
//! `inputd` publishes 32-byte [`NormalizedEvent`]s, groups them into 48-byte
//! [`InputRecord`]s and ships them in [`InputBatch`]es, along with the small
//! subscription payloads in [`inputd`].
//!
//! All fields are encoded and decoded explicitly, little-endian, one field at
//! a time. No pointer casts, no `transmute`, no `usize` in wire formats, no
//! allocation, no `unsafe`. `Debug` implementations never print text bytes.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod batch;
pub mod constants;
pub mod error;
pub mod event;
pub mod inputd;
pub mod record;

pub use batch::InputBatch;
pub use constants::*;
pub use error::InputError;
pub use event::NormalizedEvent;
pub use inputd::{Focus, Reset, Subscribe, SubscribeAck};
pub use record::InputRecord;

#[cfg(test)]
mod tests;
