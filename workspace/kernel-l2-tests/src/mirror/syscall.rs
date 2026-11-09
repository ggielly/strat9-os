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

//! Mirror of kernel/src/syscall : real error mapping + time shim.
//!
//! The real error.rs needs three error enums from hardware-bound modules;
//! they are provided as minimal shims below with identical variants so the
//! `From` impls in the included file compile unchanged.

#[path = "../../../kernel/src/syscall/error.rs"]
pub mod error;

/// Mirror of kernel/src/syscall/time.rs surface used by pure modules.
pub mod time {
    /// Host-real clock (kernel derives it from scheduler ticks).
    pub fn current_time_ns() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
}
