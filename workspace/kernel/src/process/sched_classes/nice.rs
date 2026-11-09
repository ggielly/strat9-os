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

// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::{AtomicI32, Ordering};

/// A strongly typed wrapper over nice values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NiceValue(i8);

impl Default for NiceValue {
    /// Builds a default instance.
    fn default() -> Self {
        Self(0)
    }
}

impl NiceValue {
    pub const MIN: Self = Self(-20);
    pub const MAX: Self = Self(19);

    /// Constructs a `NiceValue` from an integer.
    /// Values outside the valid range [-20, 19] are saturated.
    pub fn new(value: i8) -> Self {
        Self(value.clamp(Self::MIN.0, Self::MAX.0))
    }

    /// Gets the inner primitive value.
    pub const fn get(self) -> i8 {
        self.0
    }
}

/// Dynamic scheduling priority (nice value) for the FAIR class.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Nice(NiceValue);

impl Nice {
    /// Creates a new instance.
    pub fn new(value: i8) -> Self {
        Self(NiceValue::new(value))
    }

    /// Performs the value operation.
    pub const fn value(self) -> NiceValue {
        self.0
    }
}

pub struct AtomicNice(AtomicI32);

impl AtomicNice {
    /// Creates a new instance.
    pub const fn new(nice: Nice) -> Self {
        Self(AtomicI32::new(nice.0 .0 as i32))
    }

    /// Performs the load operation.
    pub fn load(&self, order: Ordering) -> Nice {
        Nice::new(self.0.load(order) as i8)
    }

    /// Performs the store operation.
    pub fn store(&self, nice: Nice, order: Ordering) {
        self.0.store(nice.0 .0 as i32, order)
    }
}
