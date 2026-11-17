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

//! Errors for the normalized input protocol.

/// Why a wire buffer could not be accepted, or a value could not be encoded.
///
/// `Truncated` covers a short input buffer and an undersized output slice;
/// `SizeMismatch` covers a buffer longer than the declared length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputError {
    /// The buffer is shorter than the fields it must contain.
    Truncated,
    /// The buffer is longer than the exact declared length.
    SizeMismatch,
    /// A documented range, length or enum value was violated.
    BadValue,
    /// A flag bit is set where the format forbids it.
    BadFlags,
    /// A value does not fit the documented narrower type (motion coordinate).
    Overflow,
    /// `event_type` is not one of the defined event types.
    UnknownEvent,
    /// A `TEXT` payload is not valid UTF-8.
    NotUtf8,
    /// An `InputBatch` declares more than [`crate::MAX_INPUT_RECORDS`] records.
    TooManyRecords,
    /// A subscription path exceeds [`crate::MAX_SUBSCRIBE_PATH`] bytes.
    PathTooLong,
}
