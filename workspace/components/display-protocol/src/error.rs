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

//! Decoding errors for the native display protocol.

/// Why a wire buffer could not be accepted.
///
/// `Truncated` covers both short reads and short output slices; `SizeMismatch`
/// covers a declared length that disagrees with the provided buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The buffer is shorter than the fixed fields it must contain.
    Truncated,
    /// The header magic is not `S9DP`.
    BadMagic,
    /// The protocol major/minor version is not supported.
    UnsupportedVersion,
    /// A declared length disagrees with the actual buffer length.
    SizeMismatch,
    /// Reserved flag bits are set.
    BadFlags,
    /// A field documented as reserved is non-zero.
    ReservedNonZero,
    /// `COMMIT` carries more than `MAX_RECTS` rectangles.
    TooManyRects,
    /// A computed length or coordinate extent does not fit its wire type.
    Overflow,
    /// A message targeting a surface, buffer or output carries `object_id == 0`.
    BadObject,
    /// A documented range, format, enum value or length limit was violated.
    BadValue,
    /// The opcode is not part of protocol v1 (A.3).
    UnknownOpcode,
}
