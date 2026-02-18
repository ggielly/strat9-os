//! Safe arithmetic operations with overflow detection.
//!
//! This module provides traits and functions for performing arithmetic
//! operations that detect overflow and return errors instead of panicking
//! or wrapping.
//!
//! # Security
//!
//! Arithmetic overflow in filesystem code can lead to serious security
//! vulnerabilities like buffer overflows. Always use these checked operations
//! when computing sizes, offsets, or counts from untrusted metadata.

use crate::error::{FsError, FsResult};

/// Trait for checked arithmetic operations.
///
/// Provides methods that return `FsError::ArithmeticOverflow` on overflow
/// instead of panicking or wrapping.
pub trait CheckedOps: Sized {
    /// Adds an offset, returning an error on overflow.
    fn checked_add_offset(self, offset: Self) -> FsResult<Self>;

    /// Multiplies by a size, returning an error on overflow.
    fn checked_mul_size(self, size: Self) -> FsResult<Self>;

    /// Subtracts, returning an error on underflow.
    fn checked_sub_safe(self, other: Self) -> FsResult<Self>;

    /// Left-shifts, returning an error if bits would be lost.
    fn checked_shl_safe(self, shift: u32) -> FsResult<Self>;
}

impl CheckedOps for u64 {
    #[inline]
    fn checked_add_offset(self, offset: u64) -> FsResult<Self> {
        self.checked_add(offset).ok_or(FsError::ArithmeticOverflow)
    }

    #[inline]
    fn checked_mul_size(self, size: u64) -> FsResult<Self> {
        self.checked_mul(size).ok_or(FsError::ArithmeticOverflow)
    }

    #[inline]
    fn checked_sub_safe(self, other: u64) -> FsResult<Self> {
        self.checked_sub(other).ok_or(FsError::ArithmeticOverflow)
    }

    #[inline]
    fn checked_shl_safe(self, shift: u32) -> FsResult<Self> {
        if shift >= 64 {
            return Err(FsError::ArithmeticOverflow);
        }
        // Check if any bits would be lost
        let result = self << shift;
        if (result >> shift) != self {
            return Err(FsError::ArithmeticOverflow);
        }
        Ok(result)
    }
}

impl CheckedOps for u32 {
    #[inline]
    fn checked_add_offset(self, offset: u32) -> FsResult<Self> {
        self.checked_add(offset).ok_or(FsError::ArithmeticOverflow)
    }

    #[inline]
    fn checked_mul_size(self, size: u32) -> FsResult<Self> {
        self.checked_mul(size).ok_or(FsError::ArithmeticOverflow)
    }

    #[inline]
    fn checked_sub_safe(self, other: u32) -> FsResult<Self> {
        self.checked_sub(other).ok_or(FsError::ArithmeticOverflow)
    }

    #[inline]
    fn checked_shl_safe(self, shift: u32) -> FsResult<Self> {
        if shift >= 32 {
            return Err(FsError::ArithmeticOverflow);
        }
        let result = self << shift;
        if (result >> shift) != self {
            return Err(FsError::ArithmeticOverflow);
        }
        Ok(result)
    }
}

impl CheckedOps for usize {
    #[inline]
    fn checked_add_offset(self, offset: usize) -> FsResult<Self> {
        self.checked_add(offset).ok_or(FsError::ArithmeticOverflow)
    }

    #[inline]
    fn checked_mul_size(self, size: usize) -> FsResult<Self> {
        self.checked_mul(size).ok_or(FsError::ArithmeticOverflow)
    }

    #[inline]
    fn checked_sub_safe(self, other: usize) -> FsResult<Self> {
        self.checked_sub(other).ok_or(FsError::ArithmeticOverflow)
    }

    #[inline]
    fn checked_shl_safe(self, shift: u32) -> FsResult<Self> {
        if shift >= (core::mem::size_of::<usize>() * 8) as u32 {
            return Err(FsError::ArithmeticOverflow);
        }
        let result = self << shift;
        if (result >> shift) != self {
            return Err(FsError::ArithmeticOverflow);
        }
        Ok(result)
    }
}

/// Extension trait for checked slice operations.
pub trait CheckedSliceOps {
    /// Gets a subslice with bounds checking.
    fn get_checked(&self, start: usize, len: usize) -> FsResult<&[u8]>;

    /// Reads a big-endian u16 at the given offset.
    fn read_be_u16(&self, offset: usize) -> FsResult<u16>;

    /// Reads a big-endian u32 at the given offset.
    fn read_be_u32(&self, offset: usize) -> FsResult<u32>;

    /// Reads a big-endian u64 at the given offset.
    fn read_be_u64(&self, offset: usize) -> FsResult<u64>;

    /// Reads a little-endian u16 at the given offset.
    fn read_le_u16(&self, offset: usize) -> FsResult<u16>;

    /// Reads a little-endian u32 at the given offset.
    fn read_le_u32(&self, offset: usize) -> FsResult<u32>;

    /// Reads a little-endian u64 at the given offset.
    fn read_le_u64(&self, offset: usize) -> FsResult<u64>;
}

impl CheckedSliceOps for [u8] {
    #[inline]
    fn get_checked(&self, start: usize, len: usize) -> FsResult<&[u8]> {
        let end = start.checked_add(len).ok_or(FsError::ArithmeticOverflow)?;
        if end > self.len() {
            return Err(FsError::BufferTooSmall);
        }
        Ok(&self[start..end])
    }

    #[inline]
    fn read_be_u16(&self, offset: usize) -> FsResult<u16> {
        let bytes = self.get_checked(offset, 2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    #[inline]
    fn read_be_u32(&self, offset: usize) -> FsResult<u32> {
        let bytes = self.get_checked(offset, 4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    #[inline]
    fn read_be_u64(&self, offset: usize) -> FsResult<u64> {
        let bytes = self.get_checked(offset, 8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    #[inline]
    fn read_le_u16(&self, offset: usize) -> FsResult<u16> {
        let bytes = self.get_checked(offset, 2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    #[inline]
    fn read_le_u32(&self, offset: usize) -> FsResult<u32> {
        let bytes = self.get_checked(offset, 4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    #[inline]
    fn read_le_u64(&self, offset: usize) -> FsResult<u64> {
        let bytes = self.get_checked(offset, 8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }
}

/// Saturating divide that returns 0 for division by zero.
#[inline]
pub const fn saturating_div(a: u64, b: u64) -> u64 {
    if b == 0 {
        0
    } else {
        a / b
    }
}

/// Computes ceil(a / b) without overflow.
#[inline]
pub fn div_ceil(a: u64, b: u64) -> FsResult<u64> {
    if b == 0 {
        return Err(FsError::ArithmeticOverflow);
    }
    // (a + b - 1) / b, but avoid overflow
    let result = a / b;
    if a % b != 0 {
        result.checked_add(1).ok_or(FsError::ArithmeticOverflow)
    } else {
        Ok(result)
    }
}

/// Aligns a value up to the given alignment.
///
/// # Arguments
/// * `value` - Value to align
/// * `align` - Alignment (must be a power of 2)
#[inline]
pub fn align_up(value: u64, align: u64) -> FsResult<u64> {
    if !align.is_power_of_two() {
        return Err(FsError::AlignmentError);
    }
    let mask = align - 1;
    value
        .checked_add(mask)
        .map(|v| v & !mask)
        .ok_or(FsError::ArithmeticOverflow)
}

/// Aligns a value down to the given alignment.
///
/// # Arguments
/// * `value` - Value to align
/// * `align` - Alignment (must be a power of 2)
#[inline]
pub const fn align_down(value: u64, align: u64) -> u64 {
    if !align.is_power_of_two() {
        return value; // Fallback
    }
    value & !(align - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checked_add_overflow() {
        assert!(u64::MAX.checked_add_offset(1).is_err());
        assert_eq!(1u64.checked_add_offset(2).unwrap(), 3);
    }

    #[test]
    fn test_checked_mul_overflow() {
        assert!(u64::MAX.checked_mul_size(2).is_err());
        assert_eq!(3u64.checked_mul_size(4).unwrap(), 12);
    }

    #[test]
    fn test_read_be() {
        let data = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        assert_eq!(data.read_be_u16(0).unwrap(), 0x1234);
        assert_eq!(data.read_be_u32(0).unwrap(), 0x12345678);
        assert_eq!(data.read_be_u64(0).unwrap(), 0x123456789ABCDEF0);
    }

    #[test]
    fn test_read_buffer_bounds() {
        let data = [0x12, 0x34];
        assert!(data.read_be_u32(0).is_err());
    }

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 4).unwrap(), 0);
        assert_eq!(align_up(1, 4).unwrap(), 4);
        assert_eq!(align_up(4, 4).unwrap(), 4);
        assert_eq!(align_up(5, 4).unwrap(), 8);
    }

    #[test]
    fn test_div_ceil() {
        assert_eq!(div_ceil(0, 4).unwrap(), 0);
        assert_eq!(div_ceil(1, 4).unwrap(), 1);
        assert_eq!(div_ceil(4, 4).unwrap(), 1);
        assert_eq!(div_ceil(5, 4).unwrap(), 2);
    }
}
