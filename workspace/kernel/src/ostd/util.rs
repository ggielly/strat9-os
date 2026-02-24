//! Utility types and functions for OSTD
//!
//! Provides common utility types including:
//! - ID sets for CPU/task sets
//! - Bit manipulation helpers
//! - Other common utilities

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

/// A set of IDs (e.g., CPU IDs, task IDs)
///
/// Efficiently stores sets of IDs using bitmaps for small IDs
/// and fallback vectors for sparse large IDs.
#[derive(Debug, Clone)]
pub struct IdSet {
    /// Bitmap for IDs 0-63
    low_bits: u64,
    /// Vector for IDs >= 64
    high_ids: Vec<usize>,
}

impl IdSet {
    /// Creates a new empty ID set
    pub const fn new() -> Self {
        Self {
            low_bits: 0,
            high_ids: Vec::new(),
        }
    }

    /// Creates an ID set containing all IDs from 0 to max
    pub fn all(max: usize) -> Self {
        let mut set = Self::new();
        for i in 0..=max {
            set.insert(i);
        }
        set
    }

    /// Inserts an ID into the set
    pub fn insert(&mut self, id: usize) {
        if id < 64 {
            self.low_bits |= 1 << id;
        } else {
            if !self.high_ids.contains(&id) {
                self.high_ids.push(id);
            }
        }
    }

    /// Removes an ID from the set
    pub fn remove(&mut self, id: usize) {
        if id < 64 {
            self.low_bits &= !(1 << id);
        } else {
            self.high_ids.retain(|&x| x != id);
        }
    }

    /// Checks if an ID is in the set
    pub fn contains(&self, id: usize) -> bool {
        if id < 64 {
            (self.low_bits & (1 << id)) != 0
        } else {
            self.high_ids.contains(&id)
        }
    }

    /// Returns true if the set is empty
    pub fn is_empty(&self) -> bool {
        self.low_bits == 0 && self.high_ids.is_empty()
    }

    /// Returns the number of IDs in the set
    pub fn len(&self) -> usize {
        self.low_bits.count_ones() as usize + self.high_ids.len()
    }

    /// Clears the set
    pub fn clear(&mut self) {
        self.low_bits = 0;
        self.high_ids.clear();
    }

    /// Returns an iterator over the IDs in the set
    pub fn iter(&self) -> IdSetIter<'_> {
        IdSetIter {
            low_bits: self.low_bits,
            low_index: 0,
            high_iter: self.high_ids.iter(),
        }
    }
}

impl Default for IdSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Iterator over IDs in an IdSet
pub struct IdSetIter<'a> {
    low_bits: u64,
    low_index: usize,
    high_iter: core::slice::Iter<'a, usize>,
}

impl<'a> Iterator for IdSetIter<'a> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        // Check low bits first
        while self.low_index < 64 {
            if (self.low_bits & (1 << self.low_index)) != 0 {
                let id = self.low_index;
                self.low_index += 1;
                return Some(id);
            }
            self.low_index += 1;
        }

        // Then check high IDs
        self.high_iter.next().copied()
    }
}

/// A CPU set for tracking which CPUs are online/active
pub type CpuSet = IdSet;

/// Bit manipulation utilities
pub mod bits {
    /// Aligns a value up to the given alignment
    #[inline]
    pub const fn align_up(value: usize, align: usize) -> usize {
        (value + align - 1) & !(align - 1)
    }

    /// Aligns a value down to the given alignment
    #[inline]
    pub const fn align_down(value: usize, align: usize) -> usize {
        value & !(align - 1)
    }

    /// Checks if a value is aligned to the given alignment
    #[inline]
    pub const fn is_aligned(value: usize, align: usize) -> bool {
        value & (align - 1) == 0
    }

    /// Returns the number of leading zeros in a u64
    #[inline]
    pub const fn leading_zeros(x: u64) -> u32 {
        x.leading_zeros()
    }

    /// Returns the number of trailing zeros in a u64
    #[inline]
    pub const fn trailing_zeros(x: u64) -> u32 {
        x.trailing_zeros()
    }

    /// Returns the number of set bits in a u64
    #[inline]
    pub const fn count_ones(x: u64) -> u32 {
        x.count_ones()
    }

    /// Returns the next power of two greater than or equal to x
    #[inline]
    pub const fn next_power_of_two(mut x: usize) -> usize {
        if x == 0 {
            return 1;
        }
        x -= 1;
        x |= x >> 1;
        x |= x >> 2;
        x |= x >> 4;
        x |= x >> 8;
        x |= x >> 16;
        #[cfg(target_pointer_width = "64")]
        {
            x |= x >> 32;
        }
        x + 1
    }

    /// Returns the log2 of x, rounded down
    #[inline]
    pub const fn log2_floor(x: usize) -> u32 {
        if x == 0 {
            return 0;
        }
        31 - x.leading_zeros()
    }

    /// Returns the log2 of x, rounded up
    #[inline]
    pub const fn log2_ceil(x: usize) -> u32 {
        if x == 0 {
            return 0;
        }
        let floor = log2_floor(x);
        if x.is_power_of_two() {
            floor
        } else {
            floor + 1
        }
    }
}

/// Round up a value to the nearest multiple of align
#[inline]
pub const fn round_up(value: usize, align: usize) -> usize {
    bits::align_up(value, align)
}

/// Round down a value to the nearest multiple of align
#[inline]
pub const fn round_down(value: usize, align: usize) -> usize {
    bits::align_down(value, align)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("out of memory")]
    OutOfMemory,
    #[error("invalid argument")]
    InvalidArgument,
    #[error("not found")]
    NotFound,
    #[error("already exists")]
    AlreadyExists,
    #[error("permission denied")]
    PermissionDenied,
    #[error("busy")]
    Busy,
    #[error("page fault")]
    PageFault,
    #[error("architecture error: {0}")]
    ArchError(&'static str),
}

/// Result type alias for OSTD operations
pub type Result<T> = core::result::Result<T, Error>;
