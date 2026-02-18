//! Unicode string handling for Windows.
//!
//! Windows uses UTF-16 (wide strings) for all kernel APIs. This module
//! provides utilities for converting between UTF-8 and UTF-16, and for
//! working with Windows UNICODE_STRING structures.

use crate::error::{FsError, FsResult};

/// Maximum length for a Windows path component (characters).
pub const MAX_COMPONENT_LENGTH: usize = 255;

/// Maximum length for a full Windows path (characters).
pub const MAX_PATH_LENGTH: usize = 32767;

/// UNICODE_STRING structure for Windows kernel APIs.
///
/// This is a counted Unicode string, not null-terminated.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UnicodeString {
    /// Length of the string in bytes (not including any null terminator).
    pub length: u16,
    /// Maximum size of the Buffer in bytes.
    pub maximum_length: u16,
    /// Pointer to the wide string buffer.
    pub buffer: *mut u16,
}

impl UnicodeString {
    /// Creates a `UnicodeString` from a slice of wide characters.
    ///
    /// # Safety
    ///
    /// The buffer must remain valid for the lifetime of this structure.
    pub const unsafe fn from_slice(slice: &[u16]) -> Self {
        Self {
            length: (slice.len() * 2) as u16,
            maximum_length: (slice.len() * 2) as u16,
            buffer: slice.as_ptr() as *mut u16,
        }
    }

    /// Returns the string as a slice of wide characters.
    ///
    /// # Safety
    ///
    /// The buffer pointer must be valid.
    pub unsafe fn as_slice(&self) -> &[u16] {
        if self.buffer.is_null() {
            return &[];
        }
        let char_count = (self.length / 2) as usize;
        // SAFETY: Caller ensures buffer is valid
        unsafe { core::slice::from_raw_parts(self.buffer, char_count) }
    }

    /// Returns `true` if the string is empty.
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Returns the length in characters (not bytes).
    pub const fn char_len(&self) -> usize {
        (self.length / 2) as usize
    }
}

/// In-place wide string buffer for stack allocation.
///
/// This avoids heap allocation for common path operations.
#[repr(C)]
pub struct WideStringBuffer<const N: usize> {
    buffer: [u16; N],
    len: usize,
}

impl<const N: usize> WideStringBuffer<N> {
    /// Creates an empty buffer.
    pub const fn new() -> Self {
        Self {
            buffer: [0; N],
            len: 0,
        }
    }

    /// Creates from a UTF-8 string.
    pub fn from_utf8(s: &str) -> FsResult<Self> {
        let mut result = Self::new();
        result.push_utf8(s)?;
        Ok(result)
    }

    /// Appends a UTF-8 string.
    pub fn push_utf8(&mut self, s: &str) -> FsResult<()> {
        for c in s.encode_utf16() {
            if self.len >= N {
                return Err(FsError::StringTooLong);
            }
            self.buffer[self.len] = c;
            self.len += 1;
        }
        Ok(())
    }

    /// Appends a null terminator if there's room.
    pub fn push_null(&mut self) -> FsResult<()> {
        if self.len >= N {
            return Err(FsError::StringTooLong);
        }
        self.buffer[self.len] = 0;
        self.len += 1;
        Ok(())
    }

    /// Returns the buffer as a slice.
    pub fn as_slice(&self) -> &[u16] {
        &self.buffer[..self.len]
    }

    /// Returns the buffer as a null-terminated slice (includes the null).
    pub fn as_slice_with_null(&mut self) -> FsResult<&[u16]> {
        self.push_null()?;
        Ok(&self.buffer[..self.len])
    }

    /// Returns as a UNICODE_STRING.
    pub fn as_unicode_string(&self) -> UnicodeString {
        UnicodeString {
            length: (self.len * 2) as u16,
            maximum_length: (N * 2) as u16,
            buffer: self.buffer.as_ptr() as *mut u16,
        }
    }

    /// Returns the length in characters.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Clears the buffer.
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// Returns capacity in characters.
    pub const fn capacity(&self) -> usize {
        N
    }
}

impl<const N: usize> Default for WideStringBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Wrapper for heap-allocated wide strings.
///
/// Only available with the `alloc` feature.
#[cfg(feature = "alloc")]
pub struct WindowsString {
    buffer: alloc::vec::Vec<u16>,
}

#[cfg(feature = "alloc")]
impl WindowsString {
    /// Creates a new empty WindowsString.
    pub fn new() -> Self {
        Self {
            buffer: alloc::vec::Vec::new(),
        }
    }

    /// Creates from a UTF-8 string.
    pub fn from_utf8(utf8: &str) -> FsResult<Self> {
        let wide: alloc::vec::Vec<u16> = utf8
            .encode_utf16()
            .chain(core::iter::once(0)) // Null terminator
            .collect();

        if wide.len() > MAX_PATH_LENGTH {
            return Err(FsError::StringTooLong);
        }

        Ok(Self { buffer: wide })
    }

    /// Creates a UNICODE_STRING pointing to this buffer.
    pub fn as_unicode_string(&self) -> UnicodeString {
        let len = if self.buffer.is_empty() {
            0
        } else {
            // Length excludes null terminator
            (self.buffer.len() - 1) * 2
        };

        UnicodeString {
            length: len as u16,
            maximum_length: (self.buffer.len() * 2) as u16,
            buffer: self.buffer.as_ptr() as *mut u16,
        }
    }

    /// Returns the buffer as a slice (including null terminator).
    pub fn as_slice(&self) -> &[u16] {
        &self.buffer
    }

    /// Returns the length in characters (excluding null terminator).
    pub fn len(&self) -> usize {
        if self.buffer.is_empty() {
            0
        } else {
            self.buffer.len() - 1
        }
    }

    /// Returns `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.len() <= 1
    }
}

#[cfg(feature = "alloc")]
impl Default for WindowsString {
    fn default() -> Self {
        Self::new()
    }
}

/// Compares two wide strings case-insensitively (ASCII only).
///
/// For proper Unicode case folding, use Windows APIs like
/// `RtlCompareUnicodeString`.
pub fn ascii_iequals(a: &[u16], b: &[u16]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (ca, cb) in a.iter().zip(b.iter()) {
        let ca_lower = if *ca >= 'A' as u16 && *ca <= 'Z' as u16 {
            ca + 32
        } else {
            *ca
        };
        let cb_lower = if *cb >= 'A' as u16 && *cb <= 'Z' as u16 {
            cb + 32
        } else {
            *cb
        };
        if ca_lower != cb_lower {
            return false;
        }
    }
    true
}

/// Validates that a string contains only valid filename characters.
///
/// Invalid characters: \ / : * ? " < > |
pub fn is_valid_filename(s: &[u16]) -> bool {
    const INVALID: [u16; 9] = [
        '\\' as u16,
        '/' as u16,
        ':' as u16,
        '*' as u16,
        '?' as u16,
        '"' as u16,
        '<' as u16,
        '>' as u16,
        '|' as u16,
    ];

    for c in s {
        if *c == 0 || INVALID.contains(c) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wide_buffer_utf8() {
        let mut buf = WideStringBuffer::<64>::from_utf8("Hello").unwrap();
        assert_eq!(buf.len(), 5);
        buf.push_utf8(" World").unwrap();
        assert_eq!(buf.len(), 11);
    }

    #[test]
    fn test_wide_buffer_overflow() {
        let result = WideStringBuffer::<3>::from_utf8("Hello");
        assert!(result.is_err());
    }

    #[test]
    fn test_ascii_iequals() {
        let a = [
            b'H' as u16,
            b'e' as u16,
            b'l' as u16,
            b'l' as u16,
            b'o' as u16,
        ];
        let b = [
            b'h' as u16,
            b'E' as u16,
            b'L' as u16,
            b'L' as u16,
            b'O' as u16,
        ];
        assert!(ascii_iequals(&a, &b));
    }

    #[test]
    fn test_is_valid_filename() {
        let valid = [b't' as u16, b'e' as u16, b's' as u16, b't' as u16];
        assert!(is_valid_filename(&valid));

        let invalid = [b't' as u16, b'*' as u16];
        assert!(!is_valid_filename(&invalid));
    }
}
