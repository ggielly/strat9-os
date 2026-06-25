//! Low-level helpers for encoding/decoding [`IpcMessage`] payloads.
//!
//! # Layers
//!
//! 1. **Scalar helpers** : `put_u16`/`get_u16`, `put_u32`/`get_u32`, `put_u64`/`get_u64`.
//! 2. **Variable-length helpers** : `put_bytes`/`get_bytes`, `put_str`/`get_str`.
//! 3. **Fixed-size helpers** : `encode_fixed`/`decode_fixed` for `repr(C)` zerocopy structs.
//! 4. **`InlineBlobHeader`** : minimal framing for inline variable-length data.
//!
//! All helpers are bounds-checked: they return `Option` instead of panicking.
//!
//! # Payload layout conventions
//!
//! - **Fixed messages**: the entire `payload[0..48]` (or a prefix) is a
//!   `repr(C)` struct.  Use `encode_fixed`/`decode_fixed`.
//! - **Variable messages**: the fixed-size part goes first (e.g. flags + u64s),
//!   followed by an [`InlineBlobHeader`] (4 bytes) and the inline data.
//!   Use the put/get helpers for the fixed part, then `InlineBlobHeader::write`
//!   for the variable tail.
//!
//! # Safety
//!
//! All functions are pure safe-Rust : no `unsafe` required at this layer.
//! The zerocopy traits used by payload structs are derived safely.
use crate::data::IpcMessage;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Capacity of the `IpcMessage.payload` field.
pub const PAYLOAD_CAPACITY: usize = IpcMessage::PAYLOAD_CAPACITY;

// ===========================================================================
// Scalar helpers : bounds-checked get/put for plain integer types
// ===========================================================================

/// Write a `u16` at offset `off` (little-endian).
#[inline]
pub fn put_u16(payload: &mut [u8], off: usize, v: u16) -> Option<()> {
    let end = off.checked_add(2)?;
    let buf = payload.get_mut(off..end)?;
    buf.copy_from_slice(&v.to_le_bytes());
    Some(())
}

/// Read a `u16` at offset `off` (little-endian), or `None` if out of bounds.
#[inline]
pub fn get_u16(payload: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    let buf = payload.get(off..end)?;
    Some(u16::from_le_bytes([buf[0], buf[1]]))
}

/// Write a `u32` at offset `off` (little-endian).
#[inline]
pub fn put_u32(payload: &mut [u8], off: usize, v: u32) -> Option<()> {
    let end = off.checked_add(4)?;
    let buf = payload.get_mut(off..end)?;
    buf.copy_from_slice(&v.to_le_bytes());
    Some(())
}

/// Read a `u32` at offset `off` (little-endian), or `None` if out of bounds.
#[inline]
pub fn get_u32(payload: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let buf = payload.get(off..end)?;
    Some(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
}

/// Write an `i32` at offset `off` (little-endian).
#[inline]
pub fn put_i32(payload: &mut [u8], off: usize, v: i32) -> Option<()> {
    put_u32(payload, off, v as u32)
}

/// Read an `i32` at offset `off` (little-endian), or `None` if out of bounds.
#[inline]
pub fn get_i32(payload: &[u8], off: usize) -> Option<i32> {
    Some(get_u32(payload, off)? as i32)
}

/// Write a `u64` at offset `off` (little-endian).
#[inline]
pub fn put_u64(payload: &mut [u8], off: usize, v: u64) -> Option<()> {
    let end = off.checked_add(8)?;
    let buf = payload.get_mut(off..end)?;
    buf.copy_from_slice(&v.to_le_bytes());
    Some(())
}

/// Read a `u64` at offset `off` (little-endian), or `None` if out of bounds.
#[inline]
pub fn get_u64(payload: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    let buf = payload.get(off..end)?;
    Some(u64::from_le_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]))
}

// ===========================================================================
// Variable-length helpers
// ===========================================================================

/// Copy `src` into `payload[off..off + src.len()]`.
/// Returns `None` if the slice does not fit (overflow or out of bounds).
#[inline]
pub fn put_bytes(payload: &mut [u8], off: usize, src: &[u8]) -> Option<()> {
    let end = off.checked_add(src.len())?;
    let dst = payload.get_mut(off..end)?;
    dst.copy_from_slice(src);
    Some(())
}

/// Return a reference to `payload[off..off + len]`.
/// Returns `None` if the range is out of bounds.
#[inline]
pub fn get_bytes(payload: &[u8], off: usize, len: usize) -> Option<&[u8]> {
    let end = off.checked_add(len)?;
    payload.get(off..end)
}

/// Encode a UTF-8 string into `payload[off..]`.
/// Returns `None` if the string does not fit.
#[inline]
pub fn put_str(payload: &mut [u8], off: usize, s: &str) -> Option<()> {
    put_bytes(payload, off, s.as_bytes())
}

/// Decode a UTF-8 string of `len` bytes from `payload[off..]`.
/// Returns `None` if out of bounds or invalid UTF-8.
#[inline]
pub fn get_str(payload: &[u8], off: usize, len: usize) -> Option<&str> {
    let bytes = get_bytes(payload, off, len)?;
    core::str::from_utf8(bytes).ok()
}

// ===========================================================================
// Fixed-size payload helpers
// ===========================================================================

/// Encode a fixed-size `repr(C)` struct as an [`IpcMessage`].
///
/// The body is written directly into `payload[0..size_of::<T>()]`.
/// Panics in debug if `T` exceeds [`PAYLOAD_CAPACITY`]; in release the write
/// silently truncates.
pub fn encode_fixed<T: IntoBytes + Immutable>(msg_type: u32, body: &T) -> IpcMessage {
    let mut msg = IpcMessage::new(msg_type);
    let src = body.as_bytes();
    debug_assert!(src.len() <= PAYLOAD_CAPACITY, "encode_fixed: T too large");
    let n = src.len().min(PAYLOAD_CAPACITY);
    msg.payload[..n].copy_from_slice(&src[..n]);
    msg
}

/// Encode a fixed-size reply targeting `sender`.
pub fn encode_fixed_reply<T: IntoBytes + Immutable>(
    sender: u64,
    msg_type: u32,
    body: &T,
) -> IpcMessage {
    let mut msg = encode_fixed(msg_type, body);
    msg.sender = sender;
    msg
}

/// Try to decode a fixed-size `repr(C)` struct from an [`IpcMessage`] payload.
///
/// Returns `None` if:
/// - `T` is larger than [`PAYLOAD_CAPACITY`] (size overflow), or
/// - the payload slice is not correctly aligned for `T` (alignment mismatch).
pub fn decode_fixed<T: FromBytes + Immutable + KnownLayout>(
    msg: &IpcMessage,
) -> Option<&T> {
    let size = core::mem::size_of::<T>();
    if size > PAYLOAD_CAPACITY {
        return None;
    }
    T::ref_from_bytes(&msg.payload[..size]).ok()
}

// ===========================================================================
// InlineBlobHeader : minimal framing for variable-length inline data
// ===========================================================================

/// Minimal framing header for variable-length data embedded in an IPC payload.
///
/// Layout (4 bytes): `[len: u16, kind: u16]`.
///
/// - `len`: number of data bytes that follow this header.
/// - `kind`: discriminator (e.g. `0` = path, `1` = blob data).
///
/// This lets you embed a variable-length segment in the 48-byte payload
/// without external allocators or serde.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub struct InlineBlobHeader {
    pub len: u16,
    pub kind: u16,
}

impl InlineBlobHeader {
    /// Number of wire bytes consumed by the header itself.
    pub const SIZE: usize = 4;

    /// Write `InlineBlobHeader(len, kind)` followed by `data` into
    /// `payload[off..]`.
    ///
    /// Returns `None` if the header + data do not fit in the payload slice.
    pub fn write(payload: &mut [u8], off: usize, kind: u16, data: &[u8]) -> Option<()> {
        let total = Self::SIZE.checked_add(data.len())?;
        let end = off.checked_add(total)?;
        let buf = payload.get_mut(off..end)?;
        buf[..2].copy_from_slice(&(data.len() as u16).to_le_bytes());
        buf[2..4].copy_from_slice(&kind.to_le_bytes());
        buf[Self::SIZE..].copy_from_slice(data);
        Some(())
    }

    /// Parse an `InlineBlobHeader` from `payload[off..]`.
    ///
    /// Returns `None` if the 4 header bytes are out of bounds.
    pub fn parse(payload: &[u8], off: usize) -> Option<Self> {
        let end = off.checked_add(Self::SIZE)?;
        let buf = payload.get(off..end)?;
        Some(Self {
            len: u16::from_le_bytes([buf[0], buf[1]]),
            kind: u16::from_le_bytes([buf[2], buf[3]]),
        })
    }

    /// Return the total wire size of this header + its inline data.
    pub fn total_size(&self) -> usize {
        Self::SIZE + self.len as usize
    }
}

static_assertions::assert_eq_size!(InlineBlobHeader, [u8; 4]);
