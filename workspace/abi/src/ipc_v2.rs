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

//! IPC ABI v2 types and constants.
//!
//! Mirrors `docs-site/src/ipc-abi-v2.md` §3, §4, §9.2 and §13. Every struct
//! here is `repr(C)` with explicit padding, so no uninitialised byte can
//! cross the user/kernel boundary. The `tests/ipc_v2_layout.rs` integration
//! test pins every size, alignment and field offset.

use core::sync::atomic::AtomicU32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// ===========================================================================
// §3.1 Handle encoding
// ===========================================================================

/// Bits 0..24 of a handle: index into the process handle table.
pub const HANDLE_INDEX_BITS: u32 = 24;
/// Bit position of the generation field.
pub const HANDLE_GEN_SHIFT: u32 = 24;
/// Mask selecting the index field.
pub const HANDLE_INDEX_MASK: u64 = (1 << 24) - 1;
/// Mask selecting the generation field (32 bits).
const HANDLE_GEN_MASK: u64 = 0xFFFF_FFFF;
/// Bits 56..64 are always zero, keeping handles out of the error window.
const HANDLE_HIGH_BYTE_MASK: u64 = 1 << 56;

/// A process-local capability handle.
///
/// Layout: `[63:56] = 0`, `[55:24] = generation`, `[23:0] = table index`.
/// Value `0` is never valid, and the high byte is always zero so a handle in
/// `RAX` never looks like a negative errno.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Handle(u64);

impl Handle {
    /// Build a handle from a table index and a generation.
    ///
    /// The index is masked to 24 bits, the generation to 32 bits; bits
    /// 56..64 of the result are always zero.
    pub const fn new(index: u32, generation: u32) -> Self {
        let raw = (index as u64 & HANDLE_INDEX_MASK)
            | ((generation as u64 & HANDLE_GEN_MASK) << HANDLE_GEN_SHIFT);
        Self(raw)
    }

    /// The raw 64-bit value.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// The table index (`[23:0]`).
    pub const fn index(self) -> u32 {
        (self.0 & HANDLE_INDEX_MASK) as u32
    }

    /// The generation (`[55:24]`).
    pub const fn generation(self) -> u32 {
        ((self.0 >> HANDLE_GEN_SHIFT) & HANDLE_GEN_MASK) as u32
    }

    /// A handle is valid when it is non-zero and bits 56..64 are zero.
    pub const fn is_valid(self) -> bool {
        self.0 != 0 && (self.0 & HANDLE_HIGH_BYTE_MASK) == 0
    }

    /// Rebuild a handle from a raw value, forcing bits 56..64 to zero.
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw & (HANDLE_HIGH_BYTE_MASK - 1))
    }
}

// ===========================================================================
// §4.1 Message header
// ===========================================================================

/// 40 bytes, align 8. Fields marked (K) are written by the kernel on receive;
/// on send they must be zero.
#[repr(C)]
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
pub struct MsgHeader {
    /// Protocol opcode, chosen by the sender.
    pub label: u32,
    /// Valid bytes in the data buffer.
    pub data_len: u32,
    /// Number of `CapXfer` entries used.
    pub ncaps: u16,
    /// Protocol flags, opaque to the kernel.
    pub flags: u16,
    /// (K) `MSG_KIND_*`.
    pub kind: u8,
    /// Must be zero.
    pub _rsvd0: [u8; 3],
    /// (K) sid of the sender silo, or 0 (see `EP_FLAG_SENDER_SILO`).
    pub sender_silo: u32,
    /// Must be zero.
    pub _rsvd1: u32,
    /// (K) badge of the SEND handle, or signalled bits.
    pub badge: u64,
    /// (K) Reply handle when `kind == MSG_KIND_CALL`, else 0.
    pub reply: u64,
}

/// One-way message.
pub const MSG_KIND_SEND: u8 = 1;
/// Request that expects a reply in `MsgHeader::reply`.
pub const MSG_KIND_CALL: u8 = 2;
/// Bound notification fired; `badge` holds the signalled bits.
pub const MSG_KIND_NOTIF: u8 = 3;
/// Written into the caller's response header.
pub const MSG_KIND_REPLY: u8 = 4;

// ===========================================================================
// §4.2 Capability transfer entries
// ===========================================================================

/// 16 bytes. On send: describes a handle to transfer. On receive: rewritten
/// with the new handle, its rights and its type.
#[repr(C)]
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
pub struct CapXfer {
    /// send: source handle | recv: new handle in receiver table
    pub handle: u64,
    /// send: rights mask (`RIGHTS_SAME` keeps all) | recv: effective rights
    pub rights: u32,
    /// send: `XFER_MOVE` | `XFER_COPY` | recv: `ObjType`
    pub mode: u32,
}

/// Source handle is removed on commit.
pub const XFER_MOVE: u32 = 1;
/// Requires `RIGHT_DUPLICATE` on the source.
pub const XFER_COPY: u32 = 2;
/// Keep all source rights.
pub const RIGHTS_SAME: u32 = u32::MAX;

// ===========================================================================
// §4.3 Buffer descriptors
// ===========================================================================

/// 32 bytes. Passed by pointer to every message syscall.
#[repr(C)]
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
pub struct MsgBuf {
    /// `*mut MsgHeader`
    pub hdr: u64,
    /// `*mut u8`
    pub data: u64,
    /// Capacity of `data` (receive side); ignored on send.
    pub data_cap: u32,
    /// Capacity of `caps` in entries.
    pub caps_cap: u32,
    /// `*mut CapXfer`
    pub caps: u64,
}

/// 64 bytes: request and response buffer descriptors for `SYS_EP_CALL`.
#[repr(C)]
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
pub struct MsgCall {
    /// Request buffers.
    pub req: MsgBuf,
    /// Response buffers.
    pub resp: MsgBuf,
}

/// Maximum inline message payload.
pub const IPC_MAX_DATA: usize = 4096;
/// Maximum number of capabilities per message.
pub const IPC_MAX_CAPS: usize = 4;

// ===========================================================================
// §13 common flags and §5 endpoint / §7 notification / §9 memobject rights
// ===========================================================================

/// `IPC_NONBLOCK` (bit 0 of the syscall `flags` argument).
pub const IPC_NONBLOCK: u32 = 1;

/// Kernel fills `MsgHeader::sender_silo` on every message (bit 0).
pub const EP_FLAG_SENDER_SILO: u32 = 1;
/// Hint: favour direct switch on `call` (bit 1).
pub const EP_FLAG_FASTPATH: u32 = 2;

// Generic rights (low byte, §3.2).
/// Handle may be placed in a message or granted.
pub const RIGHT_TRANSFER: u32 = 1 << 0;
/// `SYS_HANDLE_DUPLICATE` allowed.
pub const RIGHT_DUPLICATE: u32 = 1 << 1;
/// `SYS_HANDLE_INFO` allowed.
pub const RIGHT_INSPECT: u32 = 1 << 2;
/// Usable with `SYS_HANDLE_WAIT` / async poll.
pub const RIGHT_WAIT: u32 = 1 << 3;
/// Mask of all generic rights.
pub const GENERIC_RIGHTS_MASK: u32 = 0xF;

// Endpoint rights.
/// `send`, `call`.
pub const EP_SEND: u32 = 1 << 8;
/// `recv`, `reply_recv`.
pub const EP_RECV: u32 = 1 << 9;
/// Derive badged SEND handles.
pub const EP_MINT: u32 = 1 << 10;
/// Messages through this handle may carry handles.
pub const EP_XFER: u32 = 1 << 11;

// Notification rights.
/// `notif_signal`.
pub const NOTIF_SIGNAL: u32 = 1 << 8;
/// `notif_wait`.
pub const NOTIF_WAIT: u32 = 1 << 9;
/// Derive badged SIGNAL handles.
pub const NOTIF_MINT: u32 = 1 << 10;

// MemObject rights.
/// Readable mapping.
pub const MEM_READ: u32 = 1 << 8;
/// Writable mapping.
pub const MEM_WRITE: u32 = 1 << 9;
/// Executable mapping.
pub const MEM_EXEC: u32 = 1 << 10;
/// May be mapped at all.
pub const MEM_MAP: u32 = 1 << 11;

/// `SYS_MEMOBJ_MAP` protection: readable (POSIX `PROT_READ`).
pub const MEMOBJ_PROT_READ: u32 = 1;
/// `SYS_MEMOBJ_MAP` protection: writable (POSIX `PROT_WRITE`).
pub const MEMOBJ_PROT_WRITE: u32 = 2;
/// `SYS_MEMOBJ_MAP` protection: executable (POSIX `PROT_EXEC`).
pub const MEMOBJ_PROT_EXEC: u32 = 4;
/// Largest MemObject `SYS_MEMOBJ_CREATE` accepts (64 MiB).
pub const MEMOBJ_MAX_SIZE: u64 = 64 * 1024 * 1024;

/// `ObjType` values reported in a received `CapXfer::mode` (§2).
pub const OBJ_ENDPOINT: u32 = 1;
/// Reply object.
pub const OBJ_REPLY: u32 = 2;
/// Notification object.
pub const OBJ_NOTIFICATION: u32 = 3;
/// Memory object.
pub const OBJ_MEMOBJ: u32 = 4;

/// Default endpoint queue depth when `SYS_EP_CREATE` is passed `0`.
pub const EP_DEFAULT_QUEUE_DEPTH: u32 = 16;
/// Maximum endpoint queue depth.
pub const EP_MAX_QUEUE_DEPTH: u32 = 256;

// ===========================================================================
// §9.2 Ring protocol
// ===========================================================================

/// `RingHeader::magic` value, `b"S9RG"` little-endian.
pub const RING_MAGIC: u32 = u32::from_le_bytes(*b"S9RG");
/// `RingHeader::version`.
pub const RING_VERSION: u16 = 1;
/// Producer needs a wakeup on "space".
pub const RING_NEED_WAKEUP: u32 = 1;

/// First 192 bytes of an N2 shared-ring `MemObject`.
///
/// The atomics are kept as-is, so `RingHeader` itself cannot derive
/// zerocopy's byte-traits (atomics are not `FromBytes`/`IntoBytes`). Use
/// [`RingHeaderFields`] for a byte-compatible mirror with plain `u32`s, and
/// the `tail()`/`prod_flags()`/`head()`/`cons_flags()` accessors to reach the
/// atomics.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct RingHeader {
    /// `b"S9RG"`.
    pub magic: u32,
    /// Protocol version (1).
    pub version: u16,
    /// Must be zero.
    pub _rsvd0: u16,
    /// Bytes per slot, multiple of 64.
    pub slot_size: u32,
    /// Number of slots, power of two.
    pub slot_count: u32,
    /// Padding up to the producer cache line.
    pub _pad0: [u8; 48],
    // --- producer cache line (offset 64) ---
    /// Written by producer only (Release).
    pub tail: AtomicU32,
    /// `RING_NEED_WAKEUP`: producer sleeps on "space".
    pub prod_flags: AtomicU32,
    /// Padding up to the consumer cache line.
    pub _pad1: [u8; 56],
    // --- consumer cache line (offset 128) ---
    /// Written by consumer only (Release).
    pub head: AtomicU32,
    /// `RING_NEED_WAKEUP`: consumer sleeps on "data".
    pub cons_flags: AtomicU32,
    /// Padding.
    pub _pad2: [u8; 56],
}

impl RingHeader {
    /// Producer write index atomic.
    pub fn tail(&self) -> &AtomicU32 {
        &self.tail
    }
    /// Producer wakeup flags atomic.
    pub fn prod_flags(&self) -> &AtomicU32 {
        &self.prod_flags
    }
    /// Consumer read index atomic.
    pub fn head(&self) -> &AtomicU32 {
        &self.head
    }
    /// Consumer wakeup flags atomic.
    pub fn cons_flags(&self) -> &AtomicU32 {
        &self.cons_flags
    }
}

impl Default for RingHeader {
    fn default() -> Self {
        Self {
            magic: 0,
            version: 0,
            _rsvd0: 0,
            slot_size: 0,
            slot_count: 0,
            _pad0: [0; 48],
            tail: AtomicU32::new(0),
            prod_flags: AtomicU32::new(0),
            _pad1: [0; 56],
            head: AtomicU32::new(0),
            cons_flags: AtomicU32::new(0),
            _pad2: [0; 56],
        }
    }
}

/// Byte-compatible mirror of [`RingHeader`] using plain `u32` fields, so it
/// derives zerocopy's `FromBytes`/`IntoBytes`/`Immutable`/`KnownLayout`.
///
/// A const assertion below pins it to 192 bytes; it shares `RingHeader`'s
/// field offsets because `AtomicU32` has the same layout as `u32`.
#[repr(C, align(64))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct RingHeaderFields {
    /// `b"S9RG"`.
    pub magic: u32,
    /// Protocol version (1).
    pub version: u16,
    /// Must be zero.
    pub _rsvd0: u16,
    /// Bytes per slot, multiple of 64.
    pub slot_size: u32,
    /// Number of slots, power of two.
    pub slot_count: u32,
    /// Padding up to the producer cache line.
    pub _pad0: [u8; 48],
    /// Producer write index.
    pub tail: u32,
    /// Producer wakeup flags.
    pub prod_flags: u32,
    /// Padding up to the consumer cache line.
    pub _pad1: [u8; 56],
    /// Consumer read index.
    pub head: u32,
    /// Consumer wakeup flags.
    pub cons_flags: u32,
    /// Padding.
    pub _pad2: [u8; 56],
}

impl Default for RingHeaderFields {
    fn default() -> Self {
        Self {
            magic: 0,
            version: 0,
            _rsvd0: 0,
            slot_size: 0,
            slot_count: 0,
            _pad0: [0; 48],
            tail: 0,
            prod_flags: 0,
            _pad1: [0; 56],
            head: 0,
            cons_flags: 0,
            _pad2: [0; 56],
        }
    }
}

const _: () = assert!(core::mem::size_of::<RingHeaderFields>() == 192);
const _: () = assert!(core::mem::size_of::<RingHeader>() == 192);
