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

//! ABI v2 layout, handle encoding, syscall numbers and errno pinning.
//!
//! Mirrors `docs-site/src/ipc-abi-v2.md` §14 "Required ABI tests". A failure
//! here means the kernel and userspace no longer agree on the wire layout.

use core::mem::{align_of, offset_of, size_of};
use strat9_abi::{errno::*, ipc_v2::*, syscall::*};

fn assert_into_bytes<T: zerocopy::IntoBytes>() {}
fn assert_from_bytes<T: zerocopy::FromBytes>() {}

// ===========================================================================
// §4 sizes and alignments
// ===========================================================================

#[test]
fn message_struct_sizes_and_alignments() {
    assert_eq!(size_of::<MsgHeader>(), 40);
    assert_eq!(align_of::<MsgHeader>(), 8);

    assert_eq!(size_of::<CapXfer>(), 16);
    assert_eq!(align_of::<CapXfer>(), 8);

    assert_eq!(size_of::<MsgBuf>(), 32);
    assert_eq!(align_of::<MsgBuf>(), 8);

    assert_eq!(size_of::<MsgCall>(), 64);
    assert_eq!(align_of::<MsgCall>(), 8);

    assert_eq!(size_of::<RingHeader>(), 192);
    assert_eq!(align_of::<RingHeader>(), 64);

    assert_eq!(size_of::<RingHeaderFields>(), 192);
    assert_eq!(align_of::<RingHeaderFields>(), 64);
}

// ===========================================================================
// §4.1 field offsets
// ===========================================================================

#[test]
fn msg_header_offsets() {
    assert_eq!(offset_of!(MsgHeader, label), 0);
    assert_eq!(offset_of!(MsgHeader, data_len), 4);
    assert_eq!(offset_of!(MsgHeader, ncaps), 8);
    assert_eq!(offset_of!(MsgHeader, flags), 10);
    assert_eq!(offset_of!(MsgHeader, kind), 12);
    assert_eq!(offset_of!(MsgHeader, _rsvd0), 13);
    assert_eq!(offset_of!(MsgHeader, sender_silo), 16);
    assert_eq!(offset_of!(MsgHeader, _rsvd1), 20);
    assert_eq!(offset_of!(MsgHeader, badge), 24);
    assert_eq!(offset_of!(MsgHeader, reply), 32);
}

#[test]
fn cap_xfer_offsets() {
    assert_eq!(offset_of!(CapXfer, handle), 0);
    assert_eq!(offset_of!(CapXfer, rights), 8);
    assert_eq!(offset_of!(CapXfer, mode), 12);
}

#[test]
fn msg_buf_offsets() {
    assert_eq!(offset_of!(MsgBuf, hdr), 0);
    assert_eq!(offset_of!(MsgBuf, data), 8);
    assert_eq!(offset_of!(MsgBuf, data_cap), 16);
    assert_eq!(offset_of!(MsgBuf, caps_cap), 20);
    assert_eq!(offset_of!(MsgBuf, caps), 24);
}

#[test]
fn msg_call_offsets() {
    assert_eq!(offset_of!(MsgCall, req), 0);
    assert_eq!(offset_of!(MsgCall, resp), 32);
}

#[test]
fn ring_header_offsets() {
    assert_eq!(offset_of!(RingHeader, magic), 0);
    assert_eq!(offset_of!(RingHeader, version), 4);
    assert_eq!(offset_of!(RingHeader, _rsvd0), 6);
    assert_eq!(offset_of!(RingHeader, slot_size), 8);
    assert_eq!(offset_of!(RingHeader, slot_count), 12);
    assert_eq!(offset_of!(RingHeader, _pad0), 16);
    assert_eq!(offset_of!(RingHeader, tail), 64);
    assert_eq!(offset_of!(RingHeader, prod_flags), 68);
    assert_eq!(offset_of!(RingHeader, _pad1), 72);
    assert_eq!(offset_of!(RingHeader, head), 128);
    assert_eq!(offset_of!(RingHeader, cons_flags), 132);
    assert_eq!(offset_of!(RingHeader, _pad2), 136);

    // The mirror must share the same offsets.
    assert_eq!(offset_of!(RingHeaderFields, tail), 64);
    assert_eq!(offset_of!(RingHeaderFields, prod_flags), 68);
    assert_eq!(offset_of!(RingHeaderFields, head), 128);
    assert_eq!(offset_of!(RingHeaderFields, cons_flags), 132);
}

// ===========================================================================
// §14: zerocopy derives compile (no implicit padding)
// ===========================================================================

#[test]
fn byte_traits_are_implemented() {
    assert_into_bytes::<MsgHeader>();
    assert_into_bytes::<CapXfer>();
    assert_into_bytes::<MsgBuf>();
    assert_into_bytes::<MsgCall>();
    assert_into_bytes::<RingHeaderFields>();

    assert_from_bytes::<MsgHeader>();
    assert_from_bytes::<CapXfer>();
    assert_from_bytes::<MsgBuf>();
    assert_from_bytes::<MsgCall>();
    assert_from_bytes::<RingHeaderFields>();

    // And they round-trip through bytes at runtime.
    let buf = MsgBuf::default();
    let bytes = zerocopy::IntoBytes::as_bytes(&buf);
    assert_eq!(bytes.len(), size_of::<MsgBuf>());
}

// ===========================================================================
// §3.1 handle encoding
// ===========================================================================

#[test]
fn handle_round_trips() {
    for &index in &[0u32, 1, 2, 255, 4096, (1 << 24) - 1] {
        for &generation in &[0u32, 1, 2, 0xFFFF, u32::MAX] {
            let h = Handle::new(index, generation);
            assert_eq!(h.index(), index);
            assert_eq!(h.generation(), generation);
            assert_eq!(Handle::from_raw(h.raw()), h);
        }
    }
}

#[test]
fn handle_high_byte_always_zero() {
    for &index in &[0u32, 1, u32::MAX, 0x00AB_CDEF] {
        for &generation in &[0u32, 1, u32::MAX, 0xDEAD_BEEF] {
            let h = Handle::new(index, generation);
            assert_eq!(
                h.raw() >> 56,
                0,
                "high byte set for ({index}, {generation})"
            );
        }
    }

    // from_raw masks the high byte too.
    let h = Handle::from_raw(u64::MAX);
    assert_eq!(h.raw() >> 56, 0);
    assert_eq!(Handle::from_raw(0xFF00_0000_0000_0001).raw(), 1);
}

#[test]
fn zero_handle_is_invalid() {
    assert!(!Handle::new(0, 0).is_valid());
    assert!(Handle::new(0, 1).is_valid());
    assert!(Handle::new(1, 0).is_valid());
}

#[test]
fn handles_never_hit_the_error_window() {
    // Userspace detects errors with `result >= (-4095isize) as usize`.
    let errno_window_start = (-4095isize) as usize;
    for &index in &[0u32, 1, 0xFFFF, (1 << 24) - 1, u32::MAX] {
        for &generation in &[0u32, 1, 0xFFFF_FFFF, u32::MAX] {
            let raw = Handle::new(index, generation).raw() as usize;
            assert!(
                raw < errno_window_start,
                "handle {raw:#x} collides with the errno window"
            );
        }
    }
}

// ===========================================================================
// §13 syscall numbers
// ===========================================================================

#[test]
fn ipc_v2_syscall_numbers_are_unique_in_block() {
    let numbers = [
        SYS_EP_CREATE,
        SYS_IPC_MINT,
        SYS_EP_SEND,
        SYS_EP_CALL,
        SYS_EP_RECV,
        SYS_EP_REPLY,
        SYS_EP_REPLY_RECV,
        SYS_EP_BIND_NOTIF,
        SYS_NOTIF_CREATE,
        SYS_NOTIF_SIGNAL,
        SYS_NOTIF_WAIT,
        SYS_NS_BIND,
        SYS_NS_LOOKUP,
        SYS_NS_UNBIND,
        SYS_MEMOBJ_CREATE,
        SYS_MEMOBJ_MAP,
        SYS_IPC_V2_RESERVED[0],
        SYS_IPC_V2_RESERVED[1],
        SYS_IPC_V2_RESERVED[2],
        SYS_IPC_V2_RESERVED[3],
    ];

    for (i, &n) in numbers.iter().enumerate() {
        assert!((270..=289).contains(&n), "syscall {n} outside 270..=289");
        for &m in &numbers[i + 1..] {
            assert_ne!(n, m, "duplicate syscall number {n}");
        }
    }

    // The 16 real syscalls are exactly 270..=285.
    assert_eq!(&numbers[..16], &(270..=285).collect::<Vec<_>>()[..]);
    assert_eq!(SYS_IPC_V2_RESERVED, [286, 287, 288, 289]);
}

// ===========================================================================
// §13.1 errno
// ===========================================================================

#[test]
fn emsgsize_is_90_and_unique() {
    assert_eq!(EMSGSIZE, 90);

    let others = [
        EPERM,
        ENOENT,
        EINTR,
        EIO,
        EBADF,
        EAGAIN,
        ENOMEM,
        EACCES,
        EFAULT,
        EEXIST,
        EINVAL,
        ENOSPC,
        EPIPE,
        ERANGE,
        ENOSYS,
        ENOTEMPTY,
        ELOOP,
        ENOTSUP,
        EAFNOSUPPORT,
        EADDRINUSE,
        ENOBUFS,
        ETIMEDOUT,
        ECONNREFUSED,
    ];
    for &e in &others {
        assert_ne!(EMSGSIZE, e, "EMSGSIZE collides with errno {e}");
    }
}
