//! L1 — IPC payload codec: bounds, roundtrips, and corruption resistance.
//!
//! The codec is the only sanctioned way to pack data into the 240-byte
//! `IpcMessage` payload. Every helper is bounds-checked via `Option`;
//! these tests verify that NO input can panic and that valid roundtrips
//! are exact.

use strat9_abi::data::{IpcMessage, TimeSpec};
use strat9_abi::ipc_codec::*;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// ===========================================================================
// Scalar helpers
// ===========================================================================

#[test]
fn u16_roundtrip_all_offsets() {
    let mut buf = [0u8; 16];
    for off in 0..=14usize {
        assert!(put_u16(&mut buf, off, 0xBEEF).is_some());
        assert_eq!(get_u16(&buf, off), Some(0xBEEF));
    }
}

#[test]
fn u32_roundtrip_extreme_values() {
    let mut buf = [0u8; 8];
    for v in [0u32, 1, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFF] {
        assert!(put_u32(&mut buf, 0, v).is_some());
        assert_eq!(get_u32(&buf, 0), Some(v));
    }
    // i32 sign preservation through the wire format
    for v in [i32::MIN, -1, 0, 1, i32::MAX] {
        assert!(put_i32(&mut buf, 0, v).is_some());
        assert_eq!(get_i32(&buf, 0), Some(v));
    }
}

#[test]
fn u64_roundtrip_and_endianness() {
    let mut buf = [0u8; 8];
    assert!(put_u64(&mut buf, 0, 0x0102_0304_0506_0708).is_some());
    // Wire is little-endian: pin the byte order explicitly.
    assert_eq!(buf, [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    assert_eq!(get_u64(&buf, 0), Some(0x0102_0304_0506_0708));
}

#[test]
fn scalar_helpers_never_panic_on_out_of_bounds() {
    let mut buf = [0u8; 4];
    // Exactly at capacity → OK.
    assert!(put_u32(&mut buf, 0, 1).is_some());
    // One byte past → None (not panic), for every width.
    assert!(put_u16(&mut buf, 3, 0).is_none());
    assert!(put_u32(&mut buf, 1, 0).is_none());
    assert!(put_u64(&mut buf, 0, 0).is_none());
    assert!(get_u16(&buf, 3).is_none());
    assert!(get_u32(&buf, 1).is_none());
    assert!(get_u64(&buf, 0).is_none());
    // Huge offsets must not wrap around on 64-bit arithmetic.
    let huge = usize::MAX;
    assert!(put_u16(&mut buf, huge, 0).is_none());
    assert!(get_u64(&[0u8; 8], huge).is_none());
}

#[test]
fn put_bytes_get_bytes_roundtrip_and_bounds() {
    let mut buf = [0u8; 8];
    assert!(put_bytes(&mut buf, 2, b"abcd").is_some());
    assert_eq!(get_bytes(&buf, 2, 4), Some(&b"abcd"[..]));
    assert!(put_bytes(&mut buf, 5, b"abcd").is_none()); // overruns
    assert!(put_bytes(&mut buf, usize::MAX - 5, &[0u8; 10]).is_none()); // overflow-safe
    assert!(get_bytes(&buf, 6, 4).is_none());
    assert!(get_bytes(&buf, usize::MAX, 1).is_none());
}

#[test]
fn str_roundtrip_including_utf8_multibyte() {
    let mut buf = [0u8; 64];
    for s in ["", "/tmp", "/home/user/file.txt", "héllo wörld ☃"] {
        assert!(put_str(&mut buf, 0, s).is_some());
        assert_eq!(get_str(&buf, 0, s.len()), Some(s));
    }
    // Invalid UTF-8 in buffer → None, not panic.
    buf[0] = 0xFF;
    buf[1] = 0xFE;
    assert_eq!(get_str(&buf, 0, 2), None);
}

// ===========================================================================
// encode_fixed / decode_fixed
// ===========================================================================

// No padding: a: u32(4) + b: u64(8) + c: u16(2) would pad; reorder to stay packed.
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct TestReq {
    b: u64,
    a: u32,
    c: u16,
    _pad: [u8; 2], // explicit tail padding so IntoBytes is derivable
}

#[test]
fn fixed_roundtrip_preserves_fields_and_header() {
    let req = TestReq { b: 0x1234_5678_9ABC_DEF0, a: 0xDEAD_BEEF, c: 0xCAFE, _pad: [0; 2] };
    let msg = encode_fixed(0x77, &req);
    assert_eq!(msg.msg_type, 0x77);
    assert_eq!(msg.sender, 0);
    assert_eq!(&msg.payload[..size_of::<TestReq>()], req.as_bytes());

    let back: &TestReq = decode_fixed(&msg).expect("decode");
    assert_eq!(*back, req);
}

#[test]
fn fixed_reply_sets_sender() {
    let msg = encode_fixed_reply(0xABCD_EF01, 0x80, &TestReq { b: 2, a: 1, c: 3, _pad: [0; 2] });
    assert_eq!(msg.sender, 0xABCD_EF01);
    assert_eq!(msg.msg_type, 0x80);
}

#[test]
fn decode_of_zeroed_payload_is_safe_for_frombytes_structs() {
    // Any all-zero payload must decode (zerocopy guarantees this for
    // FromBytes types) and produce zeroed fields.
    let msg = IpcMessage::new(1);
    let back: &TestReq = decode_fixed(&msg).expect("all-zero decodes");
    assert_eq!(back.a, 0);
    assert_eq!(back.b, 0);
    assert_eq!(back.c, 0);
}

// ===========================================================================
// InlineBlobHeader
// ===========================================================================

#[test]
fn inline_blob_roundtrip() {
    let mut buf = [0u8; 64];
    for (kind, data) in [(0u16, &b"/etc/passwd"[..]), (1, b"\x00\x01\xff"), (0xFFFF, b"x")] {
        assert!(InlineBlobHeader::write(&mut buf, 4, kind, data).is_some());
        let hdr = InlineBlobHeader::parse(&buf, 4).unwrap();
        assert_eq!(hdr.len as usize, data.len());
        assert_eq!(hdr.kind, kind);
        assert_eq!(hdr.total_size(), 4 + data.len());
        assert_eq!(&buf[8..8 + data.len()], data);
    }
}

#[test]
fn inline_blob_empty_data() {
    let mut buf = [0u8; 16];
    assert!(InlineBlobHeader::write(&mut buf, 0, 7, b"").is_some());
    let hdr = InlineBlobHeader::parse(&buf, 0).unwrap();
    assert_eq!(hdr.len, 0);
    assert_eq!(hdr.total_size(), 4);
}

#[test]
fn inline_blob_bounds_are_enforced() {
    let mut small = [0u8; 8];
    // header(4) + 5 bytes > 8 → None
    assert!(InlineBlobHeader::write(&mut small, 0, 0, b"12345").is_none());
    // header(4) + 4 bytes == 8 → OK
    assert!(InlineBlobHeader::write(&mut small, 0, 0, b"1234").is_some());

    let mut big = [0u8; 240];
    // len field is u16 but PAYLOAD_CAPACITY caps real usage; > u16::MAX rejected.
    assert!(InlineBlobHeader::write(&mut big, 0, 0, &[0u8; u16::MAX as usize + 1]).is_none());
    // parse out of bounds
    assert!(InlineBlobHeader::parse(&small, 5).is_none());
    assert!(InlineBlobHeader::parse(&small, usize::MAX).is_none());
}

#[test]
fn inline_blob_write_rejects_data_over_u16_max_even_in_huge_buffer() {
    // 65 536 bytes cannot fit any realistic payload but must be rejected by
    // the length check before slicing (no truncation, no panic).
    let mut buf = vec![0u8; 70_000];
    assert!(InlineBlobHeader::write(&mut buf, 0, 0, &vec![7u8; 65_536]).is_none());
}

// ===========================================================================
// IpcMessage helpers
// ===========================================================================

#[test]
fn error_reply_encodes_status_as_le_i32() {
    let msg = IpcMessage::error_reply(42, strat9_abi::errno::EACCES as i32);
    assert_eq!(msg.msg_type, IpcMessage::REPLY_MSG_TYPE);
    assert_eq!(msg.msg_type, 0x80);
    assert_eq!(msg.sender, 42);
    assert_eq!(
        i32::from_le_bytes(msg.payload[0..4].try_into().unwrap()),
        strat9_abi::errno::EACCES as i32
    );
}

#[test]
fn status_reply_success_and_error() {
    let ok = IpcMessage::status_reply(1, 0);
    assert_eq!(ok.msg_type, 0x80);
    assert_eq!(ok.payload[0..4], [0, 0, 0, 0]);

    let err = IpcMessage::status_reply(1, strat9_abi::errno::EINVAL as u32);
    assert_eq!(err.payload[0..4], (strat9_abi::errno::EINVAL as u32).to_le_bytes());
}

#[test]
fn timespec_saturating_conversions() {
    // Normal roundtrip
    for nanos in [0u64, 1, 999_999_999, 1_000_000_000, 12_345_678_901] {
        assert_eq!(TimeSpec::from_nanos(nanos).to_nanos(), nanos);
    }
    // from_nanos decomposition
    let ts = TimeSpec::from_nanos(1_500_000_000);
    assert_eq!((ts.tv_sec, ts.tv_nsec), (1, 500_000_000));

    // Negative components clamp to 0 (documented security fix)
    assert_eq!(TimeSpec { tv_sec: -5, tv_nsec: 0 }.to_nanos(), 0);
    assert_eq!(TimeSpec { tv_sec: -5, tv_nsec: -5 }.to_nanos(), 0);
    // ...and are rejected by the checked variant
    assert_eq!(TimeSpec { tv_sec: -1, tv_nsec: 5 }.checked_to_nanos(), None);
    assert_eq!(TimeSpec { tv_sec: 1, tv_nsec: -5 }.checked_to_nanos(), None);

    // Saturation instead of overflow
    let huge = TimeSpec { tv_sec: i64::MAX, tv_nsec: 999_999_999 };
    assert_eq!(huge.to_nanos(), u64::MAX);
}
