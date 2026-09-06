//! Wire-format regression suite for the VFS scheme protocol.
//!
//! Each test pins behaviour changed or introduced by the IPC security
//! review. Naming convention: the doc comment of every test cites the
//! review point / commit it traces.
//!
//! Families:
//! 1. **Golden** — typed helpers emit byte-for-byte what the historical
//!    hand-rolled encodings produced (no wire drift).
//! 2. **Round-trip** — encode → parse recovers the original values.
//! 3. **Bounds** — malformed input is rejected, never truncated.

use strat9_abi::data::{
    IpcMessage, TimeSpec, IPC_FILE_FLAG_DIRECTORY, IPC_MESSAGE_ALIGN, IPC_MESSAGE_SIZE,
};
use strat9_abi::ipc_codec::{
    encode_fixed, get_str, put_u16_len_prefixed, InlineBlobHeader, PAYLOAD_CAPACITY,
};
use strat9_abi::ipc_payload::*;
use strat9_abi::ipc::{IpcHandshake, IpcHandshakeReply, IPC_HANDSHAKE_VERSION_MISMATCH};

const PATH: &str = "/etc/passwd";

// ===========================================================================
// Constants (review H4 / S2 — single source of truth for capacities)
// ===========================================================================

#[test]
fn message_constants_are_the_single_source_of_truth() {
    assert_eq!(IPC_MESSAGE_SIZE, 256);
    assert_eq!(IPC_MESSAGE_ALIGN, 64);
    assert_eq!(PAYLOAD_CAPACITY, 240);
    // P1/P4/S2: servers must derive batch sizes from these, not magic numbers.
    assert_eq!(IpcMessage::OPEN_INLINE_CAPACITY, 234);
    assert_eq!(IpcMessage::UNLINK_INLINE_CAPACITY, 238);
    assert_eq!(IpcMessage::READ_INLINE_CAPACITY, 232); // was 40 in bus scheme
    assert_eq!(IpcMessage::WRITE_INLINE_CAPACITY, 222); // was 30 in bus scheme
    assert_eq!(IpcMessage::REPLY_MSG_TYPE, 0x80); // H1
}

// ===========================================================================
// Opcodes (review H2 — wire contract lives in the ABI)
// ===========================================================================

#[test]
fn opcode_values_are_pinned() {
    assert_eq!(OPCODE_OPEN, 0x01);
    assert_eq!(OPCODE_READ, 0x02);
    assert_eq!(OPCODE_WRITE, 0x03);
    assert_eq!(OPCODE_CLOSE, 0x04);
    assert_eq!(OPCODE_CREATE_FILE, 0x05);
    assert_eq!(OPCODE_CREATE_DIR, 0x06);
    assert_eq!(OPCODE_UNLINK, 0x07);
    assert_eq!(OPCODE_READDIR, 0x08);
}

// ===========================================================================
// A1 — InlineBlobHeader length guard
// ===========================================================================

#[test]
fn a1_inline_blob_write_rejects_data_over_u16_max() {
    let mut payload = [0u8; PAYLOAD_CAPACITY];
    let big = vec![0u8; u16::MAX as usize + 1];
    // Before the fix this silently truncated `len` while writing all bytes,
    // corrupting the framing.
    assert!(InlineBlobHeader::write(&mut payload, 0, 0, &big).is_none());
}

#[test]
fn a1_inline_blob_roundtrip() {
    let mut payload = [0u8; PAYLOAD_CAPACITY];
    InlineBlobHeader::write(&mut payload, 4, 0, b"/dev/null").unwrap();
    let hdr = InlineBlobHeader::parse(&payload, 4).unwrap();
    assert_eq!((hdr.len, hdr.kind), (9, 0));
    assert_eq!(hdr.total_size(), InlineBlobHeader::SIZE + 9);
    assert_eq!(&payload[8..17], b"/dev/null");
    assert!(InlineBlobHeader::parse(&payload[..3], 0).is_none());
}

// ===========================================================================
// A2 — encode_fixed fails loudly on oversized structs
// ===========================================================================

#[test]
#[should_panic(expected = "exceeds payload capacity")]
fn a2_encode_fixed_panics_on_oversized_struct() {
    #[derive(zerocopy::IntoBytes, zerocopy::Immutable)]
    #[repr(C)]
    struct TooBig([u8; PAYLOAD_CAPACITY + 1]);
    let _ = encode_fixed(0x99, &TooBig([0u8; PAYLOAD_CAPACITY + 1]));
}

// ===========================================================================
// S4 — handshake reserved-field validation
// ===========================================================================

#[test]
fn s4_handshake_reserved_field_detection() {
    let hs = IpcHandshake::new_with_nonce(0xDEADBEEF);
    assert!(hs.is_valid());
    assert!(hs.is_compatible());
    assert!(!hs.has_reserved_bits_set());

    let reserved = IpcHandshake { flags: 1, ..hs };
    assert!(reserved.has_reserved_bits_set());
    let pad = IpcHandshake { _reserved: 7, ..hs };
    assert!(pad.has_reserved_bits_set());

    let reply = IpcHandshakeReply { flags: 1, ..IpcHandshakeReply::ok() };
    assert!(reply.has_reserved_bits_set());
    assert_eq!(
        IpcHandshakeReply::reject(IPC_HANDSHAKE_VERSION_MISMATCH).status,
        IPC_HANDSHAKE_VERSION_MISMATCH
    );
}

// ===========================================================================
// A5 — TimeSpec negative clamping
// ===========================================================================

#[test]
fn a5_timespec_negative_components_clamp_to_zero() {
    // Before the fix: (-1).tv_sec as u64 wrapped to ~u64::MAX and the
    // saturating multiply turned a negative nanosleep into an
    // almost-infinite sleep.
    let neg_sec = TimeSpec { tv_sec: -1, tv_nsec: 500_000_000 };
    assert_eq!(neg_sec.to_nanos(), 0);
    let neg_nsec = TimeSpec { tv_sec: 0, tv_nsec: -1 };
    assert_eq!(neg_nsec.to_nanos(), 0);
}

#[test]
fn a5_timespec_checked_to_nanos_rejects_negatives() {
    let ok = TimeSpec { tv_sec: 1, tv_nsec: 500_000_000 };
    assert_eq!(ok.checked_to_nanos(), Some(1_500_000_000));
    let neg = TimeSpec { tv_sec: -5, tv_nsec: 0 };
    assert_eq!(neg.checked_to_nanos(), None);
}

#[test]
fn a5_timespec_saturation_and_roundtrip() {
    let huge = TimeSpec { tv_sec: i64::MAX, tv_nsec: 999_999_999 };
    assert_eq!(huge.to_nanos(), u64::MAX);
    let back = TimeSpec::from_nanos(1_500_000_000);
    assert_eq!((back.tv_sec, back.tv_nsec), (1, 500_000_000));
    assert_eq!(back.to_nanos(), 1_500_000_000);
}

// ===========================================================================
// H1 — unified status replies
// ===========================================================================

#[test]
fn h1_status_reply_matches_legacy_encodings() {
    // Legacy BusSchemeServer::ok_reply / strate-net::reply_ok.
    let ok = IpcMessage::status_reply(3, 0);
    assert_eq!(ok.msg_type, 0x80);
    assert_eq!(ok.sender, 3);
    assert_eq!(&ok.payload[0..4], &0u32.to_le_bytes());

    // Legacy err_reply with an errno code.
    let err = IpcMessage::status_reply(3, 2 /* ENOENT */);
    assert_eq!(&err.payload[0..4], &2u32.to_le_bytes());

    // error_reply(i32) and status_reply(u32) stay byte-compatible.
    let legacy = IpcMessage::error_reply(4, -22);
    let typed = IpcMessage::status_reply(4, (-22i32) as u32);
    assert_eq!(legacy.payload[0..4], typed.payload[0..4]);
}

// ===========================================================================
// H3 — typed open/write wire format (real layout)
// ===========================================================================

#[test]
fn open_request_golden_matches_historical_kernel_encoding() {
    // Historical kernel build_open_msg:
    //   [flags u32 @0..4][len u16 @4..6][path @6..] — no InlineBlobHeader.
    let msg = OpenRequest::encode(OPCODE_OPEN, 0x02, PATH).unwrap();
    assert_eq!(msg.msg_type, OPCODE_OPEN);
    let mut expected = [0u8; PAYLOAD_CAPACITY];
    expected[0..4].copy_from_slice(&0x02u32.to_le_bytes());
    expected[4..6].copy_from_slice(&(PATH.len() as u16).to_le_bytes());
    expected[6..6 + PATH.len()].copy_from_slice(PATH.as_bytes());
    assert_eq!(msg.payload[..], expected[..]);

    let (flags, path) = OpenRequest::parse(&msg.payload).unwrap();
    assert_eq!(flags, 0x02);
    assert_eq!(path, PATH);
}

#[test]
fn open_request_parse_rejects_malformed_input() {
    assert!(OpenRequest::parse(&[]).is_none()); // truncated prefix
    assert!(OpenRequest::parse(&[0u8; 5]).is_none());

    let mut p = [0u8; 32];
    p[4..6].copy_from_slice(&100u16.to_le_bytes()); // len beyond bounds
    assert!(OpenRequest::parse(&p).is_none());

    p[4..6].copy_from_slice(&2u16.to_le_bytes());
    p[6] = 0xFF; // invalid UTF-8
    p[7] = 0xFE;
    assert!(OpenRequest::parse(&p).is_none());
}

#[test]
fn open_request_encode_rejects_path_over_inline_capacity() {
    let long = "a".repeat(IpcMessage::OPEN_INLINE_CAPACITY + 1);
    assert!(OpenRequest::encode(OPCODE_OPEN, 0, &long).is_none());
    let max = "a".repeat(IpcMessage::OPEN_INLINE_CAPACITY);
    let msg = OpenRequest::encode(OPCODE_OPEN, 0, &max).unwrap();
    let (_, path) = OpenRequest::parse(&msg.payload).unwrap();
    assert_eq!(path.len(), IpcMessage::OPEN_INLINE_CAPACITY);
}

#[test]
fn write_request_golden_and_roundtrip() {
    // Historical kernel build_write_msg:
    //   [ino u64][offset u64][len u16 @16..18][data @18..]
    let data = b"hello";
    let (msg, packed) = WriteRequest::encode(OPCODE_WRITE, 3, 512, data).unwrap();
    assert_eq!(packed, 5);
    let mut expected = [0u8; PAYLOAD_CAPACITY];
    expected[0..8].copy_from_slice(&3u64.to_le_bytes());
    expected[8..16].copy_from_slice(&512u64.to_le_bytes());
    expected[16..18].copy_from_slice(&5u16.to_le_bytes());
    expected[18..23].copy_from_slice(data);
    assert_eq!(msg.payload[..], expected[..]);

    let req = WriteRequest::parse_prefix(&msg.payload).unwrap();
    let (ino, offset) = (req.ino, req.offset);
    let data_out = req.data(&msg.payload).unwrap();
    assert_eq!((ino, offset), (3, 512));
    assert_eq!(data_out, data);
}

#[test]
fn write_request_encode_never_truncates() {
    // Chunking is the caller's policy: the helper refuses instead.
    let oversized = vec![0u8; IpcMessage::WRITE_INLINE_CAPACITY + 1];
    assert!(WriteRequest::encode(OPCODE_WRITE, 0, 0, &oversized).is_none());
    let exact = vec![0u8; IpcMessage::WRITE_INLINE_CAPACITY];
    assert!(WriteRequest::encode(OPCODE_WRITE, 0, 0, &exact).is_some());
}

#[test]
fn write_request_parse_rejects_truncated_prefix_and_bad_data_len() {
    assert!(WriteRequest::parse_prefix(&[0u8; 17]).is_none());
    let mut p = [0u8; 20];
    p[16..18].copy_from_slice(&50u16.to_le_bytes()); // data_len beyond payload
    let req = WriteRequest::parse_prefix(&p).unwrap();
    let data_len = req.data_len;
    let _ = data_len;
    assert!(req.data(&p).is_none());
}

#[test]
fn create_request_golden_and_roundtrip() {
    let msg = CreateRequest::encode(OPCODE_CREATE_FILE, 0o755, PATH).unwrap();
    let mut expected = [0u8; PAYLOAD_CAPACITY];
    expected[0..4].copy_from_slice(&0o755u32.to_le_bytes());
    expected[4..6].copy_from_slice(&(PATH.len() as u16).to_le_bytes());
    expected[6..6 + PATH.len()].copy_from_slice(PATH.as_bytes());
    assert_eq!(msg.payload[..], expected[..]);

    let (mode, path) = CreateRequest::parse(&msg.payload).unwrap();
    assert_eq!(mode, 0o755);
    assert_eq!(path, PATH);

    let dir = CreateRequest::encode(OPCODE_CREATE_DIR, 0o755, PATH).unwrap();
    assert_eq!(dir.msg_type, OPCODE_CREATE_DIR);
    assert!(CreateRequest::parse(&[0u8; 5]).is_none());
}

#[test]
fn read_request_golden_and_roundtrip() {
    let msg = ReadRequest::encode(OPCODE_READ, 7, 4096, 100);
    let mut expected = [0u8; PAYLOAD_CAPACITY];
    expected[0..8].copy_from_slice(&7u64.to_le_bytes());
    expected[8..16].copy_from_slice(&4096u64.to_le_bytes());
    expected[16..20].copy_from_slice(&100u32.to_le_bytes());
    assert_eq!(msg.payload[..], expected[..]);

    let req = ReadRequest::parse(&msg.payload).unwrap();
    assert_eq!((req.ino, req.offset, req.count_usize()), (7, 4096, 100));
    assert!(ReadRequest::parse(&[0u8; 19]).is_none());
}

#[test]
fn close_request_encoding() {
    let msg = CloseRequest::encode(OPCODE_CLOSE, 42);
    assert_eq!(msg.msg_type, OPCODE_CLOSE);
    assert_eq!(&msg.payload[0..8], &42u64.to_le_bytes());
}

// ===========================================================================
// Reply layouts (verified against strate-fs-ramfs / net / bus emitters)
// ===========================================================================

#[test]
fn open_reply_golden_matches_historical_net_encoding() {
    // Historical net reply_open:
    //   [status=0][file_id @4..12][size @12..20][flags @20..24]
    let mut msg = IpcMessage::new(IpcMessage::REPLY_MSG_TYPE);
    msg.sender = 11;
    OpenReply {
        status: 0,
        file_id: 42,
        size: 1024,
        file_flags: IPC_FILE_FLAG_DIRECTORY,
    }
    .encode_into(&mut msg.payload);

    let mut expected = [0u8; PAYLOAD_CAPACITY];
    expected[4..12].copy_from_slice(&42u64.to_le_bytes());
    expected[12..20].copy_from_slice(&1024u64.to_le_bytes());
    expected[20..24].copy_from_slice(&IPC_FILE_FLAG_DIRECTORY.to_le_bytes());
    assert_eq!(msg.payload[..], expected[..]);
}

#[test]
fn open_reply_parse_roundtrip_and_bounds() {
    let mut payload = [0u8; PAYLOAD_CAPACITY];
    payload[4..12].copy_from_slice(&7u64.to_le_bytes());
    payload[12..20].copy_from_slice(&u64::MAX.to_le_bytes()); // "size unknown"
    payload[20..24].copy_from_slice(&7u32.to_le_bytes());

    let r = OpenReply::parse(&payload).unwrap();
    // Fields are copied out first: OpenReply is repr(packed(1)), taking
    // references to its fields is not allowed.
    let (status, file_id, size, flags) = (r.status, r.file_id, r.size, r.file_flags);
    assert_eq!(status, 0);
    assert_eq!(file_id, 7);
    assert_eq!(size, u64::MAX);
    assert_eq!(flags, 7);
    assert!(OpenReply::parse(&payload[..23]).is_none());
    assert!(OpenReply::parse(&[]).is_none());
}

#[test]
fn create_reply_layout_matches_ramfs_server() {
    // ramfs emits: [status][ino @4..12] (CreateReply, 12 bytes packed).
    assert_eq!(core::mem::size_of::<CreateReply>(), 12);
    assert_eq!(core::mem::size_of::<OpenReply>(), 24);
}

#[test]
fn read_reply_encode_ok_caps_at_read_capacity() {
    // Review P1: replies use the full READ capacity (232), not 40.
    let big = vec![0xABu8; PAYLOAD_CAPACITY];
    let (msg, n) = ReadReply::encode_ok(9, &big);
    assert_eq!(n, IpcMessage::READ_INLINE_CAPACITY);
    assert_eq!(msg.sender, 9);
    assert_eq!(&msg.payload[0..4], &0u32.to_le_bytes());
    assert_eq!(&msg.payload[4..8], &(n as u32).to_le_bytes());
    assert_eq!(&msg.payload[8..12], &[0xAB; 4]); // data at DATA_OFFSET
}

#[test]
fn write_reply_layout() {
    let msg = WriteReply::encode_ok(5, 17);
    assert_eq!(msg.sender, 5);
    assert_eq!(&msg.payload[0..4], &0u32.to_le_bytes());
    assert_eq!(&msg.payload[4..8], &17u32.to_le_bytes());
}

// ===========================================================================
// UNLINK framing helper (kernel client migration)
// ===========================================================================

#[test]
fn u16_len_prefixed_framing_roundtrip_and_bounds() {
    // Historical kernel unlink encoding: [len u16 @0..2][path @2..].
    let mut payload = [0u8; PAYLOAD_CAPACITY];
    put_u16_len_prefixed(&mut payload, 0, PATH.as_bytes()).unwrap();
    assert_eq!(&payload[0..2], &(PATH.len() as u16).to_le_bytes());
    assert_eq!(get_str(&payload, 2, PATH.len()).unwrap(), PATH);

    let mut tiny = [0u8; 4];
    assert!(put_u16_len_prefixed(&mut tiny, 0, &[0u8; 70_000]).is_none()); // > u16::MAX
    assert!(put_u16_len_prefixed(&mut tiny, 0, &[0u8; 10]).is_none()); // out of bounds
}
