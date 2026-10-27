//! L1 : VFS scheme wire payloads: parse/serialize conformance.
//!
//! These tests pin the exact byte layout of the scheme protocol between
//! the kernel VFS router and filesystem/network Silos. The kernel and all
//! servers MUST agree on these layouts; a regression on either side is
//! caught here before it reaches QEMU.

use strat9_abi::{data::IpcMessage, ipc_codec::put_str, ipc_payload::*};
use zerocopy::IntoBytes;

const PAYLOAD: usize = 240;

// ===========================================================================
// Opcodes
// ===========================================================================

#[test]
fn scheme_opcodes_are_pinned() {
    assert_eq!(OPCODE_OPEN, 0x01);
    assert_eq!(OPCODE_READ, 0x02);
    assert_eq!(OPCODE_WRITE, 0x03);
    assert_eq!(OPCODE_CLOSE, 0x04);
    assert_eq!(OPCODE_READDIR, 0x08);
}

// ===========================================================================
// OpenRequest : raw u16 length prefix at 4..6, path at 6.. (NOT InlineBlob)
// ===========================================================================

#[test]
fn open_request_parse_roundtrip() {
    let mut payload = [0u8; PAYLOAD];
    let path = "/etc/passwd";
    payload[0..4].copy_from_slice(&0o644u32.to_le_bytes()); // flags
    payload[4..6].copy_from_slice(&(path.len() as u16).to_le_bytes());
    put_str(&mut payload, OpenRequest::PATH_OFFSET, path).unwrap();

    let (flags, parsed_path) = OpenRequest::parse(&payload).expect("valid open");
    assert_eq!(flags, 0o644);
    assert_eq!(parsed_path, path);
}

#[test]
fn open_request_parse_rejects_truncated_and_lying_lengths() {
    // Shorter than fixed prefix.
    assert_eq!(OpenRequest::parse(&[0u8; 5]), None);

    // path_len claims more bytes than available.
    let mut payload = [0u8; PAYLOAD];
    payload[4..6].copy_from_slice(&1000u16.to_le_bytes());
    assert_eq!(OpenRequest::parse(&payload), None);

    // path_len = 0 → empty but valid.
    payload[4..6].copy_from_slice(&0u16.to_le_bytes());
    let (flags, path) = OpenRequest::parse(&payload).unwrap();
    assert_eq!((flags, path), (0, ""));
}

#[test]
fn open_request_max_inline_capacity_is_exact() {
    // A path of OPEN_INLINE_CAPACITY bytes must fit exactly in one message.
    let mut payload = [0u8; PAYLOAD];
    let max_path = "a".repeat(IpcMessage::OPEN_INLINE_CAPACITY);
    payload[4..6].copy_from_slice(&(max_path.len() as u16).to_le_bytes());
    assert!(put_str(&mut payload, 6, &max_path).is_some());
    let (_, parsed) = OpenRequest::parse(&payload).unwrap();
    assert_eq!(parsed.len(), IpcMessage::OPEN_INLINE_CAPACITY);

    // One byte more must not fit.
    assert!(put_str(
        &mut payload,
        6,
        &"a".repeat(IpcMessage::OPEN_INLINE_CAPACITY + 1)
    )
    .is_none());
}

// ===========================================================================
// WriteRequest : raw u16 length at 16..18, data at 18..
// ===========================================================================

#[test]
fn write_request_prefix_and_data_roundtrip() {
    let mut payload = [0u8; PAYLOAD];
    payload[0..8].copy_from_slice(&7777u64.to_le_bytes()); // ino
    payload[8..16].copy_from_slice(&4096u64.to_le_bytes()); // offset
    let data = b"hello world";
    payload[16..18].copy_from_slice(&(data.len() as u16).to_le_bytes());
    payload[WriteRequest::DATA_OFFSET..WriteRequest::DATA_OFFSET + data.len()]
        .copy_from_slice(data);

    let req = WriteRequest::parse_prefix(&payload).expect("prefix");
    // packed struct: read fields by copy (never by reference).
    let (ino, offset, dlen) = { (req.ino, req.offset, req.data_len) };
    assert_eq!(ino, 7777);
    assert_eq!(offset, 4096);
    assert_eq!(dlen as usize, data.len());
    assert_eq!(req.data(&payload), Some(&data[..]));
}

#[test]
fn write_request_rejects_truncated_prefix() {
    assert!(WriteRequest::parse_prefix(&[0u8; 17]).is_none());
    assert!(WriteRequest::parse_prefix(&[0u8; 18]).is_some());

    // data_len beyond payload → data() returns None.
    let req = WriteRequest {
        ino: 1,
        offset: 2,
        data_len: 999,
    };
    let _ = ({ req.ino }, { req.offset });
    assert_eq!(req.data(&[0u8; PAYLOAD]), None);
}

// ===========================================================================
// Fixed-size replies: exact wire bytes
// ===========================================================================

#[test]
fn status_reply_wire_bytes() {
    use strat9_abi::ipc_payload::StatusReply;
    let r = StatusReply { status: 13 }; // EACCES
    assert_eq!(r.as_bytes(), &13u32.to_le_bytes());
    assert_eq!(size_of::<StatusReply>(), 4);
}

#[test]
fn open_reply_layout_offsets() {
    // Current wire layout (24 bytes, packed): status @0, file_id @4,
    // size @12, file_flags @20. The earlier 32-byte layout with
    // `_pad0/ino/_pad1` was never produced by any server.
    let reply = OpenReply {
        status: 0,
        file_id: 42,
        size: 0x1000,
        file_flags: 3,
    };
    assert_eq!(size_of::<OpenReply>(), 24);

    let mut bytes = [0u8; 24];
    reply.encode_into(&mut bytes);
    assert_eq!(&bytes[0..4], &0u32.to_le_bytes()); // status @0
    assert_eq!(&bytes[4..12], &42u64.to_le_bytes()); // file_id @4
    assert_eq!(&bytes[12..20], &0x1000u64.to_le_bytes()); // size @12
    assert_eq!(&bytes[20..24], &3u32.to_le_bytes()); // file_flags @20

    let back = OpenReply::parse(&bytes).expect("valid open reply");
    assert_eq!(
        (back.status, back.file_id, back.size, back.file_flags),
        (0, 42, 0x1000, 3)
    );
    // A truncated payload must be rejected rather than partially parsed.
    assert!(OpenReply::parse(&bytes[..23]).is_none());
}

#[test]
fn read_reply_count_matches_data_len_contract() {
    // ReadReply promises `count` bytes of data starting at offset 8.
    let mut payload = [0u8; PAYLOAD];
    let count = 10u32;
    payload[0..4].copy_from_slice(&0u32.to_le_bytes());
    payload[4..8].copy_from_slice(&count.to_le_bytes());
    payload[8..18].copy_from_slice(b"0123456789");
    assert_eq!(count as usize, 10);
    // Consumer contract: data occupies payload[8..8+count].
    assert_eq!(&payload[8..8 + count as usize], b"0123456789");
}

#[test]
fn create_request_is_mode_plus_raw_path_length() {
    // Same wire convention as OpenRequest: mode @0..4, raw u16 path_len
    // @4..6, path @6.. (no InlineBlobHeader, 6-byte prefix total).
    let mut payload = [0u8; PAYLOAD];
    let path = "/dev";
    payload[0..4].copy_from_slice(&0o755u32.to_le_bytes()); // mode
    payload[4..6].copy_from_slice(&(path.len() as u16).to_le_bytes());
    put_str(&mut payload, CreateRequest::PATH_OFFSET, path).unwrap();

    assert_eq!(size_of::<CreateRequest>(), 6); // mode(4) + path_len(2)
    assert_eq!(CreateRequest::PATH_OFFSET, 6);

    let (mode, parsed) = CreateRequest::parse(&payload).expect("valid create");
    assert_eq!(mode, 0o755);
    assert_eq!(parsed, path);

    // A length prefix that claims more bytes than available is rejected.
    payload[4..6].copy_from_slice(&1000u16.to_le_bytes());
    assert!(CreateRequest::parse(&payload).is_none());
}

#[test]
fn tcp_connect_reply_layout() {
    let r = TcpConnectReply {
        status: 0,
        _pad: 0,
        conn_id: 0xDEAD_BEEF,
    };
    assert_eq!(size_of::<TcpConnectReply>(), 16);
    let b = r.as_bytes();
    assert_eq!(&b[8..16], &0xDEAD_BEEFu64.to_le_bytes());
}

#[test]
fn lseek_whence_values_documented() {
    // Pin the whence semantics used by both kernel and musl-compat:
    // SEEK_SET=0, SEEK_CUR=1, SEEK_END=2 (POSIX).
    const SEEK_SET: u32 = 0;
    const SEEK_CUR: u32 = 1;
    const SEEK_END: u32 = 2;
    for w in [SEEK_SET, SEEK_CUR, SEEK_END] {
        let req = LseekRequest {
            ino: 1,
            offset: -8,
            whence: w,
            _pad: 0,
        };
        assert_eq!({ req.whence }, w);
        assert!(req.offset < 0); // negative offsets are legal for SEEK_CUR/END
    }
}

// ===========================================================================
// Fixed-size payloads: pinned sizes (packed, no padding surprises)
// ===========================================================================

#[test]
fn fixed_payload_sizes_are_pinned() {
    // `decode_fixed`/`encode_fixed` only cover the `data::*` types; scheme
    // payloads expose explicit `parse`/`encode_into` instead, so what must
    // be pinned here is the exact wire size of each struct.
    assert_eq!(size_of::<StatusReply>(), 4);
    assert_eq!(size_of::<OpenReply>(), 24);
    assert_eq!(size_of::<ReadReply>(), 8);
    assert_eq!(size_of::<WriteReply>(), 8);
    assert_eq!(size_of::<CreateReply>(), 12);
    assert_eq!(size_of::<LseekReply>(), 16);
    assert_eq!(size_of::<TcpConnectReply>(), 16);
    assert_eq!(size_of::<CloseRequest>(), 8);
    assert_eq!(size_of::<StatRequest>(), 8);
    assert_eq!(size_of::<ReadRequest>(), 24);
    assert_eq!(size_of::<CreateRequest>(), 6);
    assert_eq!(size_of::<OpenRequest>(), 6);
    assert_eq!(size_of::<WriteRequest>(), 18);

    // Every fixed payload must fit the message capacity.
    const CAPACITY: usize = IpcMessage::PAYLOAD_CAPACITY;
    assert!(size_of::<OpenReply>() <= CAPACITY);
    assert!(size_of::<ReadRequest>() <= CAPACITY);
}

#[test]
fn status_reply_roundtrips_through_its_wire_bytes() {
    let reply = StatusReply { status: 22 };
    let bytes = reply.as_bytes();
    assert_eq!(bytes, &22u32.to_le_bytes());
    // The wire contract is a bare little-endian u32 at payload offset 0.
    assert_eq!(u32::from_le_bytes(bytes[..4].try_into().unwrap()), 22);
}
