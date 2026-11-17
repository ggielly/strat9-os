//! Wire-format tests for the STAT / RENAME / LINK / CHMOD scheme opcodes.

use strat9_abi::{data::IpcMessage, ipc_payload::*};

#[test]
fn opcodes_are_distinct_and_stable() {
    assert_eq!(OPCODE_STAT, 0x0B);
    assert_eq!(OPCODE_RENAME, 0x0C);
    assert_eq!(OPCODE_CHMOD, 0x0D);
    assert_eq!(OPCODE_LINK, 0x0E);
    assert_eq!(OPCODE_FCHMOD, 0x11);
    let all = [
        OPCODE_OPEN, OPCODE_READ, OPCODE_WRITE, OPCODE_CLOSE, OPCODE_CREATE_FILE,
        OPCODE_CREATE_DIR, OPCODE_UNLINK, OPCODE_READDIR, OPCODE_BULK_SETUP,
        OPCODE_BULK_TEARDOWN, OPCODE_STAT, OPCODE_RENAME, OPCODE_CHMOD, OPCODE_LINK,
        OPCODE_FCHMOD,
    ];
    for (i, a) in all.iter().enumerate() {
        assert_ne!(*a, 0x10, "0x10 is reserved for the bootstrap handshake");
        for b in &all[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

#[test]
fn stat_reply_roundtrip() {
    let st = StatReply {
        status: 0,
        mode: 0o100644,
        nlink: 3,
        uid: 1000,
        gid: 100,
        blksize: 4096,
        ino: 0xdead_beef_0102,
        size: 1 << 40,
        blocks: 77,
        atime: -5,
        mtime: 1_700_000_000,
        ctime: 42,
        atime_nsec: 1,
        mtime_nsec: 999_999_999,
        ctime_nsec: 500,
    };
    let mut msg = IpcMessage::new(IpcMessage::REPLY_MSG_TYPE);
    st.encode_into(&mut msg.payload);
    assert_eq!(StatReply::parse(&msg.payload), Some(st));
    assert_eq!(StatReply::parse(&msg.payload[..71]), None);
    // A legacy 72-byte reply parses with whole-second precision.
    let legacy = StatReply::parse(&msg.payload[..72]).unwrap();
    assert_eq!((legacy.atime_nsec, legacy.mtime_nsec, legacy.ctime_nsec), (0, 0, 0));
    assert_eq!(legacy.mtime, 1_700_000_000);
    // Out-of-range nanoseconds from a buggy server are clamped.
    let mut bad = msg.clone();
    bad.payload[76..80].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(StatReply::parse(&bad.payload).unwrap().mtime_nsec, 999_999_999);
}

#[test]
fn stat_request_roundtrip() {
    let m = encode_stat_request(99);
    assert_eq!(m.msg_type, OPCODE_STAT);
    assert_eq!(parse_stat_request(&m.payload), Some(99));
}

#[test]
fn path_pair_roundtrip() {
    let m = encode_path_pair(OPCODE_RENAME, "/a/b", "/c/déjà").unwrap();
    assert_eq!(parse_path_pair(&m.payload), Some(("/a/b", "/c/déjà")));
    let big = "x".repeat(IpcMessage::PAYLOAD_CAPACITY);
    assert!(encode_path_pair(OPCODE_LINK, &big, "y").is_none());
}

#[test]
fn fchmod_roundtrip() {
    let m = encode_fchmod(7, 0o600);
    assert_eq!(m.msg_type, OPCODE_FCHMOD);
    assert_eq!(parse_fchmod(&m.payload), Some((7, 0o600)));
}

#[test]
fn chmod_reuses_create_framing() {
    let m = CreateRequest::encode(OPCODE_CHMOD, 0o640, "etc/passwd").unwrap();
    assert_eq!(CreateRequest::parse(&m.payload), Some((0o640, "etc/passwd")));
}

#[test]
fn utimens_roundtrip_with_special_nsec() {
    let m = encode_utimens("/tmp/é", (-3, 500), (1_700_000_000, UTIME_NOW)).unwrap();
    assert_eq!(m.msg_type, OPCODE_UTIMENS);
    assert_eq!(
        parse_utimens(&m.payload),
        Some(("/tmp/é", (-3, 500), (1_700_000_000, UTIME_NOW)))
    );
    let m = encode_utimens("x", (0, UTIME_OMIT), (0, UTIME_OMIT)).unwrap();
    let (_, a, mt) = parse_utimens(&m.payload).unwrap();
    assert_eq!((a.1, mt.1), (UTIME_OMIT, UTIME_OMIT));
    assert_ne!(UTIME_NOW, UTIME_OMIT);
    assert!(UTIME_NOW < 1_000_000_000 * 2, "fits the 30-bit nsec field");
    assert!(encode_utimens(&"p".repeat(IpcMessage::PAYLOAD_CAPACITY), (0, 0), (0, 0)).is_none());
}

#[test]
fn utimens_opcode_does_not_collide() {
    assert_eq!(OPCODE_UTIMENS, 0x12);
    for o in [OPCODE_STAT, OPCODE_RENAME, OPCODE_CHMOD, OPCODE_LINK, OPCODE_FCHMOD, 0x10] {
        assert_ne!(o, OPCODE_UTIMENS);
    }
}
