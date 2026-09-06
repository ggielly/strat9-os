//! L1/L0 — IPC handshake wire conformance (missed in pass 1, found in pass 2).
//!
//! The handshake is the FIRST bytes exchanged between every Silo and the
//! kernel IPC layer: magic, version negotiation and reserved-field
//! validation are security-relevant.

use strat9_abi::ipc::{
    IpcHandshake, IpcHandshakeReply, IPC_HANDSHAKE_MAGIC, IPC_HANDSHAKE_OK,
    IPC_HANDSHAKE_REJECTED, IPC_HANDSHAKE_VERSION_MISMATCH, IPC_PROTOCOL_VERSION,
};
use strat9_abi::{ABI_VERSION_MAJOR, ABI_VERSION_MINOR};
use zerocopy::IntoBytes;

#[test]
fn handshake_wire_sizes_are_pinned() {
    assert_eq!(core::mem::size_of::<IpcHandshake>(), 20);
    assert_eq!(core::mem::size_of::<IpcHandshakeReply>(), 16);
}

#[test]
fn new_handshake_carries_current_version_and_magic() {
    let h = IpcHandshake::new_with_nonce(0xCAFE_BABE);
    assert!(h.is_valid());
    assert!(h.is_compatible());
    assert!(!h.has_reserved_bits_set());
    assert_eq!(h.magic, IPC_HANDSHAKE_MAGIC);
    assert_eq!(IPC_HANDSHAKE_MAGIC, 0x4950_4339); // "IPC9"
    assert_eq!(h.protocol_version, IPC_PROTOCOL_VERSION);
    assert_eq!(IPC_PROTOCOL_VERSION, 1);
    assert_eq!(h.client_abi_major, ABI_VERSION_MAJOR);
    assert_eq!(h.client_abi_minor, ABI_VERSION_MINOR);
    assert_eq!(h.nonce, 0xCAFE_BABE);
    assert_eq!(h.flags, 0);
}

#[test]
fn magic_corruption_detected() {
    let mut h = IpcHandshake::new();
    assert!(h.is_valid());
    h.magic ^= 1;
    assert!(!h.is_valid());
    // Compatibility requires validity first.
    assert!(!h.is_compatible());
}

#[test]
fn version_mismatch_detected_but_magic_still_valid() {
    let mut h = IpcHandshake::new();
    h.protocol_version = IPC_PROTOCOL_VERSION + 1;
    assert!(h.is_valid());
    assert!(!h.is_compatible());
}

#[test]
fn reserved_fields_must_be_rejected_by_servers() {
    let mut h = IpcHandshake::new();
    h.flags = 1;
    assert!(h.has_reserved_bits_set());
    h.flags = 0;
    h._reserved = 0xFFFF;
    assert!(h.has_reserved_bits_set());

    let mut r = IpcHandshakeReply::ok();
    assert!(!r.has_reserved_bits_set());
    r.flags = 0x8000_0000;
    assert!(r.has_reserved_bits_set());
}

#[test]
fn reply_ok_and_reject_statuses() {
    let ok = IpcHandshakeReply::ok();
    assert_eq!(ok.status, IPC_HANDSHAKE_OK);
    assert_eq!(IPC_HANDSHAKE_OK, 0);

    let mismatch = IpcHandshakeReply::reject(IPC_HANDSHAKE_VERSION_MISMATCH);
    assert_eq!(mismatch.status, 1);

    let rejected = IpcHandshakeReply::reject(IPC_HANDSHAKE_REJECTED);
    assert_eq!(rejected.status, 2);

    for r in [ok, mismatch, rejected] {
        assert_eq!(r.magic, IPC_HANDSHAKE_MAGIC);
        assert_eq!(r.server_abi_major, ABI_VERSION_MAJOR);
        assert_eq!(r.server_abi_minor, ABI_VERSION_MINOR);
    }
}

#[test]
fn handshake_wire_bytes_layout() {
    // Pin exact byte offsets of the 20-byte handshake.
    let h = IpcHandshake::new_with_nonce(0x11223344);
    let b = h.as_bytes();
    assert_eq!(b.len(), 20);
    assert_eq!(&b[0..4], &IPC_HANDSHAKE_MAGIC.to_le_bytes());   // magic @0
    assert_eq!(&b[4..6], &IPC_PROTOCOL_VERSION.to_le_bytes());  // version @4
    assert_eq!(&b[8..10], &ABI_VERSION_MAJOR.to_le_bytes());    // major @8
    assert_eq!(&b[10..12], &ABI_VERSION_MINOR.to_le_bytes());   // minor @10
    assert_eq!(&b[12..16], &0x11223344u32.to_le_bytes());       // nonce @12

    // Reply layout.
    let r = IpcHandshakeReply::ok();
    let rb = r.as_bytes();
    assert_eq!(rb.len(), 16);
    assert_eq!(&rb[0..4], &IPC_HANDSHAKE_MAGIC.to_le_bytes());
    assert_eq!(&rb[6..8], &IPC_HANDSHAKE_OK.to_le_bytes());     // status @6
}
