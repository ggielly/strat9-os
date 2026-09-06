//! L1 — `strat9_syscall`: dirent records, SchemeV2, SigAbi wire conformance.
//!
//! `DirentIter` parses the packed kernel getdents format
//! (`DirentHeader(12B) + name + NUL`). Malicious or truncated buffers come
//! straight from filesystem silos — the iterator must never panic and never
//! read out of bounds.

use strat9_syscall::dirent::{Dirent, DirentIter};
use strat9_syscall::schemev2::SchemeV2;
use strat9_syscall::sigabi::SigAbi;
use strat9_abi::data::DirentHeader;

// ===========================================================================
// Dirent construction
// ===========================================================================

#[test]
fn dirent_new_and_name() {
    let d = Dirent::new(42, 4 /* DT_DIR */, b"hello.txt");
    assert_eq!(d.ino, 42);
    assert_eq!(d.type_, 4);
    assert_eq!(d.name(), b"hello.txt");
    assert_eq!(d.to_string(), "hello.txt");
}

#[test]
fn dirent_truncates_names_over_255_bytes() {
    // Inline buffer is 256 with a 255-char cap (NUL reservation).
    let long = vec![b'a'; 400];
    let d = Dirent::new(1, 1, &long);
    assert_eq!(d.name().len(), 255);
    assert_eq!(&d.name()[253..], b"aa");

    // Exactly 255 fits; 256 truncates to 255 too.
    assert_eq!(Dirent::new(1, 1, &vec![b'b'; 255]).name().len(), 255);
    assert_eq!(Dirent::new(1, 1, &vec![b'c'; 256]).name().len(), 255);
}

#[test]
fn dirent_empty_name_is_valid() {
    let d = Dirent::new(7, 2, b"");
    assert!(d.name().is_empty());
    assert_eq!(d.to_string(), "");
}

#[test]
fn dirent_display_invalid_utf8_falls_back() {
    let mut d = Dirent::new(1, 1, b"abc");
    d.name[0] = 0xFF;
    d.name[1] = 0xFE;
    d.name_len = 2;
    assert_eq!(d.to_string(), "<invalid>");
}

// ===========================================================================
// DirentIter: packed wire parsing
// ===========================================================================

/// Builds a packed record: header + name + NUL (the kernel wire format).
fn pack_record(ino: u64, file_type: u8, name: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&ino.to_le_bytes());
    v.push(file_type);
    v.extend_from_slice(&(name.len() as u16).to_le_bytes());
    v.push(0); // padding byte
    v.extend_from_slice(name);
    v.push(0); // NUL terminator
    v
}

#[test]
fn iter_parses_multiple_records() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&pack_record(1, 8 /* DT_REG */, b"a"));
    buf.extend_from_slice(&pack_record(2, 4 /* DT_DIR */, b"dir"));
    buf.extend_from_slice(&pack_record(u64::MAX, 10 /* DT_LNK */, b"link"));

    let entries: Vec<Dirent> = DirentIter::new(&buf, buf.len()).collect();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].ino, 1);
    assert_eq!(entries[0].name(), b"a");
    assert_eq!(entries[1].ino, 2);
    assert_eq!(entries[1].name(), b"dir");
    assert_eq!(entries[2].ino, u64::MAX);
    assert_eq!(entries[2].name(), b"link");
}

#[test]
fn iter_respects_valid_len_shorter_than_buffer() {
    let mut buf = pack_record(1, 1, b"one");
    buf.extend_from_slice(&pack_record(2, 1, b"two"));

    let cut = pack_record(1, 1, b"one").len();
    let entries: Vec<Dirent> = DirentIter::new(&buf, cut).collect();
    assert_eq!(entries.len(), 1);

    // valid_len larger than buf is clamped, not panicking.
    let entries: Vec<Dirent> = DirentIter::new(&buf, usize::MAX).collect();
    assert_eq!(entries.len(), 2);
}

#[test]
fn iter_survives_truncated_and_corrupt_records() {
    // Empty buffer.
    assert_eq!(DirentIter::new(&[], 0).count(), 0);

    // Header alone, no name bytes.
    let mut hdr_only = vec![0u8; DirentHeader::SIZE];
    hdr_only[9..11].copy_from_slice(&10u16.to_le_bytes()); // claims 10 name bytes
    assert_eq!(DirentIter::new(&hdr_only, hdr_only.len()).count(), 0);

    // name_len lies beyond the NUL/buffer end → record rejected, no panic.
    let mut buf = Vec::new();
    buf.extend_from_slice(&1u64.to_le_bytes());
    buf.push(1);
    buf.extend_from_slice(&999u16.to_le_bytes());
    buf.push(0);
    buf.extend_from_slice(b"short");
    buf.push(0);
    assert_eq!(DirentIter::new(&buf, buf.len()).count(), 0);
}

#[test]
fn iter_offsets_advance_by_entry_size() {
    // entry_size() must equal exactly what one iteration consumes:
    // header(12) + name_len + NUL(1).
    let rec = pack_record(9, 9, b"abcd"); // 12 + 4 + 1 = 17
    let hdr = DirentHeader {
        ino: 9,
        file_type: 9,
        name_len: 4,
        _padding: 0,
    };
    assert_eq!(hdr.entry_size(), 17);
    assert_eq!(rec.len(), 17);
}

// ===========================================================================
// SchemeV2
// ===========================================================================

#[test]
fn scheme_v2_layout_and_roundtrip() {
    assert_eq!(core::mem::size_of::<SchemeV2>(), 264); // 256 + 4 + 4

    let s = SchemeV2::new("net", 7, 0xFF);
    assert_eq!(s.name(), "net");
    assert_eq!(s.id, 7);
    assert_eq!(s.flags, 0xFF);
}

#[test]
fn scheme_v2_name_truncation_at_255() {
    let long = "x".repeat(300);
    let s = SchemeV2::new(&long, 1, 0);
    assert_eq!(s.name().len(), 255);

    // Empty scheme name is preserved.
    assert_eq!(SchemeV2::new("", 1, 0).name(), "");
}

// ===========================================================================
// SigAbi
// ===========================================================================

#[test]
fn sigabi_layout_is_pinned() {
    // Shared-memory descriptor: layout stability is part of the ABI.
    assert_eq!(core::mem::size_of::<SigAbi>(), 32); // u8@0 pad, handler@8, flags@16, pad, mask@24

    let s = SigAbi::new(9, 0xDEAD_BEEF, 0x7, 0xFFFF_FFFF_FFFF_FFFF);
    assert_eq!(s.signal, 9);
    assert_eq!(s.handler, 0xDEAD_BEEF);
    assert_eq!(s.flags, 0x7);
    assert_eq!(s.mask, u64::MAX);
}
