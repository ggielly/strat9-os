//! L1 — VFS types conformance: mode bits, FILETIME conversions, capabilities.
//!
//! `VfsFileType` maps Unix mode bits ↔ internal enum; `VfsTimestamp`
//! converts Unix epoch ↔ Windows FILETIME. Both conversions cross an ABI
//! boundary (disk on-disk format or WinFsp), so every variant and boundary
//! value is pinned.

#[cfg(feature = "alloc")]
use strate_fs_abstraction::FsCapabilities;
use strate_fs_abstraction::{VfsFileType, VfsTimestamp};

// ===========================================================================
// VfsFileType: exhaustive mode-bit mapping
// ===========================================================================

const ALL_TYPES: &[(u32, VfsFileType)] = &[
    (0o100000, VfsFileType::RegularFile),
    (0o040000, VfsFileType::Directory),
    (0o120000, VfsFileType::Symlink),
    (0o060000, VfsFileType::BlockDevice),
    (0o020000, VfsFileType::CharDevice),
    (0o010000, VfsFileType::Fifo),
    (0o140000, VfsFileType::Socket),
];

#[test]
fn file_type_from_mode_all_variants() {
    for &(mode_bits, expected) in ALL_TYPES {
        assert_eq!(VfsFileType::from_mode(mode_bits), expected);
        // Permission bits must not interfere with type detection.
        assert_eq!(VfsFileType::from_mode(mode_bits | 0o755), expected);
    }
}

#[test]
fn file_type_unknown_modes() {
    // S_IFMT values with no Strat9 meaning map to Unknown, never panic.
    // (Valid Linux S_IFMT space: 0o010000..0o140000 assigned values;
    // 0o130000/0o150000/0o160000/0o170000 are unassigned.)
    for mode in [0o130000u32, 0o150000, 0o160000, 0o170000] {
        assert_eq!(VfsFileType::from_mode(mode), VfsFileType::Unknown);
    }
    assert_eq!(VfsFileType::from_mode(0), VfsFileType::Unknown);
    // CAUTION pinned: partial type-bits alias other types after masking
    // (e.g. 0o017777 masks to 0o010000 = Fifo). Matches POSIX masking;
    // callers must pass full st_mode values.
    assert_eq!(VfsFileType::from_mode(0o017777), VfsFileType::Fifo);
}

#[test]
fn file_type_roundtrip_preserves_identity() {
    for &(_, t) in ALL_TYPES {
        assert_eq!(VfsFileType::from_mode(t.to_mode_bits()), t);
    }
}

#[test]
fn file_type_predicates() {
    assert!(VfsFileType::RegularFile.is_file());
    assert!(VfsFileType::Directory.is_dir());
    assert!(VfsFileType::Symlink.is_symlink());
    // Predicates are mutually exclusive...
    for &(_, t) in ALL_TYPES {
        let flags = [t.is_file(), t.is_dir(), t.is_symlink()];
        let set = flags.iter().filter(|&&b| b).count();
        // ...but only File/Dir/Symlink have a dedicated predicate; device,
        // FIFO, socket and Unknown legitimately have none.
        match t {
            VfsFileType::RegularFile | VfsFileType::Directory | VfsFileType::Symlink => {
                assert_eq!(set, 1);
            }
            _ => assert_eq!(set, 0),
        }
    }
    assert!(!VfsFileType::Unknown.is_file());
    assert!(!VfsFileType::Unknown.is_dir());
    assert!(!VfsFileType::Unknown.is_symlink());
}

// ===========================================================================
// VfsTimestamp: Unix epoch ↔ Windows FILETIME
// ===========================================================================

/// FILETIME of the Unix epoch: 11644473600 s × 10^7.
const UNIX_EPOCH_FILETIME: u64 = 116_444_736_000_000_000;

#[test]
fn filetime_epoch_boundaries() {
    assert_eq!(VfsTimestamp::new(0, 0).to_filetime(), UNIX_EPOCH_FILETIME);
    assert_eq!(
        VfsTimestamp::from_filetime(UNIX_EPOCH_FILETIME),
        VfsTimestamp { secs: 0, nsecs: 0 }
    );
}

#[test]
fn filetime_before_windows_epoch_clamps_to_zero() {
    // Dates before the Windows epoch (1601) cannot be represented;
    // documented clamp to 0 instead of wrapping into the future.
    assert_eq!(VfsTimestamp::new(-11_644_473_601, 0).to_filetime(), 0);
    assert_eq!(VfsTimestamp::new(i64::MIN / 2, 999_999_999).to_filetime(), 0);
    // One second BEFORE the Unix epoch is still representable (Windows
    // epoch starts in 1601).
    assert_eq!(
        VfsTimestamp::new(-1, 0).to_filetime(),
        UNIX_EPOCH_FILETIME - 10_000_000
    );
}

#[test]
fn filetime_roundtrip_sample_values() {
    const SAMPLES: &[i64] = &[
        0,
        1,
        951_782_400,      // 2000-01-01
        1_700_000_000,    // ~2023-11
        4_102_444_800,    // year 2100
    ];
    for &secs in SAMPLES {
        for &nsec in &[0u32, 1, 500_000_000, 999_999_999] {
            let ts = VfsTimestamp::new(secs, nsec);
            let back = VfsTimestamp::from_filetime(ts.to_filetime());
            assert_eq!(back.secs, ts.secs, "secs mismatch at {}", secs);
            // FILETIME has 100ns resolution: sub-100ns remainder is lost.
            assert_eq!(back.nsecs, (nsec / 100) * 100);
        }
    }
}

#[test]
#[should_panic(expected = "attempt to multiply with overflow")]
#[cfg(debug_assertions)]
fn filetime_overflow_finding_beyond_year_60k() {
    // FINDING (see testing report): `VfsTimestamp::to_filetime` computes
    // `(secs + WINDOWS_EPOCH_OFFSET) as u64 * 10_000_000` without checked
    // arithmetic. Timestamps past ~year 60000 overflow u64 and PANIC in
    // debug builds (wrap silently in release). On-disk/network input could
    // trigger this via stat paths. Recommend `checked_mul` + FsError.
    let _ = VfsTimestamp::new(i64::MAX / 2, 0).to_filetime();
}

#[test]
fn filetime_nanosecond_quantization_is_100ns() {
    let ts = VfsTimestamp::new(0, 999_999_999); // max nsec
    let ft = ts.to_filetime();
    assert_eq!(ft % 10_000_000, 9_999_999); // 999.999999 µs → 9_999_999 ticks... 
    let back = VfsTimestamp::from_filetime(ft);
    assert_eq!(back.nsecs, 999_999_900); // quantized down to 100ns grid
}

// ===========================================================================
// FsCapabilities: filesystem profile pins
// ===========================================================================

#[cfg(feature = "alloc")]
mod capabilities {
    use super::*;

    #[test]
    fn linux_profiles_are_consistent() {
        let ro = FsCapabilities::read_only_linux();
        assert!(ro.read_only && !ro.can_write());

        let rw = FsCapabilities::writable_linux();
        assert!(!rw.read_only && rw.can_write());
        // writable_linux differs from read-only ONLY by read_only flag.
        assert_eq!(rw.case_sensitive, ro.case_sensitive);
        assert_eq!(rw.max_filename_len, ro.max_filename_len);
        assert_eq!(rw.max_path_len, ro.max_path_len);

        // FsCapabilities does not derive PartialEq; pin default == read_only_linux
        // field by field.
        let d = FsCapabilities::default();
        assert!(d.read_only == ro.read_only
            && d.case_sensitive == ro.case_sensitive
            && d.max_filename_len == ro.max_filename_len
            && d.max_path_len == ro.max_path_len
            && d.supports_symlinks == ro.supports_symlinks
            && d.supports_hardlinks == ro.supports_hardlinks
            && d.max_file_size == ro.max_file_size);
    }

    #[test]
    fn fs_profiles_max_sizes_are_pinned() {
        const TIB: u64 = 1 << 40;
        const PIB: u64 = 1 << 50;
        const EIB: u64 = 1 << 60;

        assert_eq!(FsCapabilities::ext4().max_file_size, 16 * TIB);
        // FINDING (see testing report): capabilities.rs comments claim
        // "8 EiB" (XFS) and "16 EiB" (btrfs) but the literal chains contain
        // only FIVE factors of 1024 -> the actual values are 8 PiB and
        // 16 PiB. Values pinned AS IMPLEMENTED; fix the comments or the
        // arithmetic together with an explicit decision.
        assert_eq!(FsCapabilities::xfs().max_file_size, 8 * PIB);
        assert_eq!(FsCapabilities::btrfs().max_file_size, 16 * PIB);
        // Sanity: those differ from what the comments promise.
        assert_ne!(FsCapabilities::xfs().max_file_size, 8 * EIB);
        // (16 EiB does not even fit in u64 — itself evidence that the
        // comment, not the code, is wrong.)
        assert_eq!(FsCapabilities::read_only_linux().max_file_size, i64::MAX as u64);
    }

    #[test]
    fn common_naming_limits_match_kernel_vfs_expectations() {
        for caps in [
            FsCapabilities::ext4(),
            FsCapabilities::xfs(),
            FsCapabilities::btrfs(),
        ] {
            assert_eq!(caps.max_filename_len, 255);
            assert_eq!(caps.max_path_len, 4096);
            assert!(caps.case_sensitive && caps.case_preserving);
        }
    }
}

// ===========================================================================
// VfsDirEntry (alloc)
// ===========================================================================

#[cfg(feature = "alloc")]
mod dir_entry {
    use strate_fs_abstraction::{VfsDirEntry, VfsFileType};

    #[test]
    fn dir_entry_construction() {
        let e = VfsDirEntry::new("file.txt", 42, VfsFileType::RegularFile);
        assert_eq!({ e.ino }, 42);
        assert!(e.file_type.is_file());
    }
}
