//! L1 — POSIX ↔ Strat9 flags translation, exhaustively.
//!
//! `posix_oflags_to_strat9` is the single entry point used by musl-compat
//! and relibc to convert `O_*` flags. A regression here silently breaks
//! every file open performed by POSIX binaries.

use strat9_abi::flag::{posix_oflags_to_strat9, CallFlags, MapFlags, OpenFlags, UnlinkFlags};

// POSIX constants (linux x86_64 ABI), duplicated here on purpose: the test
// must not depend on libc and must pin the *expected* input encoding.
const O_RDONLY: u32 = 0o0;
const O_WRONLY: u32 = 0o1;
const O_RDWR: u32 = 0o2;
const O_CREAT: u32 = 0o100;
const O_EXCL: u32 = 0o200;
const O_NOCTTY: u32 = 0o400;
const O_TRUNC: u32 = 0o1000;
const O_APPEND: u32 = 0o2000;
const O_NONBLOCK: u32 = 0o4000;
const O_DIRECTORY: u32 = 0o200000;
const O_NOFOLLOW: u32 = 0o400000;
const O_SYNC: u32 = 0o4010000; // full Linux value incl. O_DSYNC bit (0o4000000 | O_WRONLY)

#[test]
fn access_modes_translate() {
    let rdonly = posix_oflags_to_strat9(O_RDONLY);
    assert!(rdonly.contains(OpenFlags::READ));
    assert!(!rdonly.contains(OpenFlags::WRITE));

    let wronly = posix_oflags_to_strat9(O_WRONLY);
    assert!(wronly.contains(OpenFlags::WRITE));
    assert!(!wronly.contains(OpenFlags::READ));

    let rdwr = posix_oflags_to_strat9(O_RDWR);
    assert!(rdwr.contains(OpenFlags::READ) && rdwr.contains(OpenFlags::WRITE));
}

#[test]
fn access_mode_uses_low_bits_only() {
    // POSIX semantics: access mode = posix & O_ACCMODE (low 2 bits).
    // Values ≥ 4 alias their low-bit pattern (Linux does the same):
    //   4&3=0 → RDONLY, 5&3=1 → WRONLY, 6&3=2 → RDWR,
    //   3 and 7 have low bits 0o3 → no access flag at all.
    assert!(posix_oflags_to_strat9(4).contains(OpenFlags::READ));
    assert!(posix_oflags_to_strat9(5).contains(OpenFlags::WRITE));
    let f = posix_oflags_to_strat9(6);
    assert!(f.contains(OpenFlags::READ) && f.contains(OpenFlags::WRITE));
    for bad in [3u32, 7] {
        let out = posix_oflags_to_strat9(bad);
        assert!(
            !out.contains(OpenFlags::READ) && !out.contains(OpenFlags::WRITE),
            "access mode {} unexpectedly mapped",
            bad
        );
    }
}

/// All combinations of the independent modifier bits with each access mode.
#[test]
fn all_modifier_combinations_translate() {
    const MODIFIERS: &[(u32, fn(&OpenFlags) -> bool)] = &[
        (O_CREAT, |f| f.contains(OpenFlags::CREATE)),
        (O_EXCL, |f| f.contains(OpenFlags::EXCL)),
        (O_TRUNC, |f| f.contains(OpenFlags::TRUNCATE)),
        (O_APPEND, |f| f.contains(OpenFlags::APPEND)),
        (O_NONBLOCK, |f| f.contains(OpenFlags::NONBLOCK)),
        (O_DIRECTORY, |f| f.contains(OpenFlags::DIRECTORY)),
        (O_NOFOLLOW, |f| f.contains(OpenFlags::NOFOLLOW)),
        (O_NOCTTY, |f| f.contains(OpenFlags::NOCTTY)),
        (O_SYNC, |f| f.contains(OpenFlags::SYNC)),
    ];
    const ACCESS_MODES: [u32; 3] = [O_RDONLY, O_WRONLY, O_RDWR];

    // Exhaustive: 2^9 modifiers × 3 access modes = 1536 combinations.
    for mask in 0..(1u32 << MODIFIERS.len()) {
        let mut posix = 0u32;
        for (i, (bit, _)) in MODIFIERS.iter().enumerate() {
            if mask & (1 << i) != 0 {
                posix |= bit;
            }
        }
        for &acc in &ACCESS_MODES {
            let out = posix_oflags_to_strat9(posix | acc);

            // Access mode always translated.
            match acc {
                O_RDONLY => assert!(out.contains(OpenFlags::READ) && !out.contains(OpenFlags::WRITE)),
                O_WRONLY => assert!(out.contains(OpenFlags::WRITE) && !out.contains(OpenFlags::READ)),
                _ => assert!(out.contains(OpenFlags::READ) && out.contains(OpenFlags::WRITE)),
            }
            // Every requested modifier present...
            for (i, (_, check)) in MODIFIERS.iter().enumerate() {
                if mask & (1 << i) != 0 {
                    assert!(check(&out), "modifier bit {} of {:#o} lost", 1 << i, posix | acc);
                }
            }
            // ...and no spurious CREATE/TRUNCATE/etc. when not requested.
            if mask & 1 == 0 {
                assert!(!out.contains(OpenFlags::CREATE));
            }
            if mask & 4 == 0 {
                assert!(!out.contains(OpenFlags::TRUNCATE));
            }
        }
    }
}

#[test]
fn classic_open_calls_translate_correctly() {
    // open(path, O_RDONLY) — most common case
    let f = posix_oflags_to_strat9(O_RDONLY);
    assert_eq!(f, OpenFlags::RDONLY);

    // open(path, O_WRONLY | O_CREAT | O_TRUNC, mode)
    let f = posix_oflags_to_strat9(O_WRONLY | O_CREAT | O_TRUNC);
    assert_eq!(f, OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE);

    // open(path, O_RDWR | O_CREAT | O_EXCL)
    let f = posix_oflags_to_strat9(O_RDWR | O_CREAT | O_EXCL);
    assert_eq!(f, OpenFlags::RDWR | OpenFlags::CREATE | OpenFlags::EXCL);

    // open(dir, O_RDONLY | O_DIRECTORY)
    let f = posix_oflags_to_strat9(O_RDONLY | O_DIRECTORY);
    assert_eq!(f, OpenFlags::READ | OpenFlags::DIRECTORY);
}

#[test]
fn openflags_bit_values_are_pinned() {
    assert_eq!(OpenFlags::READ.bits(), 1 << 0);
    assert_eq!(OpenFlags::WRITE.bits(), 1 << 1);
    assert_eq!(OpenFlags::CREATE.bits(), 1 << 2);
    assert_eq!(OpenFlags::TRUNCATE.bits(), 1 << 3);
    assert_eq!(OpenFlags::APPEND.bits(), 1 << 4);
    assert_eq!(OpenFlags::DIRECTORY.bits(), 1 << 5);
    assert_eq!(OpenFlags::EXCL.bits(), 1 << 6);
    assert_eq!(OpenFlags::NONBLOCK.bits(), 1 << 7);
    assert_eq!(OpenFlags::NOFOLLOW.bits(), 1 << 8);
    assert_eq!(OpenFlags::NOCTTY.bits(), 1 << 9);
    assert_eq!(OpenFlags::SYNC.bits(), 1 << 10);
}

#[test]
fn openflags_aliases_are_stable() {
    assert_eq!(OpenFlags::RDONLY, OpenFlags::READ);
    assert_eq!(OpenFlags::WRONLY, OpenFlags::WRITE);
    assert_eq!(OpenFlags::RDWR, OpenFlags::READ | OpenFlags::WRITE);
}

#[test]
fn mapflags_bit_values_are_pinned() {
    // Kernel paging code depends on these exact bits.
    assert_eq!(MapFlags::MAP_SHARED.bits(), 0x01);
    assert_eq!(MapFlags::MAP_PRIVATE.bits(), 0x02);
    assert_eq!(MapFlags::MAP_FIXED.bits(), 0x10);
    assert_eq!(MapFlags::MAP_ANONYMOUS.bits(), 0x0020);
    assert_eq!(MapFlags::MAP_NORESERVE.bits(), 0x40);
    assert_eq!(MapFlags::MAP_GROWSDOWN.bits(), 0x0100);
    assert_eq!(MapFlags::MAP_LOCKED.bits(), 0x2000);
    assert_eq!(MapFlags::MAP_POPULATE.bits(), 0x8000);
}

#[test]
fn call_and_unlink_flags_are_pinned() {
    assert_eq!(CallFlags::READ.bits(), 0x01);
    assert_eq!(CallFlags::WRITE.bits(), 0x02);
    assert_eq!(CallFlags::NONBLOCK.bits(), 0x04);
    assert_eq!(CallFlags::PEEK.bits(), 0x08);
    assert_eq!(CallFlags::WAIT.bits(), 0x10);
    assert_eq!(CallFlags::NOWAIT.bits(), 0x20);

    assert_eq!(UnlinkFlags::REMOVEDIR.bits(), 0o02000000);
}
