//! L2 — VFS scheme protocol core + router (verbatim kernel code).
//!
//! `IpcScheme` blocking request/reply paths are excluded (they hit the
//! host-panic reply shim); everything else — pseudo-stat finalization,
//! the KernelScheme static-file registry, and the global scheme router —
//! is exercised for real.

use std::sync::Arc;
use kernel_l2_tests::vfs::{
    get_initfs_file_bytes, get_scheme, list_schemes, register_initfs_file, register_scheme,
    scheme::{finalize_pseudo_stat, FileFlags, FileStat, KernelScheme},
};
use strat9_abi::data::TimeSpec;
use strat9_abi::flag::OpenFlags;

// ===========================================================================
// finalize_pseudo_stat
// ===========================================================================

#[test]
fn finalize_pseudo_stat_fills_device_and_timestamps() {
    let st = FileStat {
        st_dev: 0,
        st_ino: 77,
        st_mode: 0o100644,
        st_nlink: 1,
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
        st_size: 1234,
        st_blksize: 4096,
        st_blocks: 8,
        st_atime: TimeSpec { tv_sec: 0, tv_nsec: 0 },
        st_mtime: TimeSpec { tv_sec: 0, tv_nsec: 0 },
        st_ctime: TimeSpec { tv_sec: 0, tv_nsec: 0 },
    };
    let out = finalize_pseudo_stat(st, 123, 456);
    assert_eq!(out.st_dev, 123);
    assert_eq!(out.st_rdev, 456);
    // Timestamps stamped "now" (host-real clock): sane window check.
    let now_floor = 1_600_000_000u64; // Sept 2020 — anything earlier is a bug
    for ts in [out.st_atime, out.st_mtime, out.st_ctime] {
        assert!(ts.tv_sec as u64 >= now_floor, "timestamp not stamped: {:?}", ts);
    }
}

#[test]
fn file_flags_map_to_ipc_file_flag_bits() {
    assert_eq!(FileFlags::DIRECTORY.bits(), strat9_abi::data::IPC_FILE_FLAG_DIRECTORY);
    assert_eq!(FileFlags::DEVICE.bits(), strat9_abi::data::IPC_FILE_FLAG_DEVICE);
    assert_eq!(FileFlags::PIPE.bits(), strat9_abi::data::IPC_FILE_FLAG_PIPE);
    assert_eq!(FileFlags::APPEND.bits(), strat9_abi::data::IPC_FILE_FLAG_APPEND);
}

#[test]
fn openflags_roundtrip_through_scheme_layer() {
    // Scheme layer re-exports OpenFlags from the ABI; aliases must hold.
    assert_eq!(OpenFlags::RDONLY, OpenFlags::READ);
    assert_eq!(OpenFlags::RDWR, OpenFlags::READ | OpenFlags::WRITE);
}

// ===========================================================================
// KernelScheme: static initfs-style file registry
// ===========================================================================

#[test]
fn kernel_scheme_register_and_lookup() {
    let ks = KernelScheme::new();
    static DATA: &[u8] = b"hello initfs";
    ks.register("/bin/hello", DATA.as_ptr(), DATA.len());
    assert_eq!(ks.lookup_bytes("/bin/hello"), Some(DATA));
    assert_eq!(ks.lookup_bytes("/bin/missing"), None);
    assert_eq!(ks.lookup_bytes(""), None);
}

// ===========================================================================
// Global scheme router
// ===========================================================================

#[test]
fn router_register_get_unregister_roundtrip() {
    let name = "probe-scheme-router";
    let ks: Arc<KernelScheme> = Arc::new(KernelScheme::new());
    register_scheme(name, ks.clone()).expect("register");
    assert!(get_scheme(name).is_some(), "scheme must resolve after register");
    assert!(list_schemes().iter().any(|s| s == name));

    // Duplicate registration must be rejected (registry invariant).
    assert!(register_scheme(name, ks.clone()).is_err(), "duplicate register must fail");
    assert!(get_scheme(name).is_some());
}

#[test]
fn router_unknown_scheme_lookup_is_none() {
    assert!(get_scheme("definitely-not-registered").is_none());
}

#[test]
fn initfs_builtin_flow_register_and_lookup() {
    static PAYLOAD: &[u8] = &[1, 2, 3, 4, 5];

    // Full builtin flow: init registers "kernel" scheme + mounts /initfs
    // (mount shim = recorded no-op), then files become addressable via
    // /initfs/-prefixed paths (get_initfs_file_bytes strips the prefix).
    kernel_l2_tests::vfs::scheme_router::init_builtin_schemes()
        .expect("init_builtin_schemes with no-op mount shim");

    let res = register_initfs_file("probe.bin", PAYLOAD.as_ptr(), PAYLOAD.len());
    assert!(res.is_ok(), "register_initfs_file failed: {:?}", res.err());

    // Lookup strips "/initfs/" and matches the RELATIVE key.
    assert_eq!(get_initfs_file_bytes("/initfs/probe.bin"), Some(PAYLOAD));

    // FINDING F12 (testing-findings.md): keys registered WITH the "/initfs/"
    // prefix are unreachable via get_initfs_file_bytes — the strip produces
    // a different key than the one stored. Kernel boot (lib.rs) registers
    // Limine module paths that DO carry the "/initfs/" prefix
    // ("Registered /initfs/fs-ext4"), suggesting initfs exec may never find
    // those files through this path. Verify against runtime behavior.
    static FULL_PATH: &[u8] = &[9, 9];
    register_initfs_file("/full/path.bin", FULL_PATH.as_ptr(), FULL_PATH.len())
        .expect("register with absolute key");
    assert!(get_initfs_file_bytes("/full/path.bin").is_none(),
        "F12: absolute-key registration should be reported unreachable");
}
