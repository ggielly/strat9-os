//! ABI layout self-tests — struct sizes, alignments, field offsets, constants.
//!
//! Validates that the kernel's view of ABI structures matches the published
//! contract in `strat9_abi`. Runs under `feature = "selftest"` only.

use crate::process::{add_task, Task, TaskPriority};
use strat9_abi::{
    data::{
        DirentHeader, FileStat, HandleInfo, IpcMessage, Map, PciAddress, PciDeviceInfo,
        PciProbeCriteria, Stat, StatVfs, TimeSpec, DT_BLK, DT_CHR, DT_DIR, DT_FIFO, DT_LNK, DT_REG,
        DT_SOCK, DT_UNKNOWN, SEEK_CUR, SEEK_END, SEEK_SET,
    },
    ipc::{
        IpcHandshake, IpcHandshakeReply, IPC_HANDSHAKE_MAGIC, IPC_HANDSHAKE_OK,
        IPC_HANDSHAKE_REJECTED, IPC_HANDSHAKE_VERSION_MISMATCH, IPC_PROTOCOL_VERSION,
    },
    ABI_VERSION_MAJOR, ABI_VERSION_MINOR, ABI_VERSION_PACKED,
};

fn log_section(title: &str) {
    crate::serial_println!(
        "[abi-layout-test][STEP] ========================================================"
    );
    crate::serial_println!("[abi-layout-test][STEP] {}", title);
    crate::serial_println!(
        "[abi-layout-test][STEP] ========================================================"
    );
}

fn record(name: &str, ok: bool, passed: &mut usize, total: &mut usize) {
    *total += 1;
    if ok {
        *passed += 1;
    }
    crate::serial_println!(
        "[abi-layout-test][ASSERT][SCENARIO] {:<48} => {}",
        name,
        if ok { "PASS" } else { "FAIL" }
    );
}

fn check_size<T>(label: &str, expected: usize) -> bool {
    let actual = core::mem::size_of::<T>();
    if actual != expected {
        crate::serial_println!(
            "[abi-layout-test][ASSERT] FAIL: sizeof({}) expected {}, got {}",
            label,
            expected,
            actual
        );
        false
    } else {
        crate::serial_println!(
            "[abi-layout-test][STEP] sizeof({}) = {} (ok)",
            label,
            actual
        );
        true
    }
}

fn check_align<T>(label: &str, expected: usize) -> bool {
    let actual = core::mem::align_of::<T>();
    if actual != expected {
        crate::serial_println!(
            "[abi-layout-test][ASSERT] FAIL: alignof({}) expected {}, got {}",
            label,
            expected,
            actual
        );
        false
    } else {
        crate::serial_println!(
            "[abi-layout-test][STEP] alignof({}) = {} (ok)",
            label,
            actual
        );
        true
    }
}

fn check_offset(label: &str, actual: usize, expected: usize) -> bool {
    if actual != expected {
        crate::serial_println!(
            "[abi-layout-test][ASSERT] FAIL: offset({}) expected {}, got {}",
            label,
            expected,
            actual
        );
        false
    } else {
        crate::serial_println!(
            "[abi-layout-test][STEP] offset({}) = {} (ok)",
            label,
            actual
        );
        true
    }
}

fn check_eq(label: &str, actual: u64, expected: u64) -> bool {
    if actual != expected {
        crate::serial_println!(
            "[abi-layout-test][ASSERT] FAIL: {} expected {}, got {}",
            label,
            expected,
            actual
        );
        false
    } else {
        crate::serial_println!("[abi-layout-test][STEP] {} = {} (ok)", label, actual);
        true
    }
}

fn run_abi_layout_suite() -> bool {
    let mut passed = 0usize;
    let mut total = 0usize;

    // ── 1. Struct sizes ─────────────────────────────────────────────────────
    log_section("STRUCT SIZES");

    let mut s = true;
    s &= check_size::<TimeSpec>("TimeSpec", 16);
    s &= check_size::<Stat>("Stat", 120);
    s &= check_size::<StatVfs>("StatVfs", 88);
    s &= check_size::<Map>("Map", 32);
    s &= check_size::<HandleInfo>("HandleInfo", 16);
    s &= check_size::<FileStat>("FileStat", 112);
    s &= check_size::<IpcMessage>("IpcMessage", 64);
    s &= check_size::<DirentHeader>("DirentHeader", 12);
    s &= check_size::<PciAddress>("PciAddress", 4);
    s &= check_size::<PciProbeCriteria>("PciProbeCriteria", 12);
    s &= check_size::<PciDeviceInfo>("PciDeviceInfo", 16);
    s &= check_size::<IpcHandshake>("IpcHandshake", 20);
    s &= check_size::<IpcHandshakeReply>("IpcHandshakeReply", 16);
    record("all struct sizes", s, &mut passed, &mut total);

    // ── 2. Struct alignments ────────────────────────────────────────────────
    log_section("STRUCT ALIGNMENTS");

    let mut a = true;
    a &= check_align::<TimeSpec>("TimeSpec", 8);
    a &= check_align::<Stat>("Stat", 8);
    a &= check_align::<StatVfs>("StatVfs", 8);
    a &= check_align::<Map>("Map", 8);
    a &= check_align::<HandleInfo>("HandleInfo", 8);
    a &= check_align::<FileStat>("FileStat", 8);
    a &= check_align::<IpcMessage>("IpcMessage", 64);
    a &= check_align::<DirentHeader>("DirentHeader", 1);
    a &= check_align::<PciAddress>("PciAddress", 4);
    a &= check_align::<PciProbeCriteria>("PciProbeCriteria", 4);
    a &= check_align::<PciDeviceInfo>("PciDeviceInfo", 4);
    record("all struct alignments", a, &mut passed, &mut total);

    // ── 3. Field offsets of FileStat ────────────────────────────────────────
    log_section("FILESTAT FIELD OFFSETS");

    let base = FileStat::zeroed();
    let base_ptr = &base as *const FileStat as usize;
    let mut fo = true;
    fo &= check_offset(
        "FileStat::st_dev",
        (&base.st_dev as *const _ as usize) - base_ptr,
        0,
    );
    fo &= check_offset(
        "FileStat::st_ino",
        (&base.st_ino as *const _ as usize) - base_ptr,
        8,
    );
    fo &= check_offset(
        "FileStat::st_mode",
        (&base.st_mode as *const _ as usize) - base_ptr,
        16,
    );
    fo &= check_offset(
        "FileStat::st_nlink",
        (&base.st_nlink as *const _ as usize) - base_ptr,
        20,
    );
    fo &= check_offset(
        "FileStat::st_uid",
        (&base.st_uid as *const _ as usize) - base_ptr,
        24,
    );
    fo &= check_offset(
        "FileStat::st_gid",
        (&base.st_gid as *const _ as usize) - base_ptr,
        28,
    );
    fo &= check_offset(
        "FileStat::st_rdev",
        (&base.st_rdev as *const _ as usize) - base_ptr,
        32,
    );
    fo &= check_offset(
        "FileStat::st_size",
        (&base.st_size as *const _ as usize) - base_ptr,
        40,
    );
    fo &= check_offset(
        "FileStat::st_blksize",
        (&base.st_blksize as *const _ as usize) - base_ptr,
        48,
    );
    fo &= check_offset(
        "FileStat::st_blocks",
        (&base.st_blocks as *const _ as usize) - base_ptr,
        56,
    );
    fo &= check_offset(
        "FileStat::st_atime",
        (&base.st_atime as *const _ as usize) - base_ptr,
        64,
    );
    fo &= check_offset(
        "FileStat::st_mtime",
        (&base.st_mtime as *const _ as usize) - base_ptr,
        80,
    );
    fo &= check_offset(
        "FileStat::st_ctime",
        (&base.st_ctime as *const _ as usize) - base_ptr,
        96,
    );
    record("FileStat field offsets", fo, &mut passed, &mut total);

    // ── 4. Field offsets of IpcMessage ──────────────────────────────────────
    log_section("IPCMESSAGE FIELD OFFSETS");

    let msg = IpcMessage::new(0);
    let msg_ptr = &msg as *const IpcMessage as usize;
    let mut mo = true;
    mo &= check_offset(
        "IpcMessage::sender",
        (&msg.sender as *const _ as usize) - msg_ptr,
        0,
    );
    mo &= check_offset(
        "IpcMessage::msg_type",
        (&msg.msg_type as *const _ as usize) - msg_ptr,
        8,
    );
    mo &= check_offset(
        "IpcMessage::flags",
        (&msg.flags as *const _ as usize) - msg_ptr,
        12,
    );
    mo &= check_offset(
        "IpcMessage::payload",
        (&msg.payload as *const _ as usize) - msg_ptr,
        16,
    );
    record("IpcMessage field offsets", mo, &mut passed, &mut total);

    // ── 5. Field offsets of IpcHandshake ────────────────────────────────────
    log_section("IPCHANDSHAKE FIELD OFFSETS");

    let hs = IpcHandshake::new();
    let hs_ptr = &hs as *const IpcHandshake as usize;
    let mut ho = true;
    ho &= check_offset(
        "IpcHandshake::magic",
        (&hs.magic as *const _ as usize) - hs_ptr,
        0,
    );
    ho &= check_offset(
        "IpcHandshake::protocol_version",
        (&hs.protocol_version as *const _ as usize) - hs_ptr,
        4,
    );
    ho &= check_offset(
        "IpcHandshake::_reserved",
        (&hs._reserved as *const _ as usize) - hs_ptr,
        6,
    );
    ho &= check_offset(
        "IpcHandshake::client_abi_major",
        (&hs.client_abi_major as *const _ as usize) - hs_ptr,
        8,
    );
    ho &= check_offset(
        "IpcHandshake::client_abi_minor",
        (&hs.client_abi_minor as *const _ as usize) - hs_ptr,
        10,
    );
    ho &= check_offset(
        "IpcHandshake::nonce",
        (&hs.nonce as *const _ as usize) - hs_ptr,
        12,
    );
    ho &= check_offset(
        "IpcHandshake::flags",
        (&hs.flags as *const _ as usize) - hs_ptr,
        16,
    );
    record("IpcHandshake field offsets", ho, &mut passed, &mut total);

    // ── 6. ABI version constants ────────────────────────────────────────────
    log_section("ABI VERSION CONSTANTS");

    let mut vc = true;
    vc &= check_eq("ABI_VERSION_MAJOR", ABI_VERSION_MAJOR as u64, 0);
    vc &= check_eq("ABI_VERSION_MINOR", ABI_VERSION_MINOR as u64, 1);
    let expected_packed = ((ABI_VERSION_MAJOR as u32) << 16) | (ABI_VERSION_MINOR as u32);
    vc &= check_eq(
        "ABI_VERSION_PACKED",
        ABI_VERSION_PACKED as u64,
        expected_packed as u64,
    );
    record("ABI version constants", vc, &mut passed, &mut total);

    // ── 7. IPC handshake constants ──────────────────────────────────────────
    log_section("IPC HANDSHAKE CONSTANTS");

    let mut ic = true;
    ic &= check_eq(
        "IPC_HANDSHAKE_MAGIC",
        IPC_HANDSHAKE_MAGIC as u64,
        0x4950_4339,
    );
    ic &= check_eq("IPC_PROTOCOL_VERSION", IPC_PROTOCOL_VERSION as u64, 1);
    ic &= check_eq("IPC_HANDSHAKE_OK", IPC_HANDSHAKE_OK as u64, 0);
    ic &= check_eq(
        "IPC_HANDSHAKE_VERSION_MISMATCH",
        IPC_HANDSHAKE_VERSION_MISMATCH as u64,
        1,
    );
    ic &= check_eq("IPC_HANDSHAKE_REJECTED", IPC_HANDSHAKE_REJECTED as u64, 2);
    record("IPC handshake constants", ic, &mut passed, &mut total);

    // ── 8. IpcHandshake logic ───────────────────────────────────────────────
    log_section("IPC HANDSHAKE LOGIC");

    let mut hl = true;
    let h = IpcHandshake::new();
    hl &= h.is_valid();
    if !h.is_valid() {
        crate::serial_println!("[abi-layout-test][ASSERT] FAIL: IpcHandshake::new().is_valid()");
    }
    hl &= h.is_compatible();
    if !h.is_compatible() {
        crate::serial_println!(
            "[abi-layout-test][ASSERT] FAIL: IpcHandshake::new().is_compatible()"
        );
    }
    hl &= h.nonce == 0;
    let h42 = IpcHandshake::new_with_nonce(42);
    hl &= h42.nonce == 42;
    if h42.nonce != 42 {
        crate::serial_println!("[abi-layout-test][ASSERT] FAIL: new_with_nonce(42).nonce != 42");
    }
    hl &= h42.is_valid();
    hl &= h42.is_compatible();
    hl &= h42.magic == IPC_HANDSHAKE_MAGIC;
    hl &= h42.protocol_version == IPC_PROTOCOL_VERSION;
    hl &= h42.client_abi_major == ABI_VERSION_MAJOR;
    hl &= h42.client_abi_minor == ABI_VERSION_MINOR;
    record("IpcHandshake logic", hl, &mut passed, &mut total);

    // ── 9. IpcHandshakeReply logic ──────────────────────────────────────────
    log_section("IPC HANDSHAKE REPLY LOGIC");

    let mut rl = true;
    let rok = IpcHandshakeReply::ok();
    rl &= rok.magic == IPC_HANDSHAKE_MAGIC;
    rl &= rok.status == IPC_HANDSHAKE_OK;
    rl &= rok.protocol_version == IPC_PROTOCOL_VERSION;
    rl &= rok.server_abi_major == ABI_VERSION_MAJOR;
    rl &= rok.server_abi_minor == ABI_VERSION_MINOR;
    let rrej = IpcHandshakeReply::reject(IPC_HANDSHAKE_REJECTED);
    rl &= rrej.status == IPC_HANDSHAKE_REJECTED;
    rl &= rrej.magic == IPC_HANDSHAKE_MAGIC;
    record("IpcHandshakeReply logic", rl, &mut passed, &mut total);

    // ── 10. TimeSpec helpers ────────────────────────────────────────────────
    log_section("TIMESPEC HELPERS");

    let mut th = true;
    let z = TimeSpec::zero();
    th &= z.tv_sec == 0 && z.tv_nsec == 0;
    th &= z.to_nanos() == 0;
    let t1 = TimeSpec::from_nanos(1_500_000_000);
    th &= t1.tv_sec == 1;
    th &= t1.tv_nsec == 500_000_000;
    th &= t1.to_nanos() == 1_500_000_000;
    let t2 = TimeSpec::from_nanos(0);
    th &= t2.tv_sec == 0 && t2.tv_nsec == 0;
    let t3 = TimeSpec::from_nanos(999_999_999);
    th &= t3.tv_sec == 0;
    th &= t3.tv_nsec == 999_999_999;
    let t4 = TimeSpec::from_nanos(10_000_000_000);
    th &= t4.tv_sec == 10;
    th &= t4.tv_nsec == 0;
    th &= t4.to_nanos() == 10_000_000_000;
    if !th {
        crate::serial_println!("[abi-layout-test][ASSERT] FAIL: TimeSpec helper mismatch");
    }
    record("TimeSpec helpers", th, &mut passed, &mut total);

    // ── 11. FileStat helpers ────────────────────────────────────────────────
    log_section("FILESTAT HELPERS");

    let mut fh = true;
    let zs = FileStat::zeroed();
    fh &= zs.st_dev == 0 && zs.st_ino == 0 && zs.st_mode == 0;
    fh &= zs.st_nlink == 0 && zs.st_uid == 0 && zs.st_gid == 0;
    fh &= zs.st_rdev == 0 && zs.st_size == 0;
    fh &= zs.st_atime.tv_sec == 0 && zs.st_atime.tv_nsec == 0;
    fh &= zs.st_mtime.tv_sec == 0 && zs.st_ctime.tv_sec == 0;
    fh &= !zs.is_dir();
    fh &= !zs.is_file();
    let mut dir_st = FileStat::zeroed();
    dir_st.st_mode = 0o040755;
    fh &= dir_st.is_dir();
    fh &= !dir_st.is_file();
    let mut file_st = FileStat::zeroed();
    file_st.st_mode = 0o100644;
    fh &= file_st.is_file();
    fh &= !file_st.is_dir();
    record("FileStat helpers", fh, &mut passed, &mut total);

    // ── 12. IpcMessage helpers ──────────────────────────────────────────────
    log_section("IPCMESSAGE HELPERS");

    let mut mh = true;
    let m1 = IpcMessage::new(0x42);
    mh &= m1.msg_type == 0x42;
    mh &= m1.sender == 0;
    mh &= m1.flags == 0;
    mh &= m1.payload.iter().all(|b| *b == 0);
    let err = IpcMessage::error_reply(99, -22);
    mh &= err.sender == 99;
    mh &= err.msg_type == 0x80;
    let status_bytes = [
        err.payload[0],
        err.payload[1],
        err.payload[2],
        err.payload[3],
    ];
    let status_val = u32::from_le_bytes(status_bytes);
    mh &= status_val == (-22i32 as u32);
    if !mh {
        crate::serial_println!("[abi-layout-test][ASSERT] FAIL: IpcMessage helper mismatch");
    }
    record("IpcMessage helpers", mh, &mut passed, &mut total);

    // ── 13. DirentHeader constants ──────────────────────────────────────────
    log_section("DIRENTHEADER CONSTANTS");

    let mut dh = true;
    dh &= DirentHeader::SIZE == 12;
    let h = DirentHeader {
        ino: 1,
        file_type: DT_REG,
        name_len: 5,
        _padding: 0,
    };
    dh &= h.entry_size() == 12 + 5 + 1;
    let h2 = DirentHeader {
        ino: 2,
        file_type: DT_DIR,
        name_len: 3,
        _padding: 0,
    };
    dh &= h2.entry_size() == 12 + 3 + 1;
    record("DirentHeader constants", dh, &mut passed, &mut total);

    // ── 14. SEEK / DT constants ─────────────────────────────────────────────
    log_section("POSIX CONSTANTS");

    let mut pc = true;
    pc &= check_eq("SEEK_SET", SEEK_SET as u64, 0);
    pc &= check_eq("SEEK_CUR", SEEK_CUR as u64, 1);
    pc &= check_eq("SEEK_END", SEEK_END as u64, 2);
    pc &= check_eq("DT_UNKNOWN", DT_UNKNOWN as u64, 0);
    pc &= check_eq("DT_FIFO", DT_FIFO as u64, 1);
    pc &= check_eq("DT_CHR", DT_CHR as u64, 2);
    pc &= check_eq("DT_DIR", DT_DIR as u64, 4);
    pc &= check_eq("DT_BLK", DT_BLK as u64, 6);
    pc &= check_eq("DT_REG", DT_REG as u64, 8);
    pc &= check_eq("DT_LNK", DT_LNK as u64, 10);
    pc &= check_eq("DT_SOCK", DT_SOCK as u64, 12);
    record("POSIX constants", pc, &mut passed, &mut total);

    // ── 15. Syscall number block boundaries ─────────────────────────────────
    log_section("SYSCALL NUMBER BLOCKS");

    use strat9_abi::syscall::*;
    let mut sn = true;
    sn &= check_eq("SYS_NULL", SYS_NULL as u64, 0);
    sn &= check_eq("SYS_MMAP", SYS_MMAP as u64, 100);
    sn &= check_eq("SYS_IPC_CREATE_PORT", SYS_IPC_CREATE_PORT as u64, 200);
    sn &= check_eq("SYS_PROC_EXIT", SYS_PROC_EXIT as u64, 300);
    sn &= check_eq("SYS_OPEN", SYS_OPEN as u64, 403);
    sn &= check_eq("SYS_CLOCK_GETTIME", SYS_CLOCK_GETTIME as u64, 500);
    sn &= check_eq("SYS_DEBUG_LOG", SYS_DEBUG_LOG as u64, 600);
    sn &= check_eq("SYS_MODULE_LOAD", SYS_MODULE_LOAD as u64, 700);
    sn &= check_eq("SYS_SILO_CREATE", SYS_SILO_CREATE as u64, 800);
    sn &= check_eq("SYS_ABI_VERSION", SYS_ABI_VERSION as u64, 900);
    sn &= check_eq(
        "SYS_GETPPID alias",
        SYS_GETPPID as u64,
        SYS_PROC_GETPPID as u64,
    );
    sn &= check_eq("SYS_GETPID", SYS_GETPID as u64, 311);
    sn &= check_eq("SYS_GETTID", SYS_GETTID as u64, 312);
    sn &= check_eq("SYS_PIPE", SYS_PIPE as u64, 431);
    sn &= check_eq("SYS_DUP", SYS_DUP as u64, 432);
    sn &= check_eq("SYS_DUP2", SYS_DUP2 as u64, 433);
    sn &= check_eq("SYS_GETDENTS", SYS_GETDENTS as u64, 430);
    sn &= check_eq("SYS_CHDIR", SYS_CHDIR as u64, 440);
    sn &= check_eq("SYS_GETCWD", SYS_GETCWD as u64, 442);
    sn &= check_eq("SYS_UNLINK", SYS_UNLINK as u64, 445);
    sn &= check_eq("SYS_MKDIR", SYS_MKDIR as u64, 447);
    sn &= check_eq("SYS_RENAME", SYS_RENAME as u64, 448);
    sn &= check_eq("SYS_LINK", SYS_LINK as u64, 449);
    sn &= check_eq("SYS_SYMLINK", SYS_SYMLINK as u64, 450);
    sn &= check_eq("SYS_READLINK", SYS_READLINK as u64, 451);
    sn &= check_eq("SYS_CHMOD", SYS_CHMOD as u64, 452);
    sn &= check_eq("SYS_TRUNCATE", SYS_TRUNCATE as u64, 454);
    sn &= check_eq("SYS_PREAD", SYS_PREAD as u64, 456);
    sn &= check_eq("SYS_PWRITE", SYS_PWRITE as u64, 457);
    sn &= check_eq("SYS_POLL", SYS_POLL as u64, 460);
    sn &= check_eq("SYS_NANOSLEEP", SYS_NANOSLEEP as u64, 501);
    sn &= check_eq("SYS_FUTEX_WAIT", SYS_FUTEX_WAIT as u64, 303);
    sn &= check_eq("SYS_KILL", SYS_KILL as u64, 320);
    sn &= check_eq("SYS_SIGACTION", SYS_SIGACTION as u64, 322);
    sn &= check_eq("SYS_CHAN_CREATE", SYS_CHAN_CREATE as u64, 220);
    sn &= check_eq("SYS_SEM_CREATE", SYS_SEM_CREATE as u64, 230);
    sn &= check_eq("SYS_PCI_ENUM", SYS_PCI_ENUM as u64, 240);
    record("syscall number blocks", sn, &mut passed, &mut total);

    // ── 16. Errno values match ABI ──────────────────────────────────────────
    log_section("ERRNO VALUES");

    use strat9_abi::errno::*;
    let mut ev = true;
    ev &= check_eq("EPERM", EPERM as u64, 1);
    ev &= check_eq("ENOENT", ENOENT as u64, 2);
    ev &= check_eq("ESRCH", ESRCH as u64, 3);
    ev &= check_eq("EINTR", EINTR as u64, 4);
    ev &= check_eq("EIO", EIO as u64, 5);
    ev &= check_eq("EBADF", EBADF as u64, 9);
    ev &= check_eq("EAGAIN", EAGAIN as u64, 11);
    ev &= check_eq("ENOMEM", ENOMEM as u64, 12);
    ev &= check_eq("EACCES", EACCES as u64, 13);
    ev &= check_eq("EFAULT", EFAULT as u64, 14);
    ev &= check_eq("EEXIST", EEXIST as u64, 17);
    ev &= check_eq("EINVAL", EINVAL as u64, 22);
    ev &= check_eq("ENOSYS", ENOSYS as u64, 38);
    ev &= check_eq("ENOTSUP", ENOTSUP as u64, 52);
    ev &= check_eq("EPIPE", EPIPE as u64, 32);
    ev &= check_eq("ENOSPC", ENOSPC as u64, 28);
    record("errno values", ev, &mut passed, &mut total);

    // ── Summary ─────────────────────────────────────────────────────────────
    log_section("ABI LAYOUT TEST SUMMARY");
    let ok = passed == total;
    crate::serial_println!(
        "[abi-layout-test][ASSERT] result: {}/{} scenarios PASS",
        passed,
        total
    );
    crate::serial_println!(
        "[abi-layout-test][ASSERT] final : {}",
        if ok { "PASS" } else { "FAIL" }
    );
    ok
}

extern "C" fn abi_layout_test_main() -> ! {
    crate::serial_println!("[abi-layout-test][SETUP] task start");
    let _ = run_abi_layout_suite();
    crate::serial_println!("[abi-layout-test][CLEANUP] task done");
    crate::process::scheduler::exit_current_task(0);
}

pub fn create_abi_layout_test_task() {
    if let Ok(task) = Task::new_kernel_task(
        abi_layout_test_main,
        "abi-layout-test",
        TaskPriority::Normal,
    ) {
        add_task(task);
    } else {
        crate::serial_println!("[abi-layout-test][SETUP] failed to create task");
    }
}
