//! Errno and error-path self-test suite.
//!
//! Validates that invalid arguments, missing resources, and bad descriptors
//! return the correct error codes across all major syscall families.
//!
//! Runs only under `feature = "selftest"`.

use alloc::format;

use crate::{
    process::{add_task, scheduler::ticks, Task, TaskPriority},
    syscall::error::SyscallError,
    vfs,
};

fn log_section(title: &str) {
    crate::serial_println!(
        "[errno-test][STEP] ========================================================"
    );
    crate::serial_println!("[errno-test][STEP] {}", title);
    crate::serial_println!(
        "[errno-test][STEP] ========================================================"
    );
}

fn record(name: &str, ok: bool, passed: &mut usize, total: &mut usize) {
    *total += 1;
    if ok {
        *passed += 1;
    }
    crate::serial_println!(
        "[errno-test][ASSERT][SCENARIO] {:<48} => {}",
        name,
        if ok { "PASS" } else { "FAIL" }
    );
}

fn expect_err<T: core::fmt::Debug>(
    label: &str,
    result: Result<T, SyscallError>,
    expected: SyscallError,
) -> bool {
    match result {
        Err(e) if e == expected => {
            crate::serial_println!("[errno-test][STEP] {} => {:?} ✓", label, e);
            true
        }
        Err(e) => {
            crate::serial_println!(
                "[errno-test][ASSERT] FAIL: {} expected {:?}, got {:?}",
                label,
                expected,
                e
            );
            false
        }
        Ok(val) => {
            crate::serial_println!(
                "[errno-test][ASSERT] FAIL: {} expected {:?}, got Ok({:?})",
                label,
                expected,
                val
            );
            false
        }
    }
}

fn expect_any_err<T: core::fmt::Debug>(label: &str, result: Result<T, SyscallError>) -> bool {
    match result {
        Err(e) => {
            crate::serial_println!("[errno-test][STEP] {} => {:?} ✓", label, e);
            true
        }
        Ok(val) => {
            crate::serial_println!(
                "[errno-test][ASSERT] FAIL: {} expected error, got Ok({:?})",
                label,
                val
            );
            false
        }
    }
}

fn run_errno_suite() -> bool {
    let base = format!("/tmp/errno-{}", ticks());
    let _ = vfs::mkdir(&base, 0o755);

    let mut passed = 0usize;
    let mut total = 0usize;

    // ── 1. close invalid fd → BadHandle ─────────────────────────────────────
    log_section("1. CLOSE INVALID FD");
    let s = expect_err("close(9999)", vfs::close(9999), SyscallError::BadHandle);
    record("close(9999) → EBADF", s, &mut passed, &mut total);

    // ── 2. read invalid fd → BadHandle ──────────────────────────────────────
    log_section("2. READ INVALID FD");
    let mut buf = [0u8; 8];
    let s = expect_err(
        "read(9999)",
        vfs::read(9999, &mut buf),
        SyscallError::BadHandle,
    );
    record("read(9999) → EBADF", s, &mut passed, &mut total);

    // ── 3. write invalid fd → BadHandle ─────────────────────────────────────
    log_section("3. WRITE INVALID FD");
    let s = expect_err(
        "write(9999)",
        vfs::write(9999, b"x"),
        SyscallError::BadHandle,
    );
    record("write(9999) → EBADF", s, &mut passed, &mut total);

    // ── 4. fstat invalid fd → BadHandle ─────────────────────────────────────
    log_section("4. FSTAT INVALID FD");
    let s = expect_err("fstat(9999)", vfs::fstat(9999), SyscallError::BadHandle);
    record("fstat(9999) → EBADF", s, &mut passed, &mut total);

    // ── 5. lseek invalid fd → BadHandle ─────────────────────────────────────
    log_section("5. LSEEK INVALID FD");
    let s = expect_err(
        "lseek(9999)",
        vfs::lseek(9999, 0, 0),
        SyscallError::BadHandle,
    );
    record("lseek(9999) → EBADF", s, &mut passed, &mut total);

    // ── 6. dup invalid fd → BadHandle ───────────────────────────────────────
    log_section("6. DUP INVALID FD");
    let s = expect_err("dup(9999)", vfs::dup(9999), SyscallError::BadHandle);
    record("dup(9999) → EBADF", s, &mut passed, &mut total);

    // ── 7. dup2 invalid fd → BadHandle ──────────────────────────────────────
    log_section("7. DUP2 INVALID FD");
    let s = expect_err(
        "dup2(9999, 10)",
        vfs::dup2(9999, 10),
        SyscallError::BadHandle,
    );
    record("dup2(9999, 10) → EBADF", s, &mut passed, &mut total);

    // ── 8. double close → BadHandle ─────────────────────────────────────────
    log_section("8. DOUBLE CLOSE");
    let mut s = true;
    let f = format!("{}/dbl_close.txt", base);
    let _ = vfs::create_file(&f, 0o644);
    match vfs::open(&f, vfs::OpenFlags::READ) {
        Ok(fd) => {
            let _ = vfs::close(fd);
            s = expect_err(
                "close(fd) 2nd time",
                vfs::close(fd),
                SyscallError::BadHandle,
            );
        }
        Err(e) => {
            crate::serial_println!("[errno-test][STEP] open => {:?}", e);
            s = false;
        }
    }
    let _ = vfs::unlink(&f);
    record("double close → EBADF", s, &mut passed, &mut total);

    // ── 9. open non-existent → NotFound ─────────────────────────────────────
    log_section("9. OPEN NON-EXISTENT");
    let s = expect_err(
        "open(/tmp/does_not_exist_xyz)",
        vfs::open("/tmp/does_not_exist_xyz", vfs::OpenFlags::READ),
        SyscallError::NotFound,
    );
    record("open non-existent → ENOENT", s, &mut passed, &mut total);

    // ── 10. unlink non-existent → NotFound ──────────────────────────────────
    log_section("10. UNLINK NON-EXISTENT");
    let s = expect_err(
        "unlink(non_existent)",
        vfs::unlink(&format!("{}/nonexistent_file_xyz", base)),
        SyscallError::NotFound,
    );
    record("unlink non-existent → ENOENT", s, &mut passed, &mut total);

    // ── 11. mkdir existing → AlreadyExists ──────────────────────────────────
    log_section("11. MKDIR EXISTING");
    let existing = format!("{}/existing_dir", base);
    let _ = vfs::mkdir(&existing, 0o755);
    let s = expect_err(
        "mkdir(existing)",
        vfs::mkdir(&existing, 0o755),
        SyscallError::AlreadyExists,
    );
    let _ = vfs::unlink(&existing);
    record("mkdir existing → EEXIST", s, &mut passed, &mut total);

    // ── 12. create_file existing → AlreadyExists ────────────────────────────
    log_section("12. CREATE_FILE EXISTING");
    let exist_f = format!("{}/exists.txt", base);
    let _ = vfs::create_file(&exist_f, 0o644);
    let s = expect_err(
        "create_file(existing)",
        vfs::create_file(&exist_f, 0o644),
        SyscallError::AlreadyExists,
    );
    let _ = vfs::unlink(&exist_f);
    record("create_file existing → EEXIST", s, &mut passed, &mut total);

    // ── 13. rename non-existent source → NotFound ───────────────────────────
    log_section("13. RENAME NON-EXISTENT SRC");
    let s = expect_err(
        "rename(nonexistent, dst)",
        vfs::rename(
            &format!("{}/rename_src_xyz", base),
            &format!("{}/rename_dst_xyz", base),
        ),
        SyscallError::NotFound,
    );
    record("rename non-existent → ENOENT", s, &mut passed, &mut total);

    // ── 14. link non-existent source → NotFound ─────────────────────────────
    log_section("14. LINK NON-EXISTENT SRC");
    let s = expect_err(
        "link(nonexistent, dst)",
        vfs::link(
            &format!("{}/link_src_xyz", base),
            &format!("{}/link_dst_xyz", base),
        ),
        SyscallError::NotFound,
    );
    record("link non-existent → ENOENT", s, &mut passed, &mut total);

    // ── 15. chmod non-existent → error ──────────────────────────────────────
    log_section("15. CHMOD NON-EXISTENT");
    let s = expect_any_err(
        "chmod(nonexistent)",
        vfs::chmod(&format!("{}/chmod_xyz", base), 0o700),
    );
    record("chmod non-existent → error", s, &mut passed, &mut total);

    // ── 16. readlink on regular file → error ────────────────────────────────
    log_section("16. READLINK ON REGULAR FILE");
    let f_not_sym = format!("{}/not_a_symlink.txt", base);
    let _ = vfs::create_file(&f_not_sym, 0o644);
    let s = expect_any_err("readlink(regular_file)", vfs::readlink(&f_not_sym));
    let _ = vfs::unlink(&f_not_sym);
    record(
        "readlink on regular file → error",
        s,
        &mut passed,
        &mut total,
    );

    // ── 17. truncate non-existent → error ───────────────────────────────────
    log_section("17. TRUNCATE NON-EXISTENT");
    let s = expect_any_err(
        "truncate(nonexistent, 0)",
        vfs::truncate(&format!("{}/trunc_xyz", base), 0),
    );
    record("truncate non-existent → error", s, &mut passed, &mut total);

    // ── 18. fchmod invalid fd → BadHandle ───────────────────────────────────
    log_section("18. FCHMOD INVALID FD");
    let s = expect_err(
        "fchmod(9999)",
        vfs::fchmod(9999, 0o700),
        SyscallError::BadHandle,
    );
    record("fchmod(9999) → EBADF", s, &mut passed, &mut total);

    // ── 19. ftruncate invalid fd → BadHandle ────────────────────────────────
    log_section("19. FTRUNCATE INVALID FD");
    let s = expect_err(
        "ftruncate(9999)",
        vfs::ftruncate(9999, 0),
        SyscallError::BadHandle,
    );
    record("ftruncate(9999) → EBADF", s, &mut passed, &mut total);

    // ── 20. SyscallError::to_raw encodes correctly ──────────────────────────
    log_section("20. SYSCALL ERROR ENCODING");
    let mut s = true;
    let cases: &[(SyscallError, i64)] = &[
        (SyscallError::PermissionDenied, -1),
        (SyscallError::NotFound, -2),
        (SyscallError::Interrupted, -4),
        (SyscallError::IoError, -5),
        (SyscallError::BadHandle, -9),
        (SyscallError::NoChildren, -10),
        (SyscallError::Again, -11),
        (SyscallError::OutOfMemory, -12),
        (SyscallError::AccessDenied, -13),
        (SyscallError::Fault, -14),
        (SyscallError::AlreadyExists, -17),
        (SyscallError::InvalidArgument, -22),
        (SyscallError::Pipe, -32),
        (SyscallError::NotImplemented, -38),
        (SyscallError::NotSupported, -52),
        (SyscallError::TimedOut, -110),
    ];
    for &(err, expected_raw) in cases {
        let raw = err.to_raw();
        let as_i64 = raw as i64;
        crate::serial_println!(
            "[errno-test][STEP] {:?}.to_raw() = {:#x} (i64={})",
            err,
            raw,
            as_i64
        );
        if as_i64 != expected_raw {
            crate::serial_println!(
                "[errno-test][ASSERT] FAIL: {:?} expected raw {}, got {}",
                err,
                expected_raw,
                as_i64
            );
            s = false;
        }
    }
    record("SyscallError::to_raw encoding", s, &mut passed, &mut total);

    // ── 21. SyscallError::from_code round-trip ──────────────────────────────
    log_section("21. SYSCALL ERROR FROM_CODE");
    let mut s = true;
    for &(err, expected_raw) in cases {
        let recovered = SyscallError::from_code(expected_raw);
        crate::serial_println!(
            "[errno-test][STEP] from_code({}) => {:?}",
            expected_raw,
            recovered
        );
        if recovered != err {
            crate::serial_println!(
                "[errno-test][ASSERT] FAIL: from_code({}) expected {:?}, got {:?}",
                expected_raw,
                err,
                recovered
            );
            s = false;
        }
    }
    record(
        "SyscallError::from_code round-trip",
        s,
        &mut passed,
        &mut total,
    );

    // ── 22. SyscallError::name returns correct strings ──────────────────────
    log_section("22. SYSCALL ERROR NAMES");
    let mut s = true;
    let name_cases: &[(SyscallError, &str)] = &[
        (SyscallError::PermissionDenied, "EPERM"),
        (SyscallError::NotFound, "ENOENT"),
        (SyscallError::Interrupted, "EINTR"),
        (SyscallError::IoError, "EIO"),
        (SyscallError::BadHandle, "EBADF"),
        (SyscallError::Again, "EAGAIN"),
        (SyscallError::OutOfMemory, "ENOMEM"),
        (SyscallError::Fault, "EFAULT"),
        (SyscallError::AlreadyExists, "EEXIST"),
        (SyscallError::InvalidArgument, "EINVAL"),
        (SyscallError::Pipe, "EPIPE"),
        (SyscallError::NotImplemented, "ENOSYS"),
        (SyscallError::NotSupported, "ENOTSUP"),
        (SyscallError::TimedOut, "ETIMEDOUT"),
    ];
    for &(err, expected_name) in name_cases {
        let name = err.name();
        crate::serial_println!("[errno-test][STEP] {:?}.name() => '{}'", err, name);
        if name != expected_name {
            crate::serial_println!(
                "[errno-test][ASSERT] FAIL: {:?}.name() expected '{}', got '{}'",
                err,
                expected_name,
                name
            );
            s = false;
        }
    }
    record("SyscallError::name()", s, &mut passed, &mut total);

    // ── 23. is_retryable ────────────────────────────────────────────────────
    log_section("23. IS_RETRYABLE");
    let mut s = true;
    if !SyscallError::Interrupted.is_retryable() {
        crate::serial_println!("[errno-test][ASSERT] FAIL: Interrupted should be retryable");
        s = false;
    }
    if !SyscallError::Again.is_retryable() {
        crate::serial_println!("[errno-test][ASSERT] FAIL: Again should be retryable");
        s = false;
    }
    if SyscallError::NotFound.is_retryable() {
        crate::serial_println!("[errno-test][ASSERT] FAIL: NotFound should NOT be retryable");
        s = false;
    }
    if SyscallError::InvalidArgument.is_retryable() {
        crate::serial_println!(
            "[errno-test][ASSERT] FAIL: InvalidArgument should NOT be retryable"
        );
        s = false;
    }
    record("is_retryable", s, &mut passed, &mut total);

    // ── 24. symlink to non-existent target ──────────────────────────────────
    log_section("24. SYMLINK DANGLING");
    let sym_dangle = format!("{}/dangling_sym", base);
    let mut s = true;
    match vfs::symlink("nonexistent_target_xyz", &sym_dangle) {
        Ok(()) => {
            crate::serial_println!(
                "[errno-test][STEP] symlink to non-existent target: ok (expected)"
            );
            match vfs::readlink(&sym_dangle) {
                Ok(target) => {
                    crate::serial_println!("[errno-test][STEP] readlink => '{}'", target);
                    if target != "nonexistent_target_xyz" {
                        crate::serial_println!(
                            "[errno-test][ASSERT] FAIL: readlink content mismatch"
                        );
                        s = false;
                    }
                }
                Err(e) => {
                    crate::serial_println!("[errno-test][STEP] readlink => {:?}", e);
                    s = false;
                }
            }
            let _ = vfs::unlink(&sym_dangle);
        }
        Err(e) => {
            crate::serial_println!("[errno-test][STEP] symlink => {:?}", e);
            s = false;
        }
    }
    record("symlink to dangling target", s, &mut passed, &mut total);

    // ── Cleanup ─────────────────────────────────────────────────────────────
    crate::serial_println!("[errno-test][CLEANUP] best-effort cleanup");
    let _ = vfs::unlink(&base);

    // ── Summary ─────────────────────────────────────────────────────────────
    log_section("ERRNO TEST SUMMARY");
    let ok = passed == total;
    crate::serial_println!(
        "[errno-test][ASSERT] result: {}/{} scenarios PASS",
        passed,
        total
    );
    crate::serial_println!(
        "[errno-test][ASSERT] final : {}",
        if ok { "PASS" } else { "FAIL" }
    );
    ok
}

extern "C" fn errno_test_main() -> ! {
    crate::serial_println!("[errno-test][SETUP] task start");
    let _ = run_errno_suite();
    crate::serial_println!("[errno-test][CLEANUP] task done");
    crate::process::scheduler::exit_current_task(0);
}

pub fn create_errno_test_task() {
    if let Ok(task) = Task::new_kernel_task(errno_test_main, "errno-test", TaskPriority::Normal) {
        add_task(task);
    } else {
        crate::serial_println!("[errno-test][SETUP] failed to create task");
    }
}
