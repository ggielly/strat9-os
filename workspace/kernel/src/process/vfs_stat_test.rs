//! Runtime self-tests for VFS `stat` timestamp semantics on ramfs.
//!
//! Runs only in test ISO (`feature = "selftest"`). The test is intentionally
//! verbose and logs every step with before/after timestamp values.

use alloc::{format, string::String};

use crate::{
    process::{scheduler::ticks, Task, TaskPriority},
    syscall::time::current_time_ns,
    vfs,
};

const STRICT_MODE: bool = true;

/// Performs the ts nanos operation.
fn ts_nanos(st: &vfs::FileStat) -> (u64, u64, u64) {
    (
        st.st_atime.to_nanos(),
        st.st_mtime.to_nanos(),
        st.st_ctime.to_nanos(),
    )
}

/// Performs the log section operation.
fn log_section(title: &str) {
    crate::serial_println!(
        "[vfs-stat-test][STEP] ========================================================"
    );
    crate::serial_println!("[vfs-stat-test][STEP] {}", title);
    crate::serial_println!(
        "[vfs-stat-test][STEP] ========================================================"
    );
}

/// Performs the record scenario operation.
fn record_scenario(name: &str, ok: bool, passed: &mut usize, total: &mut usize) {
    *total += 1;
    if ok {
        *passed += 1;
    }
    crate::serial_println!(
        "[vfs-stat-test][ASSERT][SCENARIO] {:<32} => {}",
        name,
        if ok { "PASS" } else { "FAIL" }
    );
}

/// Performs the wait clock advance operation.
fn wait_clock_advance(prev_ns: u64, label: &str) -> bool {
    let start_tick = ticks();
    const TIMEOUT_TICKS: u64 = 200; // ~2s at 100Hz
    loop {
        let now = current_time_ns();
        if now > prev_ns {
            return true;
        }
        if ticks().saturating_sub(start_tick) > TIMEOUT_TICKS {
            crate::serial_println!(
                "[vfs-stat-test][ASSERT] FAIL: timeout waiting clock advance for '{}' (prev_ns={})",
                label,
                prev_ns
            );
            return false;
        }
        crate::process::yield_task();
    }
}

/// Performs the log stat operation.
fn log_stat(tag: &str, path: &str, st: &vfs::FileStat) {
    let (at, mt, ct) = ts_nanos(st);
    crate::serial_println!(
            "[vfs-stat-test][STEP] {} path='{}' dev={} ino={} mode={:#o} nlink={} uid={} gid={} rdev={} atime={} mtime={} ctime={} size={}",
        tag,
        path,
        st.st_dev,
        st.st_ino,
        st.st_mode,
        st.st_nlink,
        st.st_uid,
        st.st_gid,
        st.st_rdev,
        at,
        mt,
        ct,
        st.st_size
    );
}

/// Performs the assert ge operation.
fn assert_ge(name: &str, lhs: u64, rhs: u64) -> bool {
    if lhs < rhs {
        crate::serial_println!(
            "[vfs-stat-test][ASSERT] FAIL: {} expected >= {}, got {}",
            name,
            rhs,
            lhs
        );
        false
    } else {
        true
    }
}

/// Performs the assert gt operation.
fn assert_gt(name: &str, lhs: u64, rhs: u64) -> bool {
    if lhs <= rhs {
        crate::serial_println!(
            "[vfs-stat-test][ASSERT] FAIL: {} expected > {}, got {}",
            name,
            rhs,
            lhs
        );
        false
    } else {
        true
    }
}

/// Performs the assert eq u64 operation.
fn assert_eq_u64(name: &str, lhs: u64, rhs: u64) -> bool {
    if lhs != rhs {
        crate::serial_println!(
            "[vfs-stat-test][ASSERT] FAIL: {} expected == {}, got {}",
            name,
            rhs,
            lhs
        );
        false
    } else {
        true
    }
}

/// Performs the run vfs stat timestamp suite operation.
fn run_vfs_stat_timestamp_suite() -> bool {
    let base = format!("/tmp/vfs-ts-{}", ticks());
    let file = format!("{}/file.txt", base);
    let file2 = format!("{}/file2.txt", base);
    let hard = format!("{}/file.hard", base);
    let sym = format!("{}/file.sym", base);

    log_section("VFS STAT TIMESTAMP SUITE");
    crate::serial_println!("[vfs-stat-test][SETUP] base path: '{}'", base);
    crate::serial_println!(
        "[vfs-stat-test][SETUP] mode: {}",
        if STRICT_MODE {
            "STRICT (>)"
        } else {
            "RELAXED (>=)"
        }
    );

    if let Err(e) = vfs::mkdir(&base, 0o755) {
        crate::serial_println!("[vfs-stat-test][SETUP] FAIL: mkdir('{}') => {:?}", base, e);
        return false;
    }

    if let Err(e) = vfs::create_file(&file, 0o644) {
        crate::serial_println!(
            "[vfs-stat-test][SETUP] FAIL: create_file('{}') => {:?}",
            file,
            e
        );
        let _ = vfs::unlink(&base);
        return false;
    }

    let fd_file = match vfs::open(&file, vfs::OpenFlags::READ | vfs::OpenFlags::WRITE) {
        Ok(fd) => fd,
        Err(e) => {
            crate::serial_println!("[vfs-stat-test][SETUP] FAIL: open rw file => {:?}", e);
            let _ = vfs::unlink(&file);
            let _ = vfs::unlink(&base);
            return false;
        }
    };

    let mut st = match vfs::fstat(fd_file) {
        Ok(s) => s,
        Err(e) => {
            crate::serial_println!("[vfs-stat-test][SETUP] FAIL: fstat create => {:?}", e);
            let _ = vfs::close(fd_file);
            let _ = vfs::unlink(&file);
            let _ = vfs::unlink(&base);
            return false;
        }
    };
    log_stat("after create", &file, &st);
    let mut ok = true;
    let mut passed = 0usize;
    let mut total = 0usize;

    // 1) READ should update atime
    let mut s1_ok = true;
    let (_, m0, c0) = ts_nanos(&st);
    let anchor = core::cmp::max(core::cmp::max(ts_nanos(&st).0, m0), c0);
    if !wait_clock_advance(anchor, "before read") {
        s1_ok = false;
        ok = false;
    } else {
        let mut buf = [0u8; 8];
        let _ = vfs::read(fd_file, &mut buf);
        let st1 = vfs::fstat(fd_file).unwrap();
        log_stat("after read", &file, &st1);
        let (a1, m1, c1) = ts_nanos(&st1);
        if STRICT_MODE {
            s1_ok &= assert_gt("atime after read (strict)", a1, ts_nanos(&st).0);
            s1_ok &= assert_eq_u64("mtime unchanged after read (strict)", m1, m0);
            s1_ok &= assert_eq_u64("ctime unchanged after read (strict)", c1, c0);
        } else {
            s1_ok &= assert_ge("atime after read", a1, ts_nanos(&st).0);
            s1_ok &= assert_ge("mtime monotonic after read", m1, m0);
            s1_ok &= assert_ge("ctime monotonic after read", c1, c0);
        }
        st = st1;
    }
    ok &= s1_ok;
    record_scenario("read updates atime", s1_ok, &mut passed, &mut total);

    // 2) WRITE should update mtime and ctime
    let mut s2_ok = true;
    let prev = core::cmp::max(
        core::cmp::max(ts_nanos(&st).0, ts_nanos(&st).1),
        ts_nanos(&st).2,
    );
    if !wait_clock_advance(prev, "before write") {
        s2_ok = false;
        ok = false;
    } else {
        let payload = b"hello timestamp semantics";
        let wr = vfs::write(fd_file, payload).unwrap_or(0);
        crate::serial_println!("[vfs-stat-test][STEP] write bytes={}", wr);
        let st2 = vfs::fstat(fd_file).unwrap();
        log_stat("after write", &file, &st2);
        let (a2, m2, c2) = ts_nanos(&st2);
        if STRICT_MODE {
            s2_ok &= assert_gt("mtime after write (strict)", m2, ts_nanos(&st).1);
            s2_ok &= assert_gt("ctime after write (strict)", c2, ts_nanos(&st).2);
            s2_ok &= assert_ge("atime monotonic after write", a2, ts_nanos(&st).0);
        } else {
            s2_ok &= assert_ge("mtime after write", m2, ts_nanos(&st).1);
            s2_ok &= assert_ge("ctime after write", c2, ts_nanos(&st).2);
        }
        st = st2;
    }
    ok &= s2_ok;
    record_scenario("write updates mtime/ctime", s2_ok, &mut passed, &mut total);

    // 3) TRUNCATE should update mtime and ctime
    let mut s3_ok = true;
    let prev = core::cmp::max(
        core::cmp::max(ts_nanos(&st).0, ts_nanos(&st).1),
        ts_nanos(&st).2,
    );
    if !wait_clock_advance(prev, "before truncate") {
        s3_ok = false;
        ok = false;
    } else {
        if let Err(e) = vfs::truncate(&file, 4) {
            crate::serial_println!("[vfs-stat-test][STEP] FAIL: truncate => {:?}", e);
            s3_ok = false;
            ok = false;
        } else {
            let st3 = vfs::fstat(fd_file).unwrap();
            log_stat("after truncate", &file, &st3);
            if STRICT_MODE {
                s3_ok &= assert_gt(
                    "mtime after truncate (strict)",
                    ts_nanos(&st3).1,
                    ts_nanos(&st).1,
                );
                s3_ok &= assert_gt(
                    "ctime after truncate (strict)",
                    ts_nanos(&st3).2,
                    ts_nanos(&st).2,
                );
            } else {
                s3_ok &= assert_ge("mtime after truncate", ts_nanos(&st3).1, ts_nanos(&st).1);
                s3_ok &= assert_ge("ctime after truncate", ts_nanos(&st3).2, ts_nanos(&st).2);
            }
            st = st3;
        }
    }
    ok &= s3_ok;
    record_scenario(
        "truncate updates mtime/ctime",
        s3_ok,
        &mut passed,
        &mut total,
    );

    // 4) CHMOD should update ctime
    let mut s4_ok = true;
    let prev = core::cmp::max(
        core::cmp::max(ts_nanos(&st).0, ts_nanos(&st).1),
        ts_nanos(&st).2,
    );
    if !wait_clock_advance(prev, "before chmod") {
        s4_ok = false;
        ok = false;
    } else {
        if let Err(e) = vfs::chmod(&file, 0o600) {
            crate::serial_println!("[vfs-stat-test][STEP] FAIL: chmod => {:?}", e);
            s4_ok = false;
            ok = false;
        } else {
            let st4 = vfs::fstat(fd_file).unwrap();
            log_stat("after chmod", &file, &st4);
            if STRICT_MODE {
                s4_ok &= assert_gt(
                    "ctime after chmod (strict)",
                    ts_nanos(&st4).2,
                    ts_nanos(&st).2,
                );
                s4_ok &= assert_eq_u64(
                    "mtime unchanged after chmod (strict)",
                    ts_nanos(&st4).1,
                    ts_nanos(&st).1,
                );
            } else {
                s4_ok &= assert_ge("ctime after chmod", ts_nanos(&st4).2, ts_nanos(&st).2);
            }
            st = st4;
        }
    }
    ok &= s4_ok;
    record_scenario("chmod updates ctime", s4_ok, &mut passed, &mut total);

    // 5) LINK should raise link count and update ctime of source
    let mut s5_ok = true;
    let prev = core::cmp::max(
        core::cmp::max(ts_nanos(&st).0, ts_nanos(&st).1),
        ts_nanos(&st).2,
    );
    if !wait_clock_advance(prev, "before link") {
        s5_ok = false;
        ok = false;
    } else {
        if let Err(e) = vfs::link(&file, &hard) {
            crate::serial_println!("[vfs-stat-test][STEP] FAIL: link => {:?}", e);
            s5_ok = false;
            ok = false;
        } else {
            let st5 = vfs::fstat(fd_file).unwrap();
            log_stat("after link(src)", &file, &st5);
            s5_ok &= st5.st_nlink >= 2;
            if STRICT_MODE {
                s5_ok &= assert_gt(
                    "ctime after link (strict)",
                    ts_nanos(&st5).2,
                    ts_nanos(&st).2,
                );
            } else {
                s5_ok &= assert_ge("ctime after link", ts_nanos(&st5).2, ts_nanos(&st).2);
            }
            st = st5;
        }
    }
    ok &= s5_ok;
    record_scenario("link bumps nlink + ctime", s5_ok, &mut passed, &mut total);

    // 6) RENAME should update ctime of inode
    let mut s6_ok = true;
    let prev = core::cmp::max(
        core::cmp::max(ts_nanos(&st).0, ts_nanos(&st).1),
        ts_nanos(&st).2,
    );
    if !wait_clock_advance(prev, "before rename") {
        s6_ok = false;
        ok = false;
    } else {
        if let Err(e) = vfs::rename(&file, &file2) {
            crate::serial_println!("[vfs-stat-test][STEP] FAIL: rename => {:?}", e);
            s6_ok = false;
            ok = false;
        } else {
            let st6 = vfs::stat_path(&file2).unwrap();
            log_stat("after rename(dst)", &file2, &st6);
            if STRICT_MODE {
                s6_ok &= assert_gt(
                    "ctime after rename (strict)",
                    ts_nanos(&st6).2,
                    ts_nanos(&st).2,
                );
            } else {
                s6_ok &= assert_ge("ctime after rename", ts_nanos(&st6).2, ts_nanos(&st).2);
            }
            let st6_fd = vfs::fstat(fd_file).unwrap();
            log_stat("after rename(fd)", &file2, &st6_fd);
        }
    }
    ok &= s6_ok;
    record_scenario("rename updates ctime", s6_ok, &mut passed, &mut total);

    // 7) SYMLINK + READLINK should update symlink atime
    let mut s7_ok = true;
    if let Err(e) = vfs::symlink("file2.txt", &sym) {
        crate::serial_println!("[vfs-stat-test][STEP] FAIL: symlink => {:?}", e);
        s7_ok = false;
        ok = false;
    } else {
        match vfs::open(&sym, vfs::OpenFlags::READ) {
            Ok(fd_sym) => {
                let st_sym_before = vfs::fstat(fd_sym).unwrap();
                log_stat("symlink created", &sym, &st_sym_before);
                let prev = core::cmp::max(
                    core::cmp::max(ts_nanos(&st_sym_before).0, ts_nanos(&st_sym_before).1),
                    ts_nanos(&st_sym_before).2,
                );
                if wait_clock_advance(prev, "before readlink") {
                    let target = vfs::readlink(&sym).unwrap_or_else(|_| String::from("<err>"));
                    crate::serial_println!(
                        "[vfs-stat-test][STEP] readlink('{}') => '{}'",
                        sym,
                        target
                    );
                    let st_sym_after = vfs::fstat(fd_sym).unwrap();
                    log_stat("after readlink", &sym, &st_sym_after);
                    if STRICT_MODE {
                        s7_ok &= assert_gt(
                            "symlink atime after readlink (strict)",
                            ts_nanos(&st_sym_after).0,
                            ts_nanos(&st_sym_before).0,
                        );
                        s7_ok &= assert_eq_u64(
                            "symlink mtime unchanged after readlink (strict)",
                            ts_nanos(&st_sym_after).1,
                            ts_nanos(&st_sym_before).1,
                        );
                        s7_ok &= assert_eq_u64(
                            "symlink ctime unchanged after readlink (strict)",
                            ts_nanos(&st_sym_after).2,
                            ts_nanos(&st_sym_before).2,
                        );
                    } else {
                        s7_ok &= assert_ge(
                            "symlink atime after readlink",
                            ts_nanos(&st_sym_after).0,
                            ts_nanos(&st_sym_before).0,
                        );
                    }
                } else {
                    s7_ok = false;
                    ok = false;
                }
                let _ = vfs::close(fd_sym);
            }
            Err(e) => {
                crate::serial_println!("[vfs-stat-test][STEP] FAIL: open symlink => {:?}", e);
                s7_ok = false;
                ok = false;
            }
        }
    }
    ok &= s7_ok;
    record_scenario(
        "readlink updates symlink atime",
        s7_ok,
        &mut passed,
        &mut total,
    );

    // 8) READDIR should update directory atime
    let mut s8_ok = true;
    let fd_dir = match vfs::open(&base, vfs::OpenFlags::READ | vfs::OpenFlags::DIRECTORY) {
        Ok(fd) => fd,
        Err(e) => {
            crate::serial_println!("[vfs-stat-test][STEP] FAIL: open dir => {:?}", e);
            let _ = vfs::close(fd_file);
            return false;
        }
    };
    let st_dir_before = match vfs::fstat(fd_dir) {
        Ok(s) => s,
        Err(e) => {
            crate::serial_println!(
                "[vfs-stat-test][STEP] FAIL: fstat dir before readdir => {:?}",
                e
            );
            let _ = vfs::close(fd_dir);
            let _ = vfs::close(fd_file);
            return false;
        }
    };
    log_stat("dir before readdir", &base, &st_dir_before);
    let prev = core::cmp::max(
        core::cmp::max(ts_nanos(&st_dir_before).0, ts_nanos(&st_dir_before).1),
        ts_nanos(&st_dir_before).2,
    );
    if !wait_clock_advance(prev, "before readdir") {
        s8_ok = false;
        ok = false;
    } else {
        let entries = vfs::getdents(fd_dir).unwrap_or_default();
        crate::serial_println!(
            "[vfs-stat-test][STEP] readdir('{}') entries={}",
            base,
            entries.len()
        );
        let st_dir_after = vfs::fstat(fd_dir).unwrap();
        log_stat("dir after readdir", &base, &st_dir_after);
        if STRICT_MODE {
            s8_ok &= assert_gt(
                "dir atime after readdir (strict)",
                ts_nanos(&st_dir_after).0,
                ts_nanos(&st_dir_before).0,
            );
            s8_ok &= assert_eq_u64(
                "dir mtime unchanged after readdir (strict)",
                ts_nanos(&st_dir_after).1,
                ts_nanos(&st_dir_before).1,
            );
            s8_ok &= assert_eq_u64(
                "dir ctime unchanged after readdir (strict)",
                ts_nanos(&st_dir_after).2,
                ts_nanos(&st_dir_before).2,
            );
        } else {
            s8_ok &= assert_ge(
                "dir atime after readdir",
                ts_nanos(&st_dir_after).0,
                ts_nanos(&st_dir_before).0,
            );
        }
    }
    ok &= s8_ok;
    record_scenario("readdir updates dir atime", s8_ok, &mut passed, &mut total);
    crate::serial_println!("[vfs-stat-test][CLEANUP] best-effort unlink/close");
    let _ = vfs::close(fd_dir);

    // Cleanup best-effort
    let _ = vfs::close(fd_file);
    let _ = vfs::unlink(&sym);
    let _ = vfs::unlink(&hard);
    let _ = vfs::unlink(&file2);
    let _ = vfs::unlink(&base);

    log_section("VFS STAT TIMESTAMP SUMMARY");
    crate::serial_println!(
        "[vfs-stat-test][ASSERT] result: {}/{} scenarios PASS",
        passed,
        total
    );
    crate::serial_println!(
        "[vfs-stat-test][ASSERT] final : {}",
        if ok { "PASS" } else { "FAIL" }
    );
    ok
}

/// Performs the vfs stat test main operation.
extern "C" fn vfs_stat_test_main() -> ! {
    crate::serial_println!("[vfs-stat-test][SETUP] task start");
    let _ = run_vfs_stat_timestamp_suite();
    crate::serial_println!("[vfs-stat-test][CLEANUP] task done");
    crate::process::scheduler::exit_current_task(0);
}

/// Performs the vfs stat test entry operation.
extern "C" fn vfs_stat_test_entry() -> ! {
    vfs_stat_test_main()
}

/// Creates vfs stat test task.
pub fn create_vfs_stat_test_task() {
    if let Ok(task) = Task::new_kernel_task_with_stack(
        vfs_stat_test_entry,
        "vfs-stat-test",
        TaskPriority::Normal,
        64 * 1024,
    ) {
        crate::process::add_task(task);
    } else {
        crate::serial_println!("[vfs-stat-test][SETUP] failed to create task");
    }
}
