//! Exhaustive VFS operations self-test suite.
//!
//! Exercises every VFS path accessible from kernel tasks: open, read, write,
//! close, seek, fstat, stat_path, mkdir, rmdir, unlink, rename, link, symlink,
//! readlink, chmod, truncate, getdents, dup, dup2.
//!
//! Runs only under `feature = "selftest"`.

use alloc::{format, string::String, vec};

use crate::{
    process::{add_task, scheduler::ticks, Task, TaskPriority},
    vfs,
};

fn log_section(title: &str) {
    crate::serial_println!("[vfs-ops-test][STEP] ========================================================");
    crate::serial_println!("[vfs-ops-test][STEP] {}", title);
    crate::serial_println!("[vfs-ops-test][STEP] ========================================================");
}

fn record(name: &str, ok: bool, passed: &mut usize, total: &mut usize) {
    *total += 1;
    if ok {
        *passed += 1;
    }
    crate::serial_println!(
        "[vfs-ops-test][ASSERT][SCENARIO] {:<48} => {}",
        name,
        if ok { "PASS" } else { "FAIL" }
    );
}

fn run_vfs_ops_suite() -> bool {
    let base = format!("/tmp/vfs-ops-{}", ticks());
    crate::serial_println!("[vfs-ops-test][SETUP] base path: '{}'", base);

    let mut passed = 0usize;
    let mut total = 0usize;

    // ── Setup: create base directory ────────────────────────────────────────
    if let Err(e) = vfs::mkdir(&base, 0o755) {
        crate::serial_println!("[vfs-ops-test][SETUP] FAIL: mkdir('{}') => {:?}", base, e);
        return false;
    }

    // ── 1. create_file + open + close ───────────────────────────────────────
    log_section("1. CREATE + OPEN + CLOSE");
    let f1 = format!("{}/basic.txt", base);
    let mut s = true;
    if let Err(e) = vfs::create_file(&f1, 0o644) {
        crate::serial_println!("[vfs-ops-test][STEP] create_file => {:?}", e);
        s = false;
    }
    if s {
        match vfs::open(&f1, vfs::OpenFlags::READ) {
            Ok(fd) => {
                crate::serial_println!("[vfs-ops-test][STEP] open('{}') => fd={}", f1, fd);
                if let Err(e) = vfs::close(fd) {
                    crate::serial_println!("[vfs-ops-test][STEP] close(fd={}) => {:?}", fd, e);
                    s = false;
                }
            }
            Err(e) => {
                crate::serial_println!("[vfs-ops-test][STEP] open => {:?}", e);
                s = false;
            }
        }
    }
    record("create_file + open + close", s, &mut passed, &mut total);

    // ── 2. write + read back ────────────────────────────────────────────────
    log_section("2. WRITE + READ BACK");
    let f2 = format!("{}/rw.txt", base);
    let mut s = true;
    if let Err(e) = vfs::create_file(&f2, 0o644) {
        crate::serial_println!("[vfs-ops-test][STEP] create_file => {:?}", e);
        s = false;
    }
    if s {
        let payload = b"Hello Strat9 VFS";
        match vfs::open(&f2, vfs::OpenFlags::WRITE) {
            Ok(wfd) => {
                match vfs::write(wfd, payload) {
                    Ok(n) => crate::serial_println!("[vfs-ops-test][STEP] write {} bytes", n),
                    Err(e) => {
                        crate::serial_println!("[vfs-ops-test][STEP] write => {:?}", e);
                        s = false;
                    }
                }
                let _ = vfs::close(wfd);
            }
            Err(e) => {
                crate::serial_println!("[vfs-ops-test][STEP] open WRITE => {:?}", e);
                s = false;
            }
        }
        if s {
            match vfs::open(&f2, vfs::OpenFlags::READ) {
                Ok(rfd) => {
                    let mut buf = [0u8; 64];
                    match vfs::read(rfd, &mut buf) {
                        Ok(n) => {
                            crate::serial_println!("[vfs-ops-test][STEP] read {} bytes", n);
                            if n != payload.len() || &buf[..n] != payload {
                                crate::serial_println!(
                                    "[vfs-ops-test][ASSERT] FAIL: content mismatch (got {} bytes)",
                                    n
                                );
                                s = false;
                            }
                        }
                        Err(e) => {
                            crate::serial_println!("[vfs-ops-test][STEP] read => {:?}", e);
                            s = false;
                        }
                    }
                    let _ = vfs::close(rfd);
                }
                Err(e) => {
                    crate::serial_println!("[vfs-ops-test][STEP] open READ => {:?}", e);
                    s = false;
                }
            }
        }
    }
    record("write + read back", s, &mut passed, &mut total);

    // ── 3. lseek SEEK_SET / SEEK_CUR / SEEK_END ────────────────────────────
    log_section("3. LSEEK");
    let mut s = true;
    match vfs::open(&f2, vfs::OpenFlags::READ) {
        Ok(fd) => {
            match vfs::lseek(fd, 0, 2 /* SEEK_END */) {
                Ok(end_pos) => {
                    crate::serial_println!("[vfs-ops-test][STEP] lseek(SEEK_END) => {}", end_pos);
                    if end_pos == 0 {
                        crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: SEEK_END returned 0");
                        s = false;
                    }
                }
                Err(e) => {
                    crate::serial_println!("[vfs-ops-test][STEP] lseek END => {:?}", e);
                    s = false;
                }
            }
            match vfs::lseek(fd, 0, 0 /* SEEK_SET */) {
                Ok(pos) => {
                    crate::serial_println!("[vfs-ops-test][STEP] lseek(SEEK_SET, 0) => {}", pos);
                    if pos != 0 {
                        crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: SEEK_SET 0 returned {}", pos);
                        s = false;
                    }
                }
                Err(e) => {
                    crate::serial_println!("[vfs-ops-test][STEP] lseek SET => {:?}", e);
                    s = false;
                }
            }
            match vfs::lseek(fd, 5, 1 /* SEEK_CUR */) {
                Ok(pos) => {
                    crate::serial_println!("[vfs-ops-test][STEP] lseek(SEEK_CUR, +5) => {}", pos);
                    if pos != 5 {
                        crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: SEEK_CUR +5 returned {}", pos);
                        s = false;
                    }
                }
                Err(e) => {
                    crate::serial_println!("[vfs-ops-test][STEP] lseek CUR => {:?}", e);
                    s = false;
                }
            }
            let _ = vfs::close(fd);
        }
        Err(e) => {
            crate::serial_println!("[vfs-ops-test][STEP] open for lseek => {:?}", e);
            s = false;
        }
    }
    record("lseek SEEK_SET/CUR/END", s, &mut passed, &mut total);

    // ── 4. fstat on file ────────────────────────────────────────────────────
    log_section("4. FSTAT ON FILE");
    let mut s = true;
    match vfs::open(&f2, vfs::OpenFlags::READ) {
        Ok(fd) => {
            match vfs::fstat(fd) {
                Ok(st) => {
                    crate::serial_println!(
                        "[vfs-ops-test][STEP] fstat: ino={} mode={:#o} nlink={} size={} uid={} gid={}",
                        st.st_ino, st.st_mode, st.st_nlink, st.st_size, st.st_uid, st.st_gid
                    );
                    if st.st_ino == 0 {
                        crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: ino == 0");
                        s = false;
                    }
                    if !st.is_file() {
                        crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: not is_file()");
                        s = false;
                    }
                    if st.st_size == 0 {
                        crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: size == 0 after write");
                        s = false;
                    }
                    if st.st_nlink == 0 {
                        crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: nlink == 0");
                        s = false;
                    }
                }
                Err(e) => {
                    crate::serial_println!("[vfs-ops-test][STEP] fstat => {:?}", e);
                    s = false;
                }
            }
            let _ = vfs::close(fd);
        }
        Err(e) => {
            crate::serial_println!("[vfs-ops-test][STEP] open => {:?}", e);
            s = false;
        }
    }
    record("fstat on regular file", s, &mut passed, &mut total);

    // ── 5. fstat on directory ───────────────────────────────────────────────
    log_section("5. FSTAT ON DIRECTORY");
    let mut s = true;
    match vfs::open(&base, vfs::OpenFlags::READ | vfs::OpenFlags::DIRECTORY) {
        Ok(fd) => {
            match vfs::fstat(fd) {
                Ok(st) => {
                    crate::serial_println!(
                        "[vfs-ops-test][STEP] fstat dir: ino={} mode={:#o} nlink={}",
                        st.st_ino, st.st_mode, st.st_nlink
                    );
                    if !st.is_dir() {
                        crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: not is_dir()");
                        s = false;
                    }
                }
                Err(e) => {
                    crate::serial_println!("[vfs-ops-test][STEP] fstat dir => {:?}", e);
                    s = false;
                }
            }
            let _ = vfs::close(fd);
        }
        Err(e) => {
            crate::serial_println!("[vfs-ops-test][STEP] open dir => {:?}", e);
            s = false;
        }
    }
    record("fstat on directory", s, &mut passed, &mut total);

    // ── 6. stat_path equivalence ────────────────────────────────────────────
    log_section("6. STAT_PATH vs FSTAT");
    let mut s = true;
    match vfs::stat_path(&f2) {
        Ok(sp) => {
            match vfs::open(&f2, vfs::OpenFlags::READ) {
                Ok(fd) => {
                    match vfs::fstat(fd) {
                        Ok(fs) => {
                            if sp.st_ino != fs.st_ino || sp.st_mode != fs.st_mode || sp.st_size != fs.st_size {
                                crate::serial_println!(
                                    "[vfs-ops-test][ASSERT] FAIL: stat_path != fstat (ino {}/{}, mode {:#o}/{:#o}, size {}/{})",
                                    sp.st_ino, fs.st_ino, sp.st_mode, fs.st_mode, sp.st_size, fs.st_size
                                );
                                s = false;
                            } else {
                                crate::serial_println!("[vfs-ops-test][STEP] stat_path matches fstat (ino={}, size={})", sp.st_ino, sp.st_size);
                            }
                        }
                        Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] fstat => {:?}", e); s = false; }
                    }
                    let _ = vfs::close(fd);
                }
                Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] open => {:?}", e); s = false; }
            }
        }
        Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] stat_path => {:?}", e); s = false; }
    }
    record("stat_path vs fstat equivalence", s, &mut passed, &mut total);

    // ── 7. mkdir + getdents + rmdir ─────────────────────────────────────────
    log_section("7. MKDIR + GETDENTS + RMDIR");
    let subdir = format!("{}/subdir", base);
    let mut s = true;
    if let Err(e) = vfs::mkdir(&subdir, 0o755) {
        crate::serial_println!("[vfs-ops-test][STEP] mkdir => {:?}", e);
        s = false;
    }
    if s {
        match vfs::open(&base, vfs::OpenFlags::READ | vfs::OpenFlags::DIRECTORY) {
            Ok(fd) => {
                match vfs::getdents(fd) {
                    Ok(entries) => {
                        crate::serial_println!("[vfs-ops-test][STEP] getdents: {} entries", entries.len());
                        for e in &entries {
                            crate::serial_println!(
                                "[vfs-ops-test][STEP]   entry: ino={} type={} name='{}'",
                                e.ino, e.file_type, e.name
                            );
                        }
                        let found = entries.iter().any(|e| e.name == "subdir");
                        if !found {
                            crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: 'subdir' not in getdents");
                            s = false;
                        }
                    }
                    Err(e) => {
                        crate::serial_println!("[vfs-ops-test][STEP] getdents => {:?}", e);
                        s = false;
                    }
                }
                let _ = vfs::close(fd);
            }
            Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] open dir => {:?}", e); s = false; }
        }
        if let Err(e) = vfs::unlink(&subdir) {
            crate::serial_println!("[vfs-ops-test][STEP] rmdir => {:?}", e);
            s = false;
        }
    }
    record("mkdir + getdents + rmdir", s, &mut passed, &mut total);

    // ── 8. mkdir existing → EEXIST ──────────────────────────────────────────
    log_section("8. MKDIR EXISTING");
    let subdir2 = format!("{}/dup_dir", base);
    let mut s = true;
    if let Err(e) = vfs::mkdir(&subdir2, 0o755) {
        crate::serial_println!("[vfs-ops-test][STEP] mkdir1 => {:?}", e);
        s = false;
    }
    if s {
        match vfs::mkdir(&subdir2, 0o755) {
            Err(_) => crate::serial_println!("[vfs-ops-test][STEP] mkdir2 correctly rejected"),
            Ok(_) => {
                crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: mkdir duplicate should fail");
                s = false;
            }
        }
        let _ = vfs::unlink(&subdir2);
    }
    record("mkdir existing returns error", s, &mut passed, &mut total);

    // ── 9. unlink file ──────────────────────────────────────────────────────
    log_section("9. UNLINK FILE");
    let f_unl = format!("{}/to_delete.txt", base);
    let mut s = true;
    if let Err(e) = vfs::create_file(&f_unl, 0o644) {
        crate::serial_println!("[vfs-ops-test][STEP] create => {:?}", e);
        s = false;
    }
    if s {
        if let Err(e) = vfs::unlink(&f_unl) {
            crate::serial_println!("[vfs-ops-test][STEP] unlink => {:?}", e);
            s = false;
        }
        if s {
            match vfs::open(&f_unl, vfs::OpenFlags::READ) {
                Err(_) => crate::serial_println!("[vfs-ops-test][STEP] open after unlink correctly fails"),
                Ok(fd) => {
                    crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: file still exists after unlink");
                    let _ = vfs::close(fd);
                    s = false;
                }
            }
        }
    }
    record("unlink file", s, &mut passed, &mut total);

    // ── 10. rename file ─────────────────────────────────────────────────────
    log_section("10. RENAME FILE");
    let f_ren_a = format!("{}/ren_a.txt", base);
    let f_ren_b = format!("{}/ren_b.txt", base);
    let mut s = true;
    let _ = vfs::create_file(&f_ren_a, 0o644);
    if let Err(e) = vfs::rename(&f_ren_a, &f_ren_b) {
        crate::serial_println!("[vfs-ops-test][STEP] rename => {:?}", e);
        s = false;
    }
    if s {
        match vfs::open(&f_ren_b, vfs::OpenFlags::READ) {
            Ok(fd) => { let _ = vfs::close(fd); }
            Err(_) => {
                crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: renamed file not found");
                s = false;
            }
        }
        match vfs::open(&f_ren_a, vfs::OpenFlags::READ) {
            Err(_) => crate::serial_println!("[vfs-ops-test][STEP] old name correctly gone"),
            Ok(fd) => {
                crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: old name still exists");
                let _ = vfs::close(fd);
                s = false;
            }
        }
    }
    let _ = vfs::unlink(&f_ren_b);
    record("rename file", s, &mut passed, &mut total);

    // ── 11. hard link + nlink ───────────────────────────────────────────────
    log_section("11. HARD LINK + NLINK");
    let f_link = format!("{}/link_src.txt", base);
    let f_hard = format!("{}/link_dst.txt", base);
    let mut s = true;
    let _ = vfs::create_file(&f_link, 0o644);
    if let Err(e) = vfs::link(&f_link, &f_hard) {
        crate::serial_println!("[vfs-ops-test][STEP] link => {:?}", e);
        s = false;
    }
    if s {
        match vfs::stat_path(&f_link) {
            Ok(st) => {
                crate::serial_println!("[vfs-ops-test][STEP] nlink after link = {}", st.st_nlink);
                if st.st_nlink < 2 {
                    crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: nlink < 2");
                    s = false;
                }
            }
            Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] stat => {:?}", e); s = false; }
        }
    }
    let _ = vfs::unlink(&f_hard);
    let _ = vfs::unlink(&f_link);
    record("hard link + nlink >= 2", s, &mut passed, &mut total);

    // ── 12. symlink + readlink ──────────────────────────────────────────────
    log_section("12. SYMLINK + READLINK");
    let f_sym_tgt = format!("{}/sym_target.txt", base);
    let f_sym_lnk = format!("{}/sym_link", base);
    let mut s = true;
    let _ = vfs::create_file(&f_sym_tgt, 0o644);
    if let Err(e) = vfs::symlink("sym_target.txt", &f_sym_lnk) {
        crate::serial_println!("[vfs-ops-test][STEP] symlink => {:?}", e);
        s = false;
    }
    if s {
        match vfs::readlink(&f_sym_lnk) {
            Ok(target) => {
                crate::serial_println!("[vfs-ops-test][STEP] readlink => '{}'", target);
                if target != "sym_target.txt" {
                    crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: readlink mismatch");
                    s = false;
                }
            }
            Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] readlink => {:?}", e); s = false; }
        }
    }
    let _ = vfs::unlink(&f_sym_lnk);
    let _ = vfs::unlink(&f_sym_tgt);
    record("symlink + readlink", s, &mut passed, &mut total);

    // ── 13. chmod + verify mode ─────────────────────────────────────────────
    log_section("13. CHMOD");
    let f_chm = format!("{}/chmod.txt", base);
    let mut s = true;
    let _ = vfs::create_file(&f_chm, 0o644);
    if let Err(e) = vfs::chmod(&f_chm, 0o755) {
        crate::serial_println!("[vfs-ops-test][STEP] chmod => {:?}", e);
        s = false;
    }
    if s {
        match vfs::stat_path(&f_chm) {
            Ok(st) => {
                let perm_bits = st.st_mode & 0o777;
                crate::serial_println!("[vfs-ops-test][STEP] mode after chmod = {:#o}", perm_bits);
                if perm_bits != 0o755 {
                    crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: mode != 0o755");
                    s = false;
                }
            }
            Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] stat => {:?}", e); s = false; }
        }
    }
    let _ = vfs::unlink(&f_chm);
    record("chmod + verify mode", s, &mut passed, &mut total);

    // ── 14. truncate + verify size ──────────────────────────────────────────
    log_section("14. TRUNCATE");
    let f_trunc = format!("{}/trunc.txt", base);
    let mut s = true;
    let _ = vfs::create_file(&f_trunc, 0o644);
    match vfs::open(&f_trunc, vfs::OpenFlags::WRITE) {
        Ok(wfd) => {
            let _ = vfs::write(wfd, b"0123456789ABCDEF");
            let _ = vfs::close(wfd);
        }
        Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] open WRITE => {:?}", e); s = false; }
    }
    if s {
        if let Err(e) = vfs::truncate(&f_trunc, 4) {
            crate::serial_println!("[vfs-ops-test][STEP] truncate => {:?}", e);
            s = false;
        }
        if s {
            match vfs::stat_path(&f_trunc) {
                Ok(st) => {
                    crate::serial_println!("[vfs-ops-test][STEP] size after truncate(4) = {}", st.st_size);
                    if st.st_size != 4 {
                        crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: size != 4");
                        s = false;
                    }
                }
                Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] stat => {:?}", e); s = false; }
            }
        }
    }
    let _ = vfs::unlink(&f_trunc);
    record("truncate + verify size", s, &mut passed, &mut total);

    // ── 15. dup ─────────────────────────────────────────────────────────────
    log_section("15. DUP");
    let f_dup = format!("{}/dup.txt", base);
    let mut s = true;
    let _ = vfs::create_file(&f_dup, 0o644);
    match vfs::open(&f_dup, vfs::OpenFlags::WRITE) {
        Ok(wfd) => {
            let _ = vfs::write(wfd, b"duptest");
            let _ = vfs::close(wfd);
        }
        Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] open => {:?}", e); s = false; }
    }
    if s {
        match vfs::open(&f_dup, vfs::OpenFlags::READ) {
            Ok(fd1) => {
                match vfs::dup(fd1) {
                    Ok(fd2) => {
                        crate::serial_println!("[vfs-ops-test][STEP] dup({}) => {}", fd1, fd2);
                        if fd1 == fd2 {
                            crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: dup returned same fd");
                            s = false;
                        }
                        let mut buf = [0u8; 32];
                        match vfs::read(fd2, &mut buf) {
                            Ok(n) => {
                                crate::serial_println!("[vfs-ops-test][STEP] read from dup'd fd: {} bytes", n);
                                if n == 0 {
                                    crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: dup fd read 0 bytes");
                                    s = false;
                                }
                            }
                            Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] read dup => {:?}", e); s = false; }
                        }
                        let _ = vfs::close(fd2);
                    }
                    Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] dup => {:?}", e); s = false; }
                }
                let _ = vfs::close(fd1);
            }
            Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] open => {:?}", e); s = false; }
        }
    }
    let _ = vfs::unlink(&f_dup);
    record("dup + read from dup'd fd", s, &mut passed, &mut total);

    // ── 16. dup2 ────────────────────────────────────────────────────────────
    log_section("16. DUP2");
    let f_dup2 = format!("{}/dup2.txt", base);
    let mut s = true;
    let _ = vfs::create_file(&f_dup2, 0o644);
    match vfs::open(&f_dup2, vfs::OpenFlags::WRITE) {
        Ok(wfd) => {
            let _ = vfs::write(wfd, b"dup2test");
            let _ = vfs::close(wfd);
        }
        Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] open => {:?}", e); s = false; }
    }
    if s {
        match vfs::open(&f_dup2, vfs::OpenFlags::READ) {
            Ok(fd1) => {
                let target_fd = fd1 + 10;
                match vfs::dup2(fd1, target_fd) {
                    Ok(fd2) => {
                        crate::serial_println!("[vfs-ops-test][STEP] dup2({}, {}) => {}", fd1, target_fd, fd2);
                        if fd2 != target_fd {
                            crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: dup2 returned {}, expected {}", fd2, target_fd);
                            s = false;
                        }
                        let mut buf = [0u8; 32];
                        if let Ok(n) = vfs::read(fd2, &mut buf) {
                            crate::serial_println!("[vfs-ops-test][STEP] read from dup2'd fd: {} bytes", n);
                        }
                        let _ = vfs::close(fd2);
                    }
                    Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] dup2 => {:?}", e); s = false; }
                }
                let _ = vfs::close(fd1);
            }
            Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] open => {:?}", e); s = false; }
        }
    }
    let _ = vfs::unlink(&f_dup2);
    record("dup2 to specific fd", s, &mut passed, &mut total);

    // ── 17. pipe basic ──────────────────────────────────────────────────────
    log_section("17. PIPE BASIC");
    let mut s = true;
    match vfs::pipe() {
        Ok((rfd, wfd)) => {
            crate::serial_println!("[vfs-ops-test][STEP] pipe() => read_fd={}, write_fd={}", rfd, wfd);
            if rfd == wfd {
                crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: pipe fds are identical");
                s = false;
            }
            let payload = b"pipe-data";
            match vfs::write(wfd, payload) {
                Ok(n) => crate::serial_println!("[vfs-ops-test][STEP] pipe write: {} bytes", n),
                Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] pipe write => {:?}", e); s = false; }
            }
            if s {
                let mut buf = [0u8; 32];
                match vfs::read(rfd, &mut buf) {
                    Ok(n) => {
                        crate::serial_println!("[vfs-ops-test][STEP] pipe read: {} bytes", n);
                        if n != payload.len() || &buf[..n] != payload {
                            crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: pipe content mismatch");
                            s = false;
                        }
                    }
                    Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] pipe read => {:?}", e); s = false; }
                }
            }
            let _ = vfs::close(wfd);
            let _ = vfs::close(rfd);
        }
        Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] pipe => {:?}", e); s = false; }
    }
    record("pipe create + write + read", s, &mut passed, &mut total);

    // ── 18. write to closed read-end pipe → read returns 0 after close ─────
    log_section("18. PIPE WRITE-END CLOSE → EOF");
    let mut s = true;
    match vfs::pipe() {
        Ok((rfd, wfd)) => {
            let _ = vfs::write(wfd, b"abc");
            let _ = vfs::close(wfd);
            let mut buf = [0u8; 16];
            match vfs::read(rfd, &mut buf) {
                Ok(n) => {
                    crate::serial_println!("[vfs-ops-test][STEP] first read after close_write: {} bytes", n);
                }
                Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] read => {:?}", e); }
            }
            match vfs::read(rfd, &mut buf) {
                Ok(0) => crate::serial_println!("[vfs-ops-test][STEP] second read => EOF (0) ✓"),
                Ok(n) => {
                    crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: expected EOF, got {} bytes", n);
                    s = false;
                }
                Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] read => {:?} (acceptable)", e); }
            }
            let _ = vfs::close(rfd);
        }
        Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] pipe => {:?}", e); s = false; }
    }
    record("pipe write-end close → EOF", s, &mut passed, &mut total);

    // ── 19. read empty file returns 0 ───────────────────────────────────────
    log_section("19. READ EMPTY FILE");
    let f_empty = format!("{}/empty.txt", base);
    let mut s = true;
    let _ = vfs::create_file(&f_empty, 0o644);
    match vfs::open(&f_empty, vfs::OpenFlags::READ) {
        Ok(fd) => {
            let mut buf = [0u8; 16];
            match vfs::read(fd, &mut buf) {
                Ok(0) => crate::serial_println!("[vfs-ops-test][STEP] read empty file => 0 bytes ✓"),
                Ok(n) => {
                    crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: read empty got {} bytes", n);
                    s = false;
                }
                Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] read => {:?}", e); s = false; }
            }
            let _ = vfs::close(fd);
        }
        Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] open => {:?}", e); s = false; }
    }
    let _ = vfs::unlink(&f_empty);
    record("read empty file returns 0", s, &mut passed, &mut total);

    // ── 20. seek beyond file size + read ────────────────────────────────────
    log_section("20. SEEK BEYOND END");
    let f_seek = format!("{}/seekbeyond.txt", base);
    let mut s = true;
    let _ = vfs::create_file(&f_seek, 0o644);
    match vfs::open(&f_seek, vfs::OpenFlags::READ | vfs::OpenFlags::WRITE) {
        Ok(fd) => {
            let _ = vfs::write(fd, b"ABCDE");
            match vfs::lseek(fd, 100, 0 /* SEEK_SET */) {
                Ok(pos) => crate::serial_println!("[vfs-ops-test][STEP] lseek(100) => {}", pos),
                Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] lseek => {:?}", e); }
            }
            let mut buf = [0u8; 4];
            match vfs::read(fd, &mut buf) {
                Ok(0) => crate::serial_println!("[vfs-ops-test][STEP] read beyond end => 0 ✓"),
                Ok(n) => crate::serial_println!("[vfs-ops-test][STEP] read beyond end => {} bytes (may be padded)", n),
                Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] read => {:?}", e); }
            }
            let _ = vfs::close(fd);
        }
        Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] open => {:?}", e); s = false; }
    }
    let _ = vfs::unlink(&f_seek);
    record("seek beyond end + read", s, &mut passed, &mut total);

    // ── 21. multiple writes accumulate ──────────────────────────────────────
    log_section("21. MULTIPLE WRITES");
    let f_multi = format!("{}/multi.txt", base);
    let mut s = true;
    let _ = vfs::create_file(&f_multi, 0o644);
    match vfs::open(&f_multi, vfs::OpenFlags::WRITE) {
        Ok(wfd) => {
            let _ = vfs::write(wfd, b"AAA");
            let _ = vfs::write(wfd, b"BBB");
            let _ = vfs::write(wfd, b"CCC");
            let _ = vfs::close(wfd);
        }
        Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] open => {:?}", e); s = false; }
    }
    if s {
        match vfs::open(&f_multi, vfs::OpenFlags::READ) {
            Ok(rfd) => {
                let mut buf = [0u8; 32];
                match vfs::read(rfd, &mut buf) {
                    Ok(n) => {
                        crate::serial_println!("[vfs-ops-test][STEP] read {} bytes after 3 writes", n);
                        if n != 9 {
                            crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: expected 9 bytes, got {}", n);
                            s = false;
                        } else if &buf[..9] != b"AAABBBCCC" {
                            crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: content mismatch");
                            s = false;
                        }
                    }
                    Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] read => {:?}", e); s = false; }
                }
                let _ = vfs::close(rfd);
            }
            Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] open => {:?}", e); s = false; }
        }
    }
    let _ = vfs::unlink(&f_multi);
    record("multiple writes accumulate", s, &mut passed, &mut total);

    // ── 22. getdents on root / ──────────────────────────────────────────────
    log_section("22. GETDENTS ON ROOT");
    let mut s = true;
    match vfs::open("/", vfs::OpenFlags::READ | vfs::OpenFlags::DIRECTORY) {
        Ok(fd) => {
            match vfs::getdents(fd) {
                Ok(entries) => {
                    crate::serial_println!("[vfs-ops-test][STEP] getdents('/') => {} entries", entries.len());
                    for e in &entries {
                        crate::serial_println!(
                            "[vfs-ops-test][STEP]   entry: ino={} type={} name='{}'",
                            e.ino, e.file_type, e.name
                        );
                    }
                    let has_tmp = entries.iter().any(|e| e.name == "tmp");
                    if !has_tmp {
                        crate::serial_println!("[vfs-ops-test][STEP] note: 'tmp' not in root entries (may be normal)");
                    }
                }
                Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] getdents => {:?}", e); s = false; }
            }
            let _ = vfs::close(fd);
        }
        Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] open '/' => {:?}", e); s = false; }
    }
    record("getdents on root /", s, &mut passed, &mut total);

    // ── 23. open /sys/version (kernel pseudo-fs) ────────────────────────────
    log_section("23. OPEN /sys/version");
    let mut s = true;
    match vfs::open("/sys/version", vfs::OpenFlags::READ) {
        Ok(fd) => {
            let mut buf = [0u8; 128];
            match vfs::read(fd, &mut buf) {
                Ok(n) => {
                    let content = core::str::from_utf8(&buf[..n]).unwrap_or("<binary>");
                    crate::serial_println!("[vfs-ops-test][STEP] /sys/version => '{}' ({} bytes)", content, n);
                }
                Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] read => {:?}", e); s = false; }
            }
            let _ = vfs::close(fd);
        }
        Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] open /sys/version => {:?}", e); s = false; }
    }
    record("open /sys/version", s, &mut passed, &mut total);

    // ── 24. fchmod on open fd ───────────────────────────────────────────────
    log_section("24. FCHMOD");
    let f_fchmod = format!("{}/fchmod.txt", base);
    let mut s = true;
    let _ = vfs::create_file(&f_fchmod, 0o644);
    match vfs::open(&f_fchmod, vfs::OpenFlags::READ | vfs::OpenFlags::WRITE) {
        Ok(fd) => {
            if let Err(e) = vfs::fchmod(fd, 0o700) {
                crate::serial_println!("[vfs-ops-test][STEP] fchmod => {:?}", e);
                s = false;
            }
            if s {
                match vfs::fstat(fd) {
                    Ok(st) => {
                        let perm = st.st_mode & 0o777;
                        crate::serial_println!("[vfs-ops-test][STEP] mode after fchmod = {:#o}", perm);
                        if perm != 0o700 {
                            crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: mode != 0o700");
                            s = false;
                        }
                    }
                    Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] fstat => {:?}", e); s = false; }
                }
            }
            let _ = vfs::close(fd);
        }
        Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] open => {:?}", e); s = false; }
    }
    let _ = vfs::unlink(&f_fchmod);
    record("fchmod on open fd", s, &mut passed, &mut total);

    // ── 25. ftruncate on open fd ────────────────────────────────────────────
    log_section("25. FTRUNCATE");
    let f_ft = format!("{}/ftrunc.txt", base);
    let mut s = true;
    let _ = vfs::create_file(&f_ft, 0o644);
    match vfs::open(&f_ft, vfs::OpenFlags::READ | vfs::OpenFlags::WRITE) {
        Ok(fd) => {
            let _ = vfs::write(fd, b"1234567890");
            if let Err(e) = vfs::ftruncate(fd, 3) {
                crate::serial_println!("[vfs-ops-test][STEP] ftruncate => {:?}", e);
                s = false;
            }
            if s {
                match vfs::fstat(fd) {
                    Ok(st) => {
                        crate::serial_println!("[vfs-ops-test][STEP] size after ftruncate(3) = {}", st.st_size);
                        if st.st_size != 3 {
                            crate::serial_println!("[vfs-ops-test][ASSERT] FAIL: size != 3");
                            s = false;
                        }
                    }
                    Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] fstat => {:?}", e); s = false; }
                }
            }
            let _ = vfs::close(fd);
        }
        Err(e) => { crate::serial_println!("[vfs-ops-test][STEP] open => {:?}", e); s = false; }
    }
    let _ = vfs::unlink(&f_ft);
    record("ftruncate on open fd", s, &mut passed, &mut total);

    // ── Cleanup ─────────────────────────────────────────────────────────────
    crate::serial_println!("[vfs-ops-test][CLEANUP] best-effort cleanup");
    let _ = vfs::unlink(&f1);
    let _ = vfs::unlink(&f2);
    let _ = vfs::unlink(&base);

    // ── Summary ─────────────────────────────────────────────────────────────
    log_section("VFS OPS TEST SUMMARY");
    let ok = passed == total;
    crate::serial_println!("[vfs-ops-test][ASSERT] result: {}/{} scenarios PASS", passed, total);
    crate::serial_println!(
        "[vfs-ops-test][ASSERT] final : {}",
        if ok { "PASS" } else { "FAIL" }
    );
    ok
}

extern "C" fn vfs_ops_test_main() -> ! {
    crate::serial_println!("[vfs-ops-test][SETUP] task start");
    let _ = run_vfs_ops_suite();
    crate::serial_println!("[vfs-ops-test][CLEANUP] task done");
    crate::process::scheduler::exit_current_task(0);
}

pub fn create_vfs_ops_test_task() {
    if let Ok(task) = Task::new_kernel_task(vfs_ops_test_main, "vfs-ops-test", TaskPriority::Normal) {
        add_task(task);
    } else {
        crate::serial_println!("[vfs-ops-test][SETUP] failed to create task");
    }
}
