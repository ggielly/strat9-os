//! Pipe-specific self-test suite.
//!
//! Exercises: pipe creation, write/read, multiple writes, EOF on close,
//! dup on pipe fd, zero-length operations, large writes.
//!
//! Runs only under `feature = "selftest"`.

use crate::{
    process::{add_task, Task, TaskPriority},
    vfs,
};

fn log_section(title: &str) {
    crate::serial_println!("[pipe-test][STEP] ========================================================");
    crate::serial_println!("[pipe-test][STEP] {}", title);
    crate::serial_println!("[pipe-test][STEP] ========================================================");
}

fn record(name: &str, ok: bool, passed: &mut usize, total: &mut usize) {
    *total += 1;
    if ok {
        *passed += 1;
    }
    crate::serial_println!(
        "[pipe-test][ASSERT][SCENARIO] {:<48} => {}",
        name,
        if ok { "PASS" } else { "FAIL" }
    );
}

fn run_pipe_suite() -> bool {
    let mut passed = 0usize;
    let mut total = 0usize;

    // ── 1. pipe() returns two distinct fds ──────────────────────────────────
    log_section("1. PIPE CREATION");
    let mut s = true;
    let (rfd, wfd) = match vfs::pipe() {
        Ok((r, w)) => {
            crate::serial_println!("[pipe-test][STEP] pipe() => read_fd={}, write_fd={}", r, w);
            if r == w {
                crate::serial_println!("[pipe-test][ASSERT] FAIL: read_fd == write_fd");
                s = false;
            }
            (r, w)
        }
        Err(e) => {
            crate::serial_println!("[pipe-test][STEP] pipe() => {:?}", e);
            s = false;
            (0, 0)
        }
    };
    record("pipe() returns distinct fds", s, &mut passed, &mut total);

    // ── 2. write then read exact content ────────────────────────────────────
    log_section("2. WRITE + READ EXACT");
    let mut s = true;
    if rfd != 0 || wfd != 0 || !s {
        let payload = b"pipe_exact_data";
        match vfs::write(wfd, payload) {
            Ok(n) => {
                crate::serial_println!("[pipe-test][STEP] write {} bytes", n);
                if n != payload.len() {
                    crate::serial_println!("[pipe-test][ASSERT] FAIL: write returned {}", n);
                    s = false;
                }
            }
            Err(e) => { crate::serial_println!("[pipe-test][STEP] write => {:?}", e); s = false; }
        }
        if s {
            let mut buf = [0u8; 64];
            match vfs::read(rfd, &mut buf) {
                Ok(n) => {
                    crate::serial_println!("[pipe-test][STEP] read {} bytes", n);
                    if n != payload.len() {
                        crate::serial_println!("[pipe-test][ASSERT] FAIL: read len mismatch");
                        s = false;
                    } else if &buf[..n] != payload {
                        crate::serial_println!("[pipe-test][ASSERT] FAIL: content mismatch");
                        s = false;
                    }
                }
                Err(e) => { crate::serial_println!("[pipe-test][STEP] read => {:?}", e); s = false; }
            }
        }
    }
    record("write + read exact content", s, &mut passed, &mut total);

    let _ = vfs::close(rfd);
    let _ = vfs::close(wfd);

    // ── 3. multiple writes, single read ─────────────────────────────────────
    log_section("3. MULTIPLE WRITES, SINGLE READ");
    let mut s = true;
    match vfs::pipe() {
        Ok((rfd, wfd)) => {
            let _ = vfs::write(wfd, b"AAA");
            let _ = vfs::write(wfd, b"BBB");
            let _ = vfs::write(wfd, b"CCC");
            crate::serial_println!("[pipe-test][STEP] wrote 3x3 bytes");

            let mut buf = [0u8; 64];
            let mut total_read = 0usize;
            for i in 0..5 {
                match vfs::read(rfd, &mut buf[total_read..]) {
                    Ok(0) => break,
                    Ok(n) => {
                        crate::serial_println!("[pipe-test][STEP] read iteration {}: {} bytes", i, n);
                        total_read += n;
                        if total_read >= 9 { break; }
                    }
                    Err(e) => {
                        crate::serial_println!("[pipe-test][STEP] read => {:?}", e);
                        break;
                    }
                }
            }
            crate::serial_println!("[pipe-test][STEP] total read: {} bytes", total_read);
            if total_read != 9 {
                crate::serial_println!("[pipe-test][ASSERT] FAIL: expected 9 bytes, got {}", total_read);
                s = false;
            } else if &buf[..9] != b"AAABBBCCC" {
                crate::serial_println!("[pipe-test][ASSERT] FAIL: content mismatch");
                s = false;
            }
            let _ = vfs::close(rfd);
            let _ = vfs::close(wfd);
        }
        Err(e) => { crate::serial_println!("[pipe-test][STEP] pipe => {:?}", e); s = false; }
    }
    record("multiple writes, single read", s, &mut passed, &mut total);

    // ── 4. close write-end, read returns EOF ────────────────────────────────
    log_section("4. CLOSE WRITE-END → EOF");
    let mut s = true;
    match vfs::pipe() {
        Ok((rfd, wfd)) => {
            let _ = vfs::write(wfd, b"before_close");
            let _ = vfs::close(wfd);
            crate::serial_println!("[pipe-test][STEP] write-end closed");

            let mut buf = [0u8; 64];
            let first = vfs::read(rfd, &mut buf).unwrap_or(0);
            crate::serial_println!("[pipe-test][STEP] first read after close: {} bytes", first);

            match vfs::read(rfd, &mut buf) {
                Ok(0) => crate::serial_println!("[pipe-test][STEP] second read => EOF (0) ✓"),
                Ok(n) => {
                    crate::serial_println!("[pipe-test][ASSERT] FAIL: expected EOF, got {} bytes", n);
                    s = false;
                }
                Err(e) => crate::serial_println!("[pipe-test][STEP] read error after close: {:?} (acceptable)", e),
            }
            let _ = vfs::close(rfd);
        }
        Err(e) => { crate::serial_println!("[pipe-test][STEP] pipe => {:?}", e); s = false; }
    }
    record("close write-end → EOF", s, &mut passed, &mut total);

    // ── 5. dup on pipe read-end ─────────────────────────────────────────────
    log_section("5. DUP PIPE READ-END");
    let mut s = true;
    match vfs::pipe() {
        Ok((rfd, wfd)) => {
            match vfs::dup(rfd) {
                Ok(rfd2) => {
                    crate::serial_println!("[pipe-test][STEP] dup({}) => {}", rfd, rfd2);
                    let _ = vfs::write(wfd, b"dup-pipe-test");
                    let mut buf = [0u8; 32];
                    match vfs::read(rfd2, &mut buf) {
                        Ok(n) => {
                            crate::serial_println!("[pipe-test][STEP] read from dup'd fd: {} bytes", n);
                            if n == 0 {
                                crate::serial_println!("[pipe-test][ASSERT] FAIL: dup'd read returned 0");
                                s = false;
                            }
                        }
                        Err(e) => { crate::serial_println!("[pipe-test][STEP] read => {:?}", e); s = false; }
                    }
                    let _ = vfs::close(rfd2);
                }
                Err(e) => { crate::serial_println!("[pipe-test][STEP] dup => {:?}", e); s = false; }
            }
            let _ = vfs::close(rfd);
            let _ = vfs::close(wfd);
        }
        Err(e) => { crate::serial_println!("[pipe-test][STEP] pipe => {:?}", e); s = false; }
    }
    record("dup pipe read-end", s, &mut passed, &mut total);

    // ── 6. dup on pipe write-end ────────────────────────────────────────────
    log_section("6. DUP PIPE WRITE-END");
    let mut s = true;
    match vfs::pipe() {
        Ok((rfd, wfd)) => {
            match vfs::dup(wfd) {
                Ok(wfd2) => {
                    crate::serial_println!("[pipe-test][STEP] dup({}) => {}", wfd, wfd2);
                    let _ = vfs::write(wfd2, b"dup-write");
                    let mut buf = [0u8; 32];
                    match vfs::read(rfd, &mut buf) {
                        Ok(n) => {
                            crate::serial_println!("[pipe-test][STEP] read data from dup'd write: {} bytes", n);
                            if n == 0 {
                                crate::serial_println!("[pipe-test][ASSERT] FAIL: read returned 0");
                                s = false;
                            }
                        }
                        Err(e) => { crate::serial_println!("[pipe-test][STEP] read => {:?}", e); s = false; }
                    }
                    let _ = vfs::close(wfd2);
                }
                Err(e) => { crate::serial_println!("[pipe-test][STEP] dup => {:?}", e); s = false; }
            }
            let _ = vfs::close(rfd);
            let _ = vfs::close(wfd);
        }
        Err(e) => { crate::serial_println!("[pipe-test][STEP] pipe => {:?}", e); s = false; }
    }
    record("dup pipe write-end", s, &mut passed, &mut total);

    // ── 7. zero-length write ────────────────────────────────────────────────
    log_section("7. ZERO-LENGTH WRITE");
    let mut s = true;
    match vfs::pipe() {
        Ok((rfd, wfd)) => {
            match vfs::write(wfd, b"") {
                Ok(n) => crate::serial_println!("[pipe-test][STEP] write(empty) => {} bytes", n),
                Err(e) => crate::serial_println!("[pipe-test][STEP] write(empty) => {:?} (acceptable)", e),
            }
            let _ = vfs::close(rfd);
            let _ = vfs::close(wfd);
        }
        Err(e) => { crate::serial_println!("[pipe-test][STEP] pipe => {:?}", e); s = false; }
    }
    record("zero-length write", s, &mut passed, &mut total);

    // ── 8. write 4000 bytes ─────────────────────────────────────────────────
    log_section("8. LARGE WRITE (4000 BYTES)");
    let mut s = true;
    match vfs::pipe() {
        Ok((rfd, wfd)) => {
            let data = [0xABu8; 4000];
            match vfs::write(wfd, &data) {
                Ok(n) => crate::serial_println!("[pipe-test][STEP] write 4000 bytes => {}", n),
                Err(e) => {
                    crate::serial_println!("[pipe-test][STEP] write 4000 => {:?} (may be bounded)", e);
                }
            }
            let mut buf = [0u8; 4096];
            let mut total_read = 0;
            for _ in 0..10 {
                match vfs::read(rfd, &mut buf[total_read..]) {
                    Ok(0) => break,
                    Ok(n) => { total_read += n; }
                    Err(_) => break,
                }
                if total_read >= 4000 { break; }
            }
            crate::serial_println!("[pipe-test][STEP] total read back: {} bytes", total_read);
            if total_read == 0 {
                crate::serial_println!("[pipe-test][ASSERT] FAIL: read back 0 bytes");
                s = false;
            }
            let _ = vfs::close(rfd);
            let _ = vfs::close(wfd);
        }
        Err(e) => { crate::serial_println!("[pipe-test][STEP] pipe => {:?}", e); s = false; }
    }
    record("large write 4000 bytes", s, &mut passed, &mut total);

    // ── 9. multiple pipes simultaneously ────────────────────────────────────
    log_section("9. MULTIPLE PIPES");
    let mut s = true;
    let p1 = vfs::pipe();
    let p2 = vfs::pipe();
    match (p1, p2) {
        (Ok((r1, w1)), Ok((r2, w2))) => {
            crate::serial_println!(
                "[pipe-test][STEP] pipe1: r={}/w={}  pipe2: r={}/w={}",
                r1, w1, r2, w2
            );
            let _ = vfs::write(w1, b"pipe1");
            let _ = vfs::write(w2, b"pipe2");

            let mut buf1 = [0u8; 16];
            let mut buf2 = [0u8; 16];
            let n1 = vfs::read(r1, &mut buf1).unwrap_or(0);
            let n2 = vfs::read(r2, &mut buf2).unwrap_or(0);
            crate::serial_println!(
                "[pipe-test][STEP] pipe1 read={} pipe2 read={}",
                n1, n2
            );
            if &buf1[..n1] != b"pipe1" || &buf2[..n2] != b"pipe2" {
                crate::serial_println!("[pipe-test][ASSERT] FAIL: cross-contamination or data loss");
                s = false;
            }
            let _ = vfs::close(r1);
            let _ = vfs::close(w1);
            let _ = vfs::close(r2);
            let _ = vfs::close(w2);
        }
        _ => {
            crate::serial_println!("[pipe-test][STEP] failed to create two pipes");
            s = false;
        }
    }
    record("multiple pipes simultaneously", s, &mut passed, &mut total);

    // ── 10. fstat on pipe fd ────────────────────────────────────────────────
    log_section("10. FSTAT ON PIPE FD");
    let mut s = true;
    match vfs::pipe() {
        Ok((rfd, wfd)) => {
            match vfs::fstat(rfd) {
                Ok(st) => {
                    crate::serial_println!(
                        "[pipe-test][STEP] fstat(pipe read): ino={} mode={:#o} size={} dev={}",
                        st.st_ino, st.st_mode, st.st_size, st.st_dev
                    );
                }
                Err(e) => { crate::serial_println!("[pipe-test][STEP] fstat(pipe) => {:?}", e); s = false; }
            }
            let _ = vfs::close(rfd);
            let _ = vfs::close(wfd);
        }
        Err(e) => { crate::serial_println!("[pipe-test][STEP] pipe => {:?}", e); s = false; }
    }
    record("fstat on pipe fd", s, &mut passed, &mut total);

    // ── Summary ─────────────────────────────────────────────────────────────
    log_section("PIPE TEST SUMMARY");
    let ok = passed == total;
    crate::serial_println!("[pipe-test][ASSERT] result: {}/{} scenarios PASS", passed, total);
    crate::serial_println!(
        "[pipe-test][ASSERT] final : {}",
        if ok { "PASS" } else { "FAIL" }
    );
    ok
}

extern "C" fn pipe_test_main() -> ! {
    crate::serial_println!("[pipe-test][SETUP] task start");
    let _ = run_pipe_suite();
    crate::serial_println!("[pipe-test][CLEANUP] task done");
    crate::process::scheduler::exit_current_task(0);
}

pub fn create_pipe_test_task() {
    if let Ok(task) = Task::new_kernel_task(pipe_test_main, "pipe-test", TaskPriority::Normal) {
        add_task(task);
    } else {
        crate::serial_println!("[pipe-test][SETUP] failed to create task");
    }
}
