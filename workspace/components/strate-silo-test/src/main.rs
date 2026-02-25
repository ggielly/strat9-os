#![no_std]
#![no_main]

use core::{arch::asm, panic::PanicInfo};
use strat9_syscall::{call, error::Error, number};

static mut COW_SENTINEL: u64 = 0x1122_3344_5566_7788;
static mut COW_MULTI: [u8; 4096 * 4] = [0; 4096 * 4];

fn write_fd(fd: usize, msg: &str) {
    let _ = call::write(fd, msg.as_bytes());
}

fn log(msg: &str) {
    write_fd(1, msg);
}

fn log_err(msg: &str) {
    write_fd(2, msg);
}

fn log_nl() {
    log("\n");
}

fn log_sep_star() {
    log("************************************************************\n");
}

fn log_sep_eq() {
    log("============================================================\n");
}

fn log_section(title: &str) {
    log_sep_star();
    log("[init-test] ");
    log(title);
    log_nl();
    log_sep_eq();
}

fn log_u64(mut value: u64) {
    let mut buf = [0u8; 21];
    if value == 0 {
        write_fd(1, "0");
        return;
    }

    let mut i = buf.len();
    while value > 0 {
        i -= 1;
        buf[i] = b'0' + (value % 10) as u8;
        value /= 10;
    }

    let s = unsafe { core::str::from_utf8_unchecked(&buf[i..]) };
    write_fd(1, s);
}

fn log_i64(value: i64) {
    if value < 0 {
        write_fd(1, "-");
        log_u64(value.unsigned_abs());
    } else {
        log_u64(value as u64);
    }
}

fn log_hex_u64(mut value: u64) {
    let mut buf = [0u8; 16];
    for i in (0..16).rev() {
        let nibble = (value & 0xF) as u8;
        buf[i] = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
        value >>= 4;
    }
    write_fd(1, "0x");
    let s = unsafe { core::str::from_utf8_unchecked(&buf) };
    write_fd(1, s);
}

fn log_result(label: &str, res: core::result::Result<usize, Error>) -> Option<usize> {
    log("[init-test] ");
    log(label);
    log(" => ");
    match res {
        Ok(v) => {
            log("OK value=");
            log_u64(v as u64);
            log(" hex=");
            log_hex_u64(v as u64);
            log_nl();
            Some(v)
        }
        Err(e) => {
            log("ERR ");
            log(e.name());
            log(" (errno=");
            log_u64(e.to_errno() as u64);
            log(")");
            log_nl();
            None
        }
    }
}

fn decode_wait_status(status: i32) {
    let exit_code = ((status >> 8) & 0xff) as u8;
    let signal = (status & 0x7f) as u8;
    log("[init-test] wait status decode: raw=");
    log_i64(status as i64);
    log(" hex=");
    log_hex_u64(status as u32 as u64);
    log(" exit_code=");
    log_u64(exit_code as u64);
    log(" signal=");
    log_u64(signal as u64);
    log_nl();
}

unsafe fn raw_syscall(nr: usize, a1: usize, a2: usize, a3: usize) -> usize {
    let mut ret = nr;
    unsafe {
        asm!(
            "syscall",
            inout("rax") ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

fn log_raw_ret(label: &str, ret: usize) {
    log("[init-test] RAW ");
    log(label);
    log(" => dec=");
    log_u64(ret as u64);
    log(" hex=");
    log_hex_u64(ret as u64);
    if (ret as isize) < 0 {
        log(" signed=");
        log_i64(ret as isize as i64);
        if let Err(e) = Error::demux(ret) {
            log(" err=");
            log(e.name());
        }
    }
    log_nl();
}

fn cow_addr() -> u64 {
    core::ptr::addr_of!(COW_SENTINEL) as u64
}

fn cow_read() -> u64 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(COW_SENTINEL)) }
}

fn cow_write(value: u64) {
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(COW_SENTINEL), value);
    }
}

fn cow_multi_addr() -> u64 {
    core::ptr::addr_of!(COW_MULTI) as u64
}

fn cow_multi_read(offset: usize) -> u8 {
    unsafe { core::ptr::read_volatile((core::ptr::addr_of!(COW_MULTI) as *const u8).add(offset)) }
}

fn cow_multi_write(offset: usize, value: u8) {
    unsafe {
        core::ptr::write_volatile(
            (core::ptr::addr_of_mut!(COW_MULTI) as *mut u8).add(offset),
            value,
        );
    }
}

fn log_cow_multi_page_snapshot(prefix: &str, page: usize) {
    let base = page * 4096;
    let a = cow_multi_read(base);
    let b = cow_multi_read(base + 17);
    let c = cow_multi_read(base + 4095);
    log(prefix);
    log(" page=");
    log_u64(page as u64);
    log(" first=");
    log_hex_u64(a as u64);
    log(" mid=");
    log_hex_u64(b as u64);
    log(" last=");
    log_hex_u64(c as u64);
    log_nl();
}

fn exit_process(code: usize) -> ! {
    call::exit(code)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    log_err("[init-test] PANIC detected, exiting with code 222\n");
    exit_process(222)
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log_nl();
    log_sep_eq();
    log("[init-test] Strat9 first userspace init/test binary starting\n");
    log("[init-test] Goal: maximal verbosity for PID/FORK/WAIT/COW debugging\n");
    log_sep_eq();

    log_section("STEP 1/11: reading identifiers via high-level wrappers");
    let pid = log_result("getpid()", call::getpid()).unwrap_or(0);
    let ppid = log_result("getppid()", call::getppid()).unwrap_or(0);
    let tid = log_result("gettid()", call::gettid()).unwrap_or(0);
    log("[init-test] summary ids: pid=");
    log_u64(pid as u64);
    log(" ppid=");
    log_u64(ppid as u64);
    log(" tid=");
    log_u64(tid as u64);
    log_nl();

    log_section("STEP 2/11: reading identifiers via raw syscalls for cross-check");
    log_raw_ret("SYS_GETPID", unsafe {
        raw_syscall(number::SYS_GETPID, 0, 0, 0)
    });
    log_raw_ret("SYS_GETPPID", unsafe {
        raw_syscall(number::SYS_GETPPID, 0, 0, 0)
    });
    log_raw_ret("SYS_GETTID", unsafe {
        raw_syscall(number::SYS_GETTID, 0, 0, 0)
    });

    log_section("STEP 3/11: waitpid(-1, WNOHANG) before any fork (expect no child)");
    let mut status_nochild: i32 = -9999;
    log_result(
        "waitpid(-1, &status, WNOHANG)",
        call::waitpid(-1, Some(&mut status_nochild), call::WNOHANG),
    );
    log("[init-test] status buffer after nochild waitpid = ");
    log_i64(status_nochild as i64);
    log_nl();
    let raw_nochild = unsafe {
        raw_syscall(
            number::SYS_PROC_WAITPID,
            (-1isize) as usize,
            (&mut status_nochild as *mut i32) as usize,
            call::WNOHANG,
        )
    };
    log_raw_ret("SYS_PROC_WAITPID(-1, WNOHANG)", raw_nochild);

    log_section("STEP 4/11: forking first child (child should exit 42)");
    let fork_ret = call::fork();
    let child_pid = match fork_ret {
        Ok(v) => v,
        Err(e) => {
            log("[init-test] fork failed errno=");
            log_u64(e.to_errno() as u64);
            log_nl();
            exit_process(10);
        }
    };

    if child_pid == 0 {
        log("[init-test:child1] entered child branch\n");
        log_result("[child1] getpid()", call::getpid());
        log_result("[child1] getppid()", call::getppid());
        log_result("[child1] gettid()", call::gettid());
        log("[init-test:child1] doing sched_yield x2 to exercise scheduler\n");
        let _ = call::sched_yield();
        let _ = call::sched_yield();
        log("[init-test:child1] exiting with code 42\n");
        exit_process(42);
    }

    log("[init-test:parent] fork returned child_pid=");
    log_u64(child_pid as u64);
    log_nl();

    log_section("STEP 5/11: parent waits child1 (poll WNOHANG then blocking wait)");
    let mut child1_status: i32 = -1234;
    for i in 0..5usize {
        log("[init-test:parent] poll iteration ");
        log_u64(i as u64);
        log(": ");
        match call::waitpid(child_pid as isize, Some(&mut child1_status), call::WNOHANG) {
            Ok(0) => {
                log("no exit yet\n");
                let _ = call::sched_yield();
            }
            Ok(pid_done) => {
                log("reaped immediately pid=");
                log_u64(pid_done as u64);
                log_nl();
                decode_wait_status(child1_status);
                break;
            }
            Err(e) => {
                log("poll waitpid error errno=");
                log_u64(e.to_errno() as u64);
                log_nl();
                break;
            }
        }
    }
    let waited = call::waitpid_blocking(child_pid as isize, &mut child1_status);
    if let Some(done) = log_result("waitpid(child1, blocking)", waited) {
        log("[init-test:parent] blocking wait returned pid=");
        log_u64(done as u64);
        log_nl();
    }
    decode_wait_status(child1_status);

    log_section("STEP 6/11: process group/session syscalls (diagnostic only)");
    let _ = log_result("getpgrp()", call::getpgrp());
    let _ = log_result("getpgid(0)", call::getpgid(0));
    let _ = log_result("setpgid(0,0)", call::setpgid(0, 0));
    let _ = log_result("getsid(0)", call::getsid(0));
    let _ = log_result("setsid()", call::setsid());
    let _ = log_result("getsid(0) after setsid", call::getsid(0));

    log_section("STEP 7/11: second fork/wait any-child path (child exits 7)");
    let second = call::fork();
    let child2_pid = match second {
        Ok(v) => v,
        Err(e) => {
            log("[init-test] second fork failed errno=");
            log_u64(e.to_errno() as u64);
            log_nl();
            exit_process(11);
        }
    };
    if child2_pid == 0 {
        log("[init-test:child2] exiting with code 7 immediately\n");
        exit_process(7);
    }
    log("[init-test:parent] second child pid=");
    log_u64(child2_pid as u64);
    log_nl();
    let mut child2_status: i32 = 0;
    let _ = log_result(
        "waitpid(-1, blocking)",
        call::waitpid_blocking(-1, &mut child2_status),
    );
    decode_wait_status(child2_status);

    log_section("STEP 8/11: targeted CoW test (single 64-bit sentinel)");
    let cow_initial = 0x1122_3344_5566_7788u64;
    let cow_child_value = 0xdead_beef_cafe_babeu64;
    let cow_parent_value = 0xa1a2_a3a4_a5a6_a7a8u64;
    cow_write(cow_initial);
    log("[init-test:cow] sentinel address=");
    log_hex_u64(cow_addr());
    log(" initial=");
    log_hex_u64(cow_read());
    log_nl();
    log("[init-test:cow] expected child write value=");
    log_hex_u64(cow_child_value);
    log(" expected parent write value=");
    log_hex_u64(cow_parent_value);
    log_nl();

    let cow_fork = call::fork();
    let cow_child_pid = match cow_fork {
        Ok(v) => v,
        Err(e) => {
            log("[init-test:cow] fork failed errno=");
            log_u64(e.to_errno() as u64);
            log_nl();
            exit_process(12);
        }
    };

    if cow_child_pid == 0 {
        log("[init-test:cow:child] entered child branch\n");
        let child_seen_before = cow_read();
        log("[init-test:cow:child] sentinel before write=");
        log_hex_u64(child_seen_before);
        log_nl();
        if child_seen_before != cow_initial {
            log("[init-test:cow:child] ERROR: unexpected initial sentinel in child\n");
            exit_process(90);
        }

        log("[init-test:cow:child] writing sentinel to child-specific value\n");
        cow_write(cow_child_value);
        let child_seen_after = cow_read();
        log("[init-test:cow:child] sentinel after write=");
        log_hex_u64(child_seen_after);
        log_nl();
        if child_seen_after != cow_child_value {
            log("[init-test:cow:child] ERROR: child write did not stick\n");
            exit_process(91);
        }

        let _ = call::sched_yield();
        let _ = call::sched_yield();
        log("[init-test:cow:child] CoW child path done, exiting code 77\n");
        exit_process(77);
    }

    log("[init-test:cow:parent] child pid=");
    log_u64(cow_child_pid as u64);
    log(" parent sees sentinel pre-wait=");
    log_hex_u64(cow_read());
    log_nl();

    let mut cow_status: i32 = -1;
    let waited_cow = call::waitpid_blocking(cow_child_pid as isize, &mut cow_status);
    let waited_cow_pid =
        if let Some(done) = log_result("[cow-parent] waitpid(cow-child, blocking)", waited_cow) {
            done
        } else {
            exit_process(13);
        };
    log("[init-test:cow:parent] wait returned pid=");
    log_u64(waited_cow_pid as u64);
    log_nl();
    decode_wait_status(cow_status);

    let cow_after_child_exit = cow_read();
    log("[init-test:cow:parent] sentinel post-child-exit=");
    log_hex_u64(cow_after_child_exit);
    log_nl();
    if cow_after_child_exit != cow_initial {
        log("[init-test:cow:parent] ERROR: parent observed child write (CoW broken)\n");
        exit_process(14);
    }

    log("[init-test:cow:parent] writing parent-specific value\n");
    cow_write(cow_parent_value);
    let cow_after_parent_write = cow_read();
    log("[init-test:cow:parent] sentinel after parent write=");
    log_hex_u64(cow_after_parent_write);
    log_nl();
    if cow_after_parent_write != cow_parent_value {
        log("[init-test:cow:parent] ERROR: parent write did not stick\n");
        exit_process(15);
    }
    log("[init-test:cow] SUCCESS: CoW isolation validated for parent/child writes\n");

    log_section("STEP 9/11: targeted CoW multi-page test (4 pages)");
    log("[init-test:cow4k] buffer address=");
    log_hex_u64(cow_multi_addr());
    log(" size=");
    log_u64((4096 * 4) as u64);
    log_nl();

    for page in 0..4usize {
        let base = page * 4096;
        cow_multi_write(base, (0x10 + page as u8) as u8);
        cow_multi_write(base + 17, (0x40 + page as u8) as u8);
        cow_multi_write(base + 4095, (0x70 + page as u8) as u8);
        log_cow_multi_page_snapshot("[init-test:cow4k:parent:init]", page);
    }

    let cow_multi_fork = call::fork();
    let cow_multi_child_pid = match cow_multi_fork {
        Ok(v) => v,
        Err(e) => {
            log("[init-test:cow4k] fork failed errno=");
            log_u64(e.to_errno() as u64);
            log_nl();
            exit_process(16);
        }
    };

    if cow_multi_child_pid == 0 {
        log_sep_star();
        log("[init-test:cow4k:child] validating inherited page fingerprints\n");
        for page in 0..4usize {
            log_cow_multi_page_snapshot("[init-test:cow4k:child:before]", page);
        }
        log("[init-test:cow4k:child] mutating all 4 pages with child-only fingerprints\n");
        for page in 0..4usize {
            let base = page * 4096;
            cow_multi_write(base, (0x91 + page as u8) as u8);
            cow_multi_write(base + 17, (0xA1 + page as u8) as u8);
            cow_multi_write(base + 4095, (0xB1 + page as u8) as u8);
            log_cow_multi_page_snapshot("[init-test:cow4k:child:after]", page);
        }
        log("[init-test:cow4k:child] exiting code 88\n");
        exit_process(88);
    }

    log("[init-test:cow4k:parent] child pid=");
    log_u64(cow_multi_child_pid as u64);
    log_nl();
    let mut cow_multi_status: i32 = -1;
    let mut waited_multi_ok = false;
    for attempt in 0..2000usize {
        let waited_multi = call::waitpid(
            cow_multi_child_pid as isize,
            Some(&mut cow_multi_status),
            call::WNOHANG,
        );
        match waited_multi {
            Ok(0) => {
                if attempt % 100 == 0 {
                    log("[init-test:cow4k:parent] waitpid WNOHANG: child still running, attempt=");
                    log_u64(attempt as u64);
                    log_nl();
                }
                let _ = call::sched_yield();
            }
            Ok(pid_done) => {
                log_result("[cow4k-parent] waitpid(cow4k-child, WNOHANG)", Ok(pid_done));
                waited_multi_ok = true;
                break;
            }
            Err(Error::Interrupted) => {
                log("[init-test:cow4k:parent] waitpid interrupted (EINTR), retry attempt=");
                log_u64((attempt + 1) as u64);
                log_nl();
                let _ = call::sched_yield();
            }
            Err(e) => {
                log_result("[cow4k-parent] waitpid(cow4k-child, WNOHANG)", Err(e));
                break;
            }
        }
    }
    if !waited_multi_ok {
        log("[init-test:cow4k:parent] ERROR: waitpid timeout after retries\n");
        exit_process(17);
    }
    decode_wait_status(cow_multi_status);

    log("[init-test:cow4k:parent] verifying parent view unchanged after child writes\n");
    for page in 0..4usize {
        let base = page * 4096;
        let v0 = cow_multi_read(base);
        let v1 = cow_multi_read(base + 17);
        let v2 = cow_multi_read(base + 4095);
        if v0 != (0x10 + page as u8) as u8
            || v1 != (0x40 + page as u8) as u8
            || v2 != (0x70 + page as u8) as u8
        {
            log("[init-test:cow4k:parent] ERROR: parent observed child mutation page=");
            log_u64(page as u64);
            log_nl();
            exit_process(18);
        }
        log_cow_multi_page_snapshot("[init-test:cow4k:parent:verified]", page);
    }

    log("[init-test:cow4k:parent] now writing parent-only fingerprints\n");
    for page in 0..4usize {
        let base = page * 4096;
        cow_multi_write(base, (0x21 + page as u8) as u8);
        cow_multi_write(base + 17, (0x31 + page as u8) as u8);
        cow_multi_write(base + 4095, (0x41 + page as u8) as u8);
        log_cow_multi_page_snapshot("[init-test:cow4k:parent:after]", page);
    }
    log("[init-test:cow4k] SUCCESS: 4-page CoW isolation validated\n");

    log_section("STEP 10/11: raw syscall sanity check for waitpid on no child again");
    let mut st: i32 = 0;
    let raw = unsafe {
        raw_syscall(
            number::SYS_PROC_WAITPID,
            (-1isize) as usize,
            (&mut st as *mut i32) as usize,
            0,
        )
    };
    log_raw_ret("SYS_PROC_WAITPID(-1, blocking)", raw);
    log("[init-test] status buffer=");
    log_i64(st as i64);
    log_nl();

    log_section("STEP 11/11: completed. exiting init-test with code 0");
    log_sep_eq();
    exit_process(0)
}
