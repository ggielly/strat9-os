#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;
use strat9_syscall::{call, error::Error, number};

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
            log("ERR errno=");
            log_u64(e.to_errno() as u64);
            log(" (enum=");
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

unsafe fn raw_syscall0(nr: usize) -> usize {
    let mut ret = nr;
    unsafe {
        asm!(
            "syscall",
            inout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

unsafe fn raw_syscall1(nr: usize, a1: usize) -> usize {
    let mut ret = nr;
    unsafe {
        asm!(
            "syscall",
            inout("rax") ret,
            in("rdi") a1,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

unsafe fn raw_syscall3(nr: usize, a1: usize, a2: usize, a3: usize) -> usize {
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
    }
    log_nl();
}

fn exit_process(code: usize) -> ! {
    let _ = unsafe { raw_syscall1(number::SYS_PROC_EXIT, code) };
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    log_err("[init-test] PANIC detected, exiting with code 222\n");
    exit_process(222)
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("\n============================================================\n");
    log("[init-test] Strat9 first userspace init/test binary starting\n");
    log("[init-test] Goal: maximal verbosity for PID/FORK/WAIT debugging\n");
    log("============================================================\n");

    log("[init-test] STEP 1/9: reading identifiers via high-level wrappers\n");
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

    log("[init-test] STEP 2/9: reading identifiers via raw syscalls for cross-check\n");
    log_raw_ret("SYS_GETPID", unsafe { raw_syscall0(number::SYS_GETPID) });
    log_raw_ret("SYS_GETPPID", unsafe { raw_syscall0(number::SYS_GETPPID) });
    log_raw_ret("SYS_GETTID", unsafe { raw_syscall0(number::SYS_GETTID) });

    log("[init-test] STEP 3/9: waitpid(-1, WNOHANG) before any fork (expect no child)\n");
    let mut status_nochild: i32 = -9999;
    log_result(
        "waitpid(-1, &status, WNOHANG)",
        call::waitpid(-1, Some(&mut status_nochild), call::WNOHANG),
    );
    log("[init-test] status buffer after nochild waitpid = ");
    log_i64(status_nochild as i64);
    log_nl();
    let raw_nochild = unsafe {
        raw_syscall3(
            number::SYS_PROC_WAITPID,
            (-1isize) as usize,
            (&mut status_nochild as *mut i32) as usize,
            call::WNOHANG,
        )
    };
    log_raw_ret("SYS_PROC_WAITPID(-1, WNOHANG)", raw_nochild);

    log("[init-test] STEP 4/9: forking first child (child should exit 42)\n");
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

    log("[init-test] STEP 5/9: parent waits child1 (poll WNOHANG then blocking wait)\n");
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
    let waited = call::waitpid(child_pid as isize, Some(&mut child1_status), 0);
    if let Some(done) = log_result("waitpid(child1, blocking)", waited) {
        log("[init-test:parent] blocking wait returned pid=");
        log_u64(done as u64);
        log_nl();
    }
    decode_wait_status(child1_status);

    log("[init-test] STEP 6/9: process group/session syscalls (diagnostic only)\n");
    let _ = log_result("getpgrp()", call::getpgrp());
    let _ = log_result("getpgid(0)", call::getpgid(0));
    let _ = log_result("setpgid(0,0)", call::setpgid(0, 0));
    let _ = log_result("getsid(0)", call::getsid(0));
    let _ = log_result("setsid()", call::setsid());
    let _ = log_result("getsid(0) after setsid", call::getsid(0));

    log("[init-test] STEP 7/9: second fork/wait any-child path (child exits 7)\n");
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
    let _ = log_result("waitpid(-1, blocking)", call::waitpid(-1, Some(&mut child2_status), 0));
    decode_wait_status(child2_status);

    log("[init-test] STEP 8/9: raw syscall sanity check for waitpid on no child again\n");
    let mut st: i32 = 0;
    let raw = unsafe {
        raw_syscall3(
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

    log("[init-test] STEP 9/9: completed. exiting init-test with code 0\n");
    log("============================================================\n");
    exit_process(0)
}
