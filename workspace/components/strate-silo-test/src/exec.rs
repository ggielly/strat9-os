#![no_std]
#![no_main]

#[cfg(not(test))]
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use strat9_syscall::{call, error::Error, flag};

const F_SETFD: usize = 2;
const FD_CLOEXEC: usize = 1;
const WNOHANG: usize = 1;
const SIGUSR1: usize = 10;
const SIGUSR2: usize = 12;
const HELPER_FD: usize = 19;
const HELPER_PATH: &[u8] = b"/initfs/test_exec_helper\0";
const MULTI_EXEC_PATH: &[u8] = b"/initfs/test_exec_helper\0";

static mut EXEC_ALTSTACK: [u8; 4096] = [0; 4096];
static mut MULTI_EXEC_STACK: [u8; 8192] = [0; 8192];
static mut EXIT_GROUP_STACK: [u8; 8192] = [0; 8192];

static MULTI_EXEC_THREAD_READY: AtomicBool = AtomicBool::new(false);
static MULTI_EXEC_THREAD_STOP: AtomicBool = AtomicBool::new(false);
static EXIT_GROUP_THREAD_READY: AtomicBool = AtomicBool::new(false);
static PASS_COUNT: AtomicUsize = AtomicUsize::new(0);
static FAIL_COUNT: AtomicUsize = AtomicUsize::new(0);

#[repr(C)]
#[derive(Clone, Copy)]
struct SigActionRaw {
    sa_handler: u64,
    sa_flags: u64,
    sa_restorer: u64,
    sa_mask: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SigStackRaw {
    ss_sp: u64,
    ss_flags: i32,
    ss_size: usize,
}

fn write_fd(fd: usize, msg: &str) {
    let _ = call::write(fd, msg.as_bytes());
}

fn log(msg: &str) {
    write_fd(1, msg);
}

fn log_err(msg: &str) {
    write_fd(2, msg);
}

fn log_u64(mut value: u64) {
    let mut buf = [0u8; 21];
    if value == 0 {
        log("0");
        return;
    }
    let mut idx = buf.len();
    while value > 0 {
        idx -= 1;
        buf[idx] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    let s = unsafe { core::str::from_utf8_unchecked(&buf[idx..]) };
    log(s);
}

fn log_error_name(err: Error) {
    log_err(err.name());
}

fn pass(label: &str) {
    PASS_COUNT.fetch_add(1, Ordering::SeqCst);
    log("[PASS] ");
    log(label);
    log("\n");
}

fn fail_msg(label: &str, msg: &str) {
    FAIL_COUNT.fetch_add(1, Ordering::SeqCst);
    log_err("[FAIL] ");
    log_err(label);
    log_err(": ");
    log_err(msg);
    log_err("\n");
}

fn fail_err(label: &str, err: Error) {
    FAIL_COUNT.fetch_add(1, Ordering::SeqCst);
    log_err("[FAIL] ");
    log_err(label);
    log_err(": ");
    log_error_name(err);
    log_err("\n");
}

fn stack_top(buf: *mut u8, len: usize) -> usize {
    (buf as usize + len) & !0xFusize
}

fn wait_child_exit_code(pid: usize, label: &str) -> Option<u8> {
    let mut status = 0i32;
    match call::waitpid_blocking(pid as isize, &mut status) {
        Ok(_) => Some(((status >> 8) & 0xff) as u8),
        Err(err) => {
            fail_err(label, err);
            None
        }
    }
}

extern "C" fn multithread_exec_thread(_arg0: usize) -> ! {
    MULTI_EXEC_THREAD_READY.store(true, Ordering::SeqCst);
    while !MULTI_EXEC_THREAD_STOP.load(Ordering::SeqCst) {
        let _ = call::sched_yield();
    }
    call::thread_exit(0)
}

extern "C" fn exit_group_thread(_arg0: usize) -> ! {
    EXIT_GROUP_THREAD_READY.store(true, Ordering::SeqCst);
    loop {
        let _ = call::sched_yield();
    }
}

fn test_exec_cleanup_roundtrip() {
    log("[test_exec] exec cleanup roundtrip\n");
    match call::fork() {
        Ok(0) => {
            let fd = match call::open("/initfs/test_exec_helper", flag::O_RDONLY) {
                Ok(fd) => fd,
                Err(err) => call::exit(150 + err.to_errno()),
            };

            if call::dup2(fd, HELPER_FD).is_err() {
                let _ = call::close(fd);
                call::exit(151);
            }
            let _ = call::close(fd);

            if call::fcntl(HELPER_FD, F_SETFD, FD_CLOEXEC).is_err() {
                call::exit(152);
            }

            let catch_action = SigActionRaw {
                sa_handler: 0x1234,
                sa_flags: 0,
                sa_restorer: 0,
                sa_mask: 0,
            };
            if call::sigaction(SIGUSR1, &catch_action as *const _ as usize, 0).is_err() {
                call::exit(153);
            }

            let ignore_action = SigActionRaw {
                sa_handler: 1,
                sa_flags: 0,
                sa_restorer: 0,
                sa_mask: 0,
            };
            if call::sigaction(SIGUSR2, &ignore_action as *const _ as usize, 0).is_err() {
                call::exit(154);
            }

            let altstack = SigStackRaw {
                ss_sp: core::ptr::addr_of_mut!(EXEC_ALTSTACK) as *mut u8 as usize as u64,
                ss_flags: 0,
                ss_size: 4096,
            };
            if call::sigaltstack(&altstack as *const _ as usize, 0).is_err() {
                call::exit(155);
            }

            let argv = [HELPER_PATH.as_ptr() as usize, 0];
            let envp = [0usize];
            let exec_res = unsafe {
                call::execve(HELPER_PATH, argv.as_ptr() as usize, envp.as_ptr() as usize)
            };
            let code = exec_res
                .err()
                .map(|err| 160 + err.to_errno())
                .unwrap_or(161);
            call::exit(code)
        }
        Ok(pid) => match wait_child_exit_code(pid, "wait helper child") {
            Some(0) => pass("exec keeps SIG_IGN and resets handlers, altstack, CLOEXEC"),
            Some(code) => {
                log_err("[FAIL] exec cleanup roundtrip child exit=");
                log_u64(code as u64);
                log_err("\n");
                FAIL_COUNT.fetch_add(1, Ordering::SeqCst);
            }
            None => {}
        },
        Err(err) => fail_err("fork exec cleanup child", err),
    }
}

fn test_multithread_exec_rejected() {
    log("[test_exec] multithread exec rejection\n");
    MULTI_EXEC_THREAD_READY.store(false, Ordering::SeqCst);
    MULTI_EXEC_THREAD_STOP.store(false, Ordering::SeqCst);

    let stack_top = stack_top(core::ptr::addr_of_mut!(MULTI_EXEC_STACK) as *mut u8, 8192);
    let tid = match call::thread_create(
        multithread_exec_thread as *const () as usize,
        stack_top,
        0,
        0,
    ) {
        Ok(tid) => tid,
        Err(err) => {
            fail_err("thread_create for exec rejection", err);
            return;
        }
    };

    for _ in 0..256 {
        if MULTI_EXEC_THREAD_READY.load(Ordering::SeqCst) {
            break;
        }
        let _ = call::sched_yield();
    }

    if !MULTI_EXEC_THREAD_READY.load(Ordering::SeqCst) {
        fail_msg("multithread exec rejection", "worker thread did not start");
        let mut status = 0i32;
        let _ = call::thread_join(tid, Some(&mut status));
        return;
    }

    let argv = [MULTI_EXEC_PATH.as_ptr() as usize, 0];
    let envp = [0usize];
    match unsafe {
        call::execve(
            MULTI_EXEC_PATH,
            argv.as_ptr() as usize,
            envp.as_ptr() as usize,
        )
    } {
        Err(Error::NotSupported) => pass("exec rejects multithreaded caller"),
        Err(err) => fail_err("exec rejects multithreaded caller", err),
        Ok(_) => fail_msg(
            "exec rejects multithreaded caller",
            "exec unexpectedly succeeded",
        ),
    }

    MULTI_EXEC_THREAD_STOP.store(true, Ordering::SeqCst);
    let mut status = 0i32;
    if call::thread_join(tid, Some(&mut status)).is_err() {
        fail_msg("thread_join after rejected exec", "join failed");
    }
}

fn test_exit_group_kills_siblings() {
    log("[test_exec] exit_group kills sibling threads\n");
    match call::fork() {
        Ok(0) => {
            EXIT_GROUP_THREAD_READY.store(false, Ordering::SeqCst);
            let stack_top = stack_top(core::ptr::addr_of_mut!(EXIT_GROUP_STACK) as *mut u8, 8192);
            if call::thread_create(exit_group_thread as *const () as usize, stack_top, 0, 0)
                .is_err()
            {
                call::exit(170);
            }
            for _ in 0..256 {
                if EXIT_GROUP_THREAD_READY.load(Ordering::SeqCst) {
                    break;
                }
                let _ = call::sched_yield();
            }
            if !EXIT_GROUP_THREAD_READY.load(Ordering::SeqCst) {
                call::exit(171);
            }
            call::exit_group(77)
        }
        Ok(pid) => {
            let mut status = 0i32;
            for _ in 0..512 {
                match call::waitpid(pid as isize, Some(&mut status), WNOHANG) {
                    Ok(0) => {
                        let _ = call::sched_yield();
                    }
                    Ok(_) => {
                        let code = ((status >> 8) & 0xff) as u8;
                        if code == 77 {
                            pass("exit_group terminates thread group");
                        } else {
                            log_err("[FAIL] exit_group child exit=");
                            log_u64(code as u64);
                            log_err("\n");
                            FAIL_COUNT.fetch_add(1, Ordering::SeqCst);
                        }
                        return;
                    }
                    Err(Error::Interrupted) => {
                        let _ = call::sched_yield();
                    }
                    Err(err) => {
                        fail_err("waitpid for exit_group child", err);
                        return;
                    }
                }
            }
            fail_msg(
                "exit_group terminates thread group",
                "child stayed alive too long",
            );
        }
        Err(err) => fail_err("fork exit_group child", err),
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    log_err("[test_exec] panic\n");
    call::exit(200)
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("[test_exec] starting exec regression suite\n");

    test_exec_cleanup_roundtrip();
    test_multithread_exec_rejected();
    test_exit_group_kills_siblings();

    log("[test_exec] summary pass=");
    log_u64(PASS_COUNT.load(Ordering::SeqCst) as u64);
    log(" fail=");
    log_u64(FAIL_COUNT.load(Ordering::SeqCst) as u64);
    log("\n");

    if FAIL_COUNT.load(Ordering::SeqCst) == 0 {
        call::exit(0)
    } else {
        call::exit(1)
    }
}
