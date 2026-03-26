#![no_std]
#![no_main]

use core::panic::PanicInfo;
use strat9_syscall::{call, error::Error};

const F_GETFD: usize = 1;
const HELPER_FD: usize = 19;
const SIGUSR1: usize = 10;
const SIGUSR2: usize = 12;
const SIG_IGN: u64 = 1;
const SS_DISABLE: i32 = 1;

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

fn check_sigaction(signum: usize, expected_handler: u64, label: &str) -> bool {
    let mut old = SigActionRaw {
        sa_handler: 0,
        sa_flags: 0,
        sa_restorer: 0,
        sa_mask: 0,
    };
    match call::sigaction(signum, 0, &mut old as *mut _ as usize) {
        Ok(_) if old.sa_handler == expected_handler => true,
        Ok(_) => {
            log_err("[test_exec_helper] ");
            log_err(label);
            log_err(" mismatch\n");
            false
        }
        Err(err) => {
            log_err("[test_exec_helper] ");
            log_err(label);
            log_err(": ");
            log_err(err.name());
            log_err("\n");
            false
        }
    }
}

fn check_sigaltstack_reset() -> bool {
    let mut old = SigStackRaw {
        ss_sp: 0,
        ss_flags: 0,
        ss_size: 0,
    };
    match call::sigaltstack(0, &mut old as *mut _ as usize) {
        Ok(_) if (old.ss_flags & SS_DISABLE) != 0 => true,
        Ok(_) => {
            log_err("[test_exec_helper] sigaltstack still enabled\n");
            false
        }
        Err(err) => {
            log_err("[test_exec_helper] sigaltstack query: ");
            log_err(err.name());
            log_err("\n");
            false
        }
    }
}

fn check_cloexec_closed() -> bool {
    match call::fcntl(HELPER_FD, F_GETFD, 0) {
        Err(Error::BadHandle) => true,
        Err(err) => {
            log_err("[test_exec_helper] cloexec query: ");
            log_err(err.name());
            log_err("\n");
            false
        }
        Ok(_) => {
            log_err("[test_exec_helper] cloexec fd still open\n");
            false
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    log_err("[test_exec_helper] panic\n");
    call::exit(210)
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("[test_exec_helper] validating post-exec state\n");

    let mut ok = true;
    ok &= check_sigaction(SIGUSR1, 0, "SIGUSR1 reset to default");
    ok &= check_sigaction(SIGUSR2, SIG_IGN, "SIGUSR2 preserved as SIG_IGN");
    ok &= check_sigaltstack_reset();
    ok &= check_cloexec_closed();

    if ok {
        log("[test_exec_helper] validation passed\n");
        call::exit(0)
    } else {
        call::exit(1)
    }
}
