#![no_std]
#![no_main]

use core::panic::PanicInfo;
use strat9_syscall::{call, data, error::Error, number, syscall1, syscall2, syscall3, syscall4, syscall6};

const PAGE_SIZE: usize = 4096;

const SYS_GETUID: usize = 335;
const SYS_GETEUID: usize = 336;
const SYS_GETGID: usize = 337;
const SYS_GETEGID: usize = 338;
const SYS_SETUID: usize = 339;
const SYS_SETGID: usize = 340;
const SYS_CHDIR: usize = 440;
const SYS_FCHDIR: usize = 441;
const SYS_GETCWD: usize = 442;
const SYS_UMASK: usize = 444;
const SYS_UNLINK: usize = 445;
const SYS_RMDIR: usize = 446;
const SYS_MKDIR: usize = 447;
const SYS_RENAME: usize = 448;
const SYS_LINK: usize = 449;
const SYS_SYMLINK: usize = 450;
const SYS_READLINK: usize = 451;
const SYS_CHMOD: usize = 452;
const SYS_FCHMOD: usize = 453;
const SYS_FTRUNCATE: usize = 455;

const PROT_READ: usize = 1;
const PROT_WRITE: usize = 2;
const MAP_PRIVATE: usize = 1 << 1;
const MAP_ANON: usize = 1 << 5;
const MREMAP_MAYMOVE: usize = 1 << 0;
const SEEK_SET: usize = 0;

const O_READ: usize = 1 << 0;
const O_WRITE: usize = 1 << 1;
const O_CREATE: usize = 1 << 2;
const O_TRUNC: usize = 1 << 3;
const O_DIRECTORY: usize = 1 << 5;

struct Ctx {
    pass: u64,
    fail: u64,
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
    let mut i = buf.len();
    while value > 0 {
        i -= 1;
        buf[i] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    let s = unsafe { core::str::from_utf8_unchecked(&buf[i..]) };
    log(s);
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
    log("0x");
    let s = unsafe { core::str::from_utf8_unchecked(&buf) };
    log(s);
}

fn section(title: &str) {
    log("\n============================================================\n");
    log("[test_syscalls] ");
    log(title);
    log("\n============================================================\n");
}

fn ok(ctx: &mut Ctx, label: &str, value: usize) {
    ctx.pass += 1;
    log("[OK] ");
    log(label);
    log(" -> ");
    log_u64(value as u64);
    log(" (");
    log_hex_u64(value as u64);
    log(")\n");
}

fn fail(ctx: &mut Ctx, label: &str, err: Error) {
    ctx.fail += 1;
    log_err("[FAIL] ");
    log_err(label);
    log_err(" -> ");
    log_err(err.name());
    log_err("\n");
}

fn check_ok(ctx: &mut Ctx, label: &str, res: core::result::Result<usize, Error>) -> Option<usize> {
    match res {
        Ok(v) => {
            ok(ctx, label, v);
            Some(v)
        }
        Err(e) => {
            fail(ctx, label, e);
            None
        }
    }
}

fn check_expect_one_of(
    ctx: &mut Ctx,
    label: &str,
    res: core::result::Result<usize, Error>,
    e1: Error,
    e2: Error,
) {
    match res {
        Ok(v) => {
            if e1 == Error::Unknown(0) || e2 == Error::Unknown(0) {
                ok(ctx, label, v);
            } else {
                ctx.fail += 1;
                log_err("[FAIL] ");
                log_err(label);
                log_err(" -> expected error but got OK=");
                log_u64(v as u64);
                log_err("\n");
            }
        }
        Err(e) => {
            if e == e1 || e == e2 {
                ok(ctx, label, 0);
            } else {
                fail(ctx, label, e);
            }
        }
    }
}

fn check_expect_err(ctx: &mut Ctx, label: &str, res: core::result::Result<usize, Error>, expected: Error) {
    match res {
        Ok(v) => {
            ctx.fail += 1;
            log_err("[FAIL] ");
            log_err(label);
            log_err(" -> expected ");
            log_err(expected.name());
            log_err(" got OK=");
            log_u64(v as u64);
            log_err("\n");
        }
        Err(e) => {
            if e == expected {
                ok(ctx, label, 0);
            } else {
                fail(ctx, label, e);
            }
        }
    }
}

fn test_process_and_ids(ctx: &mut Ctx) {
    section("Process IDs / Session / Group / Credentials");

    let pid = check_ok(ctx, "getpid()", call::getpid()).unwrap_or(0);
    let _ = check_ok(ctx, "getppid()", call::getppid());
    let _ = check_ok(ctx, "gettid()", call::gettid());
    let _ = check_ok(ctx, "getpgid(0)", call::getpgid(0));
    let _ = check_ok(ctx, "getsid(0)", call::getsid(0));
    let _ = check_ok(ctx, "setpgid(0,0)", call::setpgid(0, 0));
    check_expect_one_of(ctx, "setsid()", call::setsid(), Error::PermissionDenied, Error::InvalidArgument);

    let _ = check_ok(ctx, "raw SYS_GETUID", unsafe { syscall1(SYS_GETUID, 0) });
    let _ = check_ok(ctx, "raw SYS_GETEUID", unsafe { syscall1(SYS_GETEUID, 0) });
    let _ = check_ok(ctx, "raw SYS_GETGID", unsafe { syscall1(SYS_GETGID, 0) });
    let _ = check_ok(ctx, "raw SYS_GETEGID", unsafe { syscall1(SYS_GETEGID, 0) });
    let cur_uid = unsafe { syscall1(SYS_GETUID, 0) }.unwrap_or(0);
    let cur_gid = unsafe { syscall1(SYS_GETGID, 0) }.unwrap_or(0);
    let _ = check_ok(ctx, "raw SYS_SETUID(current uid)", unsafe { syscall1(SYS_SETUID, cur_uid) });
    let _ = check_ok(ctx, "raw SYS_SETGID(current gid)", unsafe { syscall1(SYS_SETGID, cur_gid) });
}

fn test_memory(ctx: &mut Ctx) {
    section("Memory: brk / mmap / mprotect / mremap / munmap");

    let base = check_ok(ctx, "brk(0)", call::brk(0)).unwrap_or(0);
    let grow = base + PAGE_SIZE * 2;
    let _ = check_ok(ctx, "brk(grow)", call::brk(grow));
    let _ = check_ok(ctx, "brk(shrink)", call::brk(base));

    let mapped = check_ok(
        ctx,
        "SYS_MMAP anon private RW 2 pages",
        unsafe {
            syscall6(
                number::SYS_MMAP,
                0,
                PAGE_SIZE * 2,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON,
                0,
                0,
            )
        },
    )
    .unwrap_or(0);

    if mapped != 0 {
        let ptr = mapped as *mut u8;
        unsafe {
            core::ptr::write_volatile(ptr, 0xAA);
            core::ptr::write_volatile(ptr.add(PAGE_SIZE), 0xBB);
        }
    }

    let _ = check_ok(
        ctx,
        "SYS_MPROTECT RO",
        unsafe { syscall3(number::SYS_MPROTECT, mapped, PAGE_SIZE * 2, PROT_READ) },
    );
    let _ = check_ok(
        ctx,
        "SYS_MPROTECT RW",
        unsafe {
            syscall3(
                number::SYS_MPROTECT,
                mapped,
                PAGE_SIZE * 2,
                PROT_READ | PROT_WRITE,
            )
        },
    );
    let remapped = check_ok(
        ctx,
        "SYS_MREMAP grow to 3 pages (MAYMOVE)",
        unsafe { syscall4(number::SYS_MREMAP, mapped, PAGE_SIZE * 2, PAGE_SIZE * 3, MREMAP_MAYMOVE) },
    )
    .unwrap_or(mapped);
    let _ = check_ok(
        ctx,
        "SYS_MREMAP shrink back to 2 pages",
        unsafe { syscall4(number::SYS_MREMAP, remapped, PAGE_SIZE * 3, PAGE_SIZE * 2, MREMAP_MAYMOVE) },
    );
    let _ = check_ok(
        ctx,
        "SYS_MUNMAP final",
        unsafe { syscall2(number::SYS_MUNMAP, remapped, PAGE_SIZE * 2) },
    );
}

fn test_fs(ctx: &mut Ctx) {
    section("Filesystem and CWD syscalls");

    const DIR: &str = "/tmp/iso_syscalls_suite";
    const FILE: &str = "/tmp/iso_syscalls_suite/data.txt";

    let _ = unsafe { syscall2(SYS_UNLINK, FILE.as_ptr() as usize, FILE.len()) };
    let _ = unsafe { syscall2(SYS_RMDIR, DIR.as_ptr() as usize, DIR.len()) };

    let _ = check_ok(
        ctx,
        "SYS_MKDIR /tmp/iso_syscalls_suite",
        unsafe { syscall3(SYS_MKDIR, DIR.as_ptr() as usize, DIR.len(), 0o755) },
    );

    let file_fd = check_ok(
        ctx,
        "SYS_OPEN create RW file",
        unsafe {
            syscall3(
                number::SYS_OPEN,
                FILE.as_ptr() as usize,
                FILE.len(),
                O_READ | O_WRITE | O_CREATE | O_TRUNC,
            )
        },
    )
    .unwrap_or(usize::MAX);

    if file_fd != usize::MAX {
        let msg = b"syscall-iso-test\n";
        let _ = check_ok(
            ctx,
            "SYS_WRITE file",
            unsafe { syscall3(number::SYS_WRITE, file_fd, msg.as_ptr() as usize, msg.len()) },
        );
        let _ = check_ok(
            ctx,
            "SYS_LSEEK file -> 0",
            unsafe { syscall3(number::SYS_LSEEK, file_fd, 0, SEEK_SET) },
        );
        let mut buf = [0u8; 32];
        let _ = check_ok(
            ctx,
            "SYS_READ file",
            unsafe { syscall3(number::SYS_READ, file_fd, buf.as_mut_ptr() as usize, msg.len()) },
        );
        let mut st = data::FileStat::zeroed();
        let _ = check_ok(
            ctx,
            "SYS_FSTAT file",
            unsafe { syscall2(number::SYS_FSTAT, file_fd, &mut st as *mut data::FileStat as usize) },
        );
        check_expect_err(
            ctx,
            "SYS_FCHMOD expected ENOSYS",
            unsafe { syscall2(SYS_FCHMOD, file_fd, 0o644) },
            Error::NotImplemented,
        );
        check_expect_err(
            ctx,
            "SYS_FTRUNCATE expected ENOSYS",
            unsafe { syscall2(SYS_FTRUNCATE, file_fd, 4) },
            Error::NotImplemented,
        );
    }

    let dir_fd = check_ok(
        ctx,
        "SYS_OPEN dir O_DIRECTORY",
        unsafe { syscall3(number::SYS_OPEN, DIR.as_ptr() as usize, DIR.len(), O_READ | O_DIRECTORY) },
    )
    .unwrap_or(usize::MAX);

    let _ = check_ok(
        ctx,
        "SYS_CHDIR dir",
        unsafe { syscall2(SYS_CHDIR, DIR.as_ptr() as usize, DIR.len()) },
    );
    let mut cwd = [0u8; 128];
    let _ = check_ok(
        ctx,
        "SYS_GETCWD",
        unsafe { syscall2(SYS_GETCWD, cwd.as_mut_ptr() as usize, cwd.len()) },
    );
    if dir_fd != usize::MAX {
        let _ = check_ok(ctx, "SYS_FCHDIR back", unsafe { syscall1(SYS_FCHDIR, dir_fd) });
    }

    let _ = check_ok(ctx, "SYS_UMASK set 022", unsafe { syscall1(SYS_UMASK, 0o022) });
    check_expect_err(
        ctx,
        "SYS_CHMOD expected ENOSYS",
        unsafe { syscall3(SYS_CHMOD, FILE.as_ptr() as usize, FILE.len(), 0o644) },
        Error::NotImplemented,
    );
    check_expect_err(
        ctx,
        "SYS_RENAME expected ENOSYS",
        unsafe {
            syscall4(
                SYS_RENAME,
                FILE.as_ptr() as usize,
                FILE.len(),
                DIR.as_ptr() as usize,
                DIR.len(),
            )
        },
        Error::NotImplemented,
    );
    check_expect_err(
        ctx,
        "SYS_LINK expected ENOSYS",
        unsafe {
            syscall4(
                SYS_LINK,
                FILE.as_ptr() as usize,
                FILE.len(),
                DIR.as_ptr() as usize,
                DIR.len(),
            )
        },
        Error::NotImplemented,
    );
    check_expect_err(
        ctx,
        "SYS_SYMLINK expected ENOSYS",
        unsafe {
            syscall4(
                SYS_SYMLINK,
                FILE.as_ptr() as usize,
                FILE.len(),
                DIR.as_ptr() as usize,
                DIR.len(),
            )
        },
        Error::NotImplemented,
    );
    let mut rl = [0u8; 64];
    check_expect_err(
        ctx,
        "SYS_READLINK expected ENOSYS",
        unsafe {
            syscall4(
                SYS_READLINK,
                FILE.as_ptr() as usize,
                FILE.len(),
                rl.as_mut_ptr() as usize,
                rl.len(),
            )
        },
        Error::NotImplemented,
    );

    if file_fd != usize::MAX {
        let _ = check_ok(ctx, "SYS_CLOSE file", unsafe { syscall1(number::SYS_CLOSE, file_fd) });
    }
    if dir_fd != usize::MAX {
        let _ = check_ok(ctx, "SYS_CLOSE dir", unsafe { syscall1(number::SYS_CLOSE, dir_fd) });
    }
    let _ = check_ok(
        ctx,
        "SYS_UNLINK file",
        unsafe { syscall2(SYS_UNLINK, FILE.as_ptr() as usize, FILE.len()) },
    );
    let _ = check_ok(
        ctx,
        "SYS_RMDIR dir",
        unsafe { syscall2(SYS_RMDIR, DIR.as_ptr() as usize, DIR.len()) },
    );
}

fn test_handles(ctx: &mut Ctx) {
    section("Handle syscalls via semaphore handle");

    let sem = check_ok(
        ctx,
        "SYS_SEM_CREATE initial=1",
        unsafe { syscall1(number::SYS_SEM_CREATE, 1) },
    )
    .unwrap_or(usize::MAX);
    if sem == usize::MAX {
        return;
    }

    let mut info = data::HandleInfo {
        resource_type: 0,
        permissions: 0,
        resource: 0,
    };
    let _ = check_ok(ctx, "handle_info(sem)", call::handle_info(sem, &mut info));
    log("[info] resource_type=");
    log_u64(info.resource_type as u64);
    log(" perms=");
    log_hex_u64(info.permissions as u64);
    log(" resource=");
    log_hex_u64(info.resource);
    log("\n");

    let _ = check_ok(ctx, "handle_wait(sem immediate)", call::handle_wait_timeout(sem, 0));
    let _ = check_ok(ctx, "SYS_SEM_WAIT consume token", unsafe { syscall1(number::SYS_SEM_WAIT, sem) });
    check_expect_err(
        ctx,
        "handle_wait_timeout(sem empty, 1ms) -> ETIMEDOUT",
        call::handle_wait_timeout(sem, 1_000_000),
        Error::TimedOut,
    );
    let _ = check_ok(ctx, "SYS_SEM_POST produce token", unsafe { syscall1(number::SYS_SEM_POST, sem) });
    let _ = check_ok(ctx, "handle_wait(sem after post)", call::handle_wait_timeout(sem, 1_000_000));

    let self_pid = call::getpid().unwrap_or(0);
    let dup = check_ok(ctx, "handle_grant(self_pid)", call::handle_grant(sem, self_pid)).unwrap_or(usize::MAX);
    if dup != usize::MAX {
        let _ = check_ok(ctx, "handle_revoke(dup)", call::handle_revoke(dup));
    }
    match unsafe { syscall1(number::SYS_SEM_CLOSE, sem) } {
        Ok(v) => ok(ctx, "SYS_SEM_CLOSE(original)", v),
        Err(Error::NotFound) | Err(Error::BadHandle) => ok(ctx, "SYS_SEM_CLOSE(original already cleaned)", 0),
        Err(e) => fail(ctx, "SYS_SEM_CLOSE(original)", e),
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    log_err("[test_syscalls] PANIC\n");
    call::exit(250)
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let mut ctx = Ctx { pass: 0, fail: 0 };

    section("Strat9 syscall ISO test suite (verbose + broad coverage)");
    test_process_and_ids(&mut ctx);
    test_memory(&mut ctx);
    test_fs(&mut ctx);
    test_handles(&mut ctx);

    section("Summary");
    log("[summary] pass=");
    log_u64(ctx.pass);
    log(" fail=");
    log_u64(ctx.fail);
    log("\n");

    if ctx.fail == 0 {
        call::exit(0);
    } else {
        call::exit(1);
    }
}
