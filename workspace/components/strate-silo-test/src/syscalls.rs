#![no_std]
#![no_main]

use core::panic::PanicInfo;
use strat9_syscall::{
    call, data, error::Error, number, number::*, syscall1, syscall2, syscall3, syscall4, syscall6,
};

const PAGE_SIZE: usize = 4096;

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

/// Writes fd.
fn write_fd(fd: usize, msg: &str) {
    let _ = call::write(fd, msg.as_bytes());
}

/// Implements log.
fn log(msg: &str) {
    write_fd(1, msg);
}

/// Implements log err.
fn log_err(msg: &str) {
    write_fd(2, msg);
}

/// Implements log u64.
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

/// Implements log hex u64.
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

/// Implements section.
fn section(title: &str) {
    log("\n============================================================\n");
    log("[test_syscalls] ");
    log(title);
    log("\n============================================================\n");
}

/// Implements ok.
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

/// Implements fail.
fn fail(ctx: &mut Ctx, label: &str, err: Error) {
    ctx.fail += 1;
    log_err("[FAIL] ");
    log_err(label);
    log_err(" -> ");
    log_err(err.name());
    log_err("\n");
}

/// Implements check ok.
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

/// Implements check expect one of.
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

/// Implements check expect err.
fn check_expect_err(
    ctx: &mut Ctx,
    label: &str,
    res: core::result::Result<usize, Error>,
    expected: Error,
) {
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

/// Implements test process and ids.
fn test_process_and_ids(ctx: &mut Ctx) {
    section("Process IDs / Session / Group / Credentials");

    let pid = check_ok(ctx, "getpid()", call::getpid()).unwrap_or(0);
    let _ = check_ok(ctx, "getppid()", call::getppid());
    let _ = check_ok(ctx, "gettid()", call::gettid());
    let _pgid = check_ok(ctx, "getpgid(0)", call::getpgid(0)).unwrap_or(0);
    let sid = check_ok(ctx, "getsid(0)", call::getsid(0)).unwrap_or(0);
    if sid == pid {
        check_expect_err(
            ctx,
            "setpgid(0,0) while session leader -> EPERM",
            call::setpgid(0, 0),
            Error::PermissionDenied,
        );
    } else {
        let _ = check_ok(ctx, "setpgid(0,0)", call::setpgid(0, 0));
    }
    check_expect_one_of(
        ctx,
        "setsid()",
        call::setsid(),
        Error::PermissionDenied,
        Error::InvalidArgument,
    );

    let _ = check_ok(ctx, "raw SYS_GETUID", unsafe { syscall1(SYS_GETUID, 0) });
    let _ = check_ok(ctx, "raw SYS_GETEUID", unsafe { syscall1(SYS_GETEUID, 0) });
    let _ = check_ok(ctx, "raw SYS_GETGID", unsafe { syscall1(SYS_GETGID, 0) });
    let _ = check_ok(ctx, "raw SYS_GETEGID", unsafe { syscall1(SYS_GETEGID, 0) });
    let cur_uid = unsafe { syscall1(SYS_GETUID, 0) }.unwrap_or(0);
    let cur_gid = unsafe { syscall1(SYS_GETGID, 0) }.unwrap_or(0);
    let _ = check_ok(ctx, "raw SYS_SETUID(current uid)", unsafe {
        syscall1(SYS_SETUID, cur_uid)
    });
    let _ = check_ok(ctx, "raw SYS_SETGID(current gid)", unsafe {
        syscall1(SYS_SETGID, cur_gid)
    });
}

/// Implements test memory.
fn test_memory(ctx: &mut Ctx) {
    section("Memory: brk / mmap / mprotect / mremap / munmap");

    let base = check_ok(ctx, "brk(0)", call::brk(0)).unwrap_or(0);
    let grow = base + PAGE_SIZE * 2;
    let _ = check_ok(ctx, "brk(grow)", call::brk(grow));
    let _ = check_ok(ctx, "brk(shrink)", call::brk(base));

    let mapped = check_ok(ctx, "SYS_MMAP anon private RW 2 pages", unsafe {
        syscall6(
            number::SYS_MMAP,
            0,
            PAGE_SIZE * 2,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANON,
            0,
            0,
        )
    })
    .unwrap_or(0);

    if mapped != 0 {
        let ptr = mapped as *mut u8;
        unsafe {
            core::ptr::write_volatile(ptr, 0xAA);
            core::ptr::write_volatile(ptr.add(PAGE_SIZE), 0xBB);
        }
    }

    let _ = check_ok(ctx, "SYS_MPROTECT RO", unsafe {
        syscall3(number::SYS_MPROTECT, mapped, PAGE_SIZE * 2, PROT_READ)
    });
    let _ = check_ok(ctx, "SYS_MPROTECT RW", unsafe {
        syscall3(
            number::SYS_MPROTECT,
            mapped,
            PAGE_SIZE * 2,
            PROT_READ | PROT_WRITE,
        )
    });
    let remapped = check_ok(ctx, "SYS_MREMAP grow to 3 pages (MAYMOVE)", unsafe {
        syscall4(
            number::SYS_MREMAP,
            mapped,
            PAGE_SIZE * 2,
            PAGE_SIZE * 3,
            MREMAP_MAYMOVE,
        )
    })
    .unwrap_or(mapped);
    let _ = check_ok(ctx, "SYS_MREMAP shrink back to 2 pages", unsafe {
        syscall4(
            number::SYS_MREMAP,
            remapped,
            PAGE_SIZE * 3,
            PAGE_SIZE * 2,
            MREMAP_MAYMOVE,
        )
    });
    let _ = check_ok(ctx, "SYS_MUNMAP final", unsafe {
        syscall2(number::SYS_MUNMAP, remapped, PAGE_SIZE * 2)
    });
}

/// Implements test fs.
fn test_fs(ctx: &mut Ctx) {
    section("Filesystem and CWD syscalls");

    const DIR: &str = "/tmp/iso_syscalls_suite";
    const FILE: &str = "/tmp/iso_syscalls_suite/data.txt";
    const FILE_RENAMED: &str = "/tmp/iso_syscalls_suite/data_renamed.txt";
    const FILE_LINK: &str = "/tmp/iso_syscalls_suite/data_link.txt";
    const FILE_SYMLINK: &str = "/tmp/iso_syscalls_suite/data_symlink.txt";

    let _ = unsafe { syscall2(SYS_UNLINK, FILE.as_ptr() as usize, FILE.len()) };
    let _ = unsafe { syscall2(SYS_UNLINK, FILE_RENAMED.as_ptr() as usize, FILE_RENAMED.len()) };
    let _ = unsafe { syscall2(SYS_UNLINK, FILE_LINK.as_ptr() as usize, FILE_LINK.len()) };
    let _ = unsafe { syscall2(SYS_UNLINK, FILE_SYMLINK.as_ptr() as usize, FILE_SYMLINK.len()) };
    let _ = unsafe { syscall2(SYS_RMDIR, DIR.as_ptr() as usize, DIR.len()) };

    let _ = check_ok(ctx, "SYS_MKDIR /tmp/iso_syscalls_suite", unsafe {
        syscall3(SYS_MKDIR, DIR.as_ptr() as usize, DIR.len(), 0o755)
    });

    let file_fd = check_ok(ctx, "SYS_OPEN create RW file", unsafe {
        syscall3(
            number::SYS_OPEN,
            FILE.as_ptr() as usize,
            FILE.len(),
            O_READ | O_WRITE | O_CREATE | O_TRUNC,
        )
    })
    .unwrap_or(usize::MAX);

    if file_fd != usize::MAX {
        let msg = b"syscall-iso-test\n";
        let _ = check_ok(ctx, "SYS_WRITE file", unsafe {
            syscall3(number::SYS_WRITE, file_fd, msg.as_ptr() as usize, msg.len())
        });
        let _ = check_ok(ctx, "SYS_LSEEK file -> 0", unsafe {
            syscall3(number::SYS_LSEEK, file_fd, 0, SEEK_SET)
        });
        let mut buf = [0u8; 32];
        let _ = check_ok(ctx, "SYS_READ file", unsafe {
            syscall3(
                number::SYS_READ,
                file_fd,
                buf.as_mut_ptr() as usize,
                msg.len(),
            )
        });
        let mut st = data::FileStat::zeroed();
        let _ = check_ok(ctx, "SYS_FSTAT file", unsafe {
            syscall2(
                number::SYS_FSTAT,
                file_fd,
                &mut st as *mut data::FileStat as usize,
            )
        });
        let _ = check_ok(ctx, "SYS_FCHMOD file_fd 0644", unsafe {
            syscall2(SYS_FCHMOD, file_fd, 0o644)
        });
        let _ = check_ok(ctx, "SYS_FTRUNCATE file_fd -> 4", unsafe {
            syscall2(SYS_FTRUNCATE, file_fd, 4)
        });
    }

    let dir_fd = check_ok(ctx, "SYS_OPEN dir O_DIRECTORY", unsafe {
        syscall3(
            number::SYS_OPEN,
            DIR.as_ptr() as usize,
            DIR.len(),
            O_READ | O_DIRECTORY,
        )
    })
    .unwrap_or(usize::MAX);

    let _ = check_ok(ctx, "SYS_CHDIR dir", unsafe {
        syscall2(SYS_CHDIR, DIR.as_ptr() as usize, DIR.len())
    });
    let mut cwd = [0u8; 128];
    let _ = check_ok(ctx, "SYS_GETCWD", unsafe {
        syscall2(SYS_GETCWD, cwd.as_mut_ptr() as usize, cwd.len())
    });
    if dir_fd != usize::MAX {
        let _ = check_ok(ctx, "SYS_FCHDIR back", unsafe {
            syscall1(SYS_FCHDIR, dir_fd)
        });
    }

    let _ = check_ok(ctx, "SYS_UMASK set 022", unsafe {
        syscall1(SYS_UMASK, 0o022)
    });
    let _ = check_ok(ctx, "SYS_CHMOD file 0644", unsafe {
        syscall3(SYS_CHMOD, FILE.as_ptr() as usize, FILE.len(), 0o644)
    });
    let _ = check_ok(ctx, "SYS_RENAME file -> data_renamed.txt", unsafe {
        syscall4(
            SYS_RENAME,
            FILE.as_ptr() as usize,
            FILE.len(),
            FILE_RENAMED.as_ptr() as usize,
            FILE_RENAMED.len(),
        )
    });
    let _ = check_ok(ctx, "SYS_LINK renamed -> hardlink", unsafe {
        syscall4(
            SYS_LINK,
            FILE_RENAMED.as_ptr() as usize,
            FILE_RENAMED.len(),
            FILE_LINK.as_ptr() as usize,
            FILE_LINK.len(),
        )
    });
    let _ = check_ok(ctx, "SYS_SYMLINK renamed -> symlink", unsafe {
        syscall4(
            SYS_SYMLINK,
            FILE_RENAMED.as_ptr() as usize,
            FILE_RENAMED.len(),
            FILE_SYMLINK.as_ptr() as usize,
            FILE_SYMLINK.len(),
        )
    });
    let mut rl = [0u8; 64];
    check_expect_err(
        ctx,
        "SYS_READLINK regular file -> EINVAL",
        unsafe {
            syscall4(
                SYS_READLINK,
                FILE_RENAMED.as_ptr() as usize,
                FILE_RENAMED.len(),
                rl.as_mut_ptr() as usize,
                rl.len(),
            )
        },
        Error::InvalidArgument,
    );

    if file_fd != usize::MAX {
        let _ = check_ok(ctx, "SYS_CLOSE file", unsafe {
            syscall1(number::SYS_CLOSE, file_fd)
        });
    }
    if dir_fd != usize::MAX {
        let _ = check_ok(ctx, "SYS_CLOSE dir", unsafe {
            syscall1(number::SYS_CLOSE, dir_fd)
        });
    }
    let _ = check_ok(ctx, "SYS_UNLINK hardlink", unsafe {
        syscall2(SYS_UNLINK, FILE_LINK.as_ptr() as usize, FILE_LINK.len())
    });
    let _ = check_ok(ctx, "SYS_UNLINK symlink", unsafe {
        syscall2(SYS_UNLINK, FILE_SYMLINK.as_ptr() as usize, FILE_SYMLINK.len())
    });
    let _ = check_ok(ctx, "SYS_UNLINK renamed file", unsafe {
        syscall2(
            SYS_UNLINK,
            FILE_RENAMED.as_ptr() as usize,
            FILE_RENAMED.len(),
        )
    });
    let _ = check_ok(ctx, "SYS_RMDIR dir", unsafe {
        syscall2(SYS_RMDIR, DIR.as_ptr() as usize, DIR.len())
    });
}

/// Implements test handles.
fn test_handles(ctx: &mut Ctx) {
    section("Handle syscalls via semaphore handle");

    let sem = check_ok(ctx, "SYS_SEM_CREATE initial=1", unsafe {
        syscall1(number::SYS_SEM_CREATE, 1)
    })
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

    let _ = check_ok(
        ctx,
        "handle_wait(sem immediate)",
        call::handle_wait_timeout(sem, 0),
    );
    let _ = check_ok(ctx, "SYS_SEM_WAIT consume token", unsafe {
        syscall1(number::SYS_SEM_WAIT, sem)
    });
    check_expect_err(
        ctx,
        "handle_wait_timeout(sem empty, 1ms) -> ETIMEDOUT",
        call::handle_wait_timeout(sem, 1_000_000),
        Error::TimedOut,
    );
    let _ = check_ok(ctx, "SYS_SEM_POST produce token", unsafe {
        syscall1(number::SYS_SEM_POST, sem)
    });
    let _ = check_ok(
        ctx,
        "handle_wait(sem after post)",
        call::handle_wait_timeout(sem, 1_000_000),
    );

    let self_pid = call::getpid().unwrap_or(0);
    let dup = check_ok(
        ctx,
        "handle_grant(self_pid)",
        call::handle_grant(sem, self_pid),
    )
    .unwrap_or(usize::MAX);
    if dup != usize::MAX {
        let _ = check_ok(ctx, "handle_revoke(dup)", call::handle_revoke(dup));
    }
    match unsafe { syscall1(number::SYS_SEM_CLOSE, sem) } {
        Ok(v) => ok(ctx, "SYS_SEM_CLOSE(original)", v),
        Err(Error::NotFound) | Err(Error::BadHandle) => {
            ok(ctx, "SYS_SEM_CLOSE(original already cleaned)", 0)
        }
        Err(e) => fail(ctx, "SYS_SEM_CLOSE(original)", e),
    }
}

#[panic_handler]
/// Implements panic.
fn panic(_info: &PanicInfo) -> ! {
    log_err("[test_syscalls] PANIC\n");
    call::exit(250)
}

#[no_mangle]
/// Implements start.
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
