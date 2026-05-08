#![no_std]

use strat9_abi::{flag::posix_oflags_to_strat9, syscall::*};
use strat9_syscall::{syscall0, syscall1, syscall2, syscall3, syscall4, syscall5, syscall6};

// === raw syscall helpers (return i64 for musl C ABI) ===============================

#[inline(always)]
fn raw0(nr: usize) -> i64 {
    unsafe {
        match syscall0(nr) {
            Ok(v) => v as i64,
            Err(e) => -(e.to_errno() as i64),
        }
    }
}

#[inline(always)]
fn raw1(nr: usize, a1: usize) -> i64 {
    unsafe {
        match syscall1(nr, a1) {
            Ok(v) => v as i64,
            Err(e) => -(e.to_errno() as i64),
        }
    }
}

#[inline(always)]
fn raw2(nr: usize, a1: usize, a2: usize) -> i64 {
    unsafe {
        match syscall2(nr, a1, a2) {
            Ok(v) => v as i64,
            Err(e) => -(e.to_errno() as i64),
        }
    }
}

#[inline(always)]
fn raw3(nr: usize, a1: usize, a2: usize, a3: usize) -> i64 {
    unsafe {
        match syscall3(nr, a1, a2, a3) {
            Ok(v) => v as i64,
            Err(e) => -(e.to_errno() as i64),
        }
    }
}

#[inline(always)]
fn raw4(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> i64 {
    unsafe {
        match syscall4(nr, a1, a2, a3, a4) {
            Ok(v) => v as i64,
            Err(e) => -(e.to_errno() as i64),
        }
    }
}

#[inline(always)]
fn raw5(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> i64 {
    unsafe {
        match syscall5(nr, a1, a2, a3, a4, a5) {
            Ok(v) => v as i64,
            Err(e) => -(e.to_errno() as i64),
        }
    }
}

#[inline(always)]
fn raw6(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> i64 {
    unsafe {
        match syscall6(nr, a1, a2, a3, a4, a5, a6) {
            Ok(v) => v as i64,
            Err(e) => -(e.to_errno() as i64),
        }
    }
}

// === Linux clone flags ================================================

const _CLONE_VM: usize = 0x100; // share memory space
const CLONE_THREAD: usize = 0x10000;

// === Linux futex operation constants ==================================

const FUTEX_WAIT: usize = 0;
const FUTEX_WAKE: usize = 1;
const FUTEX_REQUEUE: usize = 3;
const FUTEX_CMP_REQUEUE: usize = 4;
const FUTEX_PRIVATE_FLAG: usize = 128;

// === arch_prctl sub-commands

const ARCH_SET_FS: usize = 0x1002;
const ARCH_GET_FS: usize = 0x1003;

// === Linux syscall numbers used by musl internally ==================================
// See sdk/musl/arch/x86_64/bits/syscall.h.in for the full list.
// We define the ones we actually handle; the rest fall through to the
// default -ENOSYS branch.

const LNR_read: i64 = 0;
const LNR_write: i64 = 1;
const LNR_open: i64 = 2;
const LNR_close: i64 = 3;
const LNR_stat: i64 = 4;
const LNR_fstat: i64 = 5;
const LNR_lstat: i64 = 6;
const LNR_poll: i64 = 7;
const LNR_lseek: i64 = 8;
const LNR_mmap: i64 = 9;
const LNR_mprotect: i64 = 10;
const LNR_munmap: i64 = 11;
const LNR_brk: i64 = 12;
const LNR_rt_sigaction: i64 = 13;
const LNR_rt_sigprocmask: i64 = 14;
const LNR_rt_sigreturn: i64 = 15;
const LNR_ioctl: i64 = 16;
const LNR_pread64: i64 = 17;
const LNR_pwrite64: i64 = 18;
const LNR_access: i64 = 21;
const LNR_pipe: i64 = 22;
const LNR_sched_yield: i64 = 24;
const LNR_mremap: i64 = 25;
const LNR_dup: i64 = 32;
const LNR_dup2: i64 = 33;
const LNR_nanosleep: i64 = 35;
const LNR_getitimer: i64 = 36;
const LNR_setitimer: i64 = 38;
const LNR_getpid: i64 = 39;
const LNR_clone: i64 = 56;
const LNR_fork: i64 = 57;
const LNR_execve: i64 = 59;
const LNR_exit: i64 = 60;
const LNR_wait4: i64 = 61;
const LNR_kill: i64 = 62;
const LNR_uname: i64 = 63;
const LNR_fcntl: i64 = 72;
const LNR_truncate: i64 = 76;
const LNR_ftruncate: i64 = 77;
const LNR_getdents: i64 = 78;
const LNR_getcwd: i64 = 79;
const LNR_chdir: i64 = 80;
const LNR_fchdir: i64 = 81;
const LNR_rename: i64 = 82;
const LNR_mkdir: i64 = 83;
const LNR_rmdir: i64 = 84;
const LNR_link: i64 = 86;
const LNR_unlink: i64 = 87;
const LNR_symlink: i64 = 88;
const LNR_readlink: i64 = 89;
const LNR_chmod: i64 = 90;
const LNR_fchmod: i64 = 91;
const LNR_umask: i64 = 95;
const LNR_getuid: i64 = 102;
const LNR_getgid: i64 = 104;
const LNR_setuid: i64 = 105;
const LNR_setgid: i64 = 106;
const LNR_geteuid: i64 = 107;
const LNR_getegid: i64 = 108;
const LNR_setpgid: i64 = 109;
const LNR_getppid: i64 = 110;
const LNR_getpgrp: i64 = 111;
const LNR_setsid: i64 = 112;
const LNR_getpgid: i64 = 121;
const LNR_getsid: i64 = 124;
const LNR_rt_sigpending: i64 = 127;
const LNR_rt_sigtimedwait: i64 = 128;
const LNR_rt_sigsuspend: i64 = 130;
const LNR_sigaltstack: i64 = 131;
const LNR_pause: i64 = 34;
const LNR_socket: i64 = 41;
const LNR_connect: i64 = 42;
const LNR_accept: i64 = 43;
const LNR_sendto: i64 = 44;
const LNR_recvfrom: i64 = 45;
const LNR_sendmsg: i64 = 46;
const LNR_recvmsg: i64 = 47;
const LNR_shutdown: i64 = 48;
const LNR_bind: i64 = 49;
const LNR_listen: i64 = 50;
const LNR_getsockname: i64 = 51;
const LNR_getpeername: i64 = 52;
const LNR_socketpair: i64 = 53;
const LNR_setsockopt: i64 = 54;
const LNR_getsockopt: i64 = 55;
const LNR_gettid: i64 = 186;
const LNR_tkill: i64 = 200;
const LNR_futex: i64 = 202;
const LNR_set_tid_address: i64 = 218;
const LNR_clock_gettime: i64 = 228;
const LNR_clock_getres: i64 = 229;
const LNR_clock_nanosleep: i64 = 230;
const LNR_exit_group: i64 = 231;
const LNR_tgkill: i64 = 234;
const LNR_openat: i64 = 257;
const LNR_mkdirat: i64 = 258;
const LNR_newfstatat: i64 = 262;
const LNR_unlinkat: i64 = 263;
const LNR_renameat: i64 = 264;
const LNR_readlinkat: i64 = 267;
const LNR_ppoll: i64 = 271;
const LNR_set_robust_list: i64 = 273;
const LNR_get_robust_list: i64 = 274;
const LNR_arch_prctl: i64 = 158;
const LNR_faccessat: i64 = 269;
const LNR_getrandom: i64 = 318;
const LNR_faccessat2: i64 = 439;

// === dispatcher ============================================================

/// Main entry point called from musl's `__syscallN` stubs.
///
/// Translates Linux syscall numbers to Strat9 native syscall numbers,
/// performs any necessary argument conversions, and returns the result
/// as a raw i64 (positive = success, negative = -errno).
///
/// # Safety
/// Called from musl C code. All pointer arguments are passed through
/// unchanged.  The raw* helpers internally handle the unsafe syscall boundary.
#[no_mangle]
pub unsafe extern "C" fn strat9_syscall_dispatcher(
    n: i64,
    a1: i64,
    a2: i64,
    a3: i64,
    a4: i64,
    a5: i64,
    a6: i64,
) -> i64 {
    let a1u = a1 as usize;
    let a2u = a2 as usize;
    let a3u = a3 as usize;
    let a4u = a4 as usize;
    let a5u = a5 as usize;
    let a6u = a6 as usize;

    // SAFETY: the raw* helpers internally contain their own `unsafe {}`
    // blocks around the actual `syscall` instruction.  This function is
    // itself declared `unsafe` because it is called from musl C code.
    match n {
        LNR_read => raw3(SYS_READ, a1u, a2u, a3u),
        LNR_write => raw3(SYS_WRITE, a1u, a2u, a3u),
        LNR_open => {
            // Linux open(path, flags, mode) → Strat9 open(path, flags, mode)
            // Convert POSIX O_* flags to Strat9 OpenFlags
            let sf = posix_oflags_to_strat9(a2 as u32);
            raw3(SYS_OPEN, a1u, sf.bits() as usize, a3u)
        }
        LNR_close => raw1(SYS_CLOSE, a1u),
        LNR_lseek => raw3(SYS_LSEEK, a1u, a2u, a3u),
        LNR_pread64 => raw4(SYS_PREAD, a1u, a2u, a3u, a4u),
        LNR_pwrite64 => raw4(SYS_PWRITE, a1u, a2u, a3u, a4u),
        LNR_fstat => raw2(SYS_FSTAT, a1u, a2u),
        LNR_stat => raw2(SYS_STAT, a1u, a2u),
        LNR_lstat => raw2(SYS_STAT, a1u, a2u), // no symlinks in Strat9
        LNR_access => raw3(SYS_ACCESS, a1u, a2u, a3u),
        LNR_pipe => raw1(SYS_PIPE, a1u),
        LNR_dup => raw1(SYS_DUP, a1u),
        LNR_dup2 => raw2(SYS_DUP2, a1u, a2u),
        LNR_ioctl => raw3(SYS_IOCTL, a1u, a2u, a3u),
        LNR_fcntl => raw3(SYS_FCNTL, a1u, a2u, a3u),
        LNR_truncate => raw2(SYS_TRUNCATE, a1u, a2u),
        LNR_ftruncate => raw2(SYS_FTRUNCATE, a1u, a2u),
        LNR_getdents => raw3(SYS_GETDENTS, a1u, a2u, a3u),
        LNR_poll => raw3(SYS_POLL, a1u, a2u, a3u),
        LNR_ppoll => raw5(SYS_PPOLL, a1u, a2u, a3u, a4u, a5u),

        // === *at() syscalls ================================================
        LNR_openat => {
            let sf = posix_oflags_to_strat9(a3 as u32);
            raw4(SYS_OPENAT, a1u, a2u, sf.bits() as usize, a4u)
        }
        LNR_mkdirat => raw3(SYS_MKDIRAT, a1u, a2u, a3u),
        LNR_newfstatat => raw4(SYS_FSTATAT, a1u, a2u, a3u, a4u),
        LNR_unlinkat => raw3(SYS_UNLINKAT, a1u, a2u, a3u),
        LNR_renameat => raw4(SYS_RENAMEAT, a1u, a2u, a3u, a4u),
        LNR_readlinkat => raw4(SYS_READLINKAT, a1u, a2u, a3u, a4u),
        LNR_faccessat => raw5(SYS_FACCESSAT, a1u, a2u, a3u, a4u, 0),
        LNR_faccessat2 => raw5(SYS_FACCESSAT, a1u, a2u, a3u, a4u, a5u),

        // === Directory ops ================================================
        LNR_getcwd => raw2(SYS_GETCWD, a1u, a2u),
        LNR_chdir => raw1(SYS_CHDIR, a1u),
        LNR_fchdir => raw1(SYS_FCHDIR, a1u),
        LNR_rename => raw2(SYS_RENAME, a1u, a2u),
        LNR_mkdir => raw2(SYS_MKDIR, a1u, a2u),
        LNR_rmdir => raw1(SYS_RMDIR, a1u),
        LNR_link => raw2(SYS_LINK, a1u, a2u),
        LNR_unlink => raw1(SYS_UNLINK, a1u),
        LNR_symlink => raw2(SYS_SYMLINK, a1u, a2u),
        LNR_readlink => raw3(SYS_READLINK, a1u, a2u, a3u),
        LNR_chmod => raw2(SYS_CHMOD, a1u, a2u),
        LNR_fchmod => raw2(SYS_FCHMOD, a1u, a2u),
        LNR_umask => raw1(SYS_UMASK, a1u),

        // === Memory management ================================================
        LNR_mmap => raw6(
            SYS_MMAP, a1u, a2u, a3u, /* prot */
            a4u, /* flags */
            a5u, /* fd */
            a6u, /* offset */
        ),
        LNR_munmap => raw2(SYS_MUNMAP, a1u, a2u),
        LNR_mprotect => raw3(SYS_MPROTECT, a1u, a2u, a3u),
        LNR_brk => raw1(SYS_BRK, a1u),
        LNR_mremap => raw4(SYS_MREMAP, a1u, a2u, a3u, a4u),

        // === Process / thread ================================================
        LNR_exit => {
            raw1(SYS_PROC_EXIT, a1u);
            loop {}
        }
        LNR_exit_group => {
            raw1(SYS_EXIT_GROUP, a1u);
            loop {}
        }
        LNR_sched_yield => raw0(SYS_PROC_YIELD),
        LNR_getpid => raw0(SYS_GETPID),
        LNR_getppid => raw0(SYS_GETPPID),
        LNR_gettid => raw0(SYS_GETTID),
        LNR_getuid => raw0(SYS_GETUID),
        LNR_geteuid => raw0(SYS_GETEUID),
        LNR_getgid => raw0(SYS_GETGID),
        LNR_getegid => raw0(SYS_GETEGID),
        LNR_setuid => raw1(SYS_SETUID, a1u),
        LNR_setgid => raw1(SYS_SETGID, a1u),
        LNR_setpgid => raw2(SYS_SETPGID, a1u, a2u),
        LNR_getpgid => raw1(SYS_GETPGID, a1u),
        LNR_getpgrp => raw0(SYS_GETPGRP),
        LNR_setsid => raw0(SYS_SETSID),
        LNR_getsid => raw1(SYS_GETSID, a1u),
        LNR_fork => raw0(SYS_PROC_FORK),
        LNR_execve => raw3(SYS_PROC_EXECVE, a1u, a2u, a3u),
        LNR_wait4 => raw4(SYS_PROC_WAITPID, a1u, a2u, a3u, a4u),
        LNR_uname => raw1(SYS_UNAME, a1u),
        LNR_pause => raw1(SYS_SIGSUSPEND, 0), // pause() ≈ sigsuspend(NULL)
        LNR_kill => raw2(SYS_KILL, a1u, a2u),

        // === Threading =====================================================
        LNR_clone => {
            // Linux clone(flags, stack, ptid, tls, ctid) → Strat9 fork/thread_create
            // musl uses clone for both fork() and pthread_create() on x86_64.
            //
            // Linux x86_64 raw clone ABI (via musl __clone wrapper):
            //   rdi=flags, rsi=stack, rdx=ptid, r10=ctid, r8=tls, r9=func
            //   Child stack: arg stored at [stack] by musl's __clone asm.
            //
            // Strat9 SYS_THREAD_CREATE(entry, stack, arg, flags, tls):
            //   entry → func (from r9), stack → child stack, arg → read from [stack]
            //   flags → 0 (Strat9 ignores Linux clone flags), tls → from r8
            let flags = a1u;
            if (flags & CLONE_THREAD) != 0 {
                // Read arg from child stack (stored by musl's __clone: mov %rcx,(%rsi))
                let child_stack = a2u;
                let arg = unsafe { *(child_stack as *const usize) };
                // func = a6 (r9 preserved by syscall), tls = a5 (r8)
                raw5(SYS_THREAD_CREATE, a6u, child_stack, arg, 0, a5u)
            } else {
                // Fork: clone with no CLONE_THREAD means process creation.
                // Linux clone(flags, 0, ptid, tls, ctid) → Strat9 fork()
                raw0(SYS_PROC_FORK)
            }
        }
        LNR_tkill => raw2(SYS_TGKILL, a1u, a2u),
        LNR_tgkill => raw3(SYS_TGKILL, a1u, a2u, a3u),

        // === Signals =======================================================
        LNR_rt_sigaction => raw4(SYS_SIGACTION, a1u, a2u, a3u, a4u),
        LNR_rt_sigprocmask => raw4(SYS_SIGPROCMASK, a1u, a2u, a3u, a4u),
        LNR_rt_sigreturn => raw0(SYS_RT_SIGRETURN),
        LNR_rt_sigpending => raw2(SYS_SIGPENDING, a1u, a2u),
        LNR_rt_sigtimedwait => raw4(SYS_SIGTIMEDWAIT, a1u, a2u, a3u, a4u),
        LNR_rt_sigsuspend => raw2(SYS_SIGSUSPEND, a1u, a2u),
        LNR_sigaltstack => raw2(SYS_SIGALTSTACK, a1u, a2u),

        // === Time ==========================================================
        LNR_nanosleep => raw2(SYS_NANOSLEEP, a1u, a2u),
        LNR_clock_gettime => raw2(SYS_CLOCK_GETTIME, a1u, a2u),
        LNR_clock_getres => {
            // clock_getres is almost never used; stub with success
            0
        }
        LNR_clock_nanosleep => raw4(SYS_CLOCK_NANOSLEEP, a1u, a2u, a3u, a4u),
        LNR_getitimer => raw2(SYS_GETITIMER, a1u, a2u),
        LNR_setitimer => raw3(SYS_SETITIMER, a1u, a2u, a3u),

        // === Futex ==========================================================
        LNR_futex => {
            // Linux futex(uaddr, futex_op, val, timeout, uaddr2, val3)
            let op = a2u & !FUTEX_PRIVATE_FLAG; // strip PRIVATE flag
            match op {
                FUTEX_WAIT => raw3(SYS_FUTEX_WAIT, a1u, a3u, a4u),
                FUTEX_WAKE => raw2(SYS_FUTEX_WAKE, a1u, a3u),
                FUTEX_REQUEUE => raw4(SYS_FUTEX_REQUEUE, a1u, a3u, a5u, a4u),
                FUTEX_CMP_REQUEUE => raw5(SYS_FUTEX_CMP_REQUEUE, a1u, a3u, a5u, a6u, a4u),
                _ => {
                    // Unknown futex op
                    -38 // ENOSYS
                }
            }
        }

        // === Networking (Strat9 uses Plan 9-style scheme networking) ===
        //
        // When strate-net mounts a Plan 9 /net/tcp scheme, the mapping is:
        //   LNR_socket   → open("/net/tcp/clone", O_RDWR), read "N", open("/net/tcp/N/data")
        //   LNR_connect  → write "connect ip!port" to /net/tcp/N/ctl
        //   LNR_bind     → write "bind ip!port" to /net/tcp/N/ctl
        //   LNR_listen   → implicit in Plan 9 /net/tcp/N
        //   LNR_accept   → open("/net/tcp/N/listen") or read from /net/tcp/N/data
        //   LNR_sendto   → write to /net/tcp/N/data
        //   LNR_recvfrom → read from /net/tcp/N/data
        //   LNR_setsockopt / LNR_getsockopt → no-ops or ctl writes
        //
        // Until strate-net provides the Plan 9 scheme, return ENOSYS.
        // The current /dev/net/ scheme provides raw packet I/O only.
        LNR_socket | LNR_connect | LNR_accept | LNR_sendto | LNR_recvfrom | LNR_sendmsg
        | LNR_recvmsg | LNR_shutdown | LNR_bind | LNR_listen | LNR_getsockname
        | LNR_getpeername | LNR_socketpair | LNR_setsockopt | LNR_getsockopt => {
            -38 // ENOSYS
        }

        // === Linux-specific thread init (critical for musl) ===
        LNR_set_tid_address => raw1(SYS_SET_TID_ADDRESS, a1u),
        LNR_set_robust_list => raw2(SYS_SET_ROBUST_LIST, a1u, a2u),
        LNR_get_robust_list => raw3(SYS_GET_ROBUST_LIST, a1u, a2u, a3u),
        LNR_arch_prctl => {
            match a1u {
                ARCH_SET_FS => raw2(SYS_ARCH_PRCTL, a1u, a2u),
                ARCH_GET_FS => raw2(SYS_ARCH_PRCTL, a1u, a2u),
                _ => -22, // EINVAL
            }
        }

        // === Random ==========================================================
        LNR_getrandom => raw3(SYS_GETRANDOM, a1u, a2u, a3u),

        // === Unknown / unimplemented ========================================
        _ => -38, // ENOSYS
    }
}

// panic_handler is provided by the binary crate (e.g. strate-net).
// musl-compat is a library; it must not define its own #[panic_handler].
