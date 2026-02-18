use crate::{
    c_str::CStr,
    error::{Errno, Result},
    header::{
        signal::sigevent,
        sys_resource::{rlimit, rusage},
        sys_stat::stat,
        sys_statvfs::statvfs,
        sys_time::timeval,
        sys_utsname::utsname,
        time::{itimerspec, timespec},
    },
    out::Out,
    platform::{
        pal::{Pal, PalSignal},
        types::*,
    },
};
use core::{arch::asm, ptr};

pub mod auxv_defs;

// time conversion constants
const NANOSECONDS_PER_SECOND: usize = 1_000_000_000;
const MILLISECONDS_PER_SECOND: usize = 1_000;
const MICROSECONDS_PER_MILLISECOND: usize = 1_000;

// syscall numbers (time-related)
const SYS_TIME_TICKS: usize = 500;
const SYS_NANOSLEEP: usize = 501;

pub struct Sys;

impl Pal for Sys {
    fn access(path: CStr, _mode: c_int) -> Result<()> {
        let ret = unsafe { syscall3(403, path.as_ptr() as usize, path.to_bytes().len(), 1) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            unsafe {
                let _ = syscall1(406, ret);
            }
            Ok(())
        }
    }

    unsafe fn brk(addr: *mut c_void) -> Result<*mut c_void> {
        static mut BRK_CUR: *mut c_void = ptr::null_mut();
        unsafe {
            if addr.is_null() {
                if BRK_CUR.is_null() {
                    let initial = Self::mmap(ptr::null_mut(), 65536, 0, 0, -1, 0)?;
                    BRK_CUR = initial.add(65536);
                    return Ok(initial);
                }
                return Ok(BRK_CUR);
            }
            Ok(BRK_CUR)
        }
    }

    fn chdir(_path: CStr) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn chmod(_path: CStr, _mode: mode_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn chown(_path: CStr, _owner: uid_t, _group: gid_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn clock_getres(_clk_id: clockid_t, _tp: Option<Out<timespec>>) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn clock_gettime(_clk_id: clockid_t, mut tp: Out<timespec>) -> Result<()> {
        let ns = unsafe { syscall0(SYS_TIME_TICKS) };
        tp.tv_sec = (ns / NANOSECONDS_PER_SECOND) as i64;
        tp.tv_nsec = (ns % NANOSECONDS_PER_SECOND) as i64;
        Ok(())
    }

    unsafe fn clock_settime(_clk_id: clockid_t, _tp: *const timespec) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn close(fildes: c_int) -> Result<()> {
        let ret = unsafe { syscall1(406, fildes as usize) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(())
        }
    }

    fn dup(fildes: c_int) -> Result<c_int> {
        let ret = unsafe { syscall1(1, fildes as usize) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(ret as c_int)
        }
    }

    fn dup2(_fildes: c_int, _fildes2: c_int) -> Result<c_int> {
        Err(Errno(crate::error::ENOSYS))
    }

    unsafe fn execve(
        _path: CStr,
        _argv: *const *mut c_char,
        _envp: *const *mut c_char,
    ) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    unsafe fn fexecve(
        _fildes: c_int,
        _argv: *const *mut c_char,
        _envp: *const *mut c_char,
    ) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn exit(status: c_int) -> ! {
        unsafe {
            let _ = syscall1(300, status as usize);
        }
        loop {}
    }

    unsafe fn exit_thread(_stack_base: *mut (), _stack_size: usize) -> ! {
        loop {}
    }

    fn fchdir(_fildes: c_int) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn fchmod(_fildes: c_int, _mode: mode_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn fchmodat(_dirfd: c_int, _path: Option<CStr>, _mode: mode_t, _flags: c_int) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn fchown(_fildes: c_int, _owner: uid_t, _group: gid_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn fdatasync(_fildes: c_int) -> Result<()> {
        Ok(())
    }

    fn flock(_fd: c_int, _operation: c_int) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn fstat(_fildes: c_int, _buf: Out<stat>) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn fstatat(_fildes: c_int, _path: Option<CStr>, _buf: Out<stat>, _flags: c_int) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn fstatvfs(_fildes: c_int, _buf: Out<statvfs>) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn fcntl(fildes: c_int, cmd: c_int, arg: c_ulonglong) -> Result<c_int> {
        let ret = unsafe { syscall3(407, fildes as usize, cmd as usize, arg as usize) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(ret as c_int)
        }
    }

    unsafe fn fork() -> Result<pid_t> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn fpath(_fildes: c_int, _out: &mut [u8]) -> Result<usize> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn fsync(_fildes: c_int) -> Result<()> {
        Ok(())
    }

    fn ftruncate(_fildes: c_int, _length: off_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    unsafe fn futex_wait(addr: *mut u32, val: u32, deadline: Option<&timespec>) -> Result<()> {
        let timeout_ns = if let Some(ts) = deadline {
            let secs = ts.tv_sec.max(0) as u64;
            let nsec = ts.tv_nsec.max(0) as u64;
            secs.saturating_mul(NANOSECONDS_PER_SECOND as u64)
                .saturating_add(nsec)
        } else {
            0
        };
        let ret = unsafe { syscall3(302, addr as usize, val as usize, timeout_ns as usize) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(())
        }
    }

    unsafe fn futex_wake(addr: *mut u32, num: u32) -> Result<u32> {
        let ret = unsafe { syscall2(303, addr as usize, num as usize) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(ret as u32)
        }
    }

    unsafe fn futimens(_fildes: c_int, _times: *const timespec) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    unsafe fn utimens(_path: CStr, _times: *const timespec) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn getcwd(_buf: Out<[u8]>) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn getdents(_fildes: c_int, _buf: &mut [u8], _opaque_offset: u64) -> Result<usize> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn dir_seek(_fildes: c_int, _opaque_offset: u64) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    unsafe fn dent_reclen_offset(_this_dent: &[u8], _offset: usize) -> Option<(u16, u64)> {
        None
    }

    fn getegid() -> gid_t {
        0
    }
    fn geteuid() -> uid_t {
        0
    }
    fn getgid() -> gid_t {
        0
    }
    fn getgroups(_list: Out<[gid_t]>) -> Result<c_int> {
        Ok(0)
    }
    fn getpagesize() -> usize {
        4096
    }
    fn getpgid(_pid: pid_t) -> Result<pid_t> {
        Ok(0)
    }
    fn getpid() -> pid_t {
        1
    }
    fn getppid() -> pid_t {
        0
    }
    fn getpriority(_which: c_int, _who: id_t) -> Result<c_int> {
        Ok(0)
    }
    fn getrandom(_buf: &mut [u8], _flags: c_uint) -> Result<usize> {
        Ok(0)
    }
    fn getresgid(
        _rgid: Option<Out<gid_t>>,
        _egid: Option<Out<gid_t>>,
        _sgid: Option<Out<gid_t>>,
    ) -> Result<()> {
        Ok(())
    }
    fn getresuid(
        _ruid: Option<Out<uid_t>>,
        _euid: Option<Out<uid_t>>,
        _suid: Option<Out<uid_t>>,
    ) -> Result<()> {
        Ok(())
    }
    fn getrlimit(_resource: c_int, _rlim: Out<rlimit>) -> Result<()> {
        Ok(())
    }
    unsafe fn setrlimit(_resource: c_int, _rlim: *const rlimit) -> Result<()> {
        Ok(())
    }
    fn getrusage(_who: c_int, _r_usage: Out<rusage>) -> Result<()> {
        Ok(())
    }
    fn getsid(_pid: pid_t) -> Result<pid_t> {
        Ok(0)
    }
    fn gettid() -> pid_t {
        1
    }
    fn gettimeofday(
        mut tp: Out<timeval>,
        _tzp: Option<Out<crate::header::sys_time::timezone>>,
    ) -> Result<()> {
        let ticks = unsafe { syscall0(SYS_TIME_TICKS) };
        tp.tv_sec = (ticks / MILLISECONDS_PER_SECOND) as i64;
        tp.tv_usec = ((ticks % MILLISECONDS_PER_SECOND) * MICROSECONDS_PER_MILLISECOND) as i64;
        Ok(())
    }
    fn getuid() -> uid_t {
        0
    }

    fn lchown(_path: CStr, _owner: uid_t, _group: gid_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn link(_path1: CStr, _path2: CStr) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn lseek(fildes: c_int, offset: off_t, _whence: c_int) -> Result<off_t> {
        Ok(offset)
    }

    fn mkdirat(_dirfd: c_int, _path: CStr, _mode: mode_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn mkdir(_path: CStr, _mode: mode_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn mkfifoat(_dir_fd: c_int, _path: CStr, _mode: mode_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn mkfifo(_path: CStr, _mode: mode_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn mknodat(_fildes: c_int, _path: CStr, _mode: mode_t, _dev: dev_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn mknod(_path: CStr, _mode: mode_t, _dev: dev_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    unsafe fn mlock(_addr: *const c_void, _len: usize) -> Result<()> {
        Ok(())
    }

    unsafe fn mlockall(_flags: c_int) -> Result<()> {
        Ok(())
    }

    unsafe fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: c_int,
        _flags: c_int,
        _fildes: c_int,
        _off: off_t,
    ) -> Result<*mut c_void> {
        let ret = unsafe { syscall3(100, addr as usize, len, prot as usize) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(ret as *mut c_void)
        }
    }

    unsafe fn mremap(
        _addr: *mut c_void,
        _len: usize,
        _new_len: usize,
        _flags: c_int,
        _args: *mut c_void,
    ) -> Result<*mut c_void> {
        Err(Errno(crate::error::ENOSYS))
    }

    unsafe fn mprotect(_addr: *mut c_void, _len: usize, _prot: c_int) -> Result<()> {
        Ok(())
    }

    unsafe fn msync(_addr: *mut c_void, _len: usize, _flags: c_int) -> Result<()> {
        Ok(())
    }

    unsafe fn munlock(_addr: *const c_void, _len: usize) -> Result<()> {
        Ok(())
    }

    unsafe fn madvise(_addr: *mut c_void, _len: usize, _flags: c_int) -> Result<()> {
        Ok(())
    }

    unsafe fn munlockall() -> Result<()> {
        Ok(())
    }

    unsafe fn munmap(addr: *mut c_void, len: usize) -> Result<()> {
        let ret = unsafe { syscall2(101, addr as usize, len) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(())
        }
    }

    unsafe fn nanosleep(rqtp: *const timespec, rmtp: *mut timespec) -> Result<()> {
        let ret = unsafe { syscall2(SYS_NANOSLEEP, rqtp as usize, rmtp as usize) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(())
        }
    }

    fn open(path: CStr, oflag: c_int, _mode: mode_t) -> Result<c_int> {
        let ret = unsafe {
            syscall3(
                403,
                path.as_ptr() as usize,
                path.to_bytes().len(),
                oflag as usize,
            )
        };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(ret as c_int)
        }
    }

    fn pipe2(_fildes: Out<[c_int; 2]>, _flags: c_int) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn posix_fallocate(_fd: c_int, _offset: u64, _length: core::num::NonZeroU64) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn posix_getdents(_fildes: c_int, _buf: &mut [u8]) -> Result<usize> {
        Err(Errno(crate::error::ENOSYS))
    }

    unsafe fn rlct_clone(
        _stack: *mut usize,
        _os_specific: &mut crate::ld_so::tcb::OsSpecific,
    ) -> Result<crate::pthread::OsTid, Errno> {
        Err(Errno(crate::error::ENOSYS))
    }

    unsafe fn rlct_kill(_os_tid: crate::pthread::OsTid, _signal: usize) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn current_os_tid() -> crate::pthread::OsTid {
        1
    }

    fn read(fildes: c_int, buf: &mut [u8]) -> Result<usize> {
        let ret = unsafe { syscall3(405, fildes as usize, buf.as_mut_ptr() as usize, buf.len()) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(ret)
        }
    }

    fn pread(_fildes: c_int, _buf: &mut [u8], _offset: off_t) -> Result<usize> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn readlink(_path: CStr, _out: &mut [u8]) -> Result<usize> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn readlinkat(_dirfd: c_int, _path: CStr, _out: &mut [u8]) -> Result<usize> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn rename(_old: CStr, _new: CStr) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn renameat(_old_dir: c_int, _old_path: CStr, _new_dir: c_int, _new_path: CStr) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn renameat2(
        _old_dir: c_int,
        _old_path: CStr,
        _new_dir: c_int,
        _new_path: CStr,
        _flags: c_uint,
    ) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn rmdir(_path: CStr) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn sched_yield() -> Result<()> {
        unsafe {
            let _ = syscall0(301);
        }
        Ok(())
    }

    unsafe fn setgroups(_size: size_t, _list: *const gid_t) -> Result<()> {
        Ok(())
    }

    fn setpgid(_pid: pid_t, _pgid: pid_t) -> Result<()> {
        Ok(())
    }

    fn setpriority(_which: c_int, _who: id_t, _prio: c_int) -> Result<()> {
        Ok(())
    }

    fn setresgid(_rgid: gid_t, _egid: gid_t, _sgid: gid_t) -> Result<()> {
        Ok(())
    }

    fn setresuid(_ruid: uid_t, _euid: uid_t, _suid: uid_t) -> Result<()> {
        Ok(())
    }

    fn setsid() -> Result<c_int> {
        Ok(0)
    }

    fn symlink(_path1: CStr, _path2: CStr) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn sync() -> Result<()> {
        Ok(())
    }

    fn timer_create(_clock_id: clockid_t, _evp: &sigevent, _timerid: Out<timer_t>) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn timer_delete(_timerid: timer_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn timer_gettime(_timerid: timer_t, _value: Out<itimerspec>) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn timer_settime(
        _timerid: timer_t,
        _flags: c_int,
        _value: &itimerspec,
        _ovalue: Option<Out<itimerspec>>,
    ) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn umask(_mask: mode_t) -> mode_t {
        0o022
    }

    fn uname(_utsname: Out<utsname>) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn unlink(_path: CStr) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn waitpid(_pid: pid_t, _stat_loc: Option<Out<c_int>>, _options: c_int) -> Result<pid_t> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn write(fildes: c_int, buf: &[u8]) -> Result<usize> {
        let ret = unsafe { syscall3(404, fildes as usize, buf.as_ptr() as usize, buf.len()) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(ret)
        }
    }

    fn pwrite(_fildes: c_int, _buf: &[u8], _offset: off_t) -> Result<usize> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn verify() -> bool {
        true
    }
}

impl PalSignal for Sys {}

// Low-level syscall wrappers
unsafe fn syscall0(num: usize) -> usize {
    let mut ret;
    unsafe {
        asm!("syscall", inout("rax") num => ret, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}

unsafe fn syscall1(num: usize, arg1: usize) -> usize {
    let mut ret;
    unsafe {
        asm!("syscall", inout("rax") num => ret, in("rdi") arg1, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}

unsafe fn syscall2(num: usize, arg1: usize, arg2: usize) -> usize {
    let mut ret;
    unsafe {
        asm!("syscall", inout("rax") num => ret, in("rdi") arg1, in("rsi") arg2, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}

unsafe fn syscall3(num: usize, arg1: usize, arg2: usize, arg3: usize) -> usize {
    let mut ret;
    unsafe {
        asm!("syscall", inout("rax") num => ret, in("rdi") arg1, in("rsi") arg2, in("rdx") arg3, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}
