//! Syscall wrappers for Strat9-OS kernel ABI.
//!
//! These use the correct syscall numbers for Strat9-OS.

/// Receive a network packet.
pub fn net_recv(buf: &mut [u8]) -> Result<usize> {
    unsafe { syscall2(number::SYS_NET_RECV, buf.as_mut_ptr() as usize, buf.len()) }
}

/// Time specification structure (matches kernel timespec)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TimeSpec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// Get current monotonic time in nanoseconds since boot.
pub fn clock_gettime_ns() -> Result<u64> {
    unsafe { syscall0(number::SYS_CLOCK_GETTIME).map(|v| v as u64) }
}

/// Sleep for a specified duration.
pub fn nanosleep(req: &TimeSpec) -> Result<()> {
    unsafe {
        syscall2(number::SYS_NANOSLEEP, req as *const TimeSpec as usize, 0)?;
        Ok(())
    }
}

/// Yield the current process.
pub fn proc_yield() -> Result<()> {
    unsafe {
        syscall0(number::SYS_PROC_YIELD)?;
        Ok(())
    }
}

/// Try to receive an IPC message without blocking.
pub fn ipc_try_recv(port: u64, msg: &mut crate::IpcMessage) -> Result<()> {
    unsafe {
        syscall2(
            number::SYS_IPC_TRY_RECV,
            port as usize,
            msg as *mut crate::IpcMessage as usize,
        )?;
        Ok(())
    }
}

/// Send a network packet.
pub fn net_send(buf: &[u8]) -> Result<usize> {
    unsafe { syscall2(number::SYS_NET_SEND, buf.as_ptr() as usize, buf.len()) }
}

/// Get network device information.
pub fn net_info(info_type: u64, buf: &mut [u8]) -> Result<usize> {
    unsafe {
        syscall2(
            number::SYS_NET_INFO,
            info_type as usize,
            buf.as_mut_ptr() as usize,
        )
    }
}

/// Syscall numbers (Strat9-OS ABI)
pub mod number {
    pub const SYS_IPC_CREATE_PORT: usize = 200;
    pub const SYS_IPC_SEND: usize = 201;
    pub const SYS_IPC_RECV: usize = 202;
    pub const SYS_IPC_TRY_RECV: usize = 207;
    pub const SYS_IPC_REPLY: usize = 204;
    pub const SYS_IPC_BIND_PORT: usize = 205;
    pub const SYS_PROC_EXIT: usize = 300;
    pub const SYS_PROC_YIELD: usize = 301;
    pub const SYS_OPEN: usize = 403;
    pub const SYS_READ: usize = 405;
    pub const SYS_WRITE: usize = 404;
    pub const SYS_CLOSE: usize = 406;
    pub const SYS_NET_RECV: usize = 410;
    pub const SYS_NET_SEND: usize = 411;
    pub const SYS_NET_INFO: usize = 412;
    pub const SYS_CLOCK_GETTIME: usize = 500;
    pub const SYS_NANOSLEEP: usize = 501;
    pub const SYS_DEBUG_LOG: usize = 600;
}

/// Syscall result type
pub type Result<T> = core::result::Result<T, isize>;

/// Raw syscall with 0 arguments
#[inline]
pub unsafe fn syscall0(n: usize) -> Result<usize> {
    let mut ret: usize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") n => ret,
            out("rcx") _,
            out("r11") _,
            options(nostack, preserves_flags)
        );
    }
    if (ret as isize) < 0 {
        Err(ret as isize)
    } else {
        Ok(ret)
    }
}

/// Raw syscall with 1 argument
#[inline]
pub unsafe fn syscall1(n: usize, arg1: usize) -> Result<usize> {
    let mut ret: usize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") n => ret,
            in("rdi") arg1,
            out("rcx") _,
            out("r11") _,
            options(nostack, preserves_flags)
        );
    }
    if (ret as isize) < 0 {
        Err(ret as isize)
    } else {
        Ok(ret)
    }
}

/// Raw syscall with 2 arguments
#[inline]
pub unsafe fn syscall2(n: usize, arg1: usize, arg2: usize) -> Result<usize> {
    let mut ret: usize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") n => ret,
            in("rdi") arg1,
            in("rsi") arg2,
            out("rcx") _,
            out("r11") _,
            options(nostack, preserves_flags)
        );
    }
    if (ret as isize) < 0 {
        Err(ret as isize)
    } else {
        Ok(ret)
    }
}

/// Raw syscall with 3 arguments
#[inline]
pub unsafe fn syscall3(n: usize, arg1: usize, arg2: usize, arg3: usize) -> Result<usize> {
    let mut ret: usize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") n => ret,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            out("rcx") _,
            out("r11") _,
            options(nostack, preserves_flags)
        );
    }
    if (ret as isize) < 0 {
        Err(ret as isize)
    } else {
        Ok(ret)
    }
}

/// Debug log to kernel serial
pub fn debug_log(msg: &str) {
    unsafe {
        let _ = syscall2(number::SYS_DEBUG_LOG, msg.as_ptr() as usize, msg.len());
    }
}

/// Exit current process
pub fn exit(code: usize) -> ! {
    unsafe {
        let _ = syscall1(number::SYS_PROC_EXIT, code);
    }
    loop {
        core::hint::spin_loop();
    }
}
