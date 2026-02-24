//! Syscall wrappers for Strat9-OS kernel ABI.
//!
//! Domain-specific wrappers built on top of `strat9-syscall`.

pub use strat9_syscall::error::{self, Error};
pub use strat9_syscall::number;
pub use strat9_syscall::{call, syscall0, syscall1, syscall2, syscall3};

pub type Result<T> = error::Result<T>;

/// Receive a network packet.
pub fn net_recv(buf: &mut [u8]) -> Result<usize> {
    unsafe { syscall2(number::SYS_NET_RECV, buf.as_mut_ptr() as usize, buf.len()) }
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

/// Time specification structure (matches kernel timespec).
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

/// Debug log to kernel serial.
pub fn debug_log(msg: &str) {
    unsafe {
        let _ = syscall2(number::SYS_DEBUG_LOG, msg.as_ptr() as usize, msg.len());
    }
}

/// Exit current process.
pub fn exit(code: usize) -> ! {
    call::exit(code)
}
