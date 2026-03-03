//! Domain-specific syscall wrappers for the network strate.

pub use strat9_syscall::{
    call,
    data::TimeSpec,
    error::{self, Error},
    number, syscall0, syscall2,
};

pub type Result<T> = error::Result<T>;

/// Implements net recv.
pub fn net_recv(buf: &mut [u8]) -> Result<usize> {
    call::net_recv(buf)
}

/// Implements net send.
pub fn net_send(buf: &[u8]) -> Result<usize> {
    call::net_send(buf)
}

/// Implements net info.
pub fn net_info(info_type: u64, buf: &mut [u8]) -> Result<usize> {
    call::net_info(info_type as usize, buf.as_mut_ptr() as usize)
}

/// Implements clock gettime ns.
pub fn clock_gettime_ns() -> Result<u64> {
    unsafe { syscall0(number::SYS_CLOCK_GETTIME).map(|v| v as u64) }
}

/// Implements nanosleep.
pub fn nanosleep(req: &TimeSpec) -> Result<()> {
    unsafe {
        syscall2(number::SYS_NANOSLEEP, req as *const TimeSpec as usize, 0)?;
        Ok(())
    }
}

/// Implements proc yield.
pub fn proc_yield() -> Result<()> {
    call::sched_yield()?;
    Ok(())
}

/// Implements ipc try recv.
pub fn ipc_try_recv(port: u64, msg: &mut crate::IpcMessage) -> Result<()> {
    call::ipc_try_recv(port as usize, msg)?;
    Ok(())
}

/// Implements debug log.
pub fn debug_log(msg: &str) {
    let _ = call::debug_log(msg.as_bytes());
}

/// Implements exit.
pub fn exit(code: usize) -> ! {
    call::exit(code)
}
