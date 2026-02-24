//! Domain-specific syscall wrappers for the network strate.

pub use strat9_syscall::error::{self, Error};
pub use strat9_syscall::call;
pub use strat9_syscall::data::TimeSpec;
pub use strat9_syscall::{syscall0, syscall2, number};

pub type Result<T> = error::Result<T>;

pub fn net_recv(buf: &mut [u8]) -> Result<usize> {
    call::net_recv(buf)
}

pub fn net_send(buf: &[u8]) -> Result<usize> {
    call::net_send(buf)
}

pub fn net_info(info_type: u64, buf: &mut [u8]) -> Result<usize> {
    call::net_info(info_type as usize, buf.as_mut_ptr() as usize)
}

pub fn clock_gettime_ns() -> Result<u64> {
    unsafe { syscall0(number::SYS_CLOCK_GETTIME).map(|v| v as u64) }
}

pub fn nanosleep(req: &TimeSpec) -> Result<()> {
    unsafe {
        syscall2(number::SYS_NANOSLEEP, req as *const TimeSpec as usize, 0)?;
        Ok(())
    }
}

pub fn proc_yield() -> Result<()> {
    call::sched_yield()?;
    Ok(())
}

pub fn ipc_try_recv(port: u64, msg: &mut crate::IpcMessage) -> Result<()> {
    call::ipc_try_recv(port as usize, msg)?;
    Ok(())
}

pub fn debug_log(msg: &str) {
    let _ = call::debug_log(msg.as_bytes());
}

pub fn exit(code: usize) -> ! {
    call::exit(code)
}
