//! Domain-specific syscall wrappers for the network strate.
use strat9_syscall::syscall1;

pub use strat9_syscall::{
    call,
    data::TimeSpec,
    error::{self, Error},
    number, syscall2,
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
    let mut ts = TimeSpec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    call::clock_gettime(1 /* CLOCK_MONOTONIC */, &mut ts)?;
    Ok((ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64))
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
/// Register this task as the strate-net networking silo.
/// Called once during startup so the NIC IRQ handler can wake us.
pub fn net_register() -> Result<()> {
    unsafe { syscall1(strat9_abi::syscall::SYS_NET_REGISTER, 0)? };
    Ok(())
}

pub fn debug_log(msg: &str) {
    let _ = call::debug_log(msg.as_bytes());
}

/// Implements exit.
pub fn exit(code: usize) -> ! {
    call::exit(code)
}
