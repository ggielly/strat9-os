//! Syscall wrappers for Strat9-OS kernel ABI.
//!
//! Domain-specific wrappers built on top of `strat9-syscall`.

pub use strat9_syscall::error::{self, Error};
pub use strat9_syscall::number;

pub use strat9_syscall::{call, syscall1, syscall2, syscall3, syscall4};

pub type Result<T> = error::Result<T>;

/// Read sectors from a volume into a buffer.
pub fn volume_read(handle: u64, sector: u64, buf: &mut [u8], sector_count: u64) -> Result<usize> {
    unsafe {
        syscall4(
            number::SYS_VOLUME_READ,
            handle as usize,
            sector as usize,
            buf.as_mut_ptr() as usize,
            sector_count as usize,
        )
    }
}

/// Write sectors from a buffer into a volume.
pub fn volume_write(handle: u64, sector: u64, buf: &[u8], sector_count: u64) -> Result<usize> {
    unsafe {
        syscall4(
            number::SYS_VOLUME_WRITE,
            handle as usize,
            sector as usize,
            buf.as_ptr() as usize,
            sector_count as usize,
        )
    }
}

/// Query a volume's sector count.
pub fn volume_info(handle: u64) -> Result<u64> {
    unsafe { syscall1(number::SYS_VOLUME_INFO, handle as usize).map(|v| v as u64) }
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
