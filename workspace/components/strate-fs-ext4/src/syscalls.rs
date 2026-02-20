//! Syscall wrappers for Strat9-OS kernel ABI.
//!
//! These use the correct syscall numbers for Strat9-OS.

/// Syscall numbers (Strat9-OS ABI)
pub mod number {
    pub const SYS_IPC_CREATE_PORT: usize = 200;
    pub const SYS_IPC_SEND: usize = 201;
    pub const SYS_IPC_RECV: usize = 202;
    pub const SYS_IPC_REPLY: usize = 204;
    pub const SYS_IPC_BIND_PORT: usize = 205;
    pub const SYS_IPC_TRY_RECV: usize = 207;
    pub const SYS_PROC_EXIT: usize = 300;
    pub const SYS_PROC_YIELD: usize = 301;
    pub const SYS_OPEN: usize = 403;
    pub const SYS_READ: usize = 405;
    pub const SYS_WRITE: usize = 404;
    pub const SYS_CLOSE: usize = 406;
    pub const SYS_VOLUME_READ: usize = 420;
    pub const SYS_VOLUME_WRITE: usize = 421;
    pub const SYS_VOLUME_INFO: usize = 422;
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

    // Check if return value is negative (error)
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

/// Raw syscall with 4 arguments
#[inline]
pub unsafe fn syscall4(
    n: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
) -> Result<usize> {
    let mut ret: usize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") n => ret,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            in("r10") arg4,
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
