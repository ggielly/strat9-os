//! Random number generation syscalls: getrandom
//!
//! Uses the CPU RDRAND instruction when available, with a fallback
//! to a simple jitter-based entropy source for early boot.

use crate::{memory::userslice::UserSliceWrite, syscall::error::SyscallError};

/// SYS_GETRANDOM (601): Fill a buffer with random bytes.
///
/// # Arguments
/// * `buf`   - Pointer to the userspace buffer
/// * `len`   - Number of bytes requested
/// * `flags` - GRND_NONBLOCK (1) or GRND_RANDOM (2) — currently ignored
///
/// # Returns
/// * Number of bytes written on success
/// * -EFAULT if buf pointer is invalid
/// * -EINVAL if len is 0 or flags are invalid
///
/// # POSIX compatibility
/// POSIX signature: `ssize_t getrandom(void *buf, size_t buflen, unsigned int flags)`
pub fn sys_getrandom(buf: u64, len: usize, _flags: u32) -> Result<u64, SyscallError> {
    if buf == 0 || len == 0 {
        return Err(SyscallError::InvalidArgument);
    }

    // Bound the maximum read to avoid DoS (256 bytes is reasonable for canary/seed)
    let actual_len = len.min(256);
    let mut tmp = [0u8; 256];

    for chunk in tmp[..actual_len].chunks_mut(8) {
        match rdrand64() {
            Some(val) => {
                let bytes = val.to_le_bytes();
                let n = chunk.len().min(8);
                chunk.copy_from_slice(&bytes[..n]);
            }
            None => {
                // Fallback: hash-based jitter using tick count and address entropy
                let fallback = jitter_entropy();
                let bytes = fallback.to_le_bytes();
                let n = chunk.len().min(8);
                chunk.copy_from_slice(&bytes[..n]);
            }
        }
    }

    let user = UserSliceWrite::new(buf, actual_len)?;
    user.copy_from(&tmp[..actual_len]);
    Ok(actual_len as u64)
}

/// Attempt to read a 64-bit random value using the RDRAND instruction.
///
/// Returns `Some(val)` on success, or `None` if RDRAND is not available
/// or the hardware retry limit is exceeded.
#[inline]
fn rdrand64() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        let mut val: u64 = 0;
        let mut success: u8;
        // Try up to 10 retries as recommended by Intel SDM
        for _ in 0..10 {
            unsafe {
                core::arch::asm!(   // asm block to execute RDRAND and check carry flag
                    "rdrand {0}",   // Output the random value into `val`
                    "setc {1}",   // Set `success` to 1 if CF=1 (success), or 0 if CF=0 (failure)
                    out(reg) val,
                    out(reg_byte) success,
                    options(nostack, preserves_flags)
                );
            }
            if success != 0 {
                return Some(val);
            }
        }
        None
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

/// Fallback entropy source using system jitter.
///
/// Combines the current tick count, a stack address for ASLR entropy,
/// and a simple xorshift to produce unpredictable bytes. This is NOT
/// cryptographically secure but sufficient for stack canaries and
/// non-security random seeds.
fn jitter_entropy() -> u64 {
    let ticks = crate::process::scheduler::ticks();
    let stack_ptr = core::ptr::addr_of!(ticks) as u64;

    // Mix with a simple xorshift
    let mut state = ticks
        .wrapping_mul(6364136223846793005)
        .wrapping_add(stack_ptr);
    state ^= state >> 21;
    state ^= state << 37;
    state ^= state >> 4;

    state
}
