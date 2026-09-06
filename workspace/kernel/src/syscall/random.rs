//! Random number generation syscalls: getrandom
//!
//! Fills request buffers from the kernel entropy pool, which collects
//! entropy from interrupt noise (keyboard, timer, storage IRQs) and
//! RDRAND.  Falls back to RDRAND + jitter if the pool is not yet
//! seeded during early boot.

use crate::{memory::userslice::UserSliceWrite, syscall::error::SyscallError};

/// GRND_NONBLOCK: return EAGAIN if entropy pool is not yet initialised.
const GRND_NONBLOCK: u32 = 1;
/// GRND_RANDOM: use /dev/random quality (same pool, no distinction in this impl).
const GRND_RANDOM: u32 = 2;
/// Valid flags mask.
const GRND_FLAGS_MASK: u32 = GRND_NONBLOCK | GRND_RANDOM;

/// SYS_GETRANDOM (601): Fill a buffer with random bytes.
///
/// # Arguments
/// * `buf`   - Pointer to the userspace buffer
/// * `len`   - Number of bytes requested
/// * `flags` - GRND_NONBLOCK (1) and/or GRND_RANDOM (2)
///
/// # Returns
/// * Number of bytes written on success
/// * -EAGAIN if GRND_NONBLOCK is set and entropy pool is not yet initialised
/// * -EFAULT if buf pointer is invalid
/// * -EINVAL if len is 0 or flags are invalid
///
/// # POSIX compatibility
/// POSIX signature: `ssize_t getrandom(void *buf, size_t buflen, unsigned int flags)`
pub fn sys_getrandom(buf: u64, len: usize, flags: u32) -> Result<u64, SyscallError> {
    if buf == 0 || len == 0 {
        return Err(SyscallError::InvalidArgument);
    }

    if flags & !GRND_FLAGS_MASK != 0 {
        return Err(SyscallError::InvalidArgument);
    }

    // If GRND_NONBLOCK is set, check whether the pool has enough entropy.
    // If not, return EAGAIN immediately instead of spinning.
    if flags & GRND_NONBLOCK != 0 && !crate::entropy::is_ready() {
        return Err(SyscallError::Again);
    }

    // Bound the maximum read to avoid DoS (256 bytes is reasonable for canary/seed)
    let actual_len = len.min(256);
    let mut tmp = [0u8; 256];

    // Try the entropy pool first (cryptographically sound).
    crate::entropy::fill_random(&mut tmp[..actual_len]);

    let user = UserSliceWrite::new(buf, actual_len)?;
    user.copy_from(&tmp[..actual_len]);
    Ok(actual_len as u64)
}
