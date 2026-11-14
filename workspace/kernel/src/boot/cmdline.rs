/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! Boot command line snapshot.
//!
//! The bootloader-provided command line lives in boot memory that is not
//! guaranteed to remain mapped once the allocator takes over. Copy it once
//! during `kmain` so `SYS_GETCMDLINE` can serve it later.

use crate::{memory::UserSliceWrite, sync::SpinLock, syscall::error::SyscallError};

/// Maximum number of command line bytes retained by the kernel.
pub const BOOT_CMDLINE_CAPACITY: usize = 2048;

struct BootCmdline {
    buf: [u8; BOOT_CMDLINE_CAPACITY],
    len: usize,
}

impl BootCmdline {
    const fn new() -> Self {
        Self {
            buf: [0u8; BOOT_CMDLINE_CAPACITY],
            len: 0,
        }
    }
}

static BOOT_CMDLINE: SpinLock<BootCmdline> = SpinLock::new(BootCmdline::new());

/// Store the boot command line, truncating to [`BOOT_CMDLINE_CAPACITY`].
pub fn set(bytes: &[u8]) {
    let mut cmdline = BOOT_CMDLINE.lock();
    let len = core::cmp::min(bytes.len(), BOOT_CMDLINE_CAPACITY);
    cmdline.buf[..len].copy_from_slice(&bytes[..len]);
    cmdline.len = len;
}

/// Copy the command line to a user buffer.
///
/// Returns the full command line length (like `snprintf`) and copies
/// `min(len, buf_len)` bytes. The copied bytes are not NUL-terminated.
pub fn copy_to_user(buf_ptr: u64, buf_len: u64) -> Result<usize, SyscallError> {
    let cmdline = BOOT_CMDLINE.lock();
    let total = cmdline.len;
    let n = core::cmp::min(total, buf_len as usize);
    if n > 0 {
        let user = UserSliceWrite::new(buf_ptr, n)?;
        user.copy_from(&cmdline.buf[..n]);
    }
    Ok(total)
}

/// `SYS_GETCMDLINE` handler.
pub fn sys_getcmdline(buf_ptr: u64, buf_len: u64) -> Result<u64, SyscallError> {
    copy_to_user(buf_ptr, buf_len).map(|len| len as u64)
}
