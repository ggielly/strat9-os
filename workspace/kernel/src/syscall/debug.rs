//! Debug log syscall handler.
//!
//! Provides `SYS_DEBUG_LOG` for userspace-to-kernel diagnostic messages.

use super::error::SyscallError;
use crate::memory::UserSliceRead;
/// SYS_DEBUG_LOG (600): write a debug message to serial and silo output.
///
/// arg1 = buffer pointer, arg2 = buffer length.
pub fn sys_debug_log(buf_ptr: u64, buf_len: u64) -> Result<u64, SyscallError> {
    if buf_len == 0 {
        return Ok(0);
    }

    // Restrict debug logging to admin or console-capable tasks.
    crate::silo::enforce_console_access()?;

    let len = core::cmp::min(buf_len as usize, 4096);

    // Validate the user buffer via UserSlice
    let user_buf = UserSliceRead::new(buf_ptr, len)?;

    // Copy into kernel buffer
    let mut kbuf = [0u8; 4096];
    let copied = user_buf.copy_to(&mut kbuf);

    let msg = core::str::from_utf8(&kbuf[..copied]).unwrap_or("<invalid utf8>");

    // Mirror to serial while debugging userspace/network flows; keep E9 too.
    crate::serial_println!("[user-debug] {}", msg);
    crate::e9_println!("[user-debug] {}", msg);

    // Mirror critical boot/network userspace logs to the serial console so
    // early silo failures are visible without attaching to per-silo output.
    if msg.starts_with("[init]")
        || msg.starts_with("[strate-net]")
        || msg.starts_with("[dhcp-client]")
    {
        crate::serial_print!("{}", msg);
    }

    if let Some(task) = crate::process::current_task_clone() {
        if let Some(silo_id) = crate::silo::task_silo_id(task.id) {
            crate::silo::silo_output_write(silo_id, &kbuf[..copied]);
        }
    }

    Ok(copied as u64)
}
