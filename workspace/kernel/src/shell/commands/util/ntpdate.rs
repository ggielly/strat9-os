use super::*;
use alloc::string::String;

/// NTP time synchronization stub.
///
/// Attempts to query an NTP server via `/net/ntp/<server>`. Currently
/// a stub that reports the kernel's internal clock until UDP support
/// is available in the network strate.
pub fn cmd_ntpdate(args: &[String]) -> Result<(), ShellError> {
    let server = args.first().map(|s| s.as_str()).unwrap_or("pool.ntp.org");
    shell_println!("ntpdate: querying {}...", server);

    let path = alloc::format!("/net/ntp/{}", server);
    match vfs::open(&path, vfs::OpenFlags::READ) {
        Ok(fd) => {
            let mut buf = [0u8; 64];
            let n = vfs::read(fd, &mut buf).unwrap_or(0);
            let _ = vfs::close(fd);
            if n > 0 {
                let s = core::str::from_utf8(&buf[..n]).unwrap_or("(invalid)");
                shell_println!("  server time: {}", s.trim());
            } else {
                shell_println!("  no response");
            }
        }
        Err(_) => {
            // TODO: implement when UDP socket support is available
            let ns = crate::syscall::time::current_time_ns();
            shell_println!("  NTP unavailable (no UDP), showing kernel clock:");
            shell_println!("  {}ns since boot", ns);
        }
    }
    Ok(())
}
