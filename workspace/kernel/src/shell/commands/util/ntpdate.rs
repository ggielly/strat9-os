use super::*;
use alloc::string::String;

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
                shell_println!("  unix time: {}", s.trim());
            } else {
                shell_println!("  no response");
                return Err(ShellError::ExecutionFailed);
            }
        }
        Err(_) => {
            shell_println!("  cannot open {}", path);
            return Err(ShellError::ExecutionFailed);
        }
    }
    Ok(())
}
