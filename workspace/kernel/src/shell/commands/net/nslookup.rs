use super::*;

/// Minimal DNS lookup command.
///
/// Reads the configured DNS servers and attempts a resolution via the
/// `/net/dns/resolve/<domain>` scheme path. If the network strate does
/// not yet support it, shows the configured nameservers and a TODO.
pub fn cmd_nslookup(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: nslookup <domain>");
        return Err(ShellError::InvalidArguments);
    }
    let domain = &args[0];

    let dns = match vfs::open("/net/dns", OpenFlags::READ) {
        Ok(fd) => {
            let mut buf = [0u8; 128];
            let n = vfs::read(fd, &mut buf).unwrap_or(0);
            let _ = vfs::close(fd);
            let s = core::str::from_utf8(&buf[..n]).unwrap_or("").trim();
            String::from(s)
        }
        Err(_) => String::from("(not configured)"),
    };
    shell_println!("Server: {}", dns);

    let resolve_path = alloc::format!("/net/dns/resolve/{}", domain);
    match vfs::open(&resolve_path, OpenFlags::READ) {
        Ok(fd) => {
            let mut buf = [0u8; 256];
            let n = vfs::read(fd, &mut buf).unwrap_or(0);
            let _ = vfs::close(fd);
            if n > 0 {
                let result = core::str::from_utf8(&buf[..n]).unwrap_or("(invalid)");
                shell_println!("Name:   {}", domain);
                shell_println!("Address: {}", result.trim());
            } else {
                shell_println!("** cannot resolve {}", domain);
            }
        }
        Err(_) => {
            // TODO: implement raw UDP DNS query when UDP sockets are available
            shell_println!("** DNS resolution not yet available (no UDP socket support)");
            shell_println!("   Configured nameserver(s): {}", dns);
        }
    }
    Ok(())
}
