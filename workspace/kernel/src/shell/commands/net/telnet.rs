use super::*;

/// Open a TCP connection and send/receive data interactively.
///
/// Usage: `telnet <ip> <port> [--http]`
///
/// With `--http`, sends an HTTP GET and prints the response.
pub fn cmd_telnet(args: &[String]) -> Result<(), ShellError> {
    if args.len() < 2 {
        shell_println!("Usage: telnet <ip> <port> [--http]");
        return Err(ShellError::InvalidArguments);
    }
    let ip = &args[0];
    let port = &args[1];
    let http_mode = args.get(2).map(|s| s.as_str()) == Some("--http");

    let path = alloc::format!("/net/tcp/connect/{}/{}", ip, port);
    let fd = match vfs::open(&path, OpenFlags::RDWR) {
        Ok(fd) => fd,
        Err(e) => {
            shell_println!("telnet: connect failed: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };

    shell_println!("Connected to {}:{}", ip, port);

    for _ in 0..50 {
        shell_sleep_ms(100);
        if crate::shell::is_interrupted() {
            shell_println!("^C");
            let _ = vfs::close(fd);
            return Ok(());
        }
    }

    if http_mode {
        let req = alloc::format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", ip);
        let _ = vfs::write(fd, req.as_bytes());
    }

    let mut buf = [0u8; 256];
    let mut total = 0usize;
    for _ in 0..100 {
        if crate::shell::is_interrupted() {
            shell_println!("^C");
            break;
        }
        match vfs::read(fd, &mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if let Ok(s) = core::str::from_utf8(&buf[..n]) {
                    crate::shell_print!("{}", s);
                }
                total += n;
            }
            Err(_) => {
                shell_sleep_ms(100);
            }
        }
    }
    shell_println!("\nConnection closed ({} bytes received)", total);
    let _ = vfs::close(fd);
    Ok(())
}
