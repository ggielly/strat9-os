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
        let req = alloc::format!("GET / HTTP/1.0
Host: {}

", ip);
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
    shell_println!("
Connection closed ({} bytes received)", total);
    let _ = vfs::close(fd);
    Ok(())
}
