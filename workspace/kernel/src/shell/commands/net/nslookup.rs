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
            // TODO: optional fallback resolver if /net/resolve is unavailable
            shell_println!("** DNS resolution unavailable in /net scheme");
            shell_println!("   Configured nameserver(s): {}", dns);
        }
    }
    Ok(())
}
