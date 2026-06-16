//! Network commands (ping, ifconfig)
mod ifconfig;
mod netcmd;
mod nslookup;
mod ping_userspace;
mod telnet;

use crate::{
    shell::ShellError,
    shell_println,
    vfs::{self, OpenFlags},
};
use alloc::string::String;
pub use ifconfig::cmd_ifconfig;
pub use netcmd::cmd_net;
pub use nslookup::cmd_nslookup;
pub use ping_userspace::cmd_ping;
use strat9_abi::ip::{is_ipv4_literal_candidate, parse_ipv4_literal};
pub use telnet::cmd_telnet;

/// Read an ELF binary from a VFS path into a Vec<u8>.
/// Shared helper used by ping and other commands that spawn userspace binaries.
pub(super) fn read_elf(path: &str) -> Result<alloc::vec::Vec<u8>, ShellError> {
    let fd = vfs::open(path, OpenFlags::READ).map_err(|_| {
        shell_println!("{}: not found", path);
        ShellError::ExecutionFailed
    })?;
    let data = vfs::read_all(fd).map_err(|_| {
        let _ = vfs::close(fd);
        shell_println!("{}: read error", path);
        ShellError::ExecutionFailed
    })?;
    let _ = vfs::close(fd);
    Ok(data)
}

/// Spawn a userspace ELF binary from `/initfs/bin/<name>` with the given
/// shell arguments as `argv[1..]`.  Returns immediately after scheduling.
pub(super) fn spawn_elf_with_args(
    bin_path: &str,
    task_name: &'static str,
    args: &[String],
) -> Result<(), ShellError> {
    let data = read_elf(bin_path)?;
    let arg_strs: alloc::vec::Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    match crate::process::elf::load_and_run_elf_with_args(&data, task_name, &arg_strs) {
        Ok(task_id) => {
            shell_println!("{}: started (task={})", task_name, task_id);
            Ok(())
        }
        Err(e) => {
            shell_println!("{}: failed to launch: {}", task_name, e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// Performs the cmd ping spawn operation (launches /initfs/bin/ping with args).
pub(super) fn cmd_ping_spawn_impl(args: &[String]) -> Result<(), ShellError> {
    // Early IPv4 validation — same behaviour as kping
    if let Some(target) = args.first() {
        if is_ipv4_literal_candidate(target) && parse_ipv4_literal(target).is_none() {
            shell_println!("ping: invalid IPv4 address: {}", target);
            return Ok(());
        }
    }
    spawn_elf_with_args("/initfs/bin/ping", "ping", args)
}

/// Busy-wait for approximately `ms` milliseconds, yielding to other tasks.
/// Scheduler ticks are 10ms each.
pub(super) fn shell_sleep_ms(ms: u64) {
    let ticks_to_wait = (ms + 9) / 10; // round up
    let start = crate::process::scheduler::ticks();
    loop {
        crate::process::yield_task();
        if crate::process::scheduler::ticks().wrapping_sub(start) >= ticks_to_wait {
            break;
        }
    }
}

/// Performs the cmd ifconfig operation.
pub(super) fn cmd_ifconfig_impl(args: &[String]) -> Result<(), ShellError> {
    if !args.is_empty() {
        match args[0].as_str() {
            "inet" => {
                if args.len() != 2 {
                    shell_println!("Usage: ifconfig inet <ipv4/prefix>");
                    return Err(ShellError::InvalidArguments);
                }
                let path = alloc::format!("/net/ip/set/{}", args[1]);
                write_path(&path, b"1")?;
                shell_println!("ifconfig: inet set to {}", args[1]);
                return Ok(());
            }
            "gateway" => {
                if args.len() == 2 && args[1].as_str() == "clear" {
                    write_path("/net/route/default/clear", b"1")?;
                    shell_println!("ifconfig: default gateway cleared");
                    return Ok(());
                }
                if args.len() != 2 {
                    shell_println!("Usage: ifconfig gateway <ipv4|clear>");
                    return Err(ShellError::InvalidArguments);
                }
                let path = alloc::format!("/net/route/default/set/{}", args[1]);
                write_path(&path, b"1")?;
                shell_println!("ifconfig: default gateway set to {}", args[1]);
                return Ok(());
            }
            "dns" => {
                if args.len() < 2 || args.len() > 4 {
                    shell_println!("Usage: ifconfig dns <ipv4> [ipv4] [ipv4]");
                    shell_println!("       ifconfig dns clear");
                    return Err(ShellError::InvalidArguments);
                }
                if args.len() == 2 && args[1].as_str() == "clear" {
                    write_path("/net/dns/set/0/0.0.0.0", b"1")?;
                    write_path("/net/dns/set/1/0.0.0.0", b"1")?;
                    write_path("/net/dns/set/2/0.0.0.0", b"1")?;
                    shell_println!("ifconfig: DNS cleared");
                    return Ok(());
                }
                write_path("/net/dns/set/0/0.0.0.0", b"1")?;
                write_path("/net/dns/set/1/0.0.0.0", b"1")?;
                write_path("/net/dns/set/2/0.0.0.0", b"1")?;
                for (idx, ip) in args[1..].iter().enumerate() {
                    let path = alloc::format!("/net/dns/set/{}/{}", idx, ip);
                    write_path(&path, b"1")?;
                }
                shell_println!("ifconfig: DNS updated");
                return Ok(());
            }
            "dhcp" => {
                if args.len() != 2 {
                    shell_println!("Usage: ifconfig dhcp <on|off>");
                    return Err(ShellError::InvalidArguments);
                }
                match args[1].as_str() {
                    "on" => {
                        write_path("/net/dhcp/enable", b"1")?;
                        shell_println!("ifconfig: DHCP enabled");
                        return Ok(());
                    }
                    "off" => {
                        write_path("/net/dhcp/disable", b"1")?;
                        shell_println!("ifconfig: DHCP disabled");
                        return Ok(());
                    }
                    _ => {
                        shell_println!("Usage: ifconfig dhcp <on|off>");
                        return Err(ShellError::InvalidArguments);
                    }
                }
            }
            _ => {
                shell_println!("Usage: ifconfig");
                shell_println!("       ifconfig inet <ipv4/prefix>");
                shell_println!("       ifconfig gateway <ipv4|clear>");
                shell_println!("       ifconfig dns <ipv4> [ipv4] [ipv4]");
                shell_println!("       ifconfig dns clear");
                shell_println!("       ifconfig dhcp <on|off>");
                return Err(ShellError::InvalidArguments);
            }
        }
    }

    let read_file = |path: &str| -> String {
        match vfs::open(path, OpenFlags::READ) {
            Ok(fd) => {
                let mut buf = [0u8; 96];
                let n = vfs::read(fd, &mut buf).unwrap_or(0);
                let _ = vfs::close(fd);
                let s = core::str::from_utf8(&buf[..n]).unwrap_or("").trim();
                String::from(s)
            }
            Err(_) => String::from("(unavailable)"),
        }
    };

    let ip = read_file("/net/ip");
    let ip6 = read_file("/net/ip6");
    let gw = read_file("/net/gateway");
    let gw6 = read_file("/net/ip6/gateway");
    let route = read_file("/net/route");
    let routes = read_file("/net/routes");
    let dns = read_file("/net/dns");
    let dhcp = read_file("/net/dhcp");

    shell_println!("em0:");
    shell_println!("  inet     {}", ip);
    shell_println!("  inet6    {}", ip6);
    shell_println!("  dhcp     {}", dhcp);
    shell_println!("  gateway  {}", gw);
    shell_println!("  gateway6 {}", gw6);
    shell_println!("  route    {}", route);
    shell_println!("  routes   {}", routes);
    shell_println!("  dns      {}", dns);

    Ok(())
}

/// Writes path.
fn write_path(path: &str, data: &[u8]) -> Result<(), ShellError> {
    let fd = vfs::open(path, OpenFlags::WRITE).map_err(|_| ShellError::ExecutionFailed)?;
    let res = vfs::write(fd, data).map(|_| ());
    let _ = vfs::close(fd);
    res.map_err(|_| ShellError::ExecutionFailed)
}

/// Performs the cmd net operation.
pub(super) fn cmd_net_impl(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: net route <show|add|del|default> ...");
        return Err(ShellError::InvalidArguments);
    }

    match args[0].as_str() {
        "route" => {
            if args.len() < 2 {
                shell_println!("Usage: net route <show|add|del|default> ...");
                return Err(ShellError::InvalidArguments);
            }

            match args[1].as_str() {
                "show" => {
                    let routes = match vfs::open("/net/routes", OpenFlags::READ) {
                        Ok(fd) => {
                            let mut buf = [0u8; 256];
                            let n = vfs::read(fd, &mut buf).unwrap_or(0);
                            let _ = vfs::close(fd);
                            String::from(core::str::from_utf8(&buf[..n]).unwrap_or("").trim())
                        }
                        Err(_) => String::from("(unavailable)"),
                    };
                    shell_println!("routes:");
                    shell_println!("{}", routes);
                    Ok(())
                }
                "add" => {
                    if args.len() != 4 {
                        shell_println!("Usage: net route add <cidr> <gateway>");
                        return Err(ShellError::InvalidArguments);
                    }
                    let path = alloc::format!("/net/route/add/{}/{}", args[2], args[3]);
                    write_path(&path, b"1")?;
                    shell_println!("net route add: ok ({} via {})", args[2], args[3]);
                    Ok(())
                }
                "del" => {
                    if args.len() != 3 {
                        shell_println!("Usage: net route del <cidr>");
                        return Err(ShellError::InvalidArguments);
                    }
                    let path = alloc::format!("/net/route/del/{}", args[2]);
                    write_path(&path, b"1")?;
                    shell_println!("net route del: ok ({})", args[2]);
                    Ok(())
                }
                "default" => {
                    if args.len() == 4 && args[2].as_str() == "set" {
                        let path = alloc::format!("/net/route/default/set/{}", args[3]);
                        write_path(&path, b"1")?;
                        shell_println!("net route default: ok (via {})", args[3]);
                        return Ok(());
                    }
                    if args.len() == 3 && args[2].as_str() == "clear" {
                        write_path("/net/route/default/clear", b"1")?;
                        shell_println!("net route default: cleared");
                        return Ok(());
                    }
                    shell_println!("Usage: net route default <set <gateway>|clear>");
                    Err(ShellError::InvalidArguments)
                }
                _ => {
                    shell_println!("Usage: net route <show|add|del|default> ...");
                    Err(ShellError::InvalidArguments)
                }
            }
        }
        _ => {
            shell_println!("Usage: net route <show|add|del|default> ...");
            Err(ShellError::InvalidArguments)
        }
    }
}
