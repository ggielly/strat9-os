//! Network commands (ping, ifconfig)

use crate::{
    shell::ShellError,
    shell_println,
    vfs::{self, OpenFlags},
};
use alloc::string::String;

/// Busy-wait for approximately `ms` milliseconds, yielding to other tasks.
/// Scheduler ticks are 10ms each.
fn shell_sleep_ms(ms: u64) {
    let ticks_to_wait = (ms + 9) / 10; // round up
    let start = crate::process::scheduler::ticks();
    loop {
        crate::process::yield_task();
        if crate::process::scheduler::ticks().wrapping_sub(start) >= ticks_to_wait {
            break;
        }
    }
}

fn build_ping_path<'a>(buf: &'a mut [u8; 80], target: &str) -> &'a str {
    let prefix = b"/net/ping/";
    let tlen = target.len().min(buf.len() - prefix.len());
    buf[..prefix.len()].copy_from_slice(prefix);
    buf[prefix.len()..prefix.len() + tlen].copy_from_slice(&target.as_bytes()[..tlen]);
    let total = prefix.len() + tlen;
    core::str::from_utf8(&buf[..total]).unwrap_or("/net/ping/0.0.0.0")
}

pub fn cmd_ping(args: &[String]) -> Result<(), ShellError> {
    let target = if args.is_empty() {
        match vfs::open("/net/gateway", OpenFlags::READ) {
            Ok(fd) => {
                let mut buf = [0u8; 64];
                let n = vfs::read(fd, &mut buf).unwrap_or(0);
                let _ = vfs::close(fd);
                let s = core::str::from_utf8(&buf[..n]).unwrap_or("").trim();
                if s.is_empty() || s.starts_with("0.0.0.0") {
                    shell_println!("No gateway available. Usage: ping <ip>");
                    return Ok(());
                }
                String::from(s)
            }
            Err(_) => {
                shell_println!("/net not available. Is strate-net running?");
                return Ok(());
            }
        }
    } else {
        args[0].clone()
    };

    let count: u32 = if args.len() > 1 {
        args[1].parse().unwrap_or(4)
    } else {
        4
    };

    shell_println!("PING {} ({} packets)", target, count);

    let mut path_buf = [0u8; 80];
    let path = build_ping_path(&mut path_buf, &target);

    let mut sent: u32 = 0;
    let mut received: u32 = 0;

    for seq in 0..count {
        match vfs::open(path, OpenFlags::WRITE) {
            Ok(fd) => {
                let mut req = [0u8; 4];
                req[0..2].copy_from_slice(&(seq as u16).to_le_bytes());
                let _ = vfs::write(fd, &req);
                let _ = vfs::close(fd);
                sent += 1;
            }
            Err(_) => {
                shell_println!("  send failed (seq={})", seq);
                sent += 1;
                continue;
            }
        }

        let mut got_reply = false;
        for _ in 0..20 {
            shell_sleep_ms(50);

            match vfs::open(path, OpenFlags::READ) {
                Ok(fd) => {
                    let mut reply_buf = [0u8; 10];
                    match vfs::read(fd, &mut reply_buf) {
                        Ok(n) if n >= 10 => {
                            let _ = vfs::close(fd);
                            let rtt_us = u64::from_le_bytes([
                                reply_buf[2],
                                reply_buf[3],
                                reply_buf[4],
                                reply_buf[5],
                                reply_buf[6],
                                reply_buf[7],
                                reply_buf[8],
                                reply_buf[9],
                            ]);
                            let rtt_ms = rtt_us / 1000;
                            let rtt_frac = (rtt_us % 1000) / 100;
                            shell_println!(
                                "  Reply from {}: seq={} time={}.{}ms",
                                target,
                                seq,
                                rtt_ms,
                                rtt_frac
                            );
                            received += 1;
                            got_reply = true;
                            break;
                        }
                        _ => {
                            let _ = vfs::close(fd);
                        }
                    }
                }
                Err(_) => break,
            }
        }

        if !got_reply {
            shell_println!("  Request timeout: seq={}", seq);
        }
    }

    let loss = if sent > 0 {
        ((sent - received) * 100) / sent
    } else {
        100
    };
    shell_println!("--- {} ping statistics ---", target);
    shell_println!(
        "{} transmitted, {} received, {}% loss",
        sent,
        received,
        loss
    );

    Ok(())
}

pub fn cmd_ifconfig(_args: &[String]) -> Result<(), ShellError> {
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
    let gw = read_file("/net/gateway");
    let route = read_file("/net/route");
    let dns = read_file("/net/dns");

    shell_println!("em0:");
    shell_println!("  inet     {}", ip);
    shell_println!("  gateway  {}", gw);
    shell_println!("  route    {}", route);
    shell_println!("  dns      {}", dns);

    Ok(())
}
