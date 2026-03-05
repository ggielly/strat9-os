use super::*;
use alloc::string::String;

const NTP_PORT: u16 = 123;
const NTP_UNIX_EPOCH_DELTA: u64 = 2_208_988_800; // 1900 -> 1970

/// Parses ipv4.
fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut idx = 0usize;
    let mut val: u16 = 0;
    let mut has_digit = false;

    for &b in s.as_bytes() {
        if b == b'.' {
            if !has_digit || idx >= 3 || val > 255 {
                return None;
            }
            out[idx] = val as u8;
            idx += 1;
            val = 0;
            has_digit = false;
            continue;
        }
        if !b.is_ascii_digit() {
            return None;
        }
        val = val * 10 + (b - b'0') as u16;
        has_digit = true;
    }
    if !has_digit || idx != 3 || val > 255 {
        return None;
    }
    out[3] = val as u8;
    Some(out)
}

/// Resolves ntp server.
fn resolve_ntp_server(server: &str) -> Result<[u8; 4], ShellError> {
    if let Some(ip) = parse_ipv4(server) {
        return Ok(ip);
    }

    let path = alloc::format!("/net/resolve/{}", server);
    let fd = vfs::open(&path, vfs::OpenFlags::READ).map_err(|_| ShellError::ExecutionFailed)?;
    let mut buf = [0u8; 64];
    let n = vfs::read(fd, &mut buf).unwrap_or(0);
    let _ = vfs::close(fd);
    if n == 0 {
        return Err(ShellError::ExecutionFailed);
    }
    let end = buf[..n].iter().position(|&b| b == b'\n').unwrap_or(n);
    let s = core::str::from_utf8(&buf[..end]).unwrap_or("").trim();
    parse_ipv4(s).ok_or(ShellError::ExecutionFailed)
}

/// Formats ipv4.
fn format_ipv4(ip: &[u8; 4]) -> String {
    alloc::format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

/// Sends an NTP request over UDP scheme and returns server transmit timestamp
/// as unix seconds + nanoseconds.
fn ntp_query(server_ip: &[u8; 4]) -> Result<(u64, u32), ShellError> {
    let path = alloc::format!(
        "/net/udp/connect/{}.{}.{}/{}/{}",
        server_ip[0],
        server_ip[1],
        server_ip[2],
        server_ip[3],
        NTP_PORT
    );
    let fd = vfs::open(&path, vfs::OpenFlags::RDWR).map_err(|_| ShellError::ExecutionFailed)?;

    // NTP packet: 48 bytes. LI=0, VN=4, Mode=3 (client).
    let mut req = [0u8; 48];
    req[0] = 0x23;
    req[2] = 6; // poll interval hint
    req[3] = 0xEC; // precision (~2^-20)

    // Use local monotonic clock as entropy for transmit fraction.
    let now_ns = crate::syscall::time::current_time_ns();
    let frac = (((now_ns % 1_000_000_000) as u128) << 32) / 1_000_000_000u128;
    req[44..48].copy_from_slice(&(frac as u32).to_be_bytes());

    if vfs::write(fd, &req).is_err() {
        let _ = vfs::close(fd);
        return Err(ShellError::ExecutionFailed);
    }

    let start_tick = crate::process::scheduler::ticks();
    let timeout_ticks = crate::arch::x86_64::timer::TIMER_HZ * 3; // ~3s
    let mut resp = [0u8; 64];

    loop {
        match vfs::read(fd, &mut resp) {
            Ok(n) if n >= 48 => {
                let _ = vfs::close(fd);
                let li_vn_mode = resp[0];
                let mode = li_vn_mode & 0x07;
                let stratum = resp[1];
                if mode != 4 || stratum == 0 {
                    return Err(ShellError::ExecutionFailed);
                }

                let ntp_secs = u32::from_be_bytes([resp[40], resp[41], resp[42], resp[43]]) as u64;
                let ntp_frac = u32::from_be_bytes([resp[44], resp[45], resp[46], resp[47]]);
                if ntp_secs < NTP_UNIX_EPOCH_DELTA {
                    return Err(ShellError::ExecutionFailed);
                }
                let unix_secs = ntp_secs - NTP_UNIX_EPOCH_DELTA;
                let unix_nanos = (((ntp_frac as u128) * 1_000_000_000u128) >> 32) as u32;
                return Ok((unix_secs, unix_nanos));
            }
            Ok(_) => {}
            Err(_) => {}
        }

        crate::process::yield_task();
        let elapsed = crate::process::scheduler::ticks().wrapping_sub(start_tick);
        if elapsed >= timeout_ticks {
            let _ = vfs::close(fd);
            return Err(ShellError::ExecutionFailed);
        }
    }
}

pub fn cmd_ntpdate(args: &[String]) -> Result<(), ShellError> {
    let server = args.first().map(|s| s.as_str()).unwrap_or("pool.ntp.org");
    shell_println!("ntpdate: querying {}...", server);

    let server_ip = match resolve_ntp_server(server) {
        Ok(ip) => ip,
        Err(_) => {
            shell_println!("  resolve failed for {}", server);
            return Err(ShellError::ExecutionFailed);
        }
    };

    match ntp_query(&server_ip) {
        Ok((unix_secs, unix_nanos)) => {
            shell_println!("  server: {}", format_ipv4(&server_ip));
            shell_println!("  unix:   {}.{:09} UTC", unix_secs, unix_nanos);
            shell_println!("  note: kernel realtime clock set is not implemented yet");
            Ok(())
        }
        Err(_) => {
            shell_println!(
                "  no valid NTP response from {} ({})",
                server,
                format_ipv4(&server_ip)
            );
            Err(ShellError::ExecutionFailed)
        }
    }
}
