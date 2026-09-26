use super::*;
use crate::{shell::output::format_epoch_stamp, syscall::error::SyscallError};
use alloc::string::String;
use strat9_abi::ip::parse_ipv4_literal;

const NTP_PORT: u16 = 123;
const NTP_UNIX_EPOCH_DELTA: u64 = 2_208_988_800; // 1900 -> 1970

/// Size of the NTP header (RFC 5905 §7.3). Every field this command inspects,
/// the transmit timestamp included, lies inside it.
const NTP_HEADER_LEN: usize = 48;

/// How long to wait for the reply, in scheduler ticks (~3 s at `TIMER_HZ`).
const NTP_REPLY_TIMEOUT_TICKS: u64 = 3 * crate::arch::timer::TIMER_HZ;

/// Largest root dispersion still believed, as an NTP 16.16 fixed-point second
/// count (1.0 s).
///
/// Root dispersion is the server's own stated distance from its reference
/// clock, so a large value is the server telling us its own clock is junk. The
/// 16-bit field saturates a little past 16 h, so a garbage or uninitialised
/// header decodes as something enormous and used to sail through validation.
const NTP_MAX_ROOT_DISPERSION: u32 = 0x0001_0000;

/// Mode of a server reply, i.e. the low three bits of byte 0.
const NTP_MODE_SERVER: u8 = 4;

/// Leap indicator "clock unsynchronised" (top two bits of byte 0).
const NTP_LI_UNSYNC: u8 = 3;

/// Why a received datagram is not a usable NTP reply.
///
/// Kept separate from [`ShellError`] so a rejected packet can say *which*
/// check failed: the caller only ever maps this onto `ExecutionFailed`, and
/// every one of these used to be reported as the same "no valid NTP response".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum NtpError {
    /// Fewer bytes than an NTP header, so the fixed fields cannot be read.
    Short,
    /// Not mode 4, i.e. not a server reply (a mode 3 echo of our own request,
    /// or a mode 5 broadcast, got here).
    NotServer,
    /// A version this request did not ask for and cannot interpret.
    Version,
    /// Leap indicator 3: the server considers itself unsynchronised and its
    /// timestamp is not a time.
    Unsynchronised,
    /// Stratum 0 (kiss-of-death: the server is using the transmit field to
    /// carry an error string) or > 15 (reserved).
    Stratum,
    /// Root dispersion beyond [`NTP_MAX_ROOT_DISPERSION`].
    RootDispersion,
    /// Transmit timestamp at or before the unix epoch, i.e. no usable time.
    Timestamp,
}

impl NtpError {
    /// One-line explanation printed for the user.
    const fn reason(self) -> &'static str {
        match self {
            NtpError::Short => "response shorter than the 48-byte NTP header",
            NtpError::NotServer => "not a server reply (mode != 4)",
            NtpError::Version => "unexpected NTP version",
            NtpError::Unsynchronised => "server reports itself unsynchronised (leap indicator 3)",
            NtpError::Stratum => "stratum out of range (0 = kiss-of-death, 1..=15 required)",
            NtpError::RootDispersion => "root dispersion too large to trust",
            NtpError::Timestamp => "transmit timestamp not after the unix epoch",
        }
    }
}

/// Leap indicator: the two high bits of the first header byte (RFC 5905 §7.3).
pub(super) const fn leap_indicator(b0: u8) -> u8 {
    b0 >> 6
}

/// Mode: the three low bits of the first header byte.
pub(super) const fn ntp_mode(b0: u8) -> u8 {
    b0 & 0x07
}

/// Version: bits 3..6 of the first header byte.
pub(super) const fn ntp_version(b0: u8) -> u8 {
    (b0 >> 3) & 0x07
}

/// A synchronised server is stratum 1..=15.
///
/// 0 is a kiss-of-death (the server is not giving a time at all) and 16+ is
/// reserved, so the old `stratum == 0` test let a reserved value through.
pub(super) fn is_valid_stratum(stratum: u8) -> bool {
    (1..=15).contains(&stratum)
}

/// Root dispersion in 16.16 fixed-point seconds, from header bytes 4..8.
///
/// Returns 0 for a buffer too short to hold the field; the length check in
/// [`validate_ntp_response`] runs first, so this is only a safe default.
pub(super) fn root_dispersion(resp: &[u8]) -> u32 {
    if resp.len() < 8 {
        return 0;
    }
    u32::from_be_bytes([resp[4], resp[5], resp[6], resp[7]])
}

/// Checks a received datagram and extracts the server transmit timestamp as
/// `(unix_secs, unix_nanos)`.
///
/// The transmit timestamp alone is not enough to judge a reply: a server that
/// is itself unsynchronised, one answering with a kiss-of-death, and one whose
/// root dispersion says its own clock is far off all produce a 48-byte datagram
/// with a plausible-looking timestamp, and this command exists to report a
/// time, so all three are rejected.
pub(super) fn validate_ntp_response(resp: &[u8]) -> Result<(u64, u32), NtpError> {
    if resp.len() < NTP_HEADER_LEN {
        return Err(NtpError::Short);
    }
    if ntp_mode(resp[0]) != NTP_MODE_SERVER {
        return Err(NtpError::NotServer);
    }
    // This request asks for version 4; a server that only speaks version 3
    // answers version 3, which is comparable, but version 1/2 headers predate
    // the modern fixed-point fields and 5+ is unassigned.
    if !matches!(ntp_version(resp[0]), 3 | 4) {
        return Err(NtpError::Version);
    }
    if leap_indicator(resp[0]) == NTP_LI_UNSYNC {
        return Err(NtpError::Unsynchronised);
    }
    if !is_valid_stratum(resp[1]) {
        return Err(NtpError::Stratum);
    }
    if root_dispersion(resp) > NTP_MAX_ROOT_DISPERSION {
        return Err(NtpError::RootDispersion);
    }

    let ntp_secs = u32::from_be_bytes([resp[40], resp[41], resp[42], resp[43]]);
    if ntp_secs <= NTP_UNIX_EPOCH_DELTA as u32 {
        return Err(NtpError::Timestamp);
    }
    let ntp_frac = u32::from_be_bytes([resp[44], resp[45], resp[46], resp[47]]);
    let unix_secs = ntp_secs as u64 - NTP_UNIX_EPOCH_DELTA;
    let unix_nanos = (((ntp_frac as u128) * 1_000_000_000u128) >> 32) as u32;
    Ok((unix_secs, unix_nanos))
}

/// Encodes a unix instant as the 8-byte NTP 32.32 fixed-point timestamp used
/// for the transmit field.
///
/// `monotonic_ns` supplies only the sub-second part. It is uptime-since-boot,
/// so it is aligned with the RTC second to within the RTC's 1 Hz granularity,
/// but it is a true fraction of the current second, which is what the field
/// needs. `epoch_secs == 0` encodes "clock not set", which RFC 5905 §7.3
/// allows a client to send.
pub(super) fn encode_transmit_timestamp(epoch_secs: u64, monotonic_ns: u64) -> [u8; 8] {
    if epoch_secs == 0 {
        return [0u8; 8];
    }
    // NTP era 0 ends in 2036, where these seconds wrap like any SNTP client's.
    let ntp_secs = (epoch_secs + NTP_UNIX_EPOCH_DELTA) as u32;
    let sub_ns = monotonic_ns % 1_000_000_000;
    let frac = ((sub_ns as u128) << 32) / 1_000_000_000u128;
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&ntp_secs.to_be_bytes());
    out[4..].copy_from_slice(&(frac as u32).to_be_bytes());
    out
}

/// The CMOS wall clock as unix seconds, or `None` when there is no usable one.
///
/// A stub or never-programmed CMOS reads back zeroes or `0xFF`, and
/// `RtcDateTime::to_timestamp` turns that into an instant that looks
/// believable, so the fields that a real calendar can never hold are checked
/// here before the clock is used to stamp a request or to compute a skew.
pub(super) fn rtc_epoch_secs() -> Option<u64> {
    if !crate::hardware::timer::rtc::is_available() {
        return None;
    }
    let dt = crate::hardware::timer::rtc::get_datetime();
    if !(1..=12).contains(&dt.month) || !(2000..=2100).contains(&dt.year) {
        return None;
    }
    Some(dt.to_timestamp())
}

/// Sends `data` on `fd` and requires the endpoint to accept all of it.
///
/// `vfs::write` may accept fewer bytes than it was handed, and the single call
/// this replaced discarded the count, so a request that went out truncated was
/// indistinguishable from a successful send: the server had nothing usable to
/// answer and the command sat in its poll loop for the full timeout. A partial
/// accept is a failure rather than something to resume - the request has to
/// arrive as one 48-byte datagram, and writing the tail would put a second,
/// malformed one on the wire.
fn write_all(fd: u32, data: &[u8]) -> Result<(), ShellError> {
    let mut written = 0usize;
    while written < data.len() {
        match vfs::write(fd, &data[written..]) {
            Ok(n) if n == data.len() - written => written += n,
            // Truncated or stalled: the datagram is already gone, do not retry.
            Ok(_) => return Err(ShellError::ExecutionFailed),
            Err(_) => return Err(ShellError::ExecutionFailed),
        }
    }
    Ok(())
}

/// Resolves ntp server.
fn resolve_ntp_server(server: &str) -> Result<[u8; 4], ShellError> {
    if let Some(ip) = parse_ipv4_literal(server) {
        return Ok(ip);
    }

    let path = alloc::format!("/net/resolve/{}", server);
    let fd = match vfs::open(&path, vfs::OpenFlags::READ) {
        Ok(fd) => fd,
        Err(_) => {
            shell_println!("  resolve: cannot open '{}'", path);
            return Err(ShellError::ExecutionFailed);
        }
    };
    let mut buf = [0u8; 64];
    let read = match vfs::read(fd, &mut buf) {
        Ok(n) => n.min(buf.len()),
        Err(_) => {
            let _ = vfs::close(fd);
            // A read error used to become `unwrap_or(0)`, so a failed read and
            // a resolver that answered nothing both reported as "empty".
            shell_println!("  resolve: read of '{}' failed", path);
            return Err(ShellError::ExecutionFailed);
        }
    };
    let _ = vfs::close(fd);
    if read == 0 {
        shell_println!("  resolve: '{}' returned no answer", path);
        return Err(ShellError::ExecutionFailed);
    }
    let end = buf[..read].iter().position(|&b| b == b'\n').unwrap_or(read);
    let s = core::str::from_utf8(&buf[..end]).unwrap_or("").trim();
    match parse_ipv4_literal(s) {
        Some(ip) => Ok(ip),
        None => {
            shell_println!("  resolve: '{}' is not an IPv4 literal", s);
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// Formats ipv4.
fn format_ipv4(ip: &[u8; 4]) -> String {
    alloc::format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

/// Builds the 48-byte SNTP request (RFC 5905 §7.3, client mode).
fn build_request() -> [u8; NTP_HEADER_LEN] {
    let mut req = [0u8; NTP_HEADER_LEN];
    req[0] = 0x23; // LI=0, VN=4, Mode=3 (client)
    req[2] = 6; // poll interval hint
    req[3] = 0xEC; // precision (~2^-20)

    // Transmit timestamp from the wall clock, not from the monotonic counter:
    // uptime-since-boot is not a time of day, and its sub-second part under a
    // zeroed seconds field produced a request whose transmit stamp disagreed
    // with itself. Left all-zero when the CMOS holds nothing, which RFC 5905
    // allows for a client with no clock.
    let stamp = encode_transmit_timestamp(
        rtc_epoch_secs().unwrap_or(0),
        crate::syscall::time::current_time_ns(),
    );
    req[40..48].copy_from_slice(&stamp);
    req
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
    let fd = vfs::open(&path, vfs::OpenFlags::RDWR).map_err(|_| {
        shell_println!("  query: cannot open '{}'", path);
        ShellError::ExecutionFailed
    })?;

    let req = build_request();
    if write_all(fd, &req).is_err() {
        let _ = vfs::close(fd);
        shell_println!("  query: the request was not sent in full");
        return Err(ShellError::ExecutionFailed);
    }

    let start_tick = crate::process::scheduler::ticks();
    let timeout_ticks = crate::arch::timer::TIMER_HZ * 3; // ~3s
    let mut resp = [0u8; 64];

    loop {
        // Long poll: honour Ctrl+C rather than making the user wait it out.
        if is_interrupted() {
            let _ = vfs::close(fd);
            shell_println!("  query: cancelled");
            return Err(ShellError::ExecutionFailed);
        }

        match vfs::read(fd, &mut resp) {
            // No datagram queued yet. The net scheme answers a connected UDP
            // socket with an empty receive queue with EAGAIN, which the old
            // `Err(_) => {}` swallowed along with genuine errors; any other
            // error is fatal and must not be retried for the whole timeout.
            // `Ok(0)` is the same condition spelled by an endpoint that
            // reports "nothing to read" instead of EAGAIN.
            Ok(0) | Err(SyscallError::Again) => {}
            Ok(n) => {
                // `vfs::read` cannot return more than the buffer holds, but a
                // shell command must not index-panic on a bad count.
                let n = n.min(resp.len());
                let _ = vfs::close(fd);
                if n < NTP_HEADER_LEN {
                    // A datagram this short cannot be interpreted: it is a
                    // malformed reply, not "try again". The old code kept
                    // polling to the timeout before saying so.
                    shell_println!("  rejected: response is {} bytes", n);
                    return Err(ShellError::ExecutionFailed);
                }
                // Returned by value: `resp` is a local, so the borrow ends
                // with this arm.
                return match validate_ntp_response(&resp[..n]) {
                    Ok(stamp) => Ok(stamp),
                    Err(e) => {
                        shell_println!("  rejected: {}", e.reason());
                        Err(ShellError::ExecutionFailed)
                    }
                };
            }
            Err(_) => {
                let _ = vfs::close(fd);
                shell_println!("  query: read from '{}' failed", path);
                return Err(ShellError::ExecutionFailed);
            }
        }

        crate::process::yield_task();
        let elapsed = crate::process::scheduler::ticks().wrapping_sub(start_tick);
        if elapsed >= NTP_REPLY_TIMEOUT_TICKS {
            let _ = vfs::close(fd);
            shell_println!(
                "  timeout: no reply within {} ms",
                NTP_REPLY_TIMEOUT_TICKS * 1_000 / crate::arch::timer::TIMER_HZ
            );
            return Err(ShellError::ExecutionFailed);
        }
    }
}

pub fn cmd_ntpdate(args: &[String]) -> Result<(), ShellError> {
    let server = args.first().map(|s| s.as_str()).unwrap_or("pool.ntp.org");
    shell_println!("ntpdate: querying {}...", server);

    let server_ip = resolve_ntp_server(server)?;

    match ntp_query(&server_ip) {
        Ok((unix_secs, unix_nanos)) => {
            shell_println!("  server: {}", format_ipv4(&server_ip));
            shell_println!(
                "  remote: {}.{:03} UTC",
                format_epoch_stamp(unix_secs),
                unix_nanos / 1_000_000
            );
            match rtc_epoch_secs() {
                Some(local) => {
                    shell_println!("  local:  {} (RTC)", format_epoch_stamp(local));
                    shell_println!(
                        "  offset: {:+} s (whole seconds; the RTC has no sub-second reading)",
                        unix_secs as i64 - local as i64
                    );
                }
                None => shell_println!("  local:  (no usable RTC: CMOS holds no plausible time)"),
            }
            // `hardware::timer::rtc` exposes readers and the periodic-interrupt
            // controls, but nothing that writes the date and time registers
            // back (`cmos_write` is private to that module and unused for
            // them), so the skew is reported, not applied.
            shell_println!("  note:   the kernel has no RTC setter, so the clock is unchanged");
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
