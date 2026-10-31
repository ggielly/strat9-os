//! Runtime entry point for the Strat9 BLE log dump peripheral.
//!
//! This is intentionally small: it owns device I/O, while all protocol logic
//! lives in the host-tested library modules.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use strat9_syscall::{call, data::TimeSpec, flag, number};
use strate_bt::{Session, gatt::RxAction};

const EAGAIN: usize = 11;

const HCI_PATH: &str = "/dev/bt/hci0";
const LOG_STREAM_PATH: &str = "/dev/log/stream";
const LOG_STATS_PATH: &str = "/dev/log/stats";

fn log(msg: &str) {
    let _ = call::debug_log(msg.as_bytes());
}

fn sleep_ms(ms: u64) {
    let req = TimeSpec {
        tv_sec: (ms / 1000) as i64,
        tv_nsec: ((ms % 1000) * 1_000_000) as i64,
    };
    let _ = unsafe {
        strat9_syscall::syscall2(number::SYS_NANOSLEEP, &req as *const TimeSpec as usize, 0)
    };
}

fn open_retry(path: &str) -> usize {
    let mut logged = false;
    loop {
        match call::open(path, flag::O_RDWR | flag::O_NONBLOCK) {
            Ok(fd) => {
                log("[strate-bt] device opened\n");
                return fd;
            }
            Err(_) => {
                if !logged {
                    log("[strate-bt] waiting for device\n");
                    logged = true;
                }
                sleep_ms(200);
            }
        }
    }
}

fn write_all(fd: usize, data: &[u8]) -> bool {
    let mut off = 0usize;
    let mut retries = 0u32;
    while off < data.len() {
        match call::write(fd, &data[off..]) {
            Ok(0) => return false,
            Ok(n) => {
                off += n;
                retries = 0;
            }
            Err(e) => {
                if e.to_errno() == EAGAIN {
                    retries += 1;
                    if retries > 100 {
                        return false;
                    }
                    sleep_ms(10);
                    continue;
                }
                return false;
            }
        }
    }
    true
}

fn parse_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut v = 0u64;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(v)
}

/// Find `key` in a small text buffer and parse the decimal value that follows.
fn find_field(buf: &[u8], key: &[u8]) -> Option<u64> {
    if key.is_empty() || buf.len() < key.len() {
        return None;
    }
    let mut i = 0usize;
    while i + key.len() <= buf.len() {
        if &buf[i..i + key.len()] == key {
            let mut j = i + key.len();
            while j < buf.len() && (buf[j] == b' ' || buf[j] == b'\t' || buf[j] == b'=') {
                j += 1;
            }
            let start = j;
            while j < buf.len() && buf[j].is_ascii_digit() {
                j += 1;
            }
            return parse_u64(&buf[start..j]);
        }
        i += 1;
    }
    None
}

fn read_stats(fd: usize) -> (Option<u64>, Option<u64>, Option<u64>) {
    let mut buf = [0u8; 256];
    match call::read(fd, &mut buf) {
        Ok(n) if n > 0 => (
            find_field(&buf[..n], b"written"),
            find_field(&buf[..n], b"oldest"),
            find_field(&buf[..n], b"dropped"),
        ),
        _ => (None, None, None),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    log("[strate-bt] starting\n");

    let hci = open_retry(HCI_PATH);
    let log_stream = open_retry(LOG_STREAM_PATH);

    // Absolute position of the next byte this daemon will forward. The ring can
    // wrap while no client is subscribed; `oldest` lets us detect and report
    // the loss instead of silently skipping it.
    let mut log_cursor = 0u64;
    if let Ok(fd) = call::open(LOG_STATS_PATH, flag::O_RDONLY) {
        let (_, oldest, _) = read_stats(fd);
        let _ = call::close(fd);
        log_cursor = oldest.unwrap_or(0);
    }

    let mut init = [0u8; 256];
    if let Some(n) = Session::initialization_sequence(&mut init) {
        if !write_all(hci, &init[..n]) {
            log("[strate-bt] HCI init write failed\n");
        }
    }

    let mut session = Session::new();
    let mut packet = [0u8; 1032];
    let mut out = [0u8; 700];
    let mut log_buf = [0u8; 512];
    let mut dropped_last = 0u64;
    let mut tick = 0u32;
    let mut paused = false;

    loop {
        match call::read(hci, &mut packet) {
            Ok(0) => sleep_ms(10),
            Ok(n) => {
                match session.on_hci_packet(&packet[..n], &mut out) {
                    Ok(0) => {}
                    Ok(m) => {
                        if !write_all(hci, &out[..m]) {
                            log("[strate-bt] HCI write failed\n");
                        }
                    }
                    Err(_) => log("[strate-bt] malformed HCI packet\n"),
                }
            }
            Err(e) => {
                if e.to_errno() != EAGAIN {
                    log("[strate-bt] HCI read error\n");
                    sleep_ms(50);
                }
            }
        }

        // RX commands from the NUS peer.
        while let Some(action) = session.take_action() {
            match action {
                RxAction::Pause => {
                    paused = true;
                    log("[strate-bt] dump paused\n");
                }
                RxAction::Resume => {
                    paused = false;
                    log("[strate-bt] dump resumed\n");
                }
                RxAction::Stats => {
                    log("[strate-bt] stats requested\n");
                }
                RxAction::Dump { count } => {
                    // TODO(hw): replay the last `count` bytes from the log ring
                    // once the console exposes a history read; today the dump
                    // stream is forward-only.
                    let _ = count;
                    log("[strate-bt] dump replay not supported yet\n");
                }
            }
        }

        // Pump logs only while a client is subscribed to TX notifications.
        if session.notifications_enabled() && !paused {
            match call::read(log_stream, &mut log_buf) {
                Ok(0) => {}
                Ok(n) => {
                    log_cursor = log_cursor.saturating_add(n as u64);
                    loop {
                        match session.poll_log(&log_buf[..n], &mut out) {
                            Some(m) => {
                                if !write_all(hci, &out[..m]) {
                                    log("[strate-bt] notification write dropped\n");
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                }
                Err(e) => {
                    if e.to_errno() != EAGAIN {
                        log("[strate-bt] log stream read error\n");
                    }
                }
            }
        }

        // Once per second, compare the ring's dropped counter and tell the
        // host how many bytes it will never see.
        tick = tick.wrapping_add(1);
        if tick >= 100 {
            tick = 0;
            if session.notifications_enabled() {
                if let Ok(stats_fd) = call::open(LOG_STATS_PATH, flag::O_RDONLY) {
                    let (written, oldest, dropped) = read_stats(stats_fd);
                    let _ = call::close(stats_fd);

                    // `written < cursor` means the ring was cleared; restart.
                    if let Some(written) = written {
                        if written < log_cursor {
                            log_cursor = written;
                        }
                    }
                    // `oldest > cursor` means the ring wrapped before we could
                    // forward those bytes: tell the host exactly how many.
                    if let Some(oldest) = oldest {
                        if oldest > log_cursor {
                            let lost = oldest - log_cursor;
                            log_cursor = oldest;
                            if let Some(n) = session
                                .report_drop(lost.min(u32::MAX as u64) as u32, &mut out)
                            {
                                let _ = write_all(hci, &out[..n]);
                            }
                        }
                    }
                    if let Some(dropped) = dropped {
                        if dropped > dropped_last {
                            let lost = dropped - dropped_last;
                            dropped_last = dropped;
                            if let Some(n) = session
                                .report_drop(lost.min(u32::MAX as u64) as u32, &mut out)
                            {
                                let _ = write_all(hci, &out[..n]);
                            }
                        }
                    }
                }
            }
        }

        // TODO(hw): honour LE ACL credits from Number Of Completed Packets
        // before pushing large bursts on slow controllers.
        sleep_ms(10);
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    call::handle_panic("strate-bt", info)
}
