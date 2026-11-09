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

//! Runtime entry point for the Strat9 BLE log dump peripheral.
//!
//! This is intentionally small: it owns device I/O, while all protocol logic
//! lives in the host-tested library modules.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use strat9_syscall::{call, data::TimeSpec, flag, number};
use strate_bt::{gatt::RxAction, hci, mediatek, realtek, wmt, Session};

const EAGAIN: usize = 11;

const HCI_PATH: &str = "/dev/bt/hci0";
const LOG_STREAM_PATH: &str = "/dev/log/stream";
const LOG_STATS_PATH: &str = "/dev/log/stats";

/// RTL8761BU blobs, copied into the initfs by `create-uefi-image.sh`.
const RTL_FW_PATH: &str = "/initfs/rtl8761bu_fw.bin";
const RTL_CFG_PATH: &str = "/initfs/rtl8761bu_config.bin";
/// MediaTek MT7961 (MT7921) Bluetooth RAM code.
const MTK_FW_PATH: &str = "/initfs/BT_RAM_CODE_MT7961_1_2_hdr.bin";
const CTL_PATH: &str = "/dev/bt/ctl";

const FW_MAX: usize = 600 * 1024;
const PATCH_MAX: usize = 32 * 1024;

static mut FW_BUF: [u8; FW_MAX] = [0; FW_MAX];
static mut CFG_BUF: [u8; 64] = [0; 64];
static mut PATCH_BUF: [u8; PATCH_MAX] = [0; PATCH_MAX];

fn fw_buf() -> &'static mut [u8] {
    // SAFETY: single-threaded strate; the buffer is used once during setup.
    unsafe { &mut *core::ptr::addr_of_mut!(FW_BUF) }
}

fn cfg_buf() -> &'static mut [u8] {
    // SAFETY: single-threaded strate; the buffer is used once during setup.
    unsafe { &mut *core::ptr::addr_of_mut!(CFG_BUF) }
}

fn patch_buf() -> &'static mut [u8] {
    // SAFETY: single-threaded strate; the buffer is used once during setup.
    unsafe { &mut *core::ptr::addr_of_mut!(PATCH_BUF) }
}

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
                log("[strate-bt] device opened
");
                return fd;
            }
            Err(_) => {
                if !logged {
                    log("[strate-bt] waiting for device
");
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
            while j < buf.len() && (buf[j] == b' ' || buf[j] == b'	' || buf[j] == b'=') {
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

/// Reads a whole initfs file into `buf`; returns 0 when the file is absent.
fn read_file(path: &str, buf: &mut [u8]) -> usize {
    let fd = match call::open(path, flag::O_RDONLY) {
        Ok(fd) => fd,
        Err(_) => return 0,
    };
    let mut off = 0usize;
    while off < buf.len() {
        match call::read(fd, &mut buf[off..]) {
            Ok(0) => break,
            Ok(n) => off += n,
            Err(e) if e.to_errno() == EAGAIN => sleep_ms(5),
            Err(_) => break,
        }
    }
    let _ = call::close(fd);
    off
}

/// Sends one HCI command and waits for its Command Complete/Status.
///
/// Returns the return parameters (status first) in `ret`. Other events are
/// discarded: during firmware download no ACL traffic exists yet.
fn hci_cmd_sync(
    fd: usize,
    opcode: u16,
    params: &[u8],
    ret: &mut [u8],
    timeout_ms: u32,
) -> Option<usize> {
    let mut cmd = [0u8; 300];
    let n = strate_bt::hci::command(&mut cmd, opcode, params)?;
    if !write_all(fd, &cmd[..n]) {
        return None;
    }

    let mut buf = [0u8; 1024];
    let mut status_seen: Option<u8> = None;
    for _ in 0..(timeout_ms / 10).max(1) {
        match call::read(fd, &mut buf) {
            Ok(n) if n > 0 => {
                // Command Complete: 04 0E plen ncmd opcode(2) params...
                if n >= 6 && buf[0] == 0x04 && buf[1] == 0x0E {
                    let plen = buf[2] as usize;
                    if plen >= 3 && n >= 3 + plen {
                        let ev_op = u16::from_le_bytes([buf[4], buf[5]]);
                        if ev_op == opcode {
                            let rlen = (plen - 3).min(ret.len());
                            ret[..rlen].copy_from_slice(&buf[6..6 + rlen]);
                            return Some(rlen);
                        }
                    }
                }
                // Command Status: 04 0F 04 status ncmd opcode(2).  Remember it
                // but keep waiting for the Command Complete so a stale status
                // cannot be mistaken for the next fragment's completion.
                if n >= 7 && buf[0] == 0x04 && buf[1] == 0x0F {
                    let ev_op = u16::from_le_bytes([buf[5], buf[6]]);
                    if ev_op == opcode {
                        status_seen = Some(buf[3]);
                    }
                }
            }
            _ => sleep_ms(10),
        }
    }
    if let Some(status) = status_seen {
        ret[0] = status;
        return Some(1);
    }
    None
}

/// Realtek RTL8761BU bring-up: version probe, firmware patch download.
///
/// Returns false for a non-Realtek controller or when the initfs blobs are
/// missing; the caller then falls back to the generic HCI init sequence.
fn realtek_setup(fd: usize) -> bool {
    let mut r = [0u8; 64];

    // 1. Chip subversion via 0xFC61.
    let Some(n) = hci_cmd_sync(
        fd,
        realtek::OP_READ_REG16,
        &realtek::CHIP_SUBVER_ARG,
        &mut r,
        1000,
    ) else {
        log("[strate-bt] Realtek: no answer to 0xFC61
");
        return false;
    };
    if n < 3 || r[0] != 0 {
        log("[strate-bt] Realtek: 0xFC61 failed
");
        return false;
    }
    let subver = u16::from_le_bytes([r[1], r[2]]);
    if subver != realtek::RTL_ROM_LMP_8761A {
        log("[strate-bt] Realtek: not an RTL8761BU (subver != 8761)
");
        return false;
    }

    // 2. Read Local Version, then ROM version (chip id = rom + 1).
    let _ = hci_cmd_sync(fd, 0x1001, &[], &mut r, 1000);
    let Some(n) = hci_cmd_sync(fd, realtek::OP_READ_ROM_VERSION, &[], &mut r, 1000) else {
        log("[strate-bt] Realtek: ROM version read failed
");
        return false;
    };
    if n < 2 || r[0] != 0 {
        log("[strate-bt] Realtek: ROM version status != 0
");
        return false;
    }
    let rom_version = r[1];

    // 3. Load the firmware + optional config from initfs.
    let fw = fw_buf();
    let fw_len = read_file(RTL_FW_PATH, fw);
    if fw_len == 0 {
        log("[strate-bt] Realtek: /initfs/rtl8761bu_fw.bin missing
");
        return false;
    }
    let cfg = cfg_buf();
    let cfg_len = read_file(RTL_CFG_PATH, cfg);
    let out = patch_buf();
    let info = match realtek::build_patch(&fw[..fw_len], rom_version, &cfg[..cfg_len], out) {
        Ok(info) => info,
        Err(e) => {
            log(match e {
                realtek::RtlError::UnsupportedV2 => {
                    "[strate-bt] Realtek: v2 firmware format unsupported
"
                }
                realtek::RtlError::NoPatch(_) => {
                    "[strate-bt] Realtek: no patch for this chip id
"
                }
                _ => "[strate-bt] Realtek: firmware parse failed
",
            });
            return false;
        }
    };

    // 4. Download in 0xFC20 fragments, one command at a time.
    let total = info.total_len;
    let mut payload = [0u8; realtek::RTL_FRAG_LEN + 1];
    let count = realtek::fragment_count(total);
    for i in 0..count {
        let Some(plen) = realtek::fragment(&out[..total], i, &mut payload) else {
            log("[strate-bt] Realtek: fragment build failed
");
            return false;
        };
        let Some(rn) = hci_cmd_sync(fd, realtek::OP_DOWNLOAD, &payload[..plen], &mut r, 3000)
        else {
            log("[strate-bt] Realtek: firmware download timeout
");
            return false;
        };
        if rn < 1 || r[0] != 0 {
            log("[strate-bt] Realtek: firmware download rejected
");
            return false;
        }
    }

    // 5. Confirm the new version.
    if let Some(n) = hci_cmd_sync(fd, 0x1001, &[], &mut r, 1000) {
        if n >= 4 {
            log("[strate-bt] Realtek: firmware downloaded, version updated
");
        }
    }
    true
}

/// Sends a vendor control-IN request through `/dev/bt/ctl` and reads the data.
fn ctl_in(
    ctl: usize,
    request_type: u8,
    request: u8,
    value: u16,
    index: u16,
    len: usize,
    out: &mut [u8],
) -> Option<usize> {
    if len > out.len() || len > 64 {
        return None;
    }
    let mut req = [0u8; 8];
    req[0] = request_type;
    req[1] = request;
    req[2..4].copy_from_slice(&value.to_le_bytes());
    req[4..6].copy_from_slice(&index.to_le_bytes());
    req[6..8].copy_from_slice(&(len as u16).to_le_bytes());
    if !write_all(ctl, &req) {
        return None;
    }
    for _ in 0..50 {
        match call::read(ctl, out) {
            Ok(n) if n > 0 => return Some(n),
            Err(e) if e.to_errno() == EAGAIN => sleep_ms(10),
            _ => return None,
        }
    }
    None
}

/// Sends one WMT command over HCI and fetches its vendor event via control IN.
fn wmt_cmd(hci: usize, ctl: usize, op: u8, flag: u8, data: &[u8]) -> Option<u8> {
    let mut params = [0u8; 300];
    let n = wmt::build(op, flag, data, &mut params)?;
    let mut cmd = [0u8; 320];
    let cn = hci::command(&mut cmd, wmt::HCI_OP_WMT, &params[..n])?;
    if !write_all(hci, &cmd[..cn]) {
        return None;
    }
    let mut ev = [0u8; 64];
    for _ in 0..100 {
        if let Some(en) = ctl_in(ctl, 0xC0, 1, 48, 0, 64, &mut ev) {
            if let Some(e) = wmt::parse_event(&ev[..en]) {
                if e.op == op {
                    return Some(e.flag);
                }
            }
        }
        sleep_ms(10);
    }
    None
}

/// MediaTek MT7961 (MT7921) RAM-code download.
fn mtk_setup(hci: usize, ctl: usize) -> bool {
    let fw = fw_buf();
    let fw_len = read_file(MTK_FW_PATH, fw);
    if fw_len == 0 {
        log("[strate-bt] MTK: firmware file missing
");
        return false;
    }
    let Some(count) = mediatek::section_count(&fw[..fw_len]) else {
        log("[strate-bt] MTK: bad firmware header
");
        return false;
    };
    log("[strate-bt] MTK: downloading firmware
");
    for i in 0..count {
        let Some(s) = mediatek::section(&fw[..fw_len], i) else {
            return false;
        };
        if s.size == 0 {
            continue;
        }
        let mut hdr = [0u8; mediatek::NEED_SEND_SIZE + 1];
        if mediatek::section_header(&fw[..fw_len], i, &mut hdr).is_none() {
            return false;
        }
        let mut status = mediatek::PATCH_UNDONE;
        for _ in 0..20 {
            let Some(st) = wmt_cmd(hci, ctl, wmt::OP_PATCH_DWNLD, 0, &hdr) else {
                log("[strate-bt] MTK: section query timeout
");
                return false;
            };
            status = st;
            if status == mediatek::PATCH_DONE {
                break;
            }
            if status != mediatek::PATCH_PROGRESS {
                break;
            }
            sleep_ms(100);
        }
        if status == mediatek::PATCH_DONE {
            continue;
        }
        let nfrag = mediatek::fragment_count(s.size);
        for f in 0..nfrag {
            let Some((flag, data)) = mediatek::fragment(&fw[..fw_len], s, f) else {
                return false;
            };
            if wmt_cmd(hci, ctl, wmt::OP_PATCH_DWNLD, flag, data).is_none() {
                log("[strate-bt] MTK: firmware fragment failed
");
                return false;
            }
        }
    }
    if wmt_cmd(hci, ctl, wmt::OP_FUNC_CTRL, 0, &[1]).is_none() {
        log("[strate-bt] MTK: function enable timeout
");
        return false;
    }
    log("[strate-bt] MTK: firmware downloaded
");
    true
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {    log("[strate-bt] starting
");

    let hci = open_retry(HCI_PATH);
    let log_stream = open_retry(LOG_STREAM_PATH);
    let ctl = open_retry(CTL_PATH);

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
    if realtek_setup(hci) {
        log("[strate-bt] Realtek RTL8761BU firmware ready
");
    } else if mtk_setup(hci, ctl) {
        log("[strate-bt] MediaTek MT7961 firmware ready
");
    } else {
        log("[strate-bt] no firmware loaded (generic HCI path)
");
    }
    if let Some(n) = Session::initialization_sequence(&mut init) {
        if !write_all(hci, &init[..n]) {
            log("[strate-bt] HCI init write failed
");
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
                            log("[strate-bt] HCI write failed
");
                        }
                    }
                    Err(_) => log("[strate-bt] malformed HCI packet
"),
                }
                if session.take_advertising_error() {
                    log("[strate-bt] LE advertising enable failed (firmware?)
");
                }
            }
            Err(e) => {
                if e.to_errno() != EAGAIN {
                    log("[strate-bt] HCI read error
");
                    sleep_ms(50);
                }
            }
        }

        // RX commands from the NUS peer.
        while let Some(action) = session.take_action() {
            match action {
                RxAction::Pause => {
                    paused = true;
                    log("[strate-bt] dump paused
");
                }
                RxAction::Resume => {
                    paused = false;
                    log("[strate-bt] dump resumed
");
                }
                RxAction::Stats => {
                    log("[strate-bt] stats requested
");
                }
                RxAction::Dump { count } => {
                    // TODO(hw): replay the last `count` bytes from the log ring
                    // once the console exposes a history read; today the dump
                    // stream is forward-only.
                    let _ = count;
                    log("[strate-bt] dump replay not supported yet
");
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
                                    log("[strate-bt] notification write dropped
");
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                }
                Err(e) => {
                    if e.to_errno() != EAGAIN {
                        log("[strate-bt] log stream read error
");
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
