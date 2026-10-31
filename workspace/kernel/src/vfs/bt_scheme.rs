//! Bluetooth HCI scheme : `/dev/bt`.
//!
//! Exposes the HCI-over-USB transport to userspace:
//!
//! ```text
//! /dev/bt/            directory
//!   hci0     read/write   H4-framed HCI packets
//!   stats    read         transport counters (ASCII, single line)
//! ```
//!
//! # Framing
//!
//! A single `read()` returns exactly one complete H4 packet (indicator byte
//! included). If the destination buffer is smaller than the packet nothing is
//! consumed and `EMSGSIZE` is returned, so a well-behaved reader retries with
//! a larger buffer. `EAGAIN` means both receive rings are empty.
//!
//! A `write()` accepts one or more complete H4 packets; it returns the number
//! of bytes consumed. A partial trailing packet is rejected with `EINVAL`
//! unless at least one complete packet was already consumed (then the short
//! tail is left for the next write).
//!
//! # Concurrency
//!
//! One reader and one writer are assumed, matching a single HCI daemon. The
//! scheme itself does not prevent multiple opens; ordering between concurrent
//! readers is not defined.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::{hardware::usb::btusb, sync::SpinLock, syscall::error::SyscallError};

use super::{
    scheme::{finalize_pseudo_stat, FileFlags, FileStat, OpenFlags, OpenResult, Scheme, DEV_CHAR_FS},
    scheme_router::{mount_scheme, register_scheme},
};

const HCI0_FILE_ID: u64 = 1;
const STATS_FILE_ID: u64 = 2;
const ROOT_FILE_ID: u64 = 3;
const CTL_FILE_ID: u64 = 4;

/// Last vendor control-IN response (only one consumer: strate-bt).
static CTL_RESPONSE: SpinLock<([u8; 64], usize)> = SpinLock::new(([0; 64], 0));

static SCHEME: SpinLock<Option<Arc<BtScheme>>> = SpinLock::new(None);
static REGISTERED: AtomicBool = AtomicBool::new(false);
static MOUNTED: AtomicBool = AtomicBool::new(false);

/// Kernel-backed scheme exposing the Bluetooth transport.
pub struct BtScheme;

impl BtScheme {
    /// Creates a new instance.
    pub fn new() -> Self {
        BtScheme
    }
}

impl Default for BtScheme {
    fn default() -> Self {
        Self::new()
    }
}

impl Scheme for BtScheme {
    /// Performs the open operation.
    fn open(&self, path: &str, _flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        let path = path.trim_start_matches('/');
        let file_id = match path {
            "" | "/" => {
                return Ok(OpenResult {
                    file_id: ROOT_FILE_ID,
                    size: None,
                    flags: FileFlags::DIRECTORY,
                });
            }
            "hci0" => {
                if !btusb::is_present() {
                    // No HCI device yet: let the daemon retry instead of
                    // writing commands into a transport that does not exist.
                    return Err(SyscallError::NotFound);
                }
                HCI0_FILE_ID
            }
            "stats" => STATS_FILE_ID,
            "ctl" => {
                if !btusb::is_present() {
                    return Err(SyscallError::NotFound);
                }
                CTL_FILE_ID
            }
            _ => return Err(SyscallError::NotFound),
        };

        Ok(OpenResult {
            file_id,
            size: None,
            flags: FileFlags::DEVICE,
        })
    }

    /// Performs the read operation.
    fn read(&self, file_id: u64, offset: u64, buf: &mut [u8]) -> Result<usize, SyscallError> {
        match file_id {
            HCI0_FILE_ID => btusb::read_packet(buf),
            STATS_FILE_ID => {
                let text = btusb::stats_text();
                let start = core::cmp::min(offset as usize, text.len());
                let len = core::cmp::min(text.len() - start, buf.len());
                buf[..len].copy_from_slice(&text.as_bytes()[start..start + len]);
                Ok(len)
            }
            CTL_FILE_ID => {
                let mut ctl = CTL_RESPONSE.lock();
                if ctl.1 == 0 {
                    return Err(SyscallError::Again);
                }
                let n = core::cmp::min(ctl.1, buf.len());
                buf[..n].copy_from_slice(&ctl.0[..n]);
                ctl.1 = 0;
                Ok(n)
            }
            _ => Err(SyscallError::BadHandle),
        }
    }

    /// Performs the write operation.
    fn write(&self, file_id: u64, _offset: u64, buf: &[u8]) -> Result<usize, SyscallError> {
        if file_id == CTL_FILE_ID {
            // Request: [bmRequestType][bRequest][wValue u16][wIndex u16]
            //          [wLength u16][data...]
            if buf.len() < 8 {
                return Err(SyscallError::InvalidArgument);
            }
            let setup = [
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ];
            let len = u16::from_le_bytes([buf[6], buf[7]]) as usize;
            if len > 64 {
                return Err(SyscallError::InvalidArgument);
            }
            if buf[0] & 0x80 != 0 {
                // Control IN: the response is read back through read().
                let mut resp = [0u8; 64];
                let n = btusb::vendor_control(setup, Some(&mut resp[..len]), len)
                    .map_err(|_| SyscallError::Again)?;
                let mut ctl = CTL_RESPONSE.lock();
                ctl.0[..n].copy_from_slice(&resp[..n]);
                ctl.1 = n;
            } else {
                // Control OUT: caller data follows the 8-byte header.
                if buf.len() < 8 + len {
                    return Err(SyscallError::InvalidArgument);
                }
                let mut data = [0u8; 64];
                data[..len].copy_from_slice(&buf[8..8 + len]);
                btusb::vendor_control(setup, Some(&mut data[..len]), len)
                    .map_err(|_| SyscallError::Again)?;
                CTL_RESPONSE.lock().1 = 0;
            }
            return Ok(buf.len());
        }

        if file_id != HCI0_FILE_ID {
            return Err(SyscallError::BadHandle);
        }
        if buf.is_empty() {
            return Ok(0);
        }

        let mut consumed = 0usize;
        let mut needs_tx_wait = false;
        while consumed < buf.len() {
            let remaining = &buf[consumed..];
            if remaining.len() >= 3
                && remaining[0] == 0x01
                && remaining[1] == 0x6F
                && remaining[2] == 0xFC
            {
                // MediaTek WMT command: the following control-IN must not race
                // with this bulk OUT completion.
                needs_tx_wait = true;
            }
            let total = match btusb::h4_total_len(remaining) {
                Some(total) if total <= remaining.len() => total,
                _ => {
                    // Incomplete packet (or garbage at the head). If the write
                    // already made progress, stop and let the caller retry.
                    if consumed == 0 {
                        return Err(SyscallError::InvalidArgument);
                    }
                    break;
                }
            };
            match btusb::send_h4(&remaining[..total]) {
                Ok(()) => consumed += total,
                Err(error) => {
                    if consumed == 0 {
                        return Err(error);
                    }
                    break;
                }
            }
        }

        if consumed > 0 {
            btusb::kick_tx();
            if needs_tx_wait {
                let _ = btusb::wait_tx_idle(100);
            }
        }
        Ok(consumed)
    }

    /// Performs the close operation.
    fn close(&self, _file_id: u64) -> Result<(), SyscallError> {
        Ok(())
    }

    /// Performs the stat operation.
    fn stat(&self, file_id: u64) -> Result<FileStat, SyscallError> {
        let (mode, rdev) = match file_id {
            HCI0_FILE_ID => (0o020666, 1),  // S_IFCHR | rw-rw-rw-
            STATS_FILE_ID => (0o020444, 2), // S_IFCHR | r--r--r--
            CTL_FILE_ID => (0o020666, 3),   // S_IFCHR | rw-rw-rw-
            ROOT_FILE_ID => (0o040555, 0),  // directory
            _ => return Err(SyscallError::BadHandle),
        };
        Ok(finalize_pseudo_stat(
            FileStat {
                st_ino: file_id,
                st_mode: mode,
                st_nlink: 1,
                st_size: 0,
                st_blksize: 1,
                st_blocks: 0,
                ..FileStat::zeroed()
            },
            DEV_CHAR_FS,
            rdev,
        ))
    }
}

/// Registers and mounts `/dev/bt`. Idempotent.
///
/// Called from the USB Bluetooth probe and again from `vfs::init()`: during
/// hardware init `/dev` may not be mounted yet, so the mount is retried later.
pub fn init_bt_scheme() {
    if !REGISTERED.load(Ordering::Acquire) {
        let scheme = Arc::new(BtScheme::new());
        match register_scheme("bt", scheme.clone()) {
            Ok(_) | Err(SyscallError::AlreadyExists) => {
                *SCHEME.lock() = Some(scheme);
                REGISTERED.store(true, Ordering::Release);
                log::info!("[VFS] Registered bt scheme");
            }
            Err(error) => {
                log::warn!("[VFS] Failed to register bt scheme: {:?}", error);
                return;
            }
        }
    }

    if SCHEME.lock().is_none() || MOUNTED.load(Ordering::Acquire) {
        return;
    }

    match mount_scheme("bt", "/dev/bt") {
        Ok(()) => {
            MOUNTED.store(true, Ordering::Release);
            log::info!("[VFS] Mounted /dev/bt (Bluetooth HCI)");
        }
        Err(SyscallError::AlreadyExists) => {
            MOUNTED.store(true, Ordering::Release);
        }
        Err(error) => {
            log::warn!("[VFS] /dev/bt not mounted yet: {:?}", error);
        }
    }
}
