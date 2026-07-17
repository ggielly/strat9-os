//! Input scheme : exposes raw keyboard and mouse events to userspace.
//!
//! Mounted at `/dev/input`. Provides two virtual files:
//!   `/dev/input/kbd`  : raw keyboard scancodes (1 byte per event)
//!   `/dev/input/mouse` : raw mouse events (7 bytes per event)
//!
//! The scheme reads from the kernel-internal ring buffers (keyboard.rs,
//! mouse.rs) which are filled by PS/2 and USB HID IRQ handlers.
//! Layout translation and modifier state are handled in userspace
//! by the Input Server.

use crate::syscall::error::SyscallError;
use alloc::{string::String, vec, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

use super::scheme::{
    finalize_pseudo_stat, DirEntry, FileFlags, FileStat, OpenFlags, OpenResult, Scheme, DEV_INPUT,
};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// File IDs for the two virtual input devices.
const KBD_FILE_ID: u64 = 1;
const MOUSE_FILE_ID: u64 = 2;

pub struct InputScheme;

impl InputScheme {
    pub fn new() -> Self {
        InputScheme
    }
}

impl Scheme for InputScheme {
    fn open(&self, path: &str, _flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        let file_id = match path {
            "kbd" | "keyboard" => KBD_FILE_ID,
            "mouse" => MOUSE_FILE_ID,
            "" | "/" => {
                return Ok(OpenResult {
                    file_id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
                    size: None,
                    flags: FileFlags::DIRECTORY,
                });
            }
            _ => return Err(SyscallError::NotFound),
        };

        Ok(OpenResult {
            file_id,
            size: None,
            flags: FileFlags::DEVICE,
        })
    }

    /// Read raw keyboard scancodes.
    ///
    /// Each byte is a PS/2 set-1 scancode. Bit 7 set = key released.
    /// The Input Server in userspace handles layout translation.
    fn read(&self, file_id: u64, _offset: u64, buf: &mut [u8]) -> Result<usize, SyscallError> {
        match file_id {
            KBD_FILE_ID => {
                let mut count = 0;
                for slot in buf.iter_mut() {
                    match crate::arch::x86_64::keyboard::read_char() {
                        Some(ch) => {
                            *slot = ch;
                            count += 1;
                        }
                        None => break,
                    }
                }
                Ok(count)
            }
            MOUSE_FILE_ID => {
                // Each mouse event is 7 bytes: [dx_lo, dx_hi, dy_lo, dy_hi, dz, buttons, 0]
                let mut count = 0;
                while count + 7 <= buf.len() {
                    match crate::arch::x86_64::mouse::read_event() {
                        Some(ev) => {
                            buf[count] = ev.dx as u8;
                            buf[count + 1] = (ev.dx >> 8) as u8;
                            buf[count + 2] = ev.dy as u8;
                            buf[count + 3] = (ev.dy >> 8) as u8;
                            buf[count + 4] = ev.dz as u8;
                            buf[count + 5] = (ev.left as u8)
                                | ((ev.right as u8) << 1)
                                | ((ev.middle as u8) << 2);
                            buf[count + 6] = 0; // reserved
                            count += 7;
                        }
                        None => break,
                    }
                }
                Ok(count)
            }
            _ => Err(SyscallError::BadHandle),
        }
    }

    fn write(&self, _file_id: u64, _offset: u64, _buf: &[u8]) -> Result<usize, SyscallError> {
        Err(SyscallError::PermissionDenied) // Input is read-only
    }

    fn close(&self, _file_id: u64) -> Result<(), SyscallError> {
        Ok(())
    }

    fn stat(&self, file_id: u64) -> Result<FileStat, SyscallError> {
        let (mode, size) = match file_id {
            KBD_FILE_ID => (0o020000 | 0o444, 0u64), // S_IFCHR | r--r--r--
            MOUSE_FILE_ID => (0o020000 | 0o444, 0u64),
            _ => (0o040555, 0u64), // directory
        };
        Ok(finalize_pseudo_stat(
            FileStat {
                st_ino: file_id,
                st_mode: mode,
                st_nlink: 1,
                st_size: size,
                st_blksize: 1,
                st_blocks: 0,
                ..FileStat::zeroed()
            },
            DEV_INPUT,
            0,
        ))
    }

    fn readdir(&self, _file_id: u64) -> Result<Vec<DirEntry>, SyscallError> {
        Ok(vec![
            DirEntry {
                ino: KBD_FILE_ID,
                file_type: super::scheme::DT_CHR,
                name: String::from("kbd"),
            },
            DirEntry {
                ino: MOUSE_FILE_ID,
                file_type: super::scheme::DT_CHR,
                name: String::from("mouse"),
            },
        ])
    }
}
