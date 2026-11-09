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

//! `/dev/log` : replay the kernel boot log to userspace.
//!
//! This scheme is the userspace view of [`crate::log_ring`]. The serial hook
//! feeds the ring from the very first serial byte, so a daemon started late can
//! still read what happened before it existed: opening `stream` positions the
//! cursor at the oldest *retained* byte and reports any evicted prefix via
//! [`crate::log_ring::ReadOut::lost`].
//!
//! # File layout
//!
//! ```text
//! /dev/log/
//!   stream   read    byte stream, from oldest retained byte on open
//!   stats    read    text snapshot taken at open (written/capacity/dropped/oldest)
//!   ctl      write   "clear
" or "mark <text>
"; unknown lines are ignored
//! ```
//!
//! # Semantics
//!
//! Reads never block: when no new bytes are available `stream` returns
//! `EAGAIN`, so the daemon can poll or combine the fd with a wait primitive.
//! `stats` is a regular finite snapshot (EOF at the end); open it again to get a
//! fresh one.

use alloc::{collections::BTreeMap, string::String, sync::Arc};
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::{log_ring, sync::SpinLock, syscall::error::SyscallError};

use super::{
    scheme::{
        finalize_pseudo_stat, DirEntry, DynScheme, FileFlags, FileStat, OpenFlags, OpenResult,
        Scheme, DT_REG,
    },
    scheme_router,
};

/// Stable device identity for `/dev/log`.
///
/// `DEV_THREADFS` is 11 in `scheme.rs`; the next free slot is 12. Kept local so
/// this file does not force an edit to the shared device table.
const DEV_LOG: u64 = 12;

/// Largest marker text accepted by `ctl` (`mark <text>`), excluding prefix and
/// newline. Longer markers are truncated.
const MAX_MARK_TEXT: usize = 128;

/// Allocates per-open file ids.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// What an open file id refers to.
enum Kind {
    /// `/dev/log` itself, listed by `readdir`.
    Root,
    /// Raw byte stream with its own absolute cursor.
    Stream,
    /// Immutable text snapshot taken at open.
    Stats(String),
    /// Write-only command endpoint.
    Ctl,
}

/// Per-open state.
struct LogFile {
    kind: Kind,
    /// Absolute stream cursor, or byte offset inside a `stats` snapshot.
    cursor: u64,
}

/// Plan 9-style log scheme instance.
pub struct LogScheme {
    files: SpinLock<BTreeMap<u64, LogFile>>,
}

impl LogScheme {
    /// Creates a new instance.
    pub fn new() -> Self {
        LogScheme {
            files: SpinLock::new(BTreeMap::new()),
        }
    }

    /// Builds the `stats` snapshot served by one open.
    fn stats_text() -> String {
        let s = log_ring::stats();
        let mut text = String::new();
        // Writing into a String cannot fail.
        let _ = write!(
            text,
            "written={}
capacity={}
dropped={}
oldest={}
",
            s.written, s.capacity, s.dropped, s.oldest
        );
        text
    }

    /// Applies one `ctl` write. Unknown commands are ignored (Plan 9 style:
    /// the write succeeds, nothing happens).
    fn handle_ctl(buf: &[u8]) {
        for raw in buf.split(|&b| b == b'
') {
            let line = if raw.last() == Some(&b'') {
                &raw[..raw.len() - 1]
            } else {
                raw
            };

            if line == b"clear" {
                log_ring::clear();
            } else if let Some(text) = line.strip_prefix(b"mark ") {
                push_marker(text);
            }
        }
    }
}

impl Default for LogScheme {
    fn default() -> Self {
        Self::new()
    }
}

/// Pushes a bounded `[mark] <text>
` line into the ring.
fn push_marker(text: &[u8]) {
    let n = core::cmp::min(text.len(), MAX_MARK_TEXT);
    let prefix = b"[mark] ";
    let mut line = [0u8; MAX_MARK_TEXT + 8 + 1];
    line[..prefix.len()].copy_from_slice(prefix);
    line[prefix.len()..prefix.len() + n].copy_from_slice(&text[..n]);
    let end = prefix.len() + n;
    line[end] = b'
';
    log_ring::push(&line[..end + 1]);
}

/// Serves a finite text snapshot honouring a byte offset.
fn serve_text(text: &[u8], cursor: u64, buf: &mut [u8]) -> usize {
    let len = text.len() as u64;
    if cursor >= len || buf.is_empty() {
        return 0;
    }
    let start = cursor as usize;
    let n = core::cmp::min(buf.len(), text.len() - start);
    buf[..n].copy_from_slice(&text[start..start + n]);
    n
}

impl Scheme for LogScheme {
    fn open(&self, path: &str, _flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        // The mount layer already stripped the "/dev/log" prefix.
        let path = path.trim_start_matches('/');

        let (kind, cursor, flags) = match path {
            "" | "/" => (Kind::Root, 0, FileFlags::DIRECTORY),
            "stream" => {
                // Late open: start at the oldest byte still retained.
                (Kind::Stream, log_ring::stats().oldest, FileFlags::DEVICE)
            }
            "stats" => (Kind::Stats(Self::stats_text()), 0, FileFlags::DEVICE),
            "ctl" => (Kind::Ctl, 0, FileFlags::DEVICE),
            _ => return Err(SyscallError::NotFound),
        };

        let file_id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        self.files
            .lock()
            .insert(file_id, LogFile { kind, cursor });

        Ok(OpenResult {
            file_id,
            size: None,
            flags,
        })
    }

    fn read(&self, file_id: u64, _offset: u64, buf: &mut [u8]) -> Result<usize, SyscallError> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut files = self.files.lock();
        let entry = files.get_mut(&file_id).ok_or(SyscallError::BadHandle)?;

        match &mut entry.kind {
            Kind::Stream => {
                // The ring lock is held for the duration of the copy inside
                // `read_at`, so a producer cannot lap this reader.
                let r = log_ring::read_at(entry.cursor, buf);
                entry.cursor = r.next;
                if r.copied == 0 {
                    // No new bytes yet: non-blocking contract.
                    return Err(SyscallError::Again);
                }
                Ok(r.copied)
            }
            Kind::Stats(text) => {
                let n = serve_text(text.as_bytes(), entry.cursor, buf);
                entry.cursor += n as u64;
                Ok(n)
            }
            Kind::Ctl => Err(SyscallError::IsADirectory),
            Kind::Root => Err(SyscallError::IsADirectory),
        }
    }

    fn write(&self, file_id: u64, _offset: u64, buf: &[u8]) -> Result<usize, SyscallError> {
        let mut files = self.files.lock();
        let entry = files.get_mut(&file_id).ok_or(SyscallError::BadHandle)?;

        match &entry.kind {
            Kind::Ctl => {
                Self::handle_ctl(buf);
                Ok(buf.len())
            }
            _ => Err(SyscallError::PermissionDenied),
        }
    }

    fn close(&self, file_id: u64) -> Result<(), SyscallError> {
        self.files.lock().remove(&file_id);
        Ok(())
    }

    fn stat(&self, file_id: u64) -> Result<FileStat, SyscallError> {
        let files = self.files.lock();
        let entry = files.get(&file_id).ok_or(SyscallError::BadHandle)?;

        let st = if matches!(&entry.kind, Kind::Root) {
            FileStat {
                st_ino: file_id,
                st_mode: 0o040555,
                st_nlink: 2,
                st_size: 0,
                st_blksize: 512,
                st_blocks: 0,
                ..FileStat::zeroed()
            }
        } else {
            FileStat {
                st_ino: file_id,
                st_mode: 0o020666,
                st_nlink: 1,
                st_size: 0,
                st_blksize: 1,
                st_blocks: 0,
                ..FileStat::zeroed()
            }
        };
        Ok(finalize_pseudo_stat(st, DEV_LOG, 1))
    }

    fn readdir(&self, _file_id: u64) -> Result<alloc::vec::Vec<DirEntry>, SyscallError> {
        Ok(alloc::vec![
            DirEntry {
                ino: 0,
                file_type: DT_REG,
                name: String::from("stream"),
            },
            DirEntry {
                ino: 0,
                file_type: DT_REG,
                name: String::from("stats"),
            },
            DirEntry {
                ino: 0,
                file_type: DT_REG,
                name: String::from("ctl"),
            },
        ])
    }
}

/// Registers the `log` scheme and mounts it at `/dev/log`.
///
/// Idempotent: a second call (component retry, re-init) treats an existing
/// registration or mount as success.
pub fn init_log_scheme() -> Result<(), SyscallError> {
    let scheme: DynScheme = Arc::new(LogScheme::new());

    match scheme_router::register_scheme("log", scheme) {
        Ok(_) => {}
        Err(SyscallError::AlreadyExists) => {}
        Err(e) => return Err(e),
    }

    match scheme_router::mount_scheme("log", "/dev/log") {
        Ok(()) => {
            log::info!("[log] Scheme at /dev/log/ (stream, stats, ctl)");
            Ok(())
        }
        Err(SyscallError::AlreadyExists) => Ok(()),
        Err(e) => Err(e),
    }
}
