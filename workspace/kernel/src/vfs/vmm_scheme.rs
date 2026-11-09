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

//! `/dev/vmm`: read-only user view of the s9vm engine.
//!
//! This scheme is the diagnostic mirror of the virtualization engine's
//! internal state. It exposes **no control operation**: the creation,
//! configuration and execution of worlds go exclusively through the
//! `SYS_VMM_*` syscalls and their capabilities.
//!
//! # Contents
//!
//! ```text
//! /dev/vmm/
//!   info           engine summary (snapshot taken at open)
//!   worlds         list of worlds, one line per world
//!   <id>/info      snapshot of a world
//! ```
//!
//! Each file is a **snapshot** taken at open: reading is finite (EOF at the
//! end) and never blocks. Opening the file again produces a new
//! snapshot.

use alloc::string::String;
use alloc::{collections::BTreeMap, sync::Arc};
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::s9vm::{self, vm};
use crate::sync::SpinLock;
use crate::syscall::error::SyscallError;

use super::{
    scheme::{
        finalize_pseudo_stat, DirEntry, DynScheme, FileFlags, FileStat, OpenFlags, OpenResult,
        Scheme, DT_DIR, DT_REG,
    },
    scheme_router,
};

/// Stable device identity for `/dev/vmm` (13 = first free slot).
const DEV_VMM: u64 = 13;

/// Allocates open file identifiers.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Content of an open file: root or text snapshot.
enum Kind {
    Root,
    Text(String),
}

struct VmmFile {
    kind: Kind,
    cursor: u64,
}

/// Instance of the `/dev/vmm` scheme.
pub struct VmmScheme {
    files: SpinLock<BTreeMap<u64, VmmFile>>,
}

impl VmmScheme {
    /// Creates an empty instance.
    pub fn new() -> Self {
        Self {
            files: SpinLock::new(BTreeMap::new()),
        }
    }

    fn engine_text() -> String {
        let detected = s9vm::detected();
        let mut text = String::new();
        let _ = writeln!(text, "engine={}", if detected { "detected" } else { "unavailable" });
        let _ = writeln!(text, "active_cpus={}", s9vm::active_cpu_count());
        if !detected {
            let _ = writeln!(text, "vt_x=absent reason={}", s9vm::unavailable_reason());
        }
        let _ = writeln!(text, "worlds={}", vm::count());
        let _ = writeln!(text, "abi_version={}", strat9_abi::vmm::VMM_ABI_VERSION);
        if let Some(caps) = s9vm::detect() {
            let _ = writeln!(text, "can_run={}", caps.can_run());
            let _ = writeln!(
                text,
                "ept={} ept_2mb={} ept_1gb={} vpid={}",
                caps.ept, caps.ept_2mb, caps.ept_1gb, caps.vpid
            );
        }
        text
    }

    fn list_text() -> String {
        let mut text = String::new();
        for world in vm::list() {
            let name = core::str::from_utf8(world.name_slice())
                .unwrap_or("<non-utf8>");
            let _ = writeln!(
                text,
                "world {} name={} silo={} state={} vcpus={} pages={}",
                world.id,
                name,
                world.silo_id,
                world.state,
                world.vcpu_count,
                world.mapped_pages
            );
        }
        text
    }

    fn world_text(id: u64) -> Result<String, SyscallError> {
        let world = vm::get(id).ok_or(SyscallError::NotFound)?;
        let name = core::str::from_utf8(world.name_slice()).unwrap_or("<non-utf8>");
        let mut text = String::new();
        let _ = writeln!(text, "world {}", world.id);
        let _ = writeln!(text, "name={}", name);
        let _ = writeln!(text, "silo={}", world.silo_id);
        let _ = writeln!(text, "state={}", world.state);
        let _ = writeln!(text, "vcpus={}", world.vcpu_count);
        let _ = writeln!(text, "pages={}", world.mapped_pages);
        Ok(text)
    }

    fn text_for_path(path: &str) -> Result<String, SyscallError> {
        match path {
            "info" => Ok(Self::engine_text()),
            "worlds" => Ok(Self::list_text()),
            _ => {
                // `<id>/info`
                if let Some(id_text) = path.strip_suffix("/info") {
                    if let Ok(id) = id_text.parse::<u64>() {
                        return Self::world_text(id);
                    }
                }
                Err(SyscallError::NotFound)
            }
        }
    }
}

impl Default for VmmScheme {
    fn default() -> Self {
        Self::new()
    }
}

fn serve_text(text: &[u8], cursor: u64, buf: &mut [u8]) -> usize {
    if cursor >= text.len() as u64 || buf.is_empty() {
        return 0;
    }
    let start = cursor as usize;
    let n = core::cmp::min(buf.len(), text.len() - start);
    buf[..n].copy_from_slice(&text[start..start + n]);
    n
}

impl Scheme for VmmScheme {
    fn open(&self, path: &str, _flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        let path = path.trim_start_matches('/');
        let (kind, flags) = if path.is_empty() || path == "/" {
            (Kind::Root, FileFlags::DIRECTORY)
        } else {
            (Kind::Text(Self::text_for_path(path)?), FileFlags::DEVICE)
        };
        let file_id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        self.files.lock().insert(file_id, VmmFile { kind, cursor: 0 });
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
            Kind::Root => Err(SyscallError::IsADirectory),
            Kind::Text(text) => {
                let n = serve_text(text.as_bytes(), entry.cursor, buf);
                entry.cursor += n as u64;
                Ok(n)
            }
        }
    }

    fn write(&self, _file_id: u64, _offset: u64, _buf: &[u8]) -> Result<usize, SyscallError> {
        // Strictly read-only view: every write is refused.
        Err(SyscallError::PermissionDenied)
    }

    fn close(&self, file_id: u64) -> Result<(), SyscallError> {
        self.files.lock().remove(&file_id);
        Ok(())
    }

    fn stat(&self, file_id: u64) -> Result<FileStat, SyscallError> {
        let files = self.files.lock();
        let entry = files.get(&file_id).ok_or(SyscallError::BadHandle)?;
        let st = if matches!(entry.kind, Kind::Root) {
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
                st_mode: 0o020444,
                st_nlink: 1,
                st_size: 0,
                st_blksize: 1,
                st_blocks: 0,
                ..FileStat::zeroed()
            }
        };
        Ok(finalize_pseudo_stat(st, DEV_VMM, 1))
    }

    fn readdir(&self, _file_id: u64) -> Result<alloc::vec::Vec<DirEntry>, SyscallError> {
        let mut entries = alloc::vec![
            DirEntry {
                ino: 0,
                file_type: DT_DIR,
                name: String::from("<id>"),
            },
            DirEntry {
                ino: 0,
                file_type: DT_REG,
                name: String::from("info"),
            },
            DirEntry {
                ino: 0,
                file_type: DT_REG,
                name: String::from("worlds"),
            },
        ];
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }
}

/// Registers the `vmm` scheme and mounts it on `/dev/vmm`.
///
/// Idempotent: a second call (component restart, re-init) treats the
/// existing registration or mount as a success.
pub fn init_vmm_scheme() -> Result<(), SyscallError> {
    let scheme: DynScheme = Arc::new(VmmScheme::new());
    match scheme_router::register_scheme("vmm", scheme) {
        Ok(_) => {}
        Err(SyscallError::AlreadyExists) => {}
        Err(error) => return Err(error),
    }
    match scheme_router::mount_scheme("vmm", "/dev/vmm") {
        Ok(()) => {
            log::info!("[vmm] Scheme at /dev/vmm/ (info, worlds, <id>/info)");
            Ok(())
        }
        Err(SyscallError::AlreadyExists) => Ok(()),
        Err(error) => Err(error),
    }
}
