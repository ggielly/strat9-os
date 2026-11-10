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

//! `/dev/vmm-net`: guest network frame relay for s9vm worlds.
//!
//! This scheme is the user-visible front-end of the per-world virtio-net
//! device model. It exposes one directory per world and three leaves:
//!
//! ```text
//! /dev/vmm-net/
//!   <id>/              world directory
//!   <id>/tx            write one frame → guest RX queue
//!   <id>/rx            read one frame emitted by the guest
//!   <id>/info          finite text snapshot (world + device identity)
//! ```
//!
//! # Frame semantics
//!
//! The relay is **frame oriented**: one `write` on `<id>/tx` is exactly one
//! frame (no stream reassembly, no virtio header) and one `read` on
//! `<id>/rx` returns exactly one frame the guest transmitted. Frame
//! boundaries are preserved in both directions.
//!
//! * `tx` writes are bounded by [`MAX_FRAME_SIZE`] bytes; a larger buffer is
//!   rejected with [`SyscallError::InvalidArgument`]. The write is
//!   non-blocking: when the guest RX queue is full the scheme reports
//!   [`SyscallError::Again`] so a non-blocking front-end can retry.
//! * `rx` reads are non-blocking: when no frame is pending they return `0`.
//!   A read drains **one** frame. If the caller buffer is shorter than the
//!   frame, the frame is truncated to the buffer length and the remaining
//!   bytes are dropped; the return value is the number of bytes copied.
//!   A zero-length buffer does not consume a frame and returns `0`.
//! * `<id>/info` is a snapshot taken at `open`: reading it is finite (EOF at
//!   the end). Per-world network frame counters are not exported by the
//!   engine; the snapshot reports them as unavailable instead of guessing.
//! * A world can be destroyed at any time: every operation that needs the
//!   world to exist returns [`SyscallError::NotFound`] once it is gone.
//!
//! Unknown paths, and leaves under a world that no longer exists, return
//! [`SyscallError::NotFound`].
//!
//! # Mount point
//!
//! The scheme is mounted at `/dev/vmm-net`, not at `/net`: `/net` is the
//! host network namespace, owned by the userspace network stack (a strate
//! binds it through `SYS_IPC_BIND_PORT`, and `ipc_port.rs` replaces the mount
//! on hot restart). Occupying `/net` would shadow or be replaced by the host
//! network scheme, so the guest relay lives beside `/dev/vmm` instead.

use alloc::{collections::BTreeMap, string::String, sync::Arc};
use core::{
    fmt::Write,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{
    s9vm::{
        virtio_net,
        vm::{self, MAX_FRAME_SIZE},
    },
    sync::SpinLock,
    syscall::error::SyscallError,
};

use super::{
    scheme::{
        DT_DIR, DT_REG, DirEntry, DynScheme, FileFlags, FileStat, OpenFlags, OpenResult, Scheme,
        finalize_pseudo_stat,
    },
    scheme_router,
};

/// Stable pseudo device identity for `/dev/vmm-net` (14 = first free slot after the
/// `/dev/vmm` scheme's 13).
const DEV_VMM_NET: u64 = 14;

/// Allocates open file identifiers.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Content of an open file.
enum Kind {
    /// Scheme root directory.
    Root,
    /// Directory of one world (`<id>`).
    WorldDir(u64),
    /// Guest transmit path: write one frame per call.
    Tx { world_id: u64 },
    /// Guest receive path: read one frame per call.
    Rx { world_id: u64 },
    /// Finite text snapshot taken at open.
    Info { world_id: u64, text: String },
}

struct VmmNetFile {
    kind: Kind,
    cursor: u64,
}

/// Instance of the `/dev/vmm-net` scheme.
pub struct VmmNetScheme {
    files: SpinLock<BTreeMap<u64, VmmNetFile>>,
}

impl VmmNetScheme {
    /// Creates an empty instance.
    pub fn new() -> Self {
        Self {
            files: SpinLock::new(BTreeMap::new()),
        }
    }

    /// Snapshot of one world and of its network device identity.
    ///
    /// The MAC address is the one exposed by the device model's
    /// configuration space. Frame counters are not exported by the engine:
    /// they are reported as unavailable rather than approximated.
    fn info_text(id: u64) -> Result<String, SyscallError> {
        let world = vm::get(id).ok_or(SyscallError::NotFound)?;
        let name = core::str::from_utf8(world.name_slice()).unwrap_or("<non-utf8>");
        let stats = vm::stats(id).unwrap_or_default();

        let mut text = String::new();
        let _ = writeln!(text, "world={}", world.id);
        let _ = writeln!(text, "name={}", name);
        let _ = writeln!(text, "silo={}", world.silo_id);
        let _ = writeln!(text, "state={}", world.state);
        let _ = writeln!(text, "paused={}", vm::is_paused(id));
        let _ = writeln!(text, "vcpus={}", world.vcpu_count);
        let _ = writeln!(text, "pages={}", world.mapped_pages);
        let _ = writeln!(text, "device=virtio-net");
        let _ = writeln!(text, "mac={}", MacDisplay(virtio_net::MAC));
        // Generic engine counters are available; network-specific ones are
        // not part of the exported engine statistics.
        let _ = writeln!(text, "runs={}", stats.runs);
        let _ = writeln!(text, "policy_exits={}", stats.policy_exits);
        let _ = writeln!(text, "emulated_exits={}", stats.emulated_exits);
        let _ = writeln!(text, "injected_interrupts={}", stats.injected_interrupts);
        let _ = writeln!(
            text,
            "tx_frames=unavailable (per-world network counters are not exported)"
        );
        let _ = writeln!(
            text,
            "rx_frames=unavailable (per-world network counters are not exported)"
        );
        Ok(text)
    }

    /// Builds the open-file kind for a relative scheme path.
    ///
    /// Directories are recognised here so that `<id>` can be listed; every
    /// other path must be a known leaf or the open fails with `NotFound`.
    fn kind_for_path(path: &str) -> Result<(Kind, FileFlags), SyscallError> {
        if let Ok(id) = path.parse::<u64>() {
            if vm::get(id).is_none() {
                return Err(SyscallError::NotFound);
            }
            return Ok((Kind::WorldDir(id), FileFlags::DIRECTORY));
        }
        if let Some((id_text, leaf)) = path.split_once('/') {
            let id = id_text.parse::<u64>().map_err(|_| SyscallError::NotFound)?;
            if vm::get(id).is_none() {
                return Err(SyscallError::NotFound);
            }
            return match leaf {
                "tx" => Ok((Kind::Tx { world_id: id }, FileFlags::DEVICE)),
                "rx" => Ok((Kind::Rx { world_id: id }, FileFlags::DEVICE)),
                "info" => Ok((
                    Kind::Info {
                        world_id: id,
                        text: Self::info_text(id)?,
                    },
                    FileFlags::DEVICE,
                )),
                _ => Err(SyscallError::NotFound),
            };
        }
        Err(SyscallError::NotFound)
    }

    /// Directory entries for the root or for one world.
    fn dir_entries(kind: &Kind) -> Result<alloc::vec::Vec<DirEntry>, SyscallError> {
        let mut entries = match kind {
            Kind::Root => vm::list()
                .into_iter()
                .map(|world| DirEntry {
                    ino: world.id,
                    file_type: DT_DIR,
                    name: alloc::format!("{}", world.id),
                })
                .collect(),
            Kind::WorldDir(id) => {
                if vm::get(*id).is_none() {
                    return Err(SyscallError::NotFound);
                }
                alloc::vec![
                    DirEntry {
                        ino: *id,
                        file_type: DT_REG,
                        name: String::from("info"),
                    },
                    DirEntry {
                        ino: *id,
                        file_type: DT_REG,
                        name: String::from("rx"),
                    },
                    DirEntry {
                        ino: *id,
                        file_type: DT_REG,
                        name: String::from("tx"),
                    },
                ]
            }
            Kind::Tx { .. } | Kind::Rx { .. } | Kind::Info { .. } => {
                return Err(SyscallError::NotADirectory);
            }
        };
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    /// True when the world referenced by a leaf still exists.
    fn world_alive(id: u64) -> Result<(), SyscallError> {
        if vm::get(id).is_some() {
            Ok(())
        } else {
            Err(SyscallError::NotFound)
        }
    }
}

impl Default for VmmNetScheme {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper that renders a MAC address without allocating an intermediate
/// buffer (`core::fmt::Write` into the snapshot string).
struct MacDisplay([u8; 6]);

impl core::fmt::Display for MacDisplay {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if index != 0 {
                f.write_str(":")?;
            }
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
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

impl Scheme for VmmNetScheme {
    fn open(&self, path: &str, _flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        let path = path.trim_start_matches('/');
        let (kind, flags) = if path.is_empty() {
            (Kind::Root, FileFlags::DIRECTORY)
        } else {
            Self::kind_for_path(path)?
        };
        let size = match &kind {
            Kind::Info { text, .. } => Some(text.len() as u64),
            _ => None,
        };
        let file_id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        self.files
            .lock()
            .insert(file_id, VmmNetFile { kind, cursor: 0 });
        Ok(OpenResult {
            file_id,
            size,
            flags,
        })
    }

    fn read(&self, file_id: u64, _offset: u64, buf: &mut [u8]) -> Result<usize, SyscallError> {
        let mut files = self.files.lock();
        let entry = files.get_mut(&file_id).ok_or(SyscallError::BadHandle)?;
        match &mut entry.kind {
            Kind::Root => Err(SyscallError::IsADirectory),
            Kind::WorldDir(id) => {
                // A world can be destroyed while its directory stays open.
                Self::world_alive(*id)?;
                Err(SyscallError::IsADirectory)
            }
            Kind::Tx { world_id } => {
                Self::world_alive(*world_id)?;
                Err(SyscallError::PermissionDenied)
            }
            Kind::Info { world_id, text } => {
                Self::world_alive(*world_id)?;
                let n = serve_text(text.as_bytes(), entry.cursor, buf);
                entry.cursor += n as u64;
                Ok(n)
            }
            Kind::Rx { world_id } => {
                let world_id = *world_id;
                // Empty read: do not consume a frame.
                if buf.is_empty() {
                    Self::world_alive(world_id)?;
                    return Ok(0);
                }
                match vm::read_network_frame(world_id) {
                    // The world vanished (or has no network device any more).
                    Err(()) => Err(SyscallError::NotFound),
                    // Nothing transmitted by the guest since the last read.
                    Ok(None) => Ok(0),
                    Ok(Some(frame)) => {
                        // Exactly one frame per read. A short buffer truncates
                        // the frame; the remainder is dropped by contract.
                        let n = core::cmp::min(buf.len(), frame.len());
                        buf[..n].copy_from_slice(&frame[..n]);
                        Ok(n)
                    }
                }
            }
        }
    }

    fn write(&self, file_id: u64, _offset: u64, buf: &[u8]) -> Result<usize, SyscallError> {
        let mut files = self.files.lock();
        let entry = files.get_mut(&file_id).ok_or(SyscallError::BadHandle)?;
        match &mut entry.kind {
            Kind::Tx { world_id } => {
                let world_id = *world_id;
                Self::world_alive(world_id)?;
                // One write is one frame. An empty write is a no-op rather
                // than a zero-length frame on the wire.
                if buf.is_empty() {
                    return Ok(0);
                }
                if buf.len() > MAX_FRAME_SIZE {
                    return Err(SyscallError::InvalidArgument);
                }
                match vm::push_network_frame(world_id, buf) {
                    Ok(()) => Ok(buf.len()),
                    Err(()) => {
                        // The engine only reports "queue full or world gone";
                        // re-check existence to return the accurate errno.
                        Self::world_alive(world_id)?;
                        Err(SyscallError::Again)
                    }
                }
            }
            // Every other file is read-only.
            Kind::Root | Kind::WorldDir(_) | Kind::Rx { .. } | Kind::Info { .. } => {
                Err(SyscallError::PermissionDenied)
            }
        }
    }

    fn close(&self, file_id: u64) -> Result<(), SyscallError> {
        self.files.lock().remove(&file_id);
        Ok(())
    }

    fn size(&self, file_id: u64) -> Result<u64, SyscallError> {
        let files = self.files.lock();
        let entry = files.get(&file_id).ok_or(SyscallError::BadHandle)?;
        match &entry.kind {
            Kind::Info { text, .. } => Ok(text.len() as u64),
            _ => Ok(0),
        }
    }

    fn stat(&self, file_id: u64) -> Result<FileStat, SyscallError> {
        let files = self.files.lock();
        let entry = files.get(&file_id).ok_or(SyscallError::BadHandle)?;
        let st = match &entry.kind {
            Kind::Root => FileStat {
                st_ino: file_id,
                st_mode: 0o040555,
                st_nlink: 2,
                st_size: 0,
                st_blksize: 512,
                st_blocks: 0,
                ..FileStat::zeroed()
            },
            Kind::WorldDir(id) => {
                Self::world_alive(*id)?;
                FileStat {
                    st_ino: file_id,
                    st_mode: 0o040555,
                    st_nlink: 2,
                    st_size: 0,
                    st_blksize: 512,
                    st_blocks: 0,
                    ..FileStat::zeroed()
                }
            }
            Kind::Tx { world_id } => {
                Self::world_alive(*world_id)?;
                // Write-only device file.
                FileStat {
                    st_ino: file_id,
                    st_mode: 0o020222,
                    st_nlink: 1,
                    st_size: 0,
                    st_blksize: 1,
                    st_blocks: 0,
                    ..FileStat::zeroed()
                }
            }
            Kind::Rx { world_id } => {
                Self::world_alive(*world_id)?;
                // Read-only device file.
                FileStat {
                    st_ino: file_id,
                    st_mode: 0o020444,
                    st_nlink: 1,
                    st_size: 0,
                    st_blksize: 1,
                    st_blocks: 0,
                    ..FileStat::zeroed()
                }
            }
            Kind::Info { world_id, text } => {
                Self::world_alive(*world_id)?;
                FileStat {
                    st_ino: file_id,
                    st_mode: 0o020444,
                    st_nlink: 1,
                    st_size: text.len() as u64,
                    st_blksize: 1,
                    st_blocks: 0,
                    ..FileStat::zeroed()
                }
            }
        };
        Ok(finalize_pseudo_stat(st, DEV_VMM_NET, 1))
    }

    fn readdir(&self, file_id: u64) -> Result<alloc::vec::Vec<DirEntry>, SyscallError> {
        let files = self.files.lock();
        let entry = files.get(&file_id).ok_or(SyscallError::BadHandle)?;
        Self::dir_entries(&entry.kind)
    }
}

/// Registers the `vmm-net` scheme and mounts it on `/dev/vmm-net`.
///
/// Idempotent: a second call (component restart, re-init) treats an existing
/// registration or mount as a success.
///
/// The mount point is deliberately **not** `/net`: that prefix is the host
/// network namespace (a userspace strate binds it and `ipc_port.rs` replaces
/// the mount on hot restart). The relay therefore lives beside `/dev/vmm`;
/// the hardware network scheme mounted at `/dev/net` is left untouched.
pub fn init_vmm_net_scheme() -> Result<(), SyscallError> {
    let scheme: DynScheme = Arc::new(VmmNetScheme::new());
    match scheme_router::register_scheme("vmm-net", scheme) {
        Ok(_) => {}
        Err(SyscallError::AlreadyExists) => {}
        Err(error) => return Err(error),
    }
    match scheme_router::mount_scheme("vmm-net", "/dev/vmm-net") {
        Ok(()) => {
            log::info!("[vmm] Scheme at /dev/vmm-net/ (worlds <id>/{{tx,rx,info}})");
            Ok(())
        }
        // A mount is already present (e.g. a future dedicated relay mount):
        // keep it in place rather than silently shadowing it.
        Err(SyscallError::AlreadyExists) => {
            log::warn!("[vmm] /dev/vmm-net already mounted; keeping the existing scheme");
            Ok(())
        }
        Err(error) => Err(error),
    }
}
