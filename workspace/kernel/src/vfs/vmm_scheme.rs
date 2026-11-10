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

//! `/dev/vmm`: read-mostly user view of the s9vm engine, plus one minimal
//! control file.
//!
//! This scheme is the diagnostic mirror of the virtualization engine's
//! internal state. Lifecycle operations (create, configure, run, destroy)
//! remain exclusive to the `SYS_VMM_*` syscalls and their capabilities; the
//! single write path below only reproduces the pause/resume transitions the
//! engine already exposes to a privileged mirror reader.
//!
//! # Contents
//!
//! ```text
//! /dev/vmm/
//!   info               engine summary (snapshot taken at open)
//!   worlds             list of worlds, one line per world
//!   <id>/              directory: info, stats, timing, exits, vcpus, console, disk, control
//!   <id>/info          snapshot of a world
//!   <id>/stats         snapshot of every world counter (pause, vCPUs, queue)
//!   <id>/timing        exit-latency and exit-rate aggregates (TSC cycles)
//!   <id>/exits         exit-queue snapshot (pending count + oldest event peek)
//!   <id>/vcpus         per-vCPU diagnostic snapshot
//!   <id>/console       console stream (read drains output, write queues input)
//!   <id>/disk          raw block-device view (byte-addressed, read/write)
//!   <id>/control       write-only text command file (`pause`, `resume`)
//! ```
//!
//! # Control semantics (capability-free by design)
//!
//! `<id>/control` is a **write-only** device file that accepts exactly two
//! text commands, with trailing ASCII whitespace ignored:
//!
//! * `pause`  — sets the world's paused flag (`vm::pause`);
//! * `resume` — clears it (`vm::resume`).
//!
//! Each successful `write` returns the number of bytes consumed (the full
//! command buffer, whitespace included). An unknown command is rejected with
//! [`SyscallError::InvalidArgument`]; a world destroyed after the file was
//! opened yields [`SyscallError::NotFound`]; `read` is refused with
//! [`SyscallError::PermissionDenied`].
//!
//! This file is deliberately **capability-free**: it is only reachable through
//! the kernel-provided `/dev/vmm` mirror, and it can neither create, start,
//! configure nor destroy a world. The `SYS_VMM_*` syscalls remain authoritative
//! for lifecycle operations, so a future command added here must similarly
//! stay within a diagnostic/pause-resume scope and must never bypass the
//! syscall capability checks.
//!
//! # Read semantics
//!
//! Every file except `<id>/console`, `<id>/disk` and the write-only
//! `<id>/control` is a **snapshot** taken at open: reading is finite (EOF at
//! the end) and never blocks. Opening the file again produces a new snapshot,
//! which is also true for `<id>/stats`, `<id>/exits` and `<id>/vcpus`: they
//! report the state observed at open time.
//!
//! `<id>/console` is a **stream**, not a snapshot. Each `read` drains the
//! output the guest has produced since the previous read; a read that finds
//! the buffer empty returns 0 (end of stream for that read, not a permanent
//! end of file) and a later read can return data again. Opening the file does
//! not reset or discard pending output. A `write` queues guest console input
//! and returns the number of bytes accepted by the engine's bounded input
//! queue, which may be smaller than the request; if the queue is full and
//! nothing can be accepted, the write reports `EAGAIN` so a non-blocking
//! front-end can retry later.
//!
//! `<id>/disk` is a **raw, byte-addressed view of the world's block device**.
//! Reads and writes use the file's current offset (advanced per call); a read
//! stops at the end of the disk and returns 0, and a write is short when the
//! disk ends. This is a debug/import/export path, not a coherency protocol:
//! host I/O is not synchronized with the guest's own virtio requests. Pause
//! the world (`SYS_VMM_PAUSE`) before reading or writing the disk image if the
//! guest can touch its block device concurrently.
//!
//! # Exit queue ownership
//!
//! The exit queue is owned by the policy: it is consumed through
//! `SYS_VMM_EXIT_HANDLER`. `<id>/exits` is therefore strictly non-consuming:
//! it reports the pending depth and describes the **oldest** queued event with
//! `vm::peek_exit` only. `VmmExitEvent` carries the guest physical address,
//! access size/port/value and flags; it does not carry a guest RIP.
//!
//! Unknown paths return [`SyscallError::NotFound`].

use alloc::{collections::BTreeMap, string::String, sync::Arc};
use core::{
    fmt::Write,
    sync::atomic::{AtomicU64, Ordering},
};

use strat9_abi::vmm::exit_kind;

use crate::{
    s9vm::{self, vm},
    sync::SpinLock,
    syscall::error::SyscallError,
};

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

/// Content of an open file: root, world directory, text snapshot, stream,
/// raw block device or write-only control file.
enum Kind {
    /// Scheme root directory.
    Root,
    /// Directory of one world (`<id>`).
    WorldDir(u64),
    /// Finite text snapshot taken at open.
    Text(String),
    /// Live console of one world (read drains, write queues input).
    Console { world_id: u64 },
    /// Raw block device of one world, addressed by byte offset in `cursor`.
    Disk { world_id: u64 },
    /// Write-only text command file of one world (`pause` / `resume`).
    Control { world_id: u64 },
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
        let _ = writeln!(
            text,
            "engine={}",
            if detected { "detected" } else { "unavailable" }
        );
        let _ = writeln!(text, "active_cpus={}", s9vm::active_cpu_count());
        if !detected {
            let _ = writeln!(text, "vt_x=absent reason={}", s9vm::unavailable_reason());
        }
        let _ = writeln!(text, "worlds={}", vm::count());
        let _ = writeln!(text, "abi_version={}", strat9_abi::vmm::VMM_ABI_VERSION);
        let stats = vm::total_stats();
        let _ = writeln!(
            text,
            "runs={} policy_exits={} emulated_exits={}",
            stats.runs, stats.policy_exits, stats.emulated_exits
        );
        let _ = writeln!(
            text,
            "emulated_io={} emulated_mmio={} emulated_msr={}",
            stats.emulated_io, stats.emulated_mmio, stats.emulated_msr
        );
        let _ = writeln!(
            text,
            "injected_interrupts={} windows_armed={} timer_exits={}",
            stats.injected_interrupts, stats.windows_armed, stats.timer_exits
        );
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

    /// Writes every cumulative counter of one world.
    ///
    /// Uses only `core::fmt` integer formatting, so no intermediate buffer and
    /// no arithmetic can overflow.
    fn write_stats(text: &mut String, stats: &vm::WorldStats) {
        let _ = writeln!(text, "runs={}", stats.runs);
        let _ = writeln!(text, "policy_exits={}", stats.policy_exits);
        let _ = writeln!(text, "emulated_exits={}", stats.emulated_exits);
        let _ = writeln!(text, "emulated_io={}", stats.emulated_io);
        let _ = writeln!(text, "emulated_mmio={}", stats.emulated_mmio);
        let _ = writeln!(text, "emulated_msr={}", stats.emulated_msr);
        let _ = writeln!(text, "injected_interrupts={}", stats.injected_interrupts);
        let _ = writeln!(text, "windows_armed={}", stats.windows_armed);
        let _ = writeln!(text, "timer_exits={}", stats.timer_exits);
    }

    fn list_text() -> String {
        let mut text = String::new();
        for world in vm::list() {
            let name = core::str::from_utf8(world.name_slice()).unwrap_or("<non-utf8>");
            let stats = vm::stats(world.id).unwrap_or_default();
            let pending = vm::exit_count(world.id).unwrap_or(0);
            let _ = writeln!(
                text,
                "world {} name={} silo={} state={} paused={} vcpus={} pages={} \
                 pending_exits={} runs={} emulated={} policy_exits={}",
                world.id,
                name,
                world.silo_id,
                world.state,
                vm::is_paused(world.id),
                world.vcpu_count,
                world.mapped_pages,
                pending,
                stats.runs,
                stats.emulated_exits,
                stats.policy_exits
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
        let _ = writeln!(text, "paused={}", vm::is_paused(world.id));
        let _ = writeln!(text, "vcpus={}", world.vcpu_count);
        let _ = writeln!(text, "pages={}", world.mapped_pages);
        let _ = writeln!(
            text,
            "pending_exits={}",
            vm::exit_count(world.id).unwrap_or(0)
        );
        let stats = vm::stats(world.id).unwrap_or_default();
        Self::write_stats(&mut text, &stats);
        Ok(text)
    }

    /// Snapshot of every counter plus the lifecycle facts of one world.
    fn stats_text(id: u64) -> Result<String, SyscallError> {
        let world = vm::get(id).ok_or(SyscallError::NotFound)?;
        let stats = vm::stats(id).ok_or(SyscallError::NotFound)?;
        let name = core::str::from_utf8(world.name_slice()).unwrap_or("<non-utf8>");
        let mut text = String::new();
        let _ = writeln!(text, "world {}", world.id);
        let _ = writeln!(text, "name={}", name);
        let _ = writeln!(text, "silo={}", world.silo_id);
        let _ = writeln!(text, "state={}", world.state);
        let _ = writeln!(text, "paused={}", vm::is_paused(id));
        let _ = writeln!(
            text,
            "vcpus={}",
            vm::vcpu_count(id).unwrap_or(world.vcpu_count)
        );
        let _ = writeln!(text, "pages={}", world.mapped_pages);
        let _ = writeln!(text, "exit_queue_depth={}", vm::exit_count(id).unwrap_or(0));
        Self::write_stats(&mut text, &stats);
        Ok(text)
    }

    /// Timing snapshot of one world (exit latency and rate aggregates).
    ///
    /// Cycles are time-stamp counter ticks on the CPU that ran the vCPU; the
    /// reader must convert them with the host's TSC frequency. See the timing
    /// module documentation for what each class means and why asynchronous
    /// exits include the preceding guest time slice.
    fn timing_text(id: u64) -> Result<String, SyscallError> {
        let world = vm::get(id).ok_or(SyscallError::NotFound)?;
        let timing = vm::timing(id).ok_or(SyscallError::NotFound)?;
        let mut text = String::new();
        let _ = writeln!(text, "world {}", world.id);
        let _ = writeln!(text, "exits={}", timing.exits);
        let _ = writeln!(text, "mean_cycles={}", timing.mean_cycles);
        let _ = writeln!(text, "p95_cycles={}", timing.p95_cycles);
        let _ = writeln!(text, "min_cycles={}", timing.min_cycles);
        let _ = writeln!(text, "max_cycles={}", timing.max_cycles);
        let _ = writeln!(text, "window={}", timing.window);
        let _ = writeln!(text, "peak_window={}", timing.peak_window);
        let _ = writeln!(text, "handler_samples={}", timing.handler_samples);
        let _ = writeln!(text, "handler_mean_cycles={}", timing.handler_mean_cycles);
        let _ = writeln!(text, "handler_p95_cycles={}", timing.handler_p95_cycles);
        for (index, count) in timing.per_class.iter().enumerate() {
            let _ = writeln!(text, "class_{}={}", index, count);
        }
        Ok(text)
    }

    /// Human-readable name of an ABI exit kind.
    fn exit_kind_name(kind: u32) -> &'static str {
        match kind {
            exit_kind::MMIO_READ => "mmio_read",
            exit_kind::MMIO_WRITE => "mmio_write",
            exit_kind::IO_PORT => "io_port",
            exit_kind::HALT => "halt",
            exit_kind::TRANSLATION => "translation",
            exit_kind::EXCEPTION => "exception",
            exit_kind::PREEMPTION_TIMER => "preemption_timer",
            exit_kind::OTHER => "other",
            _ => "unknown",
        }
    }

    /// Non-consuming snapshot of the exit queue of one world.
    ///
    /// The queue belongs to the policy; only `vm::peek_exit` is used, so the
    /// oldest event is described without being removed.
    fn exits_text(id: u64) -> Result<String, SyscallError> {
        if vm::get(id).is_none() {
            return Err(SyscallError::NotFound);
        }
        let pending = vm::exit_count(id).ok_or(SyscallError::NotFound)?;
        let mut text = String::new();
        let _ = writeln!(text, "world={}", id);
        let _ = writeln!(text, "pending={}", pending);
        match vm::peek_exit(id) {
            Ok(event) => {
                let _ = writeln!(
                    text,
                    "last_event=kind={} kind_id={} vcpu={} gpa={:#x} size={} \
                     port={:#x} value={:#x} flags={:#x}",
                    Self::exit_kind_name(event.kind),
                    event.kind,
                    event.vcpu_id,
                    event.gpa,
                    event.size,
                    event.port,
                    event.value,
                    event.flags
                );
            }
            Err(()) => {
                let _ = writeln!(text, "last_event=none");
            }
        }
        Ok(text)
    }

    /// Finite snapshot of every logical vCPU of one world.
    fn vcpus_text(id: u64) -> Result<String, SyscallError> {
        let snapshots = vm::vcpu_snapshots(id).ok_or(SyscallError::NotFound)?;
        let mut text = String::new();
        let _ = writeln!(text, "world={}", id);
        let _ = writeln!(text, "vcpus={}", snapshots.len());
        for vcpu in &snapshots {
            let _ = writeln!(
                text,
                "vcpu id={} apic_id={} hardware_ready={} executing={} pending_nmi={}",
                vcpu.id, vcpu.apic_id, vcpu.hardware_ready, vcpu.executing, vcpu.pending_nmi
            );
        }
        Ok(text)
    }

    /// Reads disk bytes starting at byte `offset`.
    ///
    /// The engine API is sector-addressed, so the first and last sectors are
    /// read into a scratch buffer and only the requested byte range is copied.
    fn disk_read_at(world_id: u64, offset: u64, buf: &mut [u8]) -> Result<usize, SyscallError> {
        let mut scratch = [0u8; 512];
        let mut done = 0usize;
        while done < buf.len() {
            let absolute = offset
                .checked_add(done as u64)
                .ok_or(SyscallError::InvalidArgument)?;
            let sector = absolute / 512;
            let in_sector = (absolute % 512) as usize;
            let copied = vm::read_disk(world_id, sector, &mut scratch[in_sector..])
                .map_err(|()| SyscallError::NotFound)?;
            if copied == 0 {
                break; // end of disk
            }
            let take = core::cmp::min(copied, buf.len() - done);
            buf[done..done + take].copy_from_slice(&scratch[in_sector..in_sector + take]);
            done += take;
            if take < copied {
                break; // caller buffer full
            }
        }
        Ok(done)
    }

    /// Writes disk bytes starting at byte `offset`.
    ///
    /// Unaligned ranges use a read-modify-write on the touched sector; the
    /// engine itself is sector-addressed.
    fn disk_write_at(world_id: u64, offset: u64, data: &[u8]) -> Result<usize, SyscallError> {
        let mut scratch = [0u8; 512];
        let mut done = 0usize;
        while done < data.len() {
            let absolute = offset
                .checked_add(done as u64)
                .ok_or(SyscallError::InvalidArgument)?;
            let sector = absolute / 512;
            let in_sector = (absolute % 512) as usize;
            let room = 512 - in_sector;
            let take = core::cmp::min(room, data.len() - done);
            // Read the existing sector so bytes outside the written range are
            // preserved; a sector past the end yields 0 and the write stops.
            let existing = vm::read_disk(world_id, sector, &mut scratch)
                .map_err(|()| SyscallError::NotFound)?;
            if existing == 0 {
                break; // nothing beyond the end of the disk
            }
            scratch[in_sector..in_sector + take].copy_from_slice(&data[done..done + take]);
            let written =
                vm::write_disk(world_id, sector, &scratch).map_err(|()| SyscallError::NotFound)?;
            if written <= in_sector {
                break; // no room left in the disk
            }
            let accepted = core::cmp::min(written - in_sector, take);
            done += accepted;
            if accepted < take {
                break; // short write at the end of the disk
            }
        }
        Ok(done)
    }

    /// Parses one `<id>/control` command buffer.
    ///
    /// Trailing ASCII whitespace is ignored, so `"pause\n"` sent by a console
    /// front-end is accepted. The command vocabulary is ASCII and closed:
    /// invalid UTF-8 and any other text are [`SyscallError::InvalidArgument`].
    fn control_command(buf: &[u8]) -> Result<&'static str, SyscallError> {
        let text = core::str::from_utf8(buf).map_err(|_| SyscallError::InvalidArgument)?;
        match text.trim_end_matches(|c: char| c.is_ascii_whitespace()) {
            "pause" => Ok("pause"),
            "resume" => Ok("resume"),
            _ => Err(SyscallError::InvalidArgument),
        }
    }

    /// Resolves a non-directory path to the content of an open file.
    fn text_for_path(path: &str) -> Result<String, SyscallError> {
        match path {
            "info" => Ok(Self::engine_text()),
            "worlds" => Ok(Self::list_text()),
            _ => {
                if let Some((id_text, leaf)) = path.split_once('/') {
                    if let Ok(id) = id_text.parse::<u64>() {
                        return match leaf {
                            "info" => Self::world_text(id),
                            "stats" => Self::stats_text(id),
                            "timing" => Self::timing_text(id),
                            "exits" => Self::exits_text(id),
                            "vcpus" => Self::vcpus_text(id),
                            _ => Err(SyscallError::NotFound),
                        };
                    }
                }
                Err(SyscallError::NotFound)
            }
        }
    }

    /// Builds the open-file kind for a path.
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
        if let Some(id_text) = path.strip_suffix("/console") {
            if let Ok(id) = id_text.parse::<u64>() {
                if vm::get(id).is_none() {
                    return Err(SyscallError::NotFound);
                }
                return Ok((Kind::Console { world_id: id }, FileFlags::DEVICE));
            }
        }
        if let Some(id_text) = path.strip_suffix("/control") {
            if let Ok(id) = id_text.parse::<u64>() {
                if vm::get(id).is_none() {
                    return Err(SyscallError::NotFound);
                }
                return Ok((Kind::Control { world_id: id }, FileFlags::DEVICE));
            }
        }
        if let Some(id_text) = path.strip_suffix("/disk") {
            if let Ok(id) = id_text.parse::<u64>() {
                if vm::disk_sectors(id).is_none() {
                    return Err(SyscallError::NotFound);
                }
                return Ok((Kind::Disk { world_id: id }, FileFlags::DEVICE));
            }
        }
        Ok((Kind::Text(Self::text_for_path(path)?), FileFlags::DEVICE))
    }

    /// Directory entries for the root or for one world.
    fn dir_entries(kind: &Kind) -> Result<alloc::vec::Vec<DirEntry>, SyscallError> {
        let mut entries = match kind {
            Kind::Root => alloc::vec![
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
            ],
            Kind::WorldDir(id) => {
                if vm::get(*id).is_none() {
                    return Err(SyscallError::NotFound);
                }
                alloc::vec![
                    DirEntry {
                        ino: 0,
                        file_type: DT_REG,
                        name: String::from("console"),
                    },
                    DirEntry {
                        ino: 0,
                        file_type: DT_REG,
                        name: String::from("control"),
                    },
                    DirEntry {
                        ino: 0,
                        file_type: DT_REG,
                        name: String::from("disk"),
                    },
                    DirEntry {
                        ino: 0,
                        file_type: DT_REG,
                        name: String::from("exits"),
                    },
                    DirEntry {
                        ino: 0,
                        file_type: DT_REG,
                        name: String::from("info"),
                    },
                    DirEntry {
                        ino: 0,
                        file_type: DT_REG,
                        name: String::from("stats"),
                    },
                    DirEntry {
                        ino: 0,
                        file_type: DT_REG,
                        name: String::from("timing"),
                    },
                    DirEntry {
                        ino: 0,
                        file_type: DT_REG,
                        name: String::from("vcpus"),
                    },
                ]
            }
            Kind::Text(_) | Kind::Console { .. } | Kind::Disk { .. } | Kind::Control { .. } => {
                return Err(SyscallError::NotADirectory)
            }
        };
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
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
            Self::kind_for_path(path)?
        };
        let file_id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        self.files
            .lock()
            .insert(file_id, VmmFile { kind, cursor: 0 });
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
            Kind::WorldDir(id) => {
                // A world can be destroyed while its directory stays open.
                if vm::get(*id).is_none() {
                    return Err(SyscallError::NotFound);
                }
                Err(SyscallError::IsADirectory)
            }
            Kind::Text(text) => {
                let n = serve_text(text.as_bytes(), entry.cursor, buf);
                entry.cursor += n as u64;
                Ok(n)
            }
            Kind::Console { world_id } => {
                // Streaming read: drain what the guest produced since the last
                // call. `0` means "nothing pending for this read", not a
                // permanent end of file.
                let world_id = *world_id;
                vm::read_console_output(world_id, buf).map_err(|()| SyscallError::NotFound)
            }
            Kind::Disk { world_id } => {
                let world_id = *world_id;
                let n = Self::disk_read_at(world_id, entry.cursor, buf)?;
                entry.cursor += n as u64;
                Ok(n)
            }
            // `<id>/control` is write-only: no read path exists.
            Kind::Control { .. } => Err(SyscallError::PermissionDenied),
        }
    }

    fn write(&self, file_id: u64, _offset: u64, buf: &[u8]) -> Result<usize, SyscallError> {
        let mut files = self.files.lock();
        let entry = files.get_mut(&file_id).ok_or(SyscallError::BadHandle)?;
        match &mut entry.kind {
            Kind::Console { world_id } => {
                let world_id = *world_id;
                // Returns the number of bytes accepted by the bounded input
                // queue; a short write means the queue is full. When nothing
                // at all can be accepted, report `EAGAIN` so a non-blocking
                // console front-end can retry later instead of spinning.
                let accepted =
                    vm::push_console_input(world_id, buf).map_err(|()| SyscallError::NotFound)?;
                if accepted == 0 && !buf.is_empty() {
                    return Err(SyscallError::Again);
                }
                Ok(accepted)
            }
            Kind::Disk { world_id } => {
                let world_id = *world_id;
                // Raw byte-addressed write; a short count means the end of the
                // disk was reached. Guest I/O is not synchronized: pause the
                // world first when coherency matters.
                let n = Self::disk_write_at(world_id, entry.cursor, buf)?;
                entry.cursor += n as u64;
                Ok(n)
            }
            Kind::Control { world_id } => {
                let world_id = *world_id;
                // A zero-length write carries no command: accept it as a
                // conventional no-op instead of rejecting it as unknown text.
                if buf.is_empty() {
                    return Ok(0);
                }
                // Check existence first so a destroyed world reports NotFound
                // even when the command text is also invalid.
                if vm::get(world_id).is_none() {
                    return Err(SyscallError::NotFound);
                }
                let command = Self::control_command(buf)?;
                let outcome = match command {
                    "pause" => vm::pause(world_id),
                    _ => vm::resume(world_id),
                };
                // The engine reports `VmError::Unknown` for a world that
                // vanished or is closing; both map to NotFound here.
                outcome.map_err(|_| SyscallError::NotFound)?;
                log::info!("[vmm] world {} control: {}", world_id, command);
                // Report the whole command buffer as consumed, including the
                // trailing whitespace that was ignored.
                Ok(buf.len())
            }
            // Every other file is a read-only diagnostic snapshot.
            Kind::Root | Kind::WorldDir(_) | Kind::Text(_) => Err(SyscallError::PermissionDenied),
        }
    }

    fn close(&self, file_id: u64) -> Result<(), SyscallError> {
        self.files.lock().remove(&file_id);
        Ok(())
    }

    fn stat(&self, file_id: u64) -> Result<FileStat, SyscallError> {
        let files = self.files.lock();
        let entry = files.get(&file_id).ok_or(SyscallError::BadHandle)?;
        let st = match &entry.kind {
            Kind::Root | Kind::WorldDir(_) => FileStat {
                st_ino: file_id,
                st_mode: 0o040555,
                st_nlink: 2,
                st_size: 0,
                st_blksize: 512,
                st_blocks: 0,
                ..FileStat::zeroed()
            },
            Kind::Disk { world_id } => {
                let sectors = vm::disk_sectors(*world_id).ok_or(SyscallError::NotFound)?;
                let capacity = sectors.saturating_mul(512);
                FileStat {
                    st_ino: file_id,
                    st_mode: 0o020666,
                    st_nlink: 1,
                    st_size: capacity,
                    st_blksize: 512,
                    st_blocks: capacity / 512,
                    ..FileStat::zeroed()
                }
            }
            Kind::Console { .. } => FileStat {
                st_ino: file_id,
                st_mode: 0o020666,
                st_nlink: 1,
                st_size: 0,
                st_blksize: 1,
                st_blocks: 0,
                ..FileStat::zeroed()
            },
            // Write-only device: no read permission for the owner either.
            Kind::Control { .. } => FileStat {
                st_ino: file_id,
                st_mode: 0o020200,
                st_nlink: 1,
                st_size: 0,
                st_blksize: 1,
                st_blocks: 0,
                ..FileStat::zeroed()
            },
            Kind::Text(_) => FileStat {
                st_ino: file_id,
                st_mode: 0o020444,
                st_nlink: 1,
                st_size: 0,
                st_blksize: 1,
                st_blocks: 0,
                ..FileStat::zeroed()
            },
        };
        Ok(finalize_pseudo_stat(st, DEV_VMM, 1))
    }

    fn readdir(&self, file_id: u64) -> Result<alloc::vec::Vec<DirEntry>, SyscallError> {
        let files = self.files.lock();
        let entry = files.get(&file_id).ok_or(SyscallError::BadHandle)?;
        Self::dir_entries(&entry.kind)
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
            log::info!(
                "[vmm] Scheme at /dev/vmm/ \
                 (info, worlds, <id>/{{info,stats,timing,exits,vcpus,console,disk,control}})"
            );
            Ok(())
        }
        Err(SyscallError::AlreadyExists) => Ok(()),
        Err(error) => Err(error),
    }
}
