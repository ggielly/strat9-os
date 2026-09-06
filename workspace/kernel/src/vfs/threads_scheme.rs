//! ThreadsScheme — Plan 9 style `/thread` control files.
//!
//! Exposes the userspace thread API as filesystem operations. All lifecycle
//! work is forwarded to [`crate::process::thread_ops`], the exact same
//! internals as `SYS_THREAD_CREATE/JOIN/EXIT`, so both entry points share one
//! implementation (single reap loop, single validation rules).
//!
//! # File layout
//!
//! ```text
//! /thread/            directory: TIDs of the calling process' threads
//!   create    write   32-byte ThreadCreateRequest -> read back TID (u32 LE)
//!   join/<tid>read    blocks until <tid> exits -> exit code (i32 LE)
//!                     EINVAL self-join, ENOENT absent/already-joined
//!                     (=> a second open of join/<tid> fails; documented)
//!   exit      write   exit code (i32 LE); kills current thread, no return
//!   current   read    caller's TID (u32 LE), resolved at read time
//!   yield     read    sched_yield; fd shareable across threads
//!   kill/<tid>open    terminates <tid>; ESRCH absent, EPERM cross-process
//!   stats     read    kernel-owned stack counters ("allocated N", "active M")
//! ```

use crate::{
    process::{current_task_clone, get_all_tasks, thread_ops},
    sync::SpinLock,
    syscall::error::SyscallError,
};
use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

/// Operation encoded in the high bits of a file_id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Root = 0,
    Create = 1,
    Join = 2,
    Exit = 3,
    Current = 4,
    Yield = 5,
    Kill = 6,
    Stats = 7,
}

/// Per-fd state retained between open/write/read.
#[derive(Clone)]
enum OpState {
    Root,
    /// Remembers the TID produced by write() so read() can hand it back.
    Create {
        created_tid: Option<u32>,
    },
    Join {
        target_tid: u32,
    },
    Static(Op),
}

fn op_of(state: &OpState) -> Op {
    match state {
        OpState::Root => Op::Root,
        OpState::Create { .. } => Op::Create,
        OpState::Join { .. } => Op::Join,
        OpState::Static(op) => *op,
    }
}

/// Binary protocol for `/thread/create` writes.
///
/// ```text
/// #[repr(C)] struct ThreadCreateRequest {
///     entry: u64,       // user trampoline address (< USER_TOP)
///     stack_size: u64,  // requested size; kernel allocates and places RSP
///     arg0: u64,        // passed in RDI (e.g. closure pointer)
///     tls_base: u64,    // FS.base (0 = none)
/// }
/// // write(fd, &req, 32) then read(fd, &tid, 4)
/// ```
const THREAD_CREATE_REQ_LEN: usize = 32;

pub struct ThreadsScheme {
    states: SpinLock<BTreeMap<u64, OpState>>,
}

impl ThreadsScheme {
    /// Creates a new instance.
    pub fn new() -> Self {
        ThreadsScheme {
            states: SpinLock::new(BTreeMap::new()),
        }
    }

    fn alloc_file_id(op: Op) -> u64 {
        static NEXT_SEQ: AtomicU64 = AtomicU64::new(1);
        let seq = NEXT_SEQ.fetch_add(1, Ordering::Relaxed);
        ((op as u64) << 32) | (seq & 0xFFFF_FFFF)
    }

    fn state_for(&self, file_id: u64) -> Result<(Op, OpState), SyscallError> {
        let states = self.states.lock();
        let st = states
            .get(&file_id)
            .cloned()
            .ok_or(SyscallError::BadHandle)?;
        drop(states);
        Ok((op_of(&st), st))
    }

    fn take_state(&self, file_id: u64) -> Result<OpState, SyscallError> {
        self.states
            .lock()
            .remove(&file_id)
            .ok_or(SyscallError::BadHandle)
    }

    /// Parse `join/<tid>` and validate kinship synchronously so errors surface
    /// at open time (self-join => EINVAL, missing/reaped child => ENOENT).
    ///
    /// The blocking reap itself happens on read(), via [`thread_ops::join_task`].
    fn parse_join(path: &str) -> Result<u32, SyscallError> {
        let tid_str = path.strip_prefix("join/").ok_or(SyscallError::NotFound)?;
        if tid_str.is_empty() || !tid_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err(SyscallError::InvalidArgument);
        }
        let target_tid: u32 = tid_str.parse().map_err(|_| SyscallError::InvalidArgument)?;

        let cur = current_task_clone().ok_or(SyscallError::Fault)?;
        if target_tid == cur.tid {
            return Err(SyscallError::InvalidArgument);
        }
        use crate::process::{current_task_id, get_child_task_id_by_tid};
        let parent_id = current_task_id().ok_or(SyscallError::Fault)?;
        get_child_task_id_by_tid(parent_id, target_tid).ok_or(SyscallError::NotFound)?;
        Ok(target_tid)
    }

    /// Parse `kill/<tid>`; the kill itself is performed by open() (Plan 9
    /// style: opening the control file performs the action). Errors:
    /// ESRCH unknown tid, EPERM other thread group.
    fn handle_kill_open(path: &str) -> Result<(), SyscallError> {
        let tid_str = path.strip_prefix("kill/").ok_or(SyscallError::NotFound)?;
        if tid_str.is_empty() || !tid_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err(SyscallError::InvalidArgument);
        }
        let target_tid: u32 = tid_str.parse().map_err(|_| SyscallError::InvalidArgument)?;
        let cur = current_task_clone().ok_or(SyscallError::Fault)?;
        thread_ops::kill_thread(cur.tid, target_tid)
    }

    /// Directory listing of the calling process' threads (pattern procfs).
    fn root_listing(&self) -> Result<String, SyscallError> {
        let cur = current_task_clone().ok_or(SyscallError::Fault)?;
        let mut out = String::new();
        if let Some(tasks) = get_all_tasks() {
            for t in tasks {
                if t.tgid == cur.tgid {
                    out.push_str(itoa_u32(t.tid).as_str());
                    out.push('\n');
                }
            }
        }
        Ok(out)
    }

    /// Handle a write to `/thread/create`: parse the request, build the task
    /// with a kernel-owned stack, register it, and remember its TID.
    fn handle_create_write(&self, buf: &[u8]) -> Result<u32, SyscallError> {
        if buf.len() != THREAD_CREATE_REQ_LEN {
            return Err(SyscallError::InvalidArgument);
        }
        let req_le = |i: usize| {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&buf[i..i + 8]);
            u64::from_le_bytes(raw)
        };
        let entry = req_le(0);
        let stack_size = req_le(8);
        let arg0 = req_le(16);
        let tls_base = req_le(24);

        let child = thread_ops::create_user_thread_with_kernel_stack(
            thread_ops::UserEntryContext::ring3(),
            entry,
            stack_size,
            arg0,
            tls_base,
        )?;
        Ok(child.tid)
    }
}

impl Default for ThreadsScheme {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimal decimal formatter (no formatting machinery in hot paths).
fn itoa_u32(mut v: u32) -> String {
    if v == 0 {
        return String::from("0");
    }
    let mut buf = [0u8; 10];
    let mut i = buf.len();
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    // SAFETY: buffer content is ASCII digits by construction.
    String::from(unsafe { core::str::from_utf8_unchecked(&buf[i..]) })
}

use crate::vfs::scheme::{
    finalize_pseudo_stat, DirEntry, FileFlags, FileStat, OpenFlags, OpenResult, Scheme,
    DEV_THREADFS, DT_DIR, DT_REG,
};

impl Scheme for ThreadsScheme {
    fn open(&self, path: &str, _flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        // Normalize: strip leading '/' (mount layer already stripped prefix).
        let path = path.trim_start_matches('/');

        let (op, state) = match path {
            "" | "/" => (Op::Root, OpState::Root),
            "create" => (Op::Create, OpState::Create { created_tid: None }),
            "exit" => (Op::Exit, OpState::Static(Op::Exit)),
            "current" => (Op::Current, OpState::Static(Op::Current)),
            "yield" => (Op::Yield, OpState::Static(Op::Yield)),
            "stats" => (Op::Stats, OpState::Static(Op::Stats)),
            p if p.starts_with("join/") => {
                let target = Self::parse_join(p)?;
                (Op::Join, OpState::Join { target_tid: target })
            }
            p if p.starts_with("kill/") => {
                Self::handle_kill_open(p)?;
                (Op::Kill, OpState::Static(Op::Kill))
            }
            _ => return Err(SyscallError::NotFound),
        };

        let file_id = Self::alloc_file_id(op);
        self.states.lock().insert(file_id, state);

        let flags = if op == Op::Root {
            FileFlags::DIRECTORY
        } else {
            FileFlags::empty()
        };
        Ok(OpenResult {
            file_id,
            size: None,
            flags,
        })
    }

    fn read(&self, file_id: u64, offset: u64, buf: &mut [u8]) -> Result<usize, SyscallError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let (_, state) = self.state_for(file_id)?;

        match state {
            OpState::Root => {
                let content = self.root_listing()?;
                serve_string(&content, offset, buf)
            }
            OpState::Create { created_tid } => {
                let Some(tid) = created_tid else {
                    // read before write: protocol violation.
                    return Err(SyscallError::InvalidArgument);
                };
                if offset != 0 {
                    return Ok(0);
                }
                let bytes = tid.to_le_bytes();
                let n = bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                Ok(n)
            }
            OpState::Join { target_tid } => {
                // Blocking reap loop shared with SYS_THREAD_JOIN.
                let (_tid, status) = thread_ops::join_task(target_tid)?;
                if offset != 0 {
                    return Ok(0);
                }
                let bytes = status.to_le_bytes();
                let n = bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                Ok(n)
            }
            OpState::Static(op) => match op {
                Op::Current => {
                    let tid = thread_ops::current_thread_tid()?;
                    if offset != 0 {
                        return Ok(0);
                    }
                    let bytes = tid.to_le_bytes();
                    let n = bytes.len().min(buf.len());
                    buf[..n].copy_from_slice(&bytes[..n]);
                    Ok(n)
                }
                Op::Yield => {
                    crate::process::yield_task();
                    Ok(0)
                }
                Op::Kill => Ok(0),
                Op::Stats => {
                    let (allocated, active) = thread_ops::kernel_user_stack_stats();
                    let mut content = String::from("allocated ");
                    content.push_str(itoa_u32(allocated as u32).as_str());
                    content.push('\n');
                    content.push_str("active ");
                    content.push_str(itoa_u32(active as u32).as_str());
                    content.push('\n');
                    serve_string(&content, offset, buf)
                }
                _ => Err(SyscallError::PermissionDenied),
            },
        }
    }

    fn write(&self, file_id: u64, _offset: u64, buf: &[u8]) -> Result<usize, SyscallError> {
        let (op, _) = self.state_for(file_id)?;
        match op {
            Op::Create => {
                let tid = self.handle_create_write(buf)?;
                if let Some(OpState::Create { created_tid }) = self.states.lock().get_mut(&file_id)
                {
                    *created_tid = Some(tid);
                } else {
                    return Err(SyscallError::BadHandle);
                }
                Ok(THREAD_CREATE_REQ_LEN)
            }
            Op::Exit => {
                if buf.len() < 4 {
                    return Err(SyscallError::InvalidArgument);
                }
                let code = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                // Never returns.
                thread_ops::exit_current_thread(code)
            }
            _ => Err(SyscallError::PermissionDenied),
        }
    }

    fn close(&self, file_id: u64) -> Result<(), SyscallError> {
        self.take_state(file_id)?;
        Ok(())
    }

    fn stat(&self, file_id: u64) -> Result<FileStat, SyscallError> {
        let op = (file_id >> 32) as u64;
        let is_dir = op == Op::Root as u64;
        let st = if is_dir {
            FileStat {
                st_ino: file_id,
                st_mode: 0o040555,
                st_nlink: 2,
                ..FileStat::zeroed()
            }
        } else {
            FileStat {
                st_ino: file_id,
                st_mode: 0o100666,
                st_nlink: 1,
                ..FileStat::zeroed()
            }
        };
        Ok(finalize_pseudo_stat(st, DEV_THREADFS, 0))
    }

    fn readdir(&self, _file_id: u64) -> Result<Vec<DirEntry>, SyscallError> {
        Ok(alloc::vec![
            DirEntry {
                ino: Self::alloc_file_id(Op::Create),
                file_type: DT_REG,
                name: String::from("create"),
            },
            DirEntry {
                ino: Self::alloc_file_id(Op::Join),
                file_type: DT_DIR,
                name: String::from("join"),
            },
            DirEntry {
                ino: Self::alloc_file_id(Op::Exit),
                file_type: DT_REG,
                name: String::from("exit"),
            },
            DirEntry {
                ino: Self::alloc_file_id(Op::Current),
                file_type: DT_REG,
                name: String::from("current"),
            },
            DirEntry {
                ino: Self::alloc_file_id(Op::Yield),
                file_type: DT_REG,
                name: String::from("yield"),
            },
            DirEntry {
                ino: Self::alloc_file_id(Op::Kill),
                file_type: DT_DIR,
                name: String::from("kill"),
            },
            DirEntry {
                ino: Self::alloc_file_id(Op::Stats),
                file_type: DT_REG,
                name: String::from("stats"),
            },
        ])
    }
}

/// Serve string content honoring read offsets (procfs pattern).
fn serve_string(content: &str, offset: u64, buf: &mut [u8]) -> Result<usize, SyscallError> {
    if offset >= content.len() as u64 {
        return Ok(0);
    }
    let start = offset as usize;
    let end = core::cmp::min(start + buf.len(), content.len());
    buf[..end - start].copy_from_slice(&content.as_bytes()[start..end]);
    Ok(end - start)
}

/// Convenience constructor matching the other scheme registration sites.
pub fn init_threads_scheme() -> Arc<ThreadsScheme> {
    Arc::new(ThreadsScheme::new())
}
