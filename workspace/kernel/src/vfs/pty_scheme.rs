//! Pseudo-terminal (PTY) scheme.
//!
//! A PTY pair consists of a **master** (controlling process) and a **slave**
//! (child process).  Data written to one side is readable from the other.
//!
//! # Scheme paths
//!
//! | Path          | Description                                 |
//! |---------------|---------------------------------------------|
//! | `/dev/pts/new`| Open to allocate a new PTY pair (returns master fd). |
//! | `/dev/pts/N`  | Open the slave side of PTY number N.        |
//! | `/dev/pts/`   | List existing PTYs.                         |

use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::{sync::SpinLock, syscall::error::SyscallError};

use super::scheme::{DirEntry, FileFlags, FileStat, OpenFlags, OpenResult, Scheme, DT_CHR};

const PTY_BUF_SIZE: usize = 4096;

/// Ring buffer used for each direction of a PTY pair.
struct RingBuf {
    buf: [u8; PTY_BUF_SIZE],
    head: usize,
    tail: usize,
    count: usize,
}

impl RingBuf {
    const fn new() -> Self {
        Self {
            buf: [0; PTY_BUF_SIZE],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    fn push(&mut self, data: &[u8]) -> usize {
        let mut written = 0;
        for &b in data {
            if self.count >= PTY_BUF_SIZE {
                break;
            }
            self.buf[self.tail] = b;
            self.tail = (self.tail + 1) % PTY_BUF_SIZE;
            self.count += 1;
            written += 1;
        }
        written
    }

    fn pop(&mut self, out: &mut [u8]) -> usize {
        let mut read = 0;
        for slot in out.iter_mut() {
            if self.count == 0 {
                break;
            }
            *slot = self.buf[self.head];
            self.head = (self.head + 1) % PTY_BUF_SIZE;
            self.count -= 1;
            read += 1;
        }
        read
    }
}

/// State of a single PTY pair.
struct PtyPair {
    /// Data written by master, read by slave.
    to_slave: RingBuf,
    /// Data written by slave, read by master.
    to_master: RingBuf,
    master_open: bool,
    slave_open: bool,
}

/// Manages all PTY pairs.
pub struct PtyScheme {
    pairs: SpinLock<BTreeMap<u64, PtyPair>>,
    next_pty: AtomicU64,
    next_fid: AtomicU64,
    /// Maps file_id → (pty_id, is_master).
    handles: SpinLock<BTreeMap<u64, (u64, bool)>>,
}

impl PtyScheme {
    /// Create a new PTY scheme instance.
    pub fn new() -> Self {
        Self {
            pairs: SpinLock::new(BTreeMap::new()),
            next_pty: AtomicU64::new(0),
            next_fid: AtomicU64::new(1),
            handles: SpinLock::new(BTreeMap::new()),
        }
    }

    fn alloc_fid(&self) -> u64 {
        self.next_fid.fetch_add(1, Ordering::Relaxed)
    }
}

impl Scheme for PtyScheme {
    fn open(&self, path: &str, _flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        let path = path.trim_start_matches('/');

        if path == "new" {
            let pty_id = self.next_pty.fetch_add(1, Ordering::Relaxed);
            let pair = PtyPair {
                to_slave: RingBuf::new(),
                to_master: RingBuf::new(),
                master_open: true,
                slave_open: false,
            };
            self.pairs.lock().insert(pty_id, pair);

            let fid = self.alloc_fid();
            self.handles.lock().insert(fid, (pty_id, true));

            Ok(OpenResult {
                file_id: fid,
                size: None,
                flags: FileFlags::DEVICE,
            })
        } else if let Ok(pty_id) = path.parse::<u64>() {
            let mut pairs = self.pairs.lock();
            let pair = pairs.get_mut(&pty_id).ok_or(SyscallError::NotFound)?;
            pair.slave_open = true;

            let fid = self.alloc_fid();
            self.handles.lock().insert(fid, (pty_id, false));

            Ok(OpenResult {
                file_id: fid,
                size: None,
                flags: FileFlags::DEVICE,
            })
        } else if path.is_empty() {
            let fid = self.alloc_fid();
            self.handles.lock().insert(fid, (u64::MAX, false));
            Ok(OpenResult {
                file_id: fid,
                size: None,
                flags: FileFlags::DIRECTORY,
            })
        } else {
            Err(SyscallError::NotFound)
        }
    }

    fn read(&self, file_id: u64, _offset: u64, buf: &mut [u8]) -> Result<usize, SyscallError> {
        let (pty_id, is_master) = {
            let handles = self.handles.lock();
            *handles.get(&file_id).ok_or(SyscallError::BadHandle)?
        };

        if pty_id == u64::MAX {
            return self.readdir_root(buf);
        }

        let mut pairs = self.pairs.lock();
        let pair = pairs.get_mut(&pty_id).ok_or(SyscallError::BadHandle)?;

        let ring = if is_master {
            &mut pair.to_master
        } else {
            &mut pair.to_slave
        };
        let n = ring.pop(buf);
        Ok(n)
    }

    fn write(&self, file_id: u64, _offset: u64, buf: &[u8]) -> Result<usize, SyscallError> {
        let (pty_id, is_master) = {
            let handles = self.handles.lock();
            *handles.get(&file_id).ok_or(SyscallError::BadHandle)?
        };

        let mut pairs = self.pairs.lock();
        let pair = pairs.get_mut(&pty_id).ok_or(SyscallError::BadHandle)?;

        let ring = if is_master {
            &mut pair.to_slave
        } else {
            &mut pair.to_master
        };
        let n = ring.push(buf);
        Ok(n)
    }

    fn close(&self, file_id: u64) -> Result<(), SyscallError> {
        let entry = self.handles.lock().remove(&file_id);
        if let Some((pty_id, is_master)) = entry {
            if pty_id != u64::MAX {
                let mut pairs = self.pairs.lock();
                if let Some(pair) = pairs.get_mut(&pty_id) {
                    if is_master {
                        pair.master_open = false;
                    } else {
                        pair.slave_open = false;
                    }
                    if !pair.master_open && !pair.slave_open {
                        pairs.remove(&pty_id);
                    }
                }
            }
        }
        Ok(())
    }

    fn stat(&self, file_id: u64) -> Result<FileStat, SyscallError> {
        let handles = self.handles.lock();
        let &(pty_id, _) = handles.get(&file_id).ok_or(SyscallError::BadHandle)?;
        let mut st = FileStat::zeroed();
        if pty_id == u64::MAX {
            st.st_mode = 0o40755;
        } else {
            st.st_mode = 0o20666;
            st.st_ino = pty_id;
        }
        st.st_nlink = 1;
        Ok(st)
    }

    fn readdir(&self, _file_id: u64) -> Result<Vec<DirEntry>, SyscallError> {
        let pairs = self.pairs.lock();
        let mut entries = Vec::new();
        for &pty_id in pairs.keys() {
            entries.push(DirEntry {
                ino: pty_id,
                file_type: DT_CHR,
                name: alloc::format!("{}", pty_id),
            });
        }
        Ok(entries)
    }
}

impl PtyScheme {
    fn readdir_root(&self, buf: &mut [u8]) -> Result<usize, SyscallError> {
        let pairs = self.pairs.lock();
        let mut out = String::new();
        for &pty_id in pairs.keys() {
            out.push_str(&alloc::format!("{}\n", pty_id));
        }
        let bytes = out.as_bytes();
        let n = bytes.len().min(buf.len());
        buf[..n].copy_from_slice(&bytes[..n]);
        Ok(n)
    }
}

static PTY_SCHEME: SpinLock<Option<Arc<PtyScheme>>> = SpinLock::new(None);

/// Initialize and mount the PTY scheme at `/dev/pts`.
pub fn init_pty_scheme() {
    let scheme = Arc::new(PtyScheme::new());
    *PTY_SCHEME.lock() = Some(scheme.clone());
    let _ = super::mount::mount("/dev/pts", scheme);
}

/// Get a reference to the global PTY scheme instance.
pub fn get_pty_scheme() -> Option<Arc<PtyScheme>> {
    PTY_SCHEME.lock().clone()
}
