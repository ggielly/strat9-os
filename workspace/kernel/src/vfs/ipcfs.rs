use super::scheme::{DirEntry, FileFlags, FileStat, OpenFlags, OpenResult, Scheme, DT_DIR, DT_REG};
use crate::{
    ipc::{
        semaphore::{self, SemId},
        shared_ring::{self, RingId},
    },
    memory::address_space::{VmaFlags, VmaPageSize, VmaType},
    process::current_task_clone,
    sync::SpinLock,
    syscall::error::SyscallError,
};
use alloc::{collections::BTreeMap, string::ToString, vec, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy)]
enum HandleKind {
    Root,
    ShmDir,
    SemDir,
    Ring(RingId),
    Sem(SemId),
}

struct HandleState {
    kind: HandleKind,
    last_map: Option<(u64, u64)>,
}

pub struct IpcControlScheme {
    next_file_id: AtomicU64,
    handles: SpinLock<BTreeMap<u64, HandleState>>,
}

impl IpcControlScheme {
    pub fn new() -> Self {
        Self {
            next_file_id: AtomicU64::new(1),
            handles: SpinLock::new(BTreeMap::new()),
        }
    }

    fn alloc_handle(&self, kind: HandleKind) -> u64 {
        let id = self.next_file_id.fetch_add(1, Ordering::Relaxed);
        self.handles.lock().insert(
            id,
            HandleState {
                kind,
                last_map: None,
            },
        );
        id
    }

    fn parse_u64(path: &str) -> Result<u64, SyscallError> {
        path.parse::<u64>()
            .map_err(|_| SyscallError::InvalidArgument)
    }

    fn read_static(offset: u64, out: &mut [u8], s: &str) -> usize {
        let bytes = s.as_bytes();
        let start = offset as usize;
        if start >= bytes.len() {
            return 0;
        }
        let n = core::cmp::min(out.len(), bytes.len() - start);
        out[..n].copy_from_slice(&bytes[start..start + n]);
        n
    }

    fn handle_mut<R>(
        &self,
        file_id: u64,
        f: impl FnOnce(&mut HandleState) -> Result<R, SyscallError>,
    ) -> Result<R, SyscallError> {
        let mut h = self.handles.lock();
        let state = h.get_mut(&file_id).ok_or(SyscallError::BadHandle)?;
        f(state)
    }
}

impl Scheme for IpcControlScheme {
    fn open(&self, path: &str, _flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        let p = path.trim_matches('/');
        let kind = if p.is_empty() {
            HandleKind::Root
        } else if p == "shm" {
            HandleKind::ShmDir
        } else if p == "sem" {
            HandleKind::SemDir
        } else if let Some(rest) = p.strip_prefix("shm/new/") {
            crate::silo::require_silo_admin()?;
            let size = Self::parse_u64(rest)? as usize;
            let id = shared_ring::create_ring(size).map_err(|e| match e {
                shared_ring::RingError::InvalidSize => SyscallError::InvalidArgument,
                shared_ring::RingError::Alloc => SyscallError::OutOfMemory,
                shared_ring::RingError::NotFound => SyscallError::NotFound,
            })?;
            HandleKind::Ring(id)
        } else if let Some(rest) = p.strip_prefix("sem/new/") {
            crate::silo::require_silo_admin()?;
            let initial = Self::parse_u64(rest)?;
            let initial = u32::try_from(initial).map_err(|_| SyscallError::InvalidArgument)?;
            let id = semaphore::create_semaphore(initial).map_err(|e| match e {
                semaphore::SemaphoreError::InvalidValue => SyscallError::InvalidArgument,
                semaphore::SemaphoreError::WouldBlock => SyscallError::Again,
                semaphore::SemaphoreError::Destroyed => SyscallError::Pipe,
                semaphore::SemaphoreError::NotFound => SyscallError::NotFound,
            })?;
            HandleKind::Sem(id)
        } else if let Some(rest) = p.strip_prefix("shm/") {
            let id = RingId::from_u64(Self::parse_u64(rest)?);
            let _ = shared_ring::get_ring(id).ok_or(SyscallError::NotFound)?;
            HandleKind::Ring(id)
        } else if let Some(rest) = p.strip_prefix("sem/") {
            let id = SemId::from_u64(Self::parse_u64(rest)?);
            let _ = semaphore::get_semaphore(id).ok_or(SyscallError::NotFound)?;
            HandleKind::Sem(id)
        } else {
            return Err(SyscallError::NotFound);
        };

        let (flags, size) = match kind {
            HandleKind::Root | HandleKind::ShmDir | HandleKind::SemDir => {
                (FileFlags::DIRECTORY, None)
            }
            HandleKind::Ring(id) => {
                let ring = shared_ring::get_ring(id).ok_or(SyscallError::NotFound)?;
                (FileFlags::empty(), Some(ring.size() as u64))
            }
            HandleKind::Sem(_) => (FileFlags::empty(), Some(0)),
        };
        let file_id = self.alloc_handle(kind);
        Ok(OpenResult {
            file_id,
            size,
            flags,
        })
    }

    fn read(&self, file_id: u64, offset: u64, buf: &mut [u8]) -> Result<usize, SyscallError> {
        self.handle_mut(file_id, |state| match state.kind {
            HandleKind::Root => Ok(Self::read_static(offset, buf, "shm\nsem\n")),
            HandleKind::ShmDir => Ok(Self::read_static(offset, buf, "new/<bytes>\n<ring_id>\n")),
            HandleKind::SemDir => Ok(Self::read_static(offset, buf, "new/<initial>\n<sem_id>\n")),
            HandleKind::Ring(id) => {
                let ring = shared_ring::get_ring(id).ok_or(SyscallError::NotFound)?;
                let mut line = alloc::format!(
                    "ring={} size={} pages={}",
                    id.as_u64(),
                    ring.size(),
                    ring.page_count()
                );
                if let Some((addr, size)) = state.last_map {
                    line.push_str(&alloc::format!(" mapped={:#x} mapped_size={}", addr, size));
                }
                line.push('\n');
                Ok(Self::read_static(offset, buf, &line))
            }
            HandleKind::Sem(id) => {
                let sem = semaphore::get_semaphore(id).ok_or(SyscallError::NotFound)?;
                let line = alloc::format!("sem={} count={}\n", id.as_u64(), sem.count());
                Ok(Self::read_static(offset, buf, &line))
            }
        })
    }

    fn write(&self, file_id: u64, _offset: u64, buf: &[u8]) -> Result<usize, SyscallError> {
        let cmd = core::str::from_utf8(buf)
            .map_err(|_| SyscallError::InvalidArgument)?
            .trim();

        self.handle_mut(file_id, |state| match state.kind {
            HandleKind::Sem(id) => {
                let sem = semaphore::get_semaphore(id).ok_or(SyscallError::NotFound)?;
                match cmd {
                    "post" => sem.post().map_err(|_| SyscallError::Pipe)?,
                    "wait" => sem.wait().map_err(|e| match e {
                        semaphore::SemaphoreError::WouldBlock => SyscallError::Again,
                        semaphore::SemaphoreError::Destroyed => SyscallError::Pipe,
                        semaphore::SemaphoreError::InvalidValue => SyscallError::InvalidArgument,
                        semaphore::SemaphoreError::NotFound => SyscallError::NotFound,
                    })?,
                    "trywait" => sem.try_wait().map_err(|e| match e {
                        semaphore::SemaphoreError::WouldBlock => SyscallError::Again,
                        semaphore::SemaphoreError::Destroyed => SyscallError::Pipe,
                        semaphore::SemaphoreError::InvalidValue => SyscallError::InvalidArgument,
                        semaphore::SemaphoreError::NotFound => SyscallError::NotFound,
                    })?,
                    _ => return Err(SyscallError::InvalidArgument),
                }
                Ok(buf.len())
            }
            HandleKind::Ring(id) => {
                if cmd != "map" {
                    return Err(SyscallError::InvalidArgument);
                }
                let ring = shared_ring::get_ring(id).ok_or(SyscallError::NotFound)?;
                let frame_phys_addrs = ring.frame_phys_addrs();
                let page_count = ring.page_count();
                let map_size = page_count
                    .checked_mul(4096)
                    .ok_or(SyscallError::InvalidArgument)? as u64;

                let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
                let addr_space = unsafe { &*task.process.address_space.get() };

                // Unmap the previous mapping if any, to avoid leaking VMA space.
                if let Some((old_base, old_size)) = state.last_map.take() {
                    let _ = addr_space.unmap_range(old_base, old_size);
                }

                let base = addr_space
                    .find_free_vma_range(
                        crate::syscall::mmap::MMAP_BASE,
                        page_count,
                        VmaPageSize::Small,
                    )
                    .ok_or(SyscallError::OutOfMemory)?;
                addr_space
                    .map_shared_frames(
                        base,
                        &frame_phys_addrs,
                        VmaFlags {
                            readable: true,
                            writable: true,
                            executable: false,
                            user_accessible: true,
                        },
                        VmaType::Anonymous,
                    )
                    .map_err(|_| SyscallError::OutOfMemory)?;
                state.last_map = Some((base, map_size));
                Ok(buf.len())
            }
            HandleKind::Root | HandleKind::ShmDir | HandleKind::SemDir => {
                Err(SyscallError::InvalidArgument)
            }
        })
    }

    fn close(&self, file_id: u64) -> Result<(), SyscallError> {
        let state = self
            .handles
            .lock()
            .remove(&file_id)
            .ok_or(SyscallError::BadHandle)?;

        // Unmap shared memory that was mapped into the caller's address space.
        if let Some((base, size)) = state.last_map {
            if let Some(task) = current_task_clone() {
                let addr_space = unsafe { &*task.process.address_space.get() };
                let _ = addr_space.unmap_range(base, size);
            }
        }
        Ok(())
    }

    fn unlink(&self, path: &str) -> Result<(), SyscallError> {
        crate::silo::require_silo_admin()?;
        let p = path.trim_matches('/');
        if let Some(rest) = p.strip_prefix("shm/") {
            let id = RingId::from_u64(Self::parse_u64(rest)?);
            shared_ring::destroy_ring(id).map_err(|_| SyscallError::NotFound)?;
            return Ok(());
        }
        if let Some(rest) = p.strip_prefix("sem/") {
            let id = SemId::from_u64(Self::parse_u64(rest)?);
            semaphore::destroy_semaphore(id).map_err(|_| SyscallError::NotFound)?;
            return Ok(());
        }
        Err(SyscallError::InvalidArgument)
    }

    fn stat(&self, file_id: u64) -> Result<FileStat, SyscallError> {
        self.handle_mut(file_id, |state| {
            let (mode, size) = match state.kind {
                HandleKind::Root | HandleKind::ShmDir | HandleKind::SemDir => (0o040755, 0),
                HandleKind::Ring(id) => {
                    let ring = shared_ring::get_ring(id).ok_or(SyscallError::NotFound)?;
                    (0o100660, ring.size() as u64)
                }
                HandleKind::Sem(_) => (0o100660, 0),
            };
            Ok(FileStat {
                st_ino: file_id,
                st_mode: mode,
                st_nlink: 1,
                st_size: size,
                st_blksize: 4096,
                st_blocks: (size + 511) / 512,
            })
        })
    }

    fn readdir(&self, file_id: u64) -> Result<Vec<DirEntry>, SyscallError> {
        self.handle_mut(file_id, |state| match state.kind {
            HandleKind::Root => Ok(vec![
                DirEntry {
                    ino: 1,
                    file_type: DT_DIR,
                    name: "shm".to_string(),
                },
                DirEntry {
                    ino: 2,
                    file_type: DT_DIR,
                    name: "sem".to_string(),
                },
            ]),
            HandleKind::ShmDir => Ok(vec![DirEntry {
                ino: 3,
                file_type: DT_REG,
                name: "new".to_string(),
            }]),
            HandleKind::SemDir => Ok(vec![DirEntry {
                ino: 4,
                file_type: DT_REG,
                name: "new".to_string(),
            }]),
            HandleKind::Ring(_) | HandleKind::Sem(_) => Err(SyscallError::InvalidArgument),
        })
    }
}
