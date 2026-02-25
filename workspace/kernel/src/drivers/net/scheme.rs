//! Network Scheme – VFS interface to network devices.
//!
//! Mounts at `/dev/net/` and exposes each registered NIC as a file:
//!
//! ```text
//! /dev/net/         → readdir lists interfaces ("eth0\n", "eth1\n", …)
//! /dev/net/eth0     → read = receive packet, write = transmit packet
//! ```
//!
//! This follows the Plan 9 philosophy: everything is a file.
//! A future silo-hosted driver can replace the kernel-resident driver
//! transparently — the VFS path stays the same.

use super::{get_device, list_interfaces, NetError};
use crate::{
    sync::SpinLock,
    syscall::error::SyscallError,
    vfs::scheme::{
        DirEntry, FileStat, FileFlags, OpenFlags, OpenResult, Scheme, DT_REG,
    },
    vfs::scheme_router,
};
use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// File handle state
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum HandleKind {
    Root,
    Interface(String),
}

struct OpenHandle {
    kind: HandleKind,
}

// ---------------------------------------------------------------------------
// NetScheme
// ---------------------------------------------------------------------------

pub struct NetScheme {
    handles: SpinLock<BTreeMap<u64, OpenHandle>>,
    next_id: AtomicU64,
}

impl NetScheme {
    pub fn new() -> Self {
        Self {
            handles: SpinLock::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    fn alloc_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }
}

impl Scheme for NetScheme {
    fn open(&self, path: &str, _flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        let path = path.trim_start_matches('/');

        if path.is_empty() {
            let id = self.alloc_id();
            self.handles.lock().insert(id, OpenHandle { kind: HandleKind::Root });
            return Ok(OpenResult {
                file_id: id,
                size: None,
                flags: FileFlags::DIRECTORY,
            });
        }

        // Check that the interface exists
        let ifaces = list_interfaces();
        if !ifaces.iter().any(|n| n == path) {
            return Err(SyscallError::BadHandle);
        }

        let id = self.alloc_id();
        self.handles.lock().insert(
            id,
            OpenHandle {
                kind: HandleKind::Interface(String::from(path)),
            },
        );
        Ok(OpenResult {
            file_id: id,
            size: None,
            flags: FileFlags::DEVICE,
        })
    }

    fn read(&self, file_id: u64, _offset: u64, buf: &mut [u8]) -> Result<usize, SyscallError> {
        let handles = self.handles.lock();
        let handle = handles.get(&file_id).ok_or(SyscallError::BadHandle)?;

        match &handle.kind {
            HandleKind::Root => {
                let listing: String = list_interfaces()
                    .into_iter()
                    .map(|n| n + "\n")
                    .collect();
                let bytes = listing.as_bytes();
                let to_copy = core::cmp::min(bytes.len(), buf.len());
                buf[..to_copy].copy_from_slice(&bytes[..to_copy]);
                Ok(to_copy)
            }
            HandleKind::Interface(name) => {
                let dev = get_device(name).ok_or(SyscallError::BadHandle)?;
                drop(handles);
                dev.receive(buf).map_err(|e| match e {
                    NetError::NoPacket => SyscallError::Again,
                    _ => SyscallError::IoError,
                })
            }
        }
    }

    fn write(&self, file_id: u64, _offset: u64, buf: &[u8]) -> Result<usize, SyscallError> {
        let handles = self.handles.lock();
        let handle = handles.get(&file_id).ok_or(SyscallError::BadHandle)?;

        match &handle.kind {
            HandleKind::Root => Err(SyscallError::PermissionDenied),
            HandleKind::Interface(name) => {
                let dev = get_device(name).ok_or(SyscallError::BadHandle)?;
                drop(handles);
                dev.transmit(buf).map_err(|e| match e {
                    NetError::TxQueueFull => SyscallError::Again,
                    _ => SyscallError::IoError,
                })?;
                Ok(buf.len())
            }
        }
    }

    fn close(&self, file_id: u64) -> Result<(), SyscallError> {
        self.handles.lock().remove(&file_id);
        Ok(())
    }

    fn stat(&self, file_id: u64) -> Result<FileStat, SyscallError> {
        let handles = self.handles.lock();
        let handle = handles.get(&file_id).ok_or(SyscallError::BadHandle)?;
        match &handle.kind {
            HandleKind::Root => Ok(FileStat {
                st_ino: 0,
                st_mode: 0o040555,
                st_nlink: 2,
                st_size: 0,
                st_blksize: 1514,
                st_blocks: 0,
            }),
            HandleKind::Interface(_) => Ok(FileStat {
                st_ino: file_id,
                st_mode: 0o020666, // character device
                st_nlink: 1,
                st_size: 0,
                st_blksize: 1514,
                st_blocks: 0,
            }),
        }
    }

    fn readdir(&self, file_id: u64) -> Result<Vec<DirEntry>, SyscallError> {
        let handles = self.handles.lock();
        let handle = handles.get(&file_id).ok_or(SyscallError::BadHandle)?;

        if !matches!(handle.kind, HandleKind::Root) {
            return Err(SyscallError::InvalidArgument);
        }

        let mut entries = Vec::new();
        for (i, name) in list_interfaces().into_iter().enumerate() {
            entries.push(DirEntry {
                ino: (i + 1) as u64,
                file_type: DT_REG,
                name,
            });
        }
        Ok(entries)
    }
}

// ---------------------------------------------------------------------------
// Registration helper
// ---------------------------------------------------------------------------

/// Register the `/dev/net/` scheme in the VFS.
pub fn register_net_scheme() -> Result<(), SyscallError> {
    let scheme = Arc::new(NetScheme::new());
    scheme_router::register_scheme("net", scheme)?;
    scheme_router::mount_scheme("net", "/dev/net")?;
    log::info!("[net] Scheme mounted at /dev/net/");
    Ok(())
}
