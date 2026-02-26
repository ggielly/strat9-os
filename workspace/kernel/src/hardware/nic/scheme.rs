//! Network VFS scheme – mounts at `/dev/net/`.
//!
//! read = receive packet, write = send packet.

use super::{get_device, list_interfaces};
use crate::{
    syscall::error::SyscallError,
    vfs::{
        scheme::{DirEntry, FileFlags, FileStat, OpenFlags, OpenResult, Scheme, DT_REG},
        scheme_router,
    },
};
use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use net_core::NetError;
use spin::RwLock;

#[derive(Clone)]
enum Handle {
    Root,
    Iface(String),
}

pub struct NetScheme {
    handles: RwLock<BTreeMap<u64, Handle>>,
    next: AtomicU64,
}

impl NetScheme {
    fn new() -> Self {
        Self {
            handles: RwLock::new(BTreeMap::new()),
            next: AtomicU64::new(1),
        }
    }
    fn alloc_id(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed)
    }
}

impl Scheme for NetScheme {
    fn open(&self, path: &str, _flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        let path = path.trim_start_matches('/');
        let id = self.alloc_id();
        if path.is_empty() {
            self.handles.write().insert(id, Handle::Root);
            return Ok(OpenResult {
                file_id: id,
                size: None,
                flags: FileFlags::DIRECTORY,
            });
        }
        if !list_interfaces().iter().any(|n| n == path) {
            return Err(SyscallError::BadHandle);
        }
        self.handles
            .write()
            .insert(id, Handle::Iface(String::from(path)));
        Ok(OpenResult {
            file_id: id,
            size: None,
            flags: FileFlags::DEVICE,
        })
    }

    fn read(&self, fid: u64, _off: u64, buf: &mut [u8]) -> Result<usize, SyscallError> {
        let h = self.handles.read();
        let handle = h.get(&fid).ok_or(SyscallError::BadHandle)?;
        match handle {
            Handle::Root => {
                let list: String = list_interfaces().into_iter().map(|n| n + "\n").collect();
                let b = list.as_bytes();
                let n = core::cmp::min(b.len(), buf.len());
                buf[..n].copy_from_slice(&b[..n]);
                Ok(n)
            }
            Handle::Iface(name) => {
                let dev = get_device(name).ok_or(SyscallError::BadHandle)?;
                drop(h);
                dev.receive(buf).map_err(|e| match e {
                    NetError::NoPacket => SyscallError::Again,
                    _ => SyscallError::IoError,
                })
            }
        }
    }

    fn write(&self, fid: u64, _off: u64, buf: &[u8]) -> Result<usize, SyscallError> {
        let h = self.handles.read();
        let handle = h.get(&fid).ok_or(SyscallError::BadHandle)?;
        match handle {
            Handle::Root => Err(SyscallError::PermissionDenied),
            Handle::Iface(name) => {
                let dev = get_device(name).ok_or(SyscallError::BadHandle)?;
                drop(h);
                dev.transmit(buf).map_err(|e| match e {
                    NetError::TxQueueFull => SyscallError::Again,
                    _ => SyscallError::IoError,
                })?;
                Ok(buf.len())
            }
        }
    }

    fn close(&self, fid: u64) -> Result<(), SyscallError> {
        self.handles.write().remove(&fid);
        Ok(())
    }

    fn stat(&self, fid: u64) -> Result<FileStat, SyscallError> {
        let h = self.handles.read();
        let handle = h.get(&fid).ok_or(SyscallError::BadHandle)?;
        Ok(match handle {
            Handle::Root => FileStat {
                st_ino: 0,
                st_mode: 0o040555,
                st_nlink: 2,
                st_size: 0,
                st_blksize: 1514,
                st_blocks: 0,
            },
            Handle::Iface(_) => FileStat {
                st_ino: fid,
                st_mode: 0o020666,
                st_nlink: 1,
                st_size: 0,
                st_blksize: 1514,
                st_blocks: 0,
            },
        })
    }

    fn readdir(&self, fid: u64) -> Result<Vec<DirEntry>, SyscallError> {
        let h = self.handles.read();
        if !matches!(h.get(&fid), Some(Handle::Root)) {
            return Err(SyscallError::InvalidArgument);
        }
        Ok(list_interfaces()
            .into_iter()
            .enumerate()
            .map(|(i, name)| DirEntry {
                ino: (i + 1) as u64,
                file_type: DT_REG,
                name,
            })
            .collect())
    }
}

pub fn register_net_scheme() -> Result<(), SyscallError> {
    let scheme = Arc::new(NetScheme::new());
    scheme_router::register_scheme("net", scheme)?;
    scheme_router::mount_scheme("net", "/dev/net")?;
    log::info!("[net] Scheme at /dev/net/");
    Ok(())
}
