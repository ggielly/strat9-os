//! Scheme abstraction - backends for VFS operations.
//!
//! Schemes provide the actual implementation for file operations.
//! Examples: IPC-based schemes (ext4, network), kernel schemes (devfs, procfs).

use crate::{
    ipc::{message::IpcMessage, port::PortId},
    sync::SpinLock,
    syscall::error::SyscallError,
};
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

/// File type constants (matching Linux DT_* values).
pub const DT_UNKNOWN: u8 = 0;
pub const DT_FIFO: u8 = 1;
pub const DT_CHR: u8 = 2;
pub const DT_DIR: u8 = 4;
pub const DT_BLK: u8 = 6;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;
pub const DT_SOCK: u8 = 12;

/// Metadata returned by stat operations.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FileStat {
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_size: u64,
    pub st_blksize: u64,
    pub st_blocks: u64,
}

impl FileStat {
    pub const fn zeroed() -> Self {
        FileStat {
            st_ino: 0,
            st_mode: 0,
            st_nlink: 1,
            st_size: 0,
            st_blksize: 512,
            st_blocks: 0,
        }
    }
}

/// A single directory entry returned by readdir.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub ino: u64,
    pub file_type: u8,
    pub name: String,
}

/// Result of an open operation.
#[derive(Debug, Clone)]
pub struct OpenResult {
    /// Unique file handle (opaque to caller).
    pub file_id: u64,
    /// Size of the file (if known).
    pub size: Option<u64>,
    /// Flags describing the file (directory, device, etc.).
    pub flags: FileFlags,
}

bitflags::bitflags! {
    /// Flags describing a file's properties.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FileFlags: u32 {
        const DIRECTORY = 1 << 0;
        const DEVICE    = 1 << 1;
        const PIPE      = 1 << 2;
        const APPEND    = 1 << 3;
    }
}

/// Open flags passed to open().
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct OpenFlags: u32 {
        const READ      = 1 << 0;
        const WRITE     = 1 << 1;
        const CREATE    = 1 << 2;
        const TRUNCATE  = 1 << 3;
        const APPEND    = 1 << 4;
        const DIRECTORY = 1 << 5;
    }
}

/// Abstraction for a filesystem/service backend.
pub trait Scheme: Send + Sync {
    /// Open a file/resource at the given path within this scheme.
    ///
    /// `path` is relative to the scheme's mount point.
    /// Returns a unique file handle + metadata.
    fn open(&self, path: &str, flags: OpenFlags) -> Result<OpenResult, SyscallError>;

    /// Read bytes from an open file.
    fn read(&self, file_id: u64, offset: u64, buf: &mut [u8]) -> Result<usize, SyscallError>;

    /// Write bytes to an open file.
    fn write(&self, file_id: u64, offset: u64, buf: &[u8]) -> Result<usize, SyscallError>;

    /// Close an open file.
    fn close(&self, file_id: u64) -> Result<(), SyscallError>;

    /// Get file size (if supported).
    fn size(&self, file_id: u64) -> Result<u64, SyscallError> {
        let _ = file_id;
        Err(SyscallError::NotImplemented)
    }

    /// Truncate/resize a file (if supported).
    fn truncate(&self, file_id: u64, new_size: u64) -> Result<(), SyscallError> {
        let _ = (file_id, new_size);
        Err(SyscallError::NotImplemented)
    }

    /// Sync file to storage (if applicable).
    fn sync(&self, file_id: u64) -> Result<(), SyscallError> {
        let _ = file_id;
        Ok(()) // No-op by default
    }

    /// Create a new regular file.
    fn create_file(&self, path: &str, mode: u32) -> Result<OpenResult, SyscallError> {
        let _ = (path, mode);
        Err(SyscallError::NotImplemented)
    }

    /// Create a new directory.
    fn create_directory(&self, path: &str, mode: u32) -> Result<OpenResult, SyscallError> {
        let _ = (path, mode);
        Err(SyscallError::NotImplemented)
    }

    /// Remove a file or directory.
    fn unlink(&self, path: &str) -> Result<(), SyscallError> {
        let _ = path;
        Err(SyscallError::NotImplemented)
    }

    /// Get metadata for an open file.
    fn stat(&self, file_id: u64) -> Result<FileStat, SyscallError> {
        let _ = file_id;
        Err(SyscallError::NotImplemented)
    }

    /// Read directory entries from an open directory handle.
    fn readdir(&self, file_id: u64) -> Result<Vec<DirEntry>, SyscallError> {
        let _ = file_id;
        Err(SyscallError::NotImplemented)
    }
}

/// Type-erased Scheme reference.
pub type DynScheme = Arc<dyn Scheme>;

// ============================================================================
// Built-in Schemes
// ============================================================================

/// IPC-based scheme: forwards operations to a userspace server via IPC.
pub struct IpcScheme {
    port_id: PortId,
}

impl IpcScheme {
    pub fn new(port_id: PortId) -> Self {
        IpcScheme { port_id }
    }

    /// Build an IPC message for open operation.
    fn build_open_msg(path: &str, flags: OpenFlags) -> Result<IpcMessage, SyscallError> {
        const OPCODE_OPEN: u32 = 0x01;
        let mut msg = IpcMessage::new(OPCODE_OPEN);

        // Encode: [flags: u32][path_len: u16][path bytes...]
        if path.len() > 42 {
            return Err(SyscallError::InvalidArgument); // Path too long for inline
        }

        msg.payload[0..4].copy_from_slice(&flags.bits().to_le_bytes());
        msg.payload[4..6].copy_from_slice(&(path.len() as u16).to_le_bytes());
        msg.payload[6..6 + path.len()].copy_from_slice(path.as_bytes());
        Ok(msg)
    }

    /// Build an IPC message for read operation.
    fn build_read_msg(file_id: u64, offset: u64, count: u32) -> IpcMessage {
        const OPCODE_READ: u32 = 0x02;
        let mut msg = IpcMessage::new(OPCODE_READ);
        msg.payload[0..8].copy_from_slice(&file_id.to_le_bytes());
        msg.payload[8..16].copy_from_slice(&offset.to_le_bytes());
        msg.payload[16..20].copy_from_slice(&count.to_le_bytes());
        msg
    }

    /// Build an IPC message for write operation.
    ///
    /// Returns the message and the number of bytes actually packed.
    fn build_write_msg(file_id: u64, offset: u64, data: &[u8]) -> (IpcMessage, usize) {
        const OPCODE_WRITE: u32 = 0x03;
        let mut msg = IpcMessage::new(OPCODE_WRITE);
        msg.payload[0..8].copy_from_slice(&file_id.to_le_bytes());
        msg.payload[8..16].copy_from_slice(&offset.to_le_bytes());

        // payload[18..48] leaves 30 bytes for data.
        let packed = core::cmp::min(data.len(), 30);
        msg.payload[16..18].copy_from_slice(&(packed as u16).to_le_bytes());
        msg.payload[18..18 + packed].copy_from_slice(&data[..packed]);
        (msg, packed)
    }

    /// Build an IPC message for close operation.
    fn build_close_msg(file_id: u64) -> IpcMessage {
        const OPCODE_CLOSE: u32 = 0x04;
        let mut msg = IpcMessage::new(OPCODE_CLOSE);
        msg.payload[0..8].copy_from_slice(&file_id.to_le_bytes());
        msg
    }

    fn build_readdir_msg(file_id: u64, cursor: u16) -> IpcMessage {
        const OPCODE_READDIR: u32 = 0x08;
        let mut msg = IpcMessage::new(OPCODE_READDIR);
        msg.payload[0..8].copy_from_slice(&file_id.to_le_bytes());
        msg.payload[8..10].copy_from_slice(&cursor.to_le_bytes());
        msg
    }

    fn parse_status(reply: &IpcMessage) -> Result<(), SyscallError> {
        if reply.msg_type != 0x80 {
            return Err(SyscallError::IoError);
        }

        let status = u32::from_le_bytes([
            reply.payload[0],
            reply.payload[1],
            reply.payload[2],
            reply.payload[3],
        ]);
        if status == 0 {
            return Ok(());
        }

        // Accept both forms:
        // - positive errno (2 => ENOENT)
        // - raw signed -errno encoded in u32
        let signed = status as i32;
        let code = if signed < 0 {
            signed as i64
        } else {
            -(signed as i64)
        };
        Err(SyscallError::from_code(code))
    }
}

impl IpcScheme {
    /// Perform a synchronous IPC call: send `msg` to the server port and block
    /// the current task until the server calls `ipc_reply`.  This mirrors
    /// `sys_ipc_call` exactly so that `sys_ipc_reply` can correctly route the
    /// reply back to us via `reply::deliver_reply`.
    fn call(&self, mut msg: IpcMessage) -> Result<IpcMessage, SyscallError> {
        let task_id = crate::process::current_task_id().ok_or(SyscallError::PermissionDenied)?;

        // Stamp our task-id so the server knows where to deliver the reply.
        msg.sender = task_id.as_u64();

        let port = crate::ipc::port::get_port(self.port_id).ok_or(SyscallError::BadHandle)?;
        port.send(msg).map_err(|_| SyscallError::BadHandle)?;
        // Drop the Arc before blocking so we don't hold the port alive across
        // a potentially long sleep.
        drop(port);

        Ok(crate::ipc::reply::wait_for_reply(task_id))
    }
}

impl Scheme for IpcScheme {
    fn open(&self, path: &str, flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        let msg = Self::build_open_msg(path, flags)?;
        let reply = self.call(msg)?;

        // Parse reply: [status: u32][file_id: u64][size: u64][flags: u32]
        Self::parse_status(&reply)?;

        let file_id = u64::from_le_bytes([
            reply.payload[4],
            reply.payload[5],
            reply.payload[6],
            reply.payload[7],
            reply.payload[8],
            reply.payload[9],
            reply.payload[10],
            reply.payload[11],
        ]);

        let size = u64::from_le_bytes([
            reply.payload[12],
            reply.payload[13],
            reply.payload[14],
            reply.payload[15],
            reply.payload[16],
            reply.payload[17],
            reply.payload[18],
            reply.payload[19],
        ]);

        let file_flags = u32::from_le_bytes([
            reply.payload[20],
            reply.payload[21],
            reply.payload[22],
            reply.payload[23],
        ]);

        Ok(OpenResult {
            file_id,
            size: if size == u64::MAX { None } else { Some(size) },
            flags: FileFlags::from_bits_truncate(file_flags),
        })
    }

    fn read(&self, file_id: u64, offset: u64, buf: &mut [u8]) -> Result<usize, SyscallError> {
        let msg = Self::build_read_msg(file_id, offset, buf.len() as u32);
        let reply = self.call(msg)?;

        // Parse reply: [status: u32][bytes_read: u32][data...]
        Self::parse_status(&reply)?;

        let bytes_read = u32::from_le_bytes([
            reply.payload[4],
            reply.payload[5],
            reply.payload[6],
            reply.payload[7],
        ]) as usize;

        let available = core::cmp::min(bytes_read, reply.payload.len() - 8);
        let to_copy = core::cmp::min(available, buf.len());
        buf[..to_copy].copy_from_slice(&reply.payload[8..8 + to_copy]);

        Ok(to_copy)
    }

    fn write(&self, file_id: u64, offset: u64, buf: &[u8]) -> Result<usize, SyscallError> {
        let (msg, packed) = Self::build_write_msg(file_id, offset, buf);
        let reply = self.call(msg)?;

        // Parse reply: [status: u32][bytes_written: u32]
        Self::parse_status(&reply)?;

        let bytes_written = u32::from_le_bytes([
            reply.payload[4],
            reply.payload[5],
            reply.payload[6],
            reply.payload[7],
        ]) as usize;

        // Never report more bytes than we actually sent.
        Ok(bytes_written.min(packed))
    }

    fn close(&self, file_id: u64) -> Result<(), SyscallError> {
        let msg = Self::build_close_msg(file_id);
        let reply = self.call(msg)?;

        Self::parse_status(&reply)?;

        Ok(())
    }

    fn create_file(&self, path: &str, mode: u32) -> Result<OpenResult, SyscallError> {
        const OPCODE_CREATE_FILE: u32 = 0x05;
        self.handle_create_op(OPCODE_CREATE_FILE, path, mode)
    }

    fn create_directory(&self, path: &str, mode: u32) -> Result<OpenResult, SyscallError> {
        const OPCODE_CREATE_DIR: u32 = 0x06;
        self.handle_create_op(OPCODE_CREATE_DIR, path, mode)
    }

    fn unlink(&self, path: &str) -> Result<(), SyscallError> {
        const OPCODE_UNLINK: u32 = 0x07;
        let mut msg = IpcMessage::new(OPCODE_UNLINK);

        if path.len() > 42 {
            return Err(SyscallError::InvalidArgument);
        }

        msg.payload[0..2].copy_from_slice(&(path.len() as u16).to_le_bytes());
        msg.payload[2..2 + path.len()].copy_from_slice(path.as_bytes());

        let reply = self.call(msg)?;
        Self::parse_status(&reply)?;

        Ok(())
    }

    fn readdir(&self, file_id: u64) -> Result<Vec<DirEntry>, SyscallError> {
        let mut cursor: u16 = 0;
        let mut entries = Vec::new();

        loop {
            let msg = Self::build_readdir_msg(file_id, cursor);
            let reply = self.call(msg)?;
            Self::parse_status(&reply)?;

            let next_cursor = u16::from_le_bytes([reply.payload[4], reply.payload[5]]);
            let entry_count = reply.payload[6] as usize;
            let used_bytes = reply.payload[7] as usize;
            if used_bytes > reply.payload.len() - 8 {
                return Err(SyscallError::IoError);
            }

            let mut offset = 8usize;
            for _ in 0..entry_count {
                if offset + 10 > 8 + used_bytes {
                    return Err(SyscallError::IoError);
                }

                let ino = u64::from_le_bytes([
                    reply.payload[offset],
                    reply.payload[offset + 1],
                    reply.payload[offset + 2],
                    reply.payload[offset + 3],
                    reply.payload[offset + 4],
                    reply.payload[offset + 5],
                    reply.payload[offset + 6],
                    reply.payload[offset + 7],
                ]);
                let file_type = reply.payload[offset + 8];
                let name_len = reply.payload[offset + 9] as usize;
                if offset + 10 + name_len > 8 + used_bytes {
                    return Err(SyscallError::IoError);
                }
                let name_bytes = &reply.payload[offset + 10..offset + 10 + name_len];
                let name = core::str::from_utf8(name_bytes)
                    .map_err(|_| SyscallError::IoError)?
                    .to_string();

                entries.push(DirEntry {
                    ino,
                    file_type,
                    name,
                });
                offset += 10 + name_len;
            }

            if next_cursor == u16::MAX {
                break;
            }
            if next_cursor <= cursor {
                return Err(SyscallError::IoError);
            }
            cursor = next_cursor;
        }

        Ok(entries)
    }
}

impl IpcScheme {
    fn handle_create_op(
        &self,
        opcode: u32,
        path: &str,
        mode: u32,
    ) -> Result<OpenResult, SyscallError> {
        let mut msg = IpcMessage::new(opcode);

        if path.len() > 40 {
            return Err(SyscallError::InvalidArgument);
        }

        msg.payload[0..4].copy_from_slice(&mode.to_le_bytes());
        msg.payload[4..6].copy_from_slice(&(path.len() as u16).to_le_bytes());
        msg.payload[6..6 + path.len()].copy_from_slice(path.as_bytes());

        let reply = self.call(msg)?;

        Self::parse_status(&reply)?;

        let file_id = u64::from_le_bytes([
            reply.payload[4],
            reply.payload[5],
            reply.payload[6],
            reply.payload[7],
            reply.payload[8],
            reply.payload[9],
            reply.payload[10],
            reply.payload[11],
        ]);

        Ok(OpenResult {
            file_id,
            size: Some(0),
            flags: FileFlags::empty(),
        })
    }
}

/// Kernel-backed scheme: serves files from kernel memory (read-only).
pub struct KernelScheme {
    files: SpinLock<BTreeMap<String, KernelFile>>,
    by_id: SpinLock<BTreeMap<u64, String>>,
}

#[derive(Clone)]
struct KernelFile {
    id: u64,
    base: *const u8,
    len: usize,
}

// SAFETY: KernelFile only stores kernel-static pointers
unsafe impl Send for KernelFile {}
unsafe impl Sync for KernelFile {}

impl KernelScheme {
    pub fn new() -> Self {
        KernelScheme {
            files: SpinLock::new(BTreeMap::new()),
            by_id: SpinLock::new(BTreeMap::new()),
        }
    }

    /// Register a static kernel file.
    pub fn register(&self, path: &str, base: *const u8, len: usize) {
        static NEXT_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
        let id = NEXT_ID.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        self.files
            .lock()
            .insert(String::from(path), KernelFile { id, base, len });
        self.by_id.lock().insert(id, String::from(path));
    }

    fn get_by_id(&self, file_id: u64) -> Option<KernelFile> {
        let name = self.by_id.lock().get(&file_id)?.clone();
        self.files.lock().get(&name).cloned()
    }
}

impl Scheme for KernelScheme {
    fn open(&self, path: &str, _flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        if path.is_empty() || path == "/" {
            return Ok(OpenResult {
                file_id: 0, // Root directory ID
                size: None,
                flags: FileFlags::DIRECTORY,
            });
        }

        let files = self.files.lock();
        let file = files.get(path).ok_or(SyscallError::BadHandle)?;
        Ok(OpenResult {
            file_id: file.id,
            size: Some(file.len as u64),
            flags: FileFlags::empty(),
        })
    }

    fn read(&self, file_id: u64, offset: u64, buf: &mut [u8]) -> Result<usize, SyscallError> {
        if file_id == 0 {
            // Handle directory listing for root
            let mut list = String::new();
            let files = self.files.lock();
            for name in files.keys() {
                list.push_str(name);
                list.push('\n');
            }

            if offset >= list.len() as u64 {
                return Ok(0);
            }

            let start = offset as usize;
            let end = core::cmp::min(start + buf.len(), list.len());
            let to_copy = end - start;
            buf[..to_copy].copy_from_slice(&list.as_bytes()[start..end]);
            return Ok(to_copy);
        }

        let file = self.get_by_id(file_id).ok_or(SyscallError::BadHandle)?;

        if offset >= file.len as u64 {
            return Ok(0);
        }

        let remaining = file.len - offset as usize;
        let to_copy = core::cmp::min(remaining, buf.len());

        // SAFETY: file.base is a kernel-static pointer, bounds checked above
        unsafe {
            let src = file.base.add(offset as usize);
            core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), to_copy);
        }

        Ok(to_copy)
    }

    fn write(&self, _file_id: u64, _offset: u64, _buf: &[u8]) -> Result<usize, SyscallError> {
        Err(SyscallError::PermissionDenied) // Read-only
    }

    fn close(&self, _file_id: u64) -> Result<(), SyscallError> {
        Ok(()) // No-op for kernel files
    }

    fn size(&self, file_id: u64) -> Result<u64, SyscallError> {
        let file = self.get_by_id(file_id).ok_or(SyscallError::BadHandle)?;
        Ok(file.len as u64)
    }

    fn stat(&self, file_id: u64) -> Result<FileStat, SyscallError> {
        if file_id == 0 {
            return Ok(FileStat {
                st_ino: 0,
                st_mode: 0o040555,
                st_nlink: 2,
                st_size: 0,
                st_blksize: 512,
                st_blocks: 0,
            });
        }
        let file = self.get_by_id(file_id).ok_or(SyscallError::BadHandle)?;
        Ok(FileStat {
            st_ino: file_id,
            st_mode: 0o100444,
            st_nlink: 1,
            st_size: file.len as u64,
            st_blksize: 512,
            st_blocks: ((file.len as u64) + 511) / 512,
        })
    }

    fn readdir(&self, file_id: u64) -> Result<Vec<DirEntry>, SyscallError> {
        if file_id != 0 {
            return Err(SyscallError::InvalidArgument);
        }
        let files = self.files.lock();
        let mut entries = Vec::new();
        for (name, kf) in files.iter() {
            entries.push(DirEntry {
                ino: kf.id,
                file_type: DT_REG,
                name: name.clone(),
            });
        }
        Ok(entries)
    }
}
