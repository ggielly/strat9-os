//! Scheme abstraction : backends for VFS operations.
//!
//! Schemes provide the actual implementation for file operations.
//! Examples: IPC-based schemes (ext4, network), kernel schemes (devfs, procfs).

use crate::{
    ipc::{message::IpcMessage, port::PortId},
    memory::{UserSliceRead, UserSliceWrite},
    sync::SpinLock,
    syscall::error::SyscallError,
};
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

pub use strat9_abi::data::{
    FileStat, DT_BLK, DT_CHR, DT_DIR, DT_FIFO, DT_LNK, DT_REG, DT_SOCK, DT_UNKNOWN,
    IPC_FILE_FLAG_APPEND, IPC_FILE_FLAG_CHUNK_READ, IPC_FILE_FLAG_CHUNK_WRITE,
    IPC_FILE_FLAG_DEVICE, IPC_FILE_FLAG_DIRECTORY, IPC_FILE_FLAG_PIPE,
};
use strat9_abi::{
    ipc_codec::{get_u32, put_u16_len_prefixed},
    ipc_payload::{
        CloseRequest, CreateRequest, OpenReply, OpenRequest, ReadReply, ReadRequest, WriteRequest,
        OPCODE_CLOSE, OPCODE_CREATE_DIR, OPCODE_CREATE_FILE, OPCODE_OPEN, OPCODE_READ,
        OPCODE_READDIR, OPCODE_UNLINK, OPCODE_WRITE,
    },
};

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
        const DIRECTORY   = IPC_FILE_FLAG_DIRECTORY;
        const DEVICE      = IPC_FILE_FLAG_DEVICE;
        const PIPE        = IPC_FILE_FLAG_PIPE;
        const APPEND      = IPC_FILE_FLAG_APPEND;
        const CHUNK_READ  = IPC_FILE_FLAG_CHUNK_READ;
        const CHUNK_WRITE = IPC_FILE_FLAG_CHUNK_WRITE;
    }
}

pub use strat9_abi::flag::OpenFlags;

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

    /// Submit a read against a userspace buffer for async I/O.
    ///
    /// The default implementation performs the read synchronously and copies
    /// the result back into the validated userspace slice before returning a
    /// completed result.
    fn async_read(
        &self,
        file_id: u64,
        offset: u64,
        user_buf_vaddr: u64,
        len: usize,
        _ring_id: u64,
        _user_data: u64,
    ) -> Result<AsyncSubmitResult, SyscallError> {
        // Guard against userspace-controlled sizes causing kernel OOM.
        // Schemes that need larger transfers must override async_read.
        const MAX_SYNC_FALLBACK_LEN: usize = 4 * 1024 * 1024; // 4 MiB
        if len > MAX_SYNC_FALLBACK_LEN {
            return Err(SyscallError::InvalidArgument);
        }
        let user_buf = UserSliceWrite::new(user_buf_vaddr, len)?;
        let mut kernel_buf = alloc::vec![0u8; len];
        let n = self.read(file_id, offset, &mut kernel_buf)?;
        user_buf.copy_from(&kernel_buf[..n]);
        Ok(AsyncSubmitResult::Completed(n as i32))
    }

    /// Submit a write sourced from a userspace buffer for async I/O.
    ///
    /// The default implementation validates and copies the user buffer, then
    /// performs the write synchronously before returning a completed result.
    fn async_write(
        &self,
        file_id: u64,
        offset: u64,
        user_buf_vaddr: u64,
        len: usize,
        _ring_id: u64,
        _user_data: u64,
    ) -> Result<AsyncSubmitResult, SyscallError> {
        // Guard against userspace-controlled sizes causing kernel OOM.
        const MAX_SYNC_FALLBACK_LEN: usize = 4 * 1024 * 1024; // 4 MiB
        if len > MAX_SYNC_FALLBACK_LEN {
            return Err(SyscallError::InvalidArgument);
        }
        let user_buf = UserSliceRead::new(user_buf_vaddr, len)?;
        let kernel_buf = user_buf.read_to_vec();
        let n = self.write(file_id, offset, &kernel_buf)?;
        Ok(AsyncSubmitResult::Completed(n as i32))
    }

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

    /// Truncate a file by path (avoids open/close round-trip).
    ///
    /// Default implementation returns NotImplemented, causing the caller
    /// to fall back to open+truncate+close.
    fn truncate_by_path(&self, _path: &str, _new_size: u64) -> Result<(), SyscallError> {
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

    /// Rename/move an entry within this scheme.
    fn rename(&self, old_path: &str, new_path: &str) -> Result<(), SyscallError> {
        let _ = (old_path, new_path);
        Err(SyscallError::NotImplemented)
    }

    /// Change permission bits on a path.
    fn chmod(&self, path: &str, mode: u32) -> Result<(), SyscallError> {
        let _ = (path, mode);
        Err(SyscallError::NotImplemented)
    }

    /// Change permission bits on an open file handle.
    fn fchmod(&self, file_id: u64, mode: u32) -> Result<(), SyscallError> {
        let _ = (file_id, mode);
        Err(SyscallError::NotImplemented)
    }

    /// Create a hard link.
    fn link(&self, old_path: &str, new_path: &str) -> Result<(), SyscallError> {
        let _ = (old_path, new_path);
        Err(SyscallError::NotImplemented)
    }

    /// Create a symbolic link.
    fn symlink(&self, target: &str, link_path: &str) -> Result<(), SyscallError> {
        let _ = (target, link_path);
        Err(SyscallError::NotImplemented)
    }

    /// Read the target of a symbolic link.
    fn readlink(&self, path: &str) -> Result<String, SyscallError> {
        let _ = path;
        Err(SyscallError::NotImplemented)
    }
}

/// Type-erased Scheme reference.
pub type DynScheme = Arc<dyn Scheme>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsyncSubmitResult {
    Completed(i32),
    InFlight,
}

pub const DEV_RAMFS: u64 = 1;
pub const DEV_SYSFS: u64 = 2;
pub const DEV_PROCFS: u64 = 3;
pub const DEV_DEVFS: u64 = 4;
pub const DEV_CONSOLE: u64 = 5;
pub const DEV_PIPEFS: u64 = 6;
pub const DEV_IPCFS: u64 = 7;
pub const DEV_NETFS: u64 = 8;
pub const DEV_CHAR_FS: u64 = 9;
pub const DEV_INPUT: u64 = 10;

/// Finalize pseudo-filesystem stats with a stable device identity and
/// synthetic timestamps.
pub fn finalize_pseudo_stat(mut st: FileStat, st_dev: u64, st_rdev: u64) -> FileStat {
    let now = strat9_abi::data::TimeSpec::from_nanos(crate::syscall::time::current_time_ns());
    st.st_dev = st_dev;
    st.st_rdev = st_rdev;
    st.st_atime = now;
    st.st_mtime = now;
    st.st_ctime = now;
    st
}

// ============================================================================
// Built-in Schemes
// ============================================================================

/// IPC-based scheme: forwards operations to a userspace server via IPC.
pub struct IpcScheme {
    port_id: PortId,
    open_file_flags: SpinLock<BTreeMap<u64, FileFlags>>,
}

impl IpcScheme {
    /// Creates a new instance.
    pub fn new(port_id: PortId) -> Self {
        IpcScheme {
            port_id,
            open_file_flags: SpinLock::new(BTreeMap::new()),
        }
    }

    fn remember_open_flags(&self, file_id: u64, flags: FileFlags) {
        self.open_file_flags.lock().insert(file_id, flags);
    }

    fn take_open_flags(&self, file_id: u64) {
        self.open_file_flags.lock().remove(&file_id);
    }

    fn open_flags_for(&self, file_id: u64) -> FileFlags {
        self.open_file_flags
            .lock()
            .get(&file_id)
            .copied()
            .unwrap_or_else(FileFlags::empty)
    }

    /// Build an IPC message for open operation.
    fn build_open_msg(path: &str, flags: OpenFlags) -> Result<IpcMessage, SyscallError> {
        // Typed encode: bounds-checks the inline path; no hand-rolled offsets.
        OpenRequest::encode(OPCODE_OPEN, flags.bits(), path).ok_or(SyscallError::InvalidArgument)
        // path too long for inline
    }

    /// Build an IPC message for read operation.
    fn build_read_msg(file_id: u64, offset: u64, count: u32) -> IpcMessage {
        ReadRequest::encode(OPCODE_READ, file_id, offset, count)
    }

    /// Build an IPC message for write operation.
    ///
    /// Returns the message and the number of bytes actually packed, or
    /// `MessageSize` if `data` exceeds the inline capacity (the caller's
    /// chunking logic guarantees this never happens; we refuse rather
    /// than truncate or emit an empty write).
    fn build_write_msg(
        file_id: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<(IpcMessage, usize), SyscallError> {
        WriteRequest::encode(OPCODE_WRITE, file_id, offset, data)
            .ok_or(SyscallError::MessageSize)
    }

    /// Build an IPC message for close operation.
    fn build_close_msg(file_id: u64) -> IpcMessage {
        CloseRequest::encode(OPCODE_CLOSE, file_id)
    }

    /// Performs the build readdir msg operation.
    fn build_readdir_msg(file_id: u64, cursor: u16) -> IpcMessage {
        // Wire layout: [ino: u64][cursor: u16 @ 8..10].
        let mut msg = IpcMessage::new(OPCODE_READDIR);
        msg.payload[0..8].copy_from_slice(&file_id.to_le_bytes());
        msg.payload[8..10].copy_from_slice(&cursor.to_le_bytes());
        msg
    }

    /// Parses status.
    fn parse_status(reply: &IpcMessage) -> Result<(), SyscallError> {
        if reply.msg_type != IpcMessage::REPLY_MSG_TYPE {
            return Err(SyscallError::IoError);
        }

        let status = get_u32(&reply.payload, 0).ok_or(SyscallError::IoError)?;
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
        let port_owner = port.owner;
        port.send(msg).map_err(|_| SyscallError::BadHandle)?;
        // Drop the Arc before blocking so we don't hold the port alive across
        // a potentially long sleep.
        drop(port);

        Ok(crate::ipc::reply::wait_for_reply(task_id, port_owner))
    }
}

impl Scheme for IpcScheme {
    /// Performs the open operation.
    fn open(&self, path: &str, flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        let msg = Self::build_open_msg(path, flags)?;
        let reply = self.call(msg)?;

        // Parse reply via the typed ABI struct:
        // [status: u32][file_id: u64][size: u64][flags: u32]
        Self::parse_status(&reply)?;

        let reply = OpenReply::parse(&reply.payload).ok_or(SyscallError::IoError)?;
        let file_id = reply.file_id;
        let size = reply.size;
        let file_flags = reply.file_flags;
        let flags = FileFlags::from_bits_truncate(file_flags);
        self.remember_open_flags(file_id, flags);

        Ok(OpenResult {
            file_id,
            size: if size == u64::MAX { None } else { Some(size) },
            flags,
        })
    }

    /// Performs the read operation.
    fn read(&self, file_id: u64, offset: u64, buf: &mut [u8]) -> Result<usize, SyscallError> {
        let flags = self.open_flags_for(file_id);
        let chunked = flags.contains(FileFlags::CHUNK_READ);
        let chunk_size = if chunked {
            IpcMessage::READ_INLINE_CAPACITY
        } else {
            buf.len()
        };

        let mut total = 0usize;
        let mut current_offset = offset;
        while total < buf.len() {
            let request_len = core::cmp::min(buf.len() - total, chunk_size);
            let msg = Self::build_read_msg(file_id, current_offset, request_len as u32);
            let reply = self.call(msg)?;

            Self::parse_status(&reply)?;

            // READ reply: [status][count u32 @ 4..8][data @ 8..] (ReadReply).
            let count = get_u32(&reply.payload, 4).ok_or(SyscallError::IoError)? as usize;
            let available = core::cmp::min(count, reply.payload.len() - ReadReply::DATA_OFFSET);
            let to_copy = core::cmp::min(available, request_len);
            buf[total..total + to_copy].copy_from_slice(
                &reply.payload[ReadReply::DATA_OFFSET..ReadReply::DATA_OFFSET + to_copy],
            );

            total += to_copy;
            current_offset += to_copy as u64;

            if !chunked || to_copy < request_len {
                break;
            }
        }

        Ok(total)
    }

    /// Performs the write operation.
    fn write(&self, file_id: u64, offset: u64, buf: &[u8]) -> Result<usize, SyscallError> {
        let flags = self.open_flags_for(file_id);
        let chunked = flags.contains(FileFlags::CHUNK_WRITE);
        // Non-chunked handles (control endpoints, datagrams) must fit in one IPC
        // message; chunked handles (streams, files) can split across multiple calls.
        if !chunked && buf.len() > IpcMessage::WRITE_INLINE_CAPACITY {
            return Err(SyscallError::MessageSize);
        }
        let chunk_size = if chunked {
            IpcMessage::WRITE_INLINE_CAPACITY
        } else {
            buf.len()
        };

        let mut total = 0usize;
        let mut current_offset = offset;
        while total < buf.len() {
            let request_len = core::cmp::min(buf.len() - total, chunk_size);
            let (msg, packed) =
                Self::build_write_msg(file_id, current_offset, &buf[total..total + request_len])?;
            let reply = self.call(msg)?;

            Self::parse_status(&reply)?;

            // WRITE reply: [status][written u32 @ 4..8] (WriteReply).
            let bytes_written = get_u32(&reply.payload, 4).ok_or(SyscallError::IoError)? as usize;

            let chunk_written = bytes_written.min(packed);
            total += chunk_written;
            current_offset += chunk_written as u64;

            if !chunked || chunk_written < packed {
                break;
            }
        }

        Ok(total)
    }

    /// Performs the close operation.
    fn close(&self, file_id: u64) -> Result<(), SyscallError> {
        let msg = Self::build_close_msg(file_id);
        let reply = self.call(msg)?;
        Self::parse_status(&reply)?;
        self.take_open_flags(file_id);
        Ok(())
    }

    /// Creates file.
    fn create_file(&self, path: &str, mode: u32) -> Result<OpenResult, SyscallError> {
        self.handle_create_op(OPCODE_CREATE_FILE, path, mode)
    }

    /// Creates directory.
    fn create_directory(&self, path: &str, mode: u32) -> Result<OpenResult, SyscallError> {
        self.handle_create_op(OPCODE_CREATE_DIR, path, mode)
    }

    /// Performs the unlink operation.
    fn unlink(&self, path: &str) -> Result<(), SyscallError> {
        let mut msg = IpcMessage::new(OPCODE_UNLINK);

        if path.len() > IpcMessage::UNLINK_INLINE_CAPACITY {
            return Err(SyscallError::InvalidArgument);
        }

        // Wire framing: [path_len: u16][path bytes...] (put_u16_len_prefixed).
        put_u16_len_prefixed(&mut msg.payload, 0, path.as_bytes())
            .ok_or(SyscallError::InvalidArgument)?;

        let reply = self.call(msg)?;
        Self::parse_status(&reply)?;

        Ok(())
    }

    /// Performs the readdir operation.
    fn readdir(&self, file_id: u64) -> Result<Vec<DirEntry>, SyscallError> {
        const MAX_READDIR_ENTRIES: usize = 8192;
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

            // The cursor protocol bounds the number of round-trips, but a
            // buggy or malicious server could keep us accumulating entries
            // for up to 64K iterations. Cap the total to bound kernel
            // memory under our trust boundary.
            if entries.len() > MAX_READDIR_ENTRIES {
                return Err(SyscallError::IoError);
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
    /// Handles create op.
    fn handle_create_op(
        &self,
        opcode: u32,
        path: &str,
        mode: u32,
    ) -> Result<OpenResult, SyscallError> {
        // Typed encode: [mode: u32][path_len: u16][path bytes...]
        let msg = CreateRequest::encode(opcode, mode, path).ok_or(SyscallError::InvalidArgument)?;

        let reply = self.call(msg)?;

        Self::parse_status(&reply)?;

        // Reply layout: [status: u32][file_id: u64 @ 4..12] (CreateReply).
        let file_id = {
            let payload = &reply.payload;
            if payload.len() < 12 {
                return Err(SyscallError::IoError);
            }
            u64::from_le_bytes(
                payload[4..12]
                    .try_into()
                    .map_err(|_| SyscallError::IoError)?,
            )
        };

        Ok(OpenResult {
            file_id,
            size: Some(0),
            flags: FileFlags::empty(),
        })
    }
}

/// Kernel-backed scheme: serves files from kernel memory (read-only).
///
/// SAFETY: All stored pointers are kernel-static (`'static`) and accessed
/// only through the scheme trait methods which are `&self` (shared reference).
pub struct KernelScheme {
    /// Files indexed by path => (id, base, len).
    files: SpinLock<BTreeMap<String, (u64, *const u8, usize)>>,
    /// Reverse lookup: file_id => path name.
    by_id: SpinLock<BTreeMap<u64, String>>,
}

// SAFETY: KernelScheme only stores kernel-static pointers that are valid
// for the entire kernel lifetime. No mutable access through raw pointers.
unsafe impl Send for KernelScheme {}
unsafe impl Sync for KernelScheme {}

impl KernelScheme {
    /// Creates a new instance.
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
            .insert(String::from(path), (id, base, len));
        self.by_id.lock().insert(id, String::from(path));
    }

    /// Returns (id, base, len) for a given file_id.
    fn get_by_id(&self, file_id: u64) -> Option<(u64, *const u8, usize)> {
        let name = self.by_id.lock().get(&file_id)?.clone();
        let entry = self.files.lock().get(&name).cloned()?;
        Some(entry)
    }

    /// Returns the bytes of a registered static kernel file.
    pub fn lookup_bytes(&self, path: &str) -> Option<&'static [u8]> {
        let (_, base, len) = self.files.lock().get(path).cloned()?;
        // SAFETY: initfs files are bootloader-provided mappings kept alive for
        // the full kernel lifetime.
        Some(unsafe { core::slice::from_raw_parts(base, len) })
    }
}

impl Scheme for KernelScheme {
    /// Performs the open operation.
    fn open(&self, path: &str, _flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        if path.is_empty() || path == "/" {
            return Ok(OpenResult {
                file_id: 0, // Root directory ID
                size: None,
                flags: FileFlags::DIRECTORY,
            });
        }

        let files = self.files.lock();
        let (id, _, len) = files.get(path).ok_or(SyscallError::BadHandle)?;
        Ok(OpenResult {
            file_id: *id,
            size: Some(*len as u64),
            flags: FileFlags::empty(),
        })
    }

    /// Performs the read operation.
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

        let (_, base, len) = self.get_by_id(file_id).ok_or(SyscallError::BadHandle)?;

        if offset >= len as u64 {
            return Ok(0);
        }

        let remaining = len - offset as usize;
        let to_copy = core::cmp::min(remaining, buf.len());

        // SAFETY: file.base is a kernel-static pointer, bounds checked above
        unsafe {
            let src = base.add(offset as usize);
            core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), to_copy);
        }

        Ok(to_copy)
    }

    /// Performs the write operation.
    fn write(&self, _file_id: u64, _offset: u64, _buf: &[u8]) -> Result<usize, SyscallError> {
        Err(SyscallError::PermissionDenied) // Read-only
    }

    /// Performs the close operation.
    fn close(&self, _file_id: u64) -> Result<(), SyscallError> {
        Ok(()) // No-op for kernel files
    }

    /// Performs the size operation.
    fn size(&self, file_id: u64) -> Result<u64, SyscallError> {
        let (_, _, len) = self.get_by_id(file_id).ok_or(SyscallError::BadHandle)?;
        Ok(len as u64)
    }

    /// Performs the stat operation.
    fn stat(&self, file_id: u64) -> Result<FileStat, SyscallError> {
        if file_id == 0 {
            return Ok(finalize_pseudo_stat(
                FileStat {
                    st_ino: 0,
                    st_mode: 0o040555,
                    st_nlink: 2,
                    st_size: 0,
                    st_blksize: 512,
                    st_blocks: 0,
                    ..FileStat::zeroed()
                },
                DEV_SYSFS,
                0,
            ));
        }
        let (_, _, len) = self.get_by_id(file_id).ok_or(SyscallError::BadHandle)?;
        Ok(finalize_pseudo_stat(
            FileStat {
                st_ino: file_id,
                st_mode: 0o100444,
                st_nlink: 1,
                st_size: len as u64,
                st_blksize: 512,
                st_blocks: ((len as u64) + 511) / 512,
                ..FileStat::zeroed()
            },
            DEV_SYSFS,
            0,
        ))
    }

    /// Performs the readdir operation.
    fn readdir(&self, file_id: u64) -> Result<Vec<DirEntry>, SyscallError> {
        if file_id != 0 {
            return Err(SyscallError::InvalidArgument);
        }
        let files = self.files.lock();
        let mut entries = Vec::new();
        for (name, (id, _, _)) in files.iter() {
            entries.push(DirEntry {
                ino: *id,
                file_type: DT_REG,
                name: name.clone(),
            });
        }
        Ok(entries)
    }
}
