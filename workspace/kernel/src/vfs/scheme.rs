//! Scheme abstraction - backends for VFS operations.
//!
//! Schemes provide the actual implementation for file operations.
//! Examples: IPC-based schemes (ext4, network), kernel schemes (devfs, procfs).

use crate::{
    ipc::{message::IpcMessage, port::PortId},
    syscall::error::SyscallError,
};
use alloc::{string::String, sync::Arc};

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
    fn build_write_msg(file_id: u64, offset: u64, data: &[u8]) -> IpcMessage {
        const OPCODE_WRITE: u32 = 0x03;
        let mut msg = IpcMessage::new(OPCODE_WRITE);
        msg.payload[0..8].copy_from_slice(&file_id.to_le_bytes());
        msg.payload[8..16].copy_from_slice(&offset.to_le_bytes());

        let len = core::cmp::min(data.len(), 32);
        msg.payload[16..18].copy_from_slice(&(len as u16).to_le_bytes());
        msg.payload[18..18 + len].copy_from_slice(&data[..len]);
        msg
    }

    /// Build an IPC message for close operation.
    fn build_close_msg(file_id: u64) -> IpcMessage {
        const OPCODE_CLOSE: u32 = 0x04;
        let mut msg = IpcMessage::new(OPCODE_CLOSE);
        msg.payload[0..8].copy_from_slice(&file_id.to_le_bytes());
        msg
    }
}

impl Scheme for IpcScheme {
    fn open(&self, path: &str, flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        let msg = Self::build_open_msg(path, flags)?;
        let port = crate::ipc::port::get_port(self.port_id).ok_or(SyscallError::BadHandle)?;

        // Send request and wait for reply
        port.send(msg).map_err(|_| SyscallError::BadHandle)?;
        let reply = port.recv().map_err(|_| SyscallError::BadHandle)?;

        // Parse reply: [status: u32][file_id: u64][size: u64][flags: u32]
        if reply.msg_type != 0x80 {
            // 0x80 = generic success reply
            return Err(SyscallError::IoError);
        }

        let status = u32::from_le_bytes([
            reply.payload[0],
            reply.payload[1],
            reply.payload[2],
            reply.payload[3],
        ]);
        if status != 0 {
            return Err(SyscallError::from_code(status as i64));
        }

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
        let port = crate::ipc::port::get_port(self.port_id).ok_or(SyscallError::BadHandle)?;

        let msg = Self::build_read_msg(file_id, offset, buf.len() as u32);
        port.send(msg).map_err(|_| SyscallError::BadHandle)?;
        let reply = port.recv().map_err(|_| SyscallError::BadHandle)?;

        // Parse reply: [status: u32][bytes_read: u32][data...]
        let status = u32::from_le_bytes([
            reply.payload[0],
            reply.payload[1],
            reply.payload[2],
            reply.payload[3],
        ]);
        if status != 0 {
            return Err(SyscallError::from_code(status as i64));
        }

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
        let port = crate::ipc::port::get_port(self.port_id).ok_or(SyscallError::BadHandle)?;

        let msg = Self::build_write_msg(file_id, offset, buf);
        port.send(msg).map_err(|_| SyscallError::BadHandle)?;
        let reply = port.recv().map_err(|_| SyscallError::BadHandle)?;

        // Parse reply: [status: u32][bytes_written: u32]
        let status = u32::from_le_bytes([
            reply.payload[0],
            reply.payload[1],
            reply.payload[2],
            reply.payload[3],
        ]);
        if status != 0 {
            return Err(SyscallError::from_code(status as i64));
        }

        let bytes_written = u32::from_le_bytes([
            reply.payload[4],
            reply.payload[5],
            reply.payload[6],
            reply.payload[7],
        ]) as usize;

        Ok(bytes_written)
    }

    fn close(&self, file_id: u64) -> Result<(), SyscallError> {
        let port = crate::ipc::port::get_port(self.port_id).ok_or(SyscallError::BadHandle)?;

        let msg = Self::build_close_msg(file_id);
        port.send(msg).map_err(|_| SyscallError::BadHandle)?;
        let reply = port.recv().map_err(|_| SyscallError::BadHandle)?;

        let status = u32::from_le_bytes([
            reply.payload[0],
            reply.payload[1],
            reply.payload[2],
            reply.payload[3],
        ]);
        if status != 0 {
            return Err(SyscallError::from_code(status as i64));
        }

        Ok(())
    }
}

/// Kernel-backed scheme: serves files from kernel memory (read-only).
pub struct KernelScheme {
    files: alloc::collections::BTreeMap<String, KernelFile>,
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
            files: alloc::collections::BTreeMap::new(),
        }
    }

    /// Register a static kernel file.
    pub fn register(&mut self, path: &str, base: *const u8, len: usize) {
        static NEXT_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
        let id = NEXT_ID.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        self.files
            .insert(String::from(path), KernelFile { id, base, len });
    }
}

impl Scheme for KernelScheme {
    fn open(&self, path: &str, _flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        let file = self.files.get(path).ok_or(SyscallError::BadHandle)?;
        Ok(OpenResult {
            file_id: file.id,
            size: Some(file.len as u64),
            flags: FileFlags::empty(),
        })
    }

    fn read(&self, file_id: u64, offset: u64, buf: &mut [u8]) -> Result<usize, SyscallError> {
        let file = self
            .files
            .values()
            .find(|f| f.id == file_id)
            .ok_or(SyscallError::BadHandle)?;

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
        let file = self
            .files
            .values()
            .find(|f| f.id == file_id)
            .ok_or(SyscallError::BadHandle)?;
        Ok(file.len as u64)
    }
}
