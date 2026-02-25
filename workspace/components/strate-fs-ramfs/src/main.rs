//! RAM Filesystem Strate Server
//!
//! Receives IPC messages from the kernel VFS and executes operations
//! on the RamFileSystem.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::{alloc::Layout, panic::PanicInfo};
use linked_list_allocator::LockedHeap;
use strat9_syscall::{
    error::{EBADF, EINVAL, ENOSYS},
    *,
};
use strate_fs_abstraction::{FsError, VfsFileSystem, VfsFileType};
use strate_fs_ramfs::{split_path, RamFileSystem};

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

const HEAP_SIZE: usize = 2 * 1024 * 1024; // 2 MiB
static mut HEAP: [u8; HEAP_SIZE] = [0u8; HEAP_SIZE];

#[alloc_error_handler]
fn oom(_: Layout) -> ! {
    call::exit(12)
}

fn exit(code: usize) -> ! {
    call::exit(code)
}

// --- IPC Protocol ---
const OPCODE_OPEN: u32 = 0x01;
const OPCODE_READ: u32 = 0x02;
const OPCODE_WRITE: u32 = 0x03;
const OPCODE_CLOSE: u32 = 0x04;
const OPCODE_CREATE_FILE: u32 = 0x05;
const OPCODE_CREATE_DIR: u32 = 0x06;
const OPCODE_UNLINK: u32 = 0x07;
const OPCODE_READDIR: u32 = 0x08;
const REPLY_MSG_TYPE: u32 = 0x80;
const STATUS_OK: u32 = 0;
const MAX_OPEN_PATH: usize = 42;
const MAX_CREATE_PATH: usize = 40;
const MAX_UNLINK_PATH: usize = 42;
const MAX_READ_DATA: usize = 40; // payload[8..48]
const MAX_WRITE_DATA: usize = 30; // payload[18..48]
const OPEN_CREATE: u32 = 1 << 2;
const OPEN_TRUNCATE: u32 = 1 << 3;
const OPEN_DIRECTORY: u32 = 1 << 5;

use strat9_syscall::data::IpcMessage;

struct StrateRamServer {
    fs: RamFileSystem,
}

impl StrateRamServer {
    fn new() -> Self {
        Self {
            fs: RamFileSystem::new(),
        }
    }

    fn ok_reply(sender: u64) -> IpcMessage {
        let mut reply = IpcMessage::new(REPLY_MSG_TYPE);
        reply.sender = sender;
        reply.payload[0..4].copy_from_slice(&STATUS_OK.to_le_bytes());
        reply
    }

    fn err_reply(sender: u64, status: u32) -> IpcMessage {
        let mut reply = IpcMessage::new(REPLY_MSG_TYPE);
        reply.sender = sender;
        reply.payload[0..4].copy_from_slice(&status.to_le_bytes());
        reply
    }

    fn read_u16(payload: &[u8], start: usize) -> core::result::Result<u16, u32> {
        let end = start.checked_add(2).ok_or(EINVAL as u32)?;
        let bytes = payload.get(start..end).ok_or(EINVAL as u32)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(payload: &[u8], start: usize) -> core::result::Result<u32, u32> {
        let end = start.checked_add(4).ok_or(EINVAL as u32)?;
        let bytes = payload.get(start..end).ok_or(EINVAL as u32)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(payload: &[u8], start: usize) -> core::result::Result<u64, u32> {
        let end = start.checked_add(8).ok_or(EINVAL as u32)?;
        let bytes = payload.get(start..end).ok_or(EINVAL as u32)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn fs_status(err: FsError) -> u32 {
        let code: strat9_syscall::error::Error = err.into();
        code.to_errno() as u32
    }

    fn parse_path<'a>(
        payload: &'a [u8],
        len_offset: usize,
        data_offset: usize,
        max_len: usize,
    ) -> core::result::Result<&'a str, u32> {
        let path_len = Self::read_u16(payload, len_offset)? as usize;
        if path_len > max_len {
            return Err(EINVAL as u32);
        }
        let end = data_offset.checked_add(path_len).ok_or(EINVAL as u32)?;
        let path_bytes = payload.get(data_offset..end).ok_or(EINVAL as u32)?;
        core::str::from_utf8(path_bytes).map_err(|_| EINVAL as u32)
    }

    fn dirent_type(file_type: VfsFileType) -> u8 {
        match file_type {
            VfsFileType::RegularFile => 8, // DT_REG
            VfsFileType::Directory => 4,   // DT_DIR
            VfsFileType::Symlink => 10,    // DT_LNK
            _ => 0,                        // DT_UNKNOWN
        }
    }

    fn handle_open(&mut self, sender: u64, payload: &[u8]) -> IpcMessage {
        let flags = match Self::read_u32(payload, 0) {
            Ok(v) => v,
            Err(code) => return Self::err_reply(sender, code),
        };
        let path = match Self::parse_path(payload, 4, 6, MAX_OPEN_PATH) {
            Ok(path) => path,
            Err(code) => return Self::err_reply(sender, code),
        };

        let ino = match self.fs.resolve_path_internal(path) {
            Ok(ino) => ino,
            Err(FsError::NotFound) if (flags & OPEN_CREATE) != 0 => {
                if (flags & OPEN_DIRECTORY) != 0 {
                    return Self::err_reply(sender, EINVAL as u32);
                }
                if path.is_empty() || path == "/" {
                    return Self::err_reply(sender, EINVAL as u32);
                }
                let (parent_path, name) = split_path(path);
                let parent_ino = match self.fs.resolve_path_internal(parent_path) {
                    Ok(v) => v,
                    Err(err) => return Self::err_reply(sender, Self::fs_status(err)),
                };
                match self.fs.create_file(parent_ino, name, 0o644) {
                    Ok(info) => info.ino,
                    Err(err) => return Self::err_reply(sender, Self::fs_status(err)),
                }
            }
            Err(err) => return Self::err_reply(sender, Self::fs_status(err)),
        };

        let mut info = match self.fs.stat(ino) {
            Ok(info) => info,
            Err(err) => return Self::err_reply(sender, Self::fs_status(err)),
        };

        if (flags & OPEN_DIRECTORY) != 0 && !info.is_dir() {
            return Self::err_reply(sender, EINVAL as u32);
        }

        if (flags & OPEN_TRUNCATE) != 0 && !info.is_dir() {
            if let Err(err) = self.fs.set_size(info.ino, 0) {
                return Self::err_reply(sender, Self::fs_status(err));
            }
            info = match self.fs.stat(info.ino) {
                Ok(i) => i,
                Err(err) => return Self::err_reply(sender, Self::fs_status(err)),
            };
        }

        if let Err(err) = self.fs.register_open(info.ino) {
            return Self::err_reply(sender, Self::fs_status(err));
        }

        let mut reply = Self::ok_reply(sender);
        reply.payload[4..12].copy_from_slice(&info.ino.to_le_bytes());
        reply.payload[12..20].copy_from_slice(&info.size.to_le_bytes());
        let f_flags: u32 = if info.is_dir() { 1 } else { 0 };
        reply.payload[20..24].copy_from_slice(&f_flags.to_le_bytes());
        reply
    }

    fn handle_read(&mut self, sender: u64, payload: &[u8]) -> IpcMessage {
        let ino = match Self::read_u64(payload, 0) {
            Ok(v) => v,
            Err(code) => return Self::err_reply(sender, code),
        };
        let offset = match Self::read_u64(payload, 8) {
            Ok(v) => v,
            Err(code) => return Self::err_reply(sender, code),
        };
        let requested = match Self::read_u32(payload, 16) {
            Ok(v) => v as usize,
            Err(code) => return Self::err_reply(sender, code),
        };

        let mut reply = Self::ok_reply(sender);
        let mut buf = [0u8; MAX_READ_DATA];
        let to_read = requested.min(MAX_READ_DATA);
        match self.fs.read(ino, offset, &mut buf[..to_read]) {
            Ok(n) => {
                reply.payload[4..8].copy_from_slice(&(n as u32).to_le_bytes());
                reply.payload[8..8 + n].copy_from_slice(&buf[..n]);
            }
            Err(err) => {
                return Self::err_reply(sender, Self::fs_status(err));
            }
        }
        reply
    }

    fn handle_create(&mut self, sender: u64, payload: &[u8], is_dir: bool) -> IpcMessage {
        let mode = match Self::read_u32(payload, 0) {
            Ok(v) => v,
            Err(code) => return Self::err_reply(sender, code),
        };
        let path = match Self::parse_path(payload, 4, 6, MAX_CREATE_PATH) {
            Ok(path) => path,
            Err(code) => return Self::err_reply(sender, code),
        };

        if path.is_empty() || path == "/" {
            return Self::err_reply(sender, EINVAL as u32);
        }

        let (parent_path, name) = split_path(path);
        let result = match self.fs.resolve_path_internal(parent_path) {
            Ok(parent_ino) => {
                if is_dir {
                    self.fs.create_directory(parent_ino, name, mode)
                } else {
                    self.fs.create_file(parent_ino, name, mode)
                }
            }
            Err(err) => Err(err),
        };

        match result {
            Ok(info) => {
                let mut reply = Self::ok_reply(sender);
                reply.payload[4..12].copy_from_slice(&info.ino.to_le_bytes());
                reply
            }
            Err(err) => Self::err_reply(sender, Self::fs_status(err)),
        }
    }

    fn handle_write(&mut self, sender: u64, payload: &[u8]) -> IpcMessage {
        let ino = match Self::read_u64(payload, 0) {
            Ok(v) => v,
            Err(code) => return Self::err_reply(sender, code),
        };
        let offset = match Self::read_u64(payload, 8) {
            Ok(v) => v,
            Err(code) => return Self::err_reply(sender, code),
        };
        let len = match Self::read_u16(payload, 16) {
            Ok(v) => v as usize,
            Err(code) => return Self::err_reply(sender, code),
        };
        if len > MAX_WRITE_DATA {
            return Self::err_reply(sender, EINVAL as u32);
        }
        let end = 18 + len;
        let data = match payload.get(18..end) {
            Some(slice) => slice,
            None => return Self::err_reply(sender, EINVAL as u32),
        };

        let mut reply = Self::ok_reply(sender);
        match self.fs.write(ino, offset, data) {
            Ok(n) => {
                reply.payload[4..8].copy_from_slice(&(n as u32).to_le_bytes());
            }
            Err(err) => {
                return Self::err_reply(sender, Self::fs_status(err));
            }
        }
        reply
    }

    fn handle_close(&mut self, sender: u64, payload: &[u8]) -> IpcMessage {
        let ino = match Self::read_u64(payload, 0) {
            Ok(v) => v,
            Err(code) => return Self::err_reply(sender, code),
        };

        match self.fs.unregister_open(ino) {
            Ok(()) => Self::ok_reply(sender),
            Err(FsError::InodeNotFound) => Self::err_reply(sender, EBADF as u32),
            Err(err) => Self::err_reply(sender, Self::fs_status(err)),
        }
    }

    fn handle_unlink(&mut self, sender: u64, payload: &[u8]) -> IpcMessage {
        let path = match Self::parse_path(payload, 0, 2, MAX_UNLINK_PATH) {
            Ok(path) => path,
            Err(code) => return Self::err_reply(sender, code),
        };
        if path.is_empty() || path == "/" {
            return Self::err_reply(sender, EINVAL as u32);
        }

        let (parent_path, name) = split_path(path);
        let res = match self.fs.resolve_path_internal(parent_path) {
            Ok(parent_ino) => match self.fs.lookup(parent_ino, name) {
                Ok(info) => self.fs.unlink(parent_ino, name, info.ino),
                Err(err) => Err(err),
            },
            Err(err) => Err(err),
        };

        match res {
            Ok(_) => Self::ok_reply(sender),
            Err(err) => Self::err_reply(sender, Self::fs_status(err)),
        }
    }

    fn handle_readdir(&mut self, sender: u64, payload: &[u8]) -> IpcMessage {
        let ino = match Self::read_u64(payload, 0) {
            Ok(v) => v,
            Err(code) => return Self::err_reply(sender, code),
        };
        let cursor = match Self::read_u16(payload, 8) {
            Ok(v) => v as usize,
            Err(code) => return Self::err_reply(sender, code),
        };

        let entries = match self.fs.readdir(ino) {
            Ok(entries) => entries,
            Err(err) => return Self::err_reply(sender, Self::fs_status(err)),
        };
        if cursor > entries.len() {
            return Self::err_reply(sender, EINVAL as u32);
        }

        // reply payload layout:
        // [0..4] status
        // [4..6] next_cursor (u16, u16::MAX=end)
        // [6]    entry_count
        // [7]    payload_bytes_used in entries area
        // [8..]  repeated [ino:u64][type:u8][name_len:u8][name bytes]
        let mut reply = Self::ok_reply(sender);
        let mut write_pos = 8usize;
        let mut index = cursor;
        let mut count: u8 = 0;

        while index < entries.len() {
            let entry = &entries[index];
            let name_bytes = entry.name.as_bytes();
            if name_bytes.len() > u8::MAX as usize {
                return Self::err_reply(sender, EINVAL as u32);
            }

            let needed = 8 + 1 + 1 + name_bytes.len();
            if write_pos + needed > reply.payload.len() {
                break;
            }

            reply.payload[write_pos..write_pos + 8].copy_from_slice(&entry.ino.to_le_bytes());
            reply.payload[write_pos + 8] = Self::dirent_type(entry.file_type);
            reply.payload[write_pos + 9] = name_bytes.len() as u8;
            reply.payload[write_pos + 10..write_pos + 10 + name_bytes.len()]
                .copy_from_slice(name_bytes);

            write_pos += needed;
            index += 1;
            count = count.saturating_add(1);
        }

        let next_cursor = if index >= entries.len() {
            u16::MAX
        } else if index > u16::MAX as usize {
            return Self::err_reply(sender, EINVAL as u32);
        } else {
            index as u16
        };
        reply.payload[4..6].copy_from_slice(&next_cursor.to_le_bytes());
        reply.payload[6] = count;
        reply.payload[7] = (write_pos - 8) as u8;
        reply
    }

    fn serve(&mut self, port: u64) -> ! {
        loop {
            let mut msg = IpcMessage::new(0);
            if call::ipc_recv(port as usize, &mut msg).is_ok() {
                let reply = match msg.msg_type {
                    OPCODE_OPEN => self.handle_open(msg.sender, &msg.payload),
                    OPCODE_READ => self.handle_read(msg.sender, &msg.payload),
                    OPCODE_WRITE => self.handle_write(msg.sender, &msg.payload),
                    OPCODE_CLOSE => self.handle_close(msg.sender, &msg.payload),
                    OPCODE_UNLINK => self.handle_unlink(msg.sender, &msg.payload),
                    OPCODE_CREATE_FILE => self.handle_create(msg.sender, &msg.payload, false),
                    OPCODE_CREATE_DIR => self.handle_create(msg.sender, &msg.payload, true),
                    OPCODE_READDIR => self.handle_readdir(msg.sender, &msg.payload),
                    _ => Self::err_reply(msg.sender, ENOSYS as u32),
                };
                let _ = call::ipc_reply(&reply);
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        ALLOCATOR.lock().init(HEAP.as_mut_ptr(), HEAP_SIZE);
    }

    let port = match call::ipc_create_port(0) {
        Ok(p) => p as u64,
        Err(_) => exit(1),
    };

    let _ = call::ipc_bind_port(port as usize, b"/ram");

    let mut server = StrateRamServer::new();
    server.serve(port)
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    exit(255);
}
