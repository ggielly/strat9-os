//! EXT4 Filesystem Strate (userspace)
//!
//! IPC-based filesystem strate that mounts an EXT4 volume and serves
//! file operations via the kernel VFS.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

mod syscalls;

use alloc::{format, string::String, vec, vec::Vec};
use core::{alloc::Layout, panic::PanicInfo};
use fs_ext4::{BlockDevice, BlockDeviceError, Ext4FileSystem};
use strat9_syscall::error::{EINVAL, ENOSYS};
use syscalls::*;

// ---------------------------------------------------------------------------
// Minimal bump allocator (temporary until userspace heap is wired).
// ---------------------------------------------------------------------------

alloc_freelist::define_freelist_allocator!(pub struct BumpAllocator; heap_size = 1024 * 1024;);

#[global_allocator]
static GLOBAL_ALLOCATOR: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
/// Implements alloc error.
fn alloc_error(_layout: Layout) -> ! {
    debug_log("[fs-ext4] OOM\n");
    exit(12);
}

use strat9_syscall::data::IpcMessage;

const OPCODE_OPEN: u32 = 0x01;
const OPCODE_READ: u32 = 0x02;
const OPCODE_WRITE: u32 = 0x03;
const OPCODE_CLOSE: u32 = 0x04;
const OPCODE_CREATE_FILE: u32 = 0x05;
const OPCODE_CREATE_DIR: u32 = 0x06;
const OPCODE_UNLINK: u32 = 0x07;
const OPCODE_READDIR: u32 = 0x08;
const OPCODE_BOOTSTRAP: u32 = 0x10;
const REPLY_MSG_TYPE: u32 = 0x80;
const STATUS_OK: u32 = 0;
const INITIAL_BIND_PATH: &[u8] = b"/srv/strate-fs-ext4/default";

const MAX_OPEN_PATH: usize = 42;
const MAX_WRITE_DATA: usize = 30;

struct BootstrapInfo {
    handle: u64,
    label: String,
}

/// Implements sanitize label.
fn sanitize_label(raw: &str) -> String {
    let mut out = String::new();
    for b in raw.bytes().take(31) {
        let ok = (b as char).is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.';
        out.push(if ok { b as char } else { '_' });
    }
    if out.is_empty() {
        String::from("default")
    } else {
        out
    }
}

/// Parses bootstrap label.
fn parse_bootstrap_label(payload: &[u8]) -> String {
    let len = payload.first().copied().unwrap_or(0) as usize;
    if len == 0 {
        return String::from("default");
    }
    let end = 1usize.saturating_add(len);
    let Some(bytes) = payload.get(1..end) else {
        return String::from("default");
    };
    match core::str::from_utf8(bytes) {
        Ok(s) => sanitize_label(s),
        Err(_) => String::from("default"),
    }
}

/// Implements bind srv alias.
fn bind_srv_alias(port_handle: u64, label: &str) {
    let path = format!("/srv/strate-fs-ext4/{}", label);
    match call::ipc_bind_port(port_handle as usize, path.as_bytes()) {
        Ok(_) => {
            let msg = format!("[fs-ext4] Port alias bound to {}\n", path);
            debug_log(&msg);
        }
        Err(e) => {
            let msg = format!(
                "[fs-ext4] Failed to bind port alias {}: {}\n",
                path,
                e.name()
            );
            debug_log(&msg);
        }
    }
}

/// EXT4 Strate state
struct Ext4Strate {
    _fs: Ext4FileSystem,
}

impl Ext4Strate {
    /// Creates a new instance.
    fn new(fs: Ext4FileSystem) -> Self {
        Ext4Strate { _fs: fs }
    }

    /// Implements ok reply.
    fn ok_reply(sender: u64) -> IpcMessage {
        let mut reply = IpcMessage::new(REPLY_MSG_TYPE);
        reply.sender = sender;
        reply.payload[0..4].copy_from_slice(&STATUS_OK.to_le_bytes());
        reply
    }

    /// Implements err reply.
    fn err_reply(sender: u64, status: u32) -> IpcMessage {
        let mut reply = IpcMessage::new(REPLY_MSG_TYPE);
        reply.sender = sender;
        reply.payload[0..4].copy_from_slice(&status.to_le_bytes());
        reply
    }

    /// Reads u16.
    fn read_u16(payload: &[u8], start: usize) -> core::result::Result<u16, u32> {
        let end = start.checked_add(2).ok_or(EINVAL as u32)?;
        let bytes = payload.get(start..end).ok_or(EINVAL as u32)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Reads u32.
    fn read_u32(payload: &[u8], start: usize) -> core::result::Result<u32, u32> {
        let end = start.checked_add(4).ok_or(EINVAL as u32)?;
        let bytes = payload.get(start..end).ok_or(EINVAL as u32)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Reads u64.
    fn read_u64(payload: &[u8], start: usize) -> core::result::Result<u64, u32> {
        let end = start.checked_add(8).ok_or(EINVAL as u32)?;
        let bytes = payload.get(start..end).ok_or(EINVAL as u32)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
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

    /// Implements handle open.
    fn handle_open(&mut self, sender: u64, payload: &[u8]) -> IpcMessage {
        let _flags = match Self::read_u32(payload, 0) {
            Ok(v) => v,
            Err(code) => return Self::err_reply(sender, code),
        };
        let _path = match Self::parse_path(payload, 4, 6, MAX_OPEN_PATH) {
            Ok(v) => v,
            Err(code) => return Self::err_reply(sender, code),
        };
        Self::err_reply(sender, ENOSYS as u32)
    }

    /// Implements handle read.
    fn handle_read(&mut self, sender: u64, payload: &[u8]) -> IpcMessage {
        let _file_id = match Self::read_u64(payload, 0) {
            Ok(v) => v,
            Err(code) => return Self::err_reply(sender, code),
        };
        let _offset = match Self::read_u64(payload, 8) {
            Ok(v) => v,
            Err(code) => return Self::err_reply(sender, code),
        };
        let _requested = match Self::read_u32(payload, 16) {
            Ok(v) => v as usize,
            Err(code) => return Self::err_reply(sender, code),
        };
        Self::err_reply(sender, ENOSYS as u32)
    }

    /// Implements handle write.
    fn handle_write(&mut self, sender: u64, payload: &[u8]) -> IpcMessage {
        let _file_id = match Self::read_u64(payload, 0) {
            Ok(v) => v,
            Err(code) => return Self::err_reply(sender, code),
        };
        let _offset = match Self::read_u64(payload, 8) {
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
        let _data = match payload.get(18..end) {
            Some(s) => s,
            None => return Self::err_reply(sender, EINVAL as u32),
        };
        Self::err_reply(sender, ENOSYS as u32)
    }

    /// Implements handle close.
    fn handle_close(&mut self, sender: u64, payload: &[u8]) -> IpcMessage {
        let _file_id = match Self::read_u64(payload, 0) {
            Ok(v) => v,
            Err(code) => return Self::err_reply(sender, code),
        };
        Self::err_reply(sender, ENOSYS as u32)
    }

    /// Main strate loop
    fn serve(&mut self, port_handle: u64) -> ! {
        loop {
            let mut msg = IpcMessage::new(0);
            if call::ipc_recv(port_handle as usize, &mut msg).is_err() {
                let _ = call::sched_yield();
                continue;
            }

            let reply = match msg.msg_type {
                OPCODE_BOOTSTRAP => {
                    let label = parse_bootstrap_label(&msg.payload);
                    bind_srv_alias(port_handle, &label);
                    Self::ok_reply(msg.sender)
                }
                OPCODE_OPEN => self.handle_open(msg.sender, &msg.payload),
                OPCODE_READ => self.handle_read(msg.sender, &msg.payload),
                OPCODE_WRITE => self.handle_write(msg.sender, &msg.payload),
                OPCODE_CLOSE => self.handle_close(msg.sender, &msg.payload),
                OPCODE_CREATE_FILE | OPCODE_CREATE_DIR | OPCODE_UNLINK | OPCODE_READDIR => {
                    Self::err_reply(msg.sender, ENOSYS as u32)
                }
                _ => Self::err_reply(msg.sender, ENOSYS as u32),
            };
            let _ = call::ipc_reply(&reply);
        }
    }
}

// ---------------------------------------------------------------------------
// Volume-backed block device (uses SYS_VOLUME_* syscalls)
// ---------------------------------------------------------------------------

const SECTOR_SIZE: usize = 512;
const BLOCK_SIZE: usize = 4096;

struct VolumeBlockDevice {
    handle: u64,
    sector_count: u64,
}

impl VolumeBlockDevice {
    /// Creates a new instance.
    fn new(handle: u64) -> core::result::Result<Self, BlockDeviceError> {
        let sector_count = volume_info(handle).map_err(map_sys_err)?;
        Ok(Self {
            handle,
            sector_count,
        })
    }
}

/// Implements map sys err.
fn map_sys_err(err: Error) -> BlockDeviceError {
    match err {
        Error::Again => BlockDeviceError::NotReady,
        Error::IoError => BlockDeviceError::Io,
        Error::InvalidArgument => BlockDeviceError::InvalidOffset,
        _ => BlockDeviceError::Other,
    }
}

/// Implements log sys err.
fn log_sys_err(prefix: &str, err: Error) {
    let msg = format!("[fs-ext4] {}: {} ({})\n", prefix, err.name(), err);
    debug_log(&msg);
}

/// Implements validate volume handle.
fn validate_volume_handle(handle: u64) -> Result<u64> {
    let msg = format!("[fs-ext4] Probing volume handle={}\n", handle);
    debug_log(&msg);
    let sectors = volume_info(handle)?;
    if sectors == 0 {
        return Err(Error::InvalidArgument);
    }
    let msg = format!(
        "[fs-ext4] Volume info OK: handle={} sectors={}\n",
        handle, sectors
    );
    debug_log(&msg);
    let mut probe = [0u8; SECTOR_SIZE];
    let _ = volume_read(handle, 0, &mut probe, 1)?;
    let msg = format!("[fs-ext4] Sector-0 probe OK: handle={}\n", handle);
    debug_log(&msg);
    Ok(sectors)
}

/// Implements discover volume handle local.
fn discover_volume_handle_local() -> Option<u64> {
    // Pragmatic fallback: probe low capability ids for a usable Volume handle.
    // In current boot flow, init often receives the first inserted capability.
    for h in 0u64..256u64 {
        if let Ok(sectors) = validate_volume_handle(h) {
            let msg = format!(
                "[fs-ext4] Discovered local volume handle={} sectors={}\n",
                h, sectors
            );
            debug_log(&msg);
            return Some(h);
        }
    }
    None
}

impl BlockDevice for VolumeBlockDevice {
    /// Reads offset.
    fn read_offset(&self, offset: usize) -> core::result::Result<Vec<u8>, BlockDeviceError> {
        if offset % SECTOR_SIZE != 0 {
            return Err(BlockDeviceError::InvalidOffset);
        }
        let sector = (offset / SECTOR_SIZE) as u64;
        let sector_count = (BLOCK_SIZE / SECTOR_SIZE) as u64;
        if sector_count == 0 {
            return Err(BlockDeviceError::InvalidOffset);
        }
        let mut buf = vec![0u8; (sector_count as usize) * SECTOR_SIZE];
        volume_read(self.handle, sector, &mut buf, sector_count).map_err(map_sys_err)?;
        Ok(buf)
    }

    /// Writes offset.
    fn write_offset(
        &mut self,
        offset: usize,
        data: &[u8],
    ) -> core::result::Result<(), BlockDeviceError> {
        if offset % SECTOR_SIZE != 0 || data.len() % SECTOR_SIZE != 0 {
            return Err(BlockDeviceError::InvalidOffset);
        }
        let sector = (offset / SECTOR_SIZE) as u64;
        let sector_count = (data.len() / SECTOR_SIZE) as u64;
        if sector_count == 0 {
            return Err(BlockDeviceError::InvalidOffset);
        }
        volume_write(self.handle, sector, data, sector_count).map_err(map_sys_err)?;
        Ok(())
    }

    /// Implements size.
    fn size(&self) -> core::result::Result<usize, BlockDeviceError> {
        Ok(self.sector_count as usize * SECTOR_SIZE)
    }
}

/// Implements wait for bootstrap.
fn wait_for_bootstrap(port_handle: u64) -> BootstrapInfo {
    debug_log("[fs-ext4] Waiting for volume bootstrap...\n");
    loop {
        let mut msg = IpcMessage::new(0);
        if call::ipc_recv(port_handle as usize, &mut msg).is_err() {
            let _ = call::sched_yield();
            continue;
        }

        if msg.msg_type == OPCODE_BOOTSTRAP && msg.flags != 0 {
            let reply = Ext4Strate::ok_reply(msg.sender);
            let _ = call::ipc_reply(&reply);
            return BootstrapInfo {
                handle: msg.flags as u64,
                label: parse_bootstrap_label(&msg.payload),
            };
        }

        let reply = Ext4Strate::err_reply(msg.sender, ENOSYS as u32);
        let _ = call::ipc_reply(&reply);
    }
}

/// Attempts to wait for bootstrap.
fn try_wait_for_bootstrap(port_handle: u64, attempts: usize) -> Option<BootstrapInfo> {
    for _ in 0..attempts {
        let mut msg = IpcMessage::new(0);
        match call::ipc_try_recv(port_handle as usize, &mut msg) {
            Ok(_) => {
                if msg.msg_type == OPCODE_BOOTSTRAP && msg.flags != 0 {
                    let reply = Ext4Strate::ok_reply(msg.sender);
                    let _ = call::ipc_reply(&reply);
                    return Some(BootstrapInfo {
                        handle: msg.flags as u64,
                        label: parse_bootstrap_label(&msg.payload),
                    });
                }
                let reply = Ext4Strate::err_reply(msg.sender, ENOSYS as u32);
                let _ = call::ipc_reply(&reply);
            }
            Err(Error::Again) => {}
            Err(err) => {
                log_sys_err("try_recv bootstrap failed", err);
            }
        }
        let _ = call::sched_yield();
    }
    None
}

#[unsafe(no_mangle)]
/// Implements start.
pub extern "C" fn _start(bootstrap_handle: u64) -> ! {
    // TODO: Initialize allocator (we need heap)
    // For now, this will panic since we can't allocate

    debug_log("[fs-ext4] Starting EXT4 filesystem strate\n");

    let port_handle = match call::ipc_create_port(0) {
        Ok(h) => h as u64,
        Err(_) => {
            debug_log("[fs-ext4] Failed to create IPC port\n");
            exit(1);
        }
    };

    debug_log("[fs-ext4] IPC port created\n");

    if call::ipc_bind_port(port_handle as usize, INITIAL_BIND_PATH).is_err() {
        debug_log("[fs-ext4] Failed to bind initial port alias\n");
        exit(2);
    }

    debug_log("[fs-ext4] Port bound to /srv/strate-fs-ext4/default\n");

    let mut volume_handle = bootstrap_handle;
    let mut bootstrap_label = String::from("default");
    if volume_handle == 0 {
        debug_log("[fs-ext4] Waiting for early bootstrap message...\n");
        if let Some(info) = try_wait_for_bootstrap(port_handle, 2048) {
            let msg = format!(
                "[fs-ext4] Received bootstrap handle: {} label: {}\n",
                info.handle, info.label
            );
            debug_log(&msg);
            volume_handle = info.handle;
            bootstrap_label = info.label;
        } else if let Some(h) = discover_volume_handle_local() {
            debug_log("[fs-ext4] Bootstrap message timeout, using local discovery fallback\n");
            volume_handle = h;
        } else {
            debug_log("[fs-ext4] Bootstrap message timeout, switching to blocking wait\n");
            let info = wait_for_bootstrap(port_handle);
            volume_handle = info.handle;
            bootstrap_label = info.label;
        }
    }
    {
        let msg = format!(
            "[fs-ext4] Volume handle ready: {} label: {}\n",
            volume_handle, bootstrap_label
        );
        debug_log(&msg);
    }
    bind_srv_alias(port_handle, &bootstrap_label);

    // Mount EXT4 with retry/backoff instead of hard exit.
    let mut attempts: u64 = 0;
    loop {
        attempts = attempts.wrapping_add(1);
        if attempts <= 4 || attempts % 16 == 0 {
            let msg = format!(
                "[fs-ext4] Mount loop attempt={} handle={} label={}\n",
                attempts, volume_handle, bootstrap_label
            );
            debug_log(&msg);
        }
        match validate_volume_handle(volume_handle) {
            Ok(sectors) => {
                let msg = format!(
                    "[fs-ext4] volume probe OK: handle={} sectors={} (attempt={})\n",
                    volume_handle, sectors, attempts
                );
                debug_log(&msg);
            }
            Err(err) => {
                log_sys_err("volume probe failed", err);
                // If we started without bootstrap capability, wait for a fresh handle periodically.
                if bootstrap_handle == 0 && attempts % 8 == 0 {
                    debug_log("[fs-ext4] Waiting for refreshed bootstrap handle...\n");
                    let info = wait_for_bootstrap(port_handle);
                    volume_handle = info.handle;
                    bootstrap_label = info.label;
                    let msg = format!(
                        "[fs-ext4] Refreshed volume handle: {} label: {}\n",
                        volume_handle, bootstrap_label
                    );
                    debug_log(&msg);
                }
                for _ in 0..2048 {
                    let _ = call::sched_yield();
                }
                continue;
            }
        }

        let device = match VolumeBlockDevice::new(volume_handle) {
            Ok(dev) => alloc::sync::Arc::new(dev),
            Err(e) => {
                let msg = format!(
                    "[fs-ext4] Failed to init volume device (attempt={}): {:?}\n",
                    attempts, e
                );
                debug_log(&msg);
                for _ in 0..2048 {
                    let _ = call::sched_yield();
                }
                continue;
            }
        };

        let msg = format!(
            "[fs-ext4] Block device ready: handle={} (attempt={})\n",
            volume_handle, attempts
        );
        debug_log(&msg);

        let fs = match Ext4FileSystem::mount(device) {
            Ok(fs) => fs,
            Err(e) => {
                let msg = format!(
                    "[fs-ext4] Failed to mount EXT4 filesystem (attempt={}): {:?}\n",
                    attempts, e
                );
                debug_log(&msg);
                for _ in 0..2048 {
                    let _ = call::sched_yield();
                }
                continue;
            }
        };

        debug_log("[fs-ext4] EXT4 mounted successfully\n");
        debug_log("[fs-ext4] Strate ready, waiting for requests...\n");

        // Create strate and start serving
        let mut strate = Ext4Strate::new(fs);
        strate.serve(port_handle);
    }
}

#[panic_handler]
/// Implements panic.
fn panic(_info: &PanicInfo) -> ! {
    debug_log("[fs-ext4] PANIC!\n");
    exit(255);
}
