//! EXT4 Filesystem Strate (userspace)
//!
//! IPC-based filesystem strate that mounts an EXT4 volume and serves
//! file operations via the kernel VFS.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

mod syscalls;

use alloc::{collections::BTreeMap, format, vec, vec::Vec};
use core::{
    alloc::Layout,
    panic::PanicInfo,
    sync::atomic::{AtomicUsize, Ordering},
};
use fs_ext4::{BlockDevice, BlockDeviceError, Ext4FileSystem};
use syscalls::*;

// ---------------------------------------------------------------------------
// Minimal bump allocator (temporary until userspace heap is wired).
// ---------------------------------------------------------------------------

struct BumpAllocator;

const HEAP_SIZE: usize = 1024 * 1024; // 1 MiB heap for now.
static mut HEAP: [u8; HEAP_SIZE] = [0u8; HEAP_SIZE];
static HEAP_OFFSET: AtomicUsize = AtomicUsize::new(0);

unsafe impl core::alloc::GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align().max(1);
        let size = layout.size();
        let mut offset = HEAP_OFFSET.load(Ordering::Relaxed);
        loop {
            let aligned = (offset + align - 1) & !(align - 1);
            let new_offset = match aligned.checked_add(size) {
                Some(v) => v,
                None => return core::ptr::null_mut(),
            };
            if new_offset > HEAP_SIZE {
                return core::ptr::null_mut();
            }
            match HEAP_OFFSET.compare_exchange(
                offset,
                new_offset,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    let heap_ptr = core::ptr::addr_of_mut!(HEAP) as *mut u8;
                    return unsafe { heap_ptr.add(aligned) };
                }
                Err(prev) => offset = prev,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static GLOBAL_ALLOCATOR: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    debug_log("[fs-ext4] OOM\n");
    exit(12);
}

/// IPC message opcodes (9P-style)
const OPCODE_OPEN: u32 = 0x01;
const OPCODE_READ: u32 = 0x02;
const OPCODE_WRITE: u32 = 0x03;
const OPCODE_CLOSE: u32 = 0x04;
const OPCODE_BOOTSTRAP: u32 = 0x10;

/// Maximum open files
const MAX_OPEN_FILES: usize = 256;

/// IPC Message format (64 bytes, cache-line aligned)
#[repr(C, align(64))]
struct IpcMessage {
    sender: u64,
    msg_type: u32,
    flags: u32,
    payload: [u8; 48],
}

impl IpcMessage {
    fn new(msg_type: u32) -> Self {
        IpcMessage {
            sender: 0,
            msg_type,
            flags: 0,
            payload: [0u8; 48],
        }
    }

    fn error_reply(sender: u64) -> Self {
        let mut msg = IpcMessage::new(1);
        msg.sender = sender;
        msg
    }
}

/// Open file handle
struct OpenFileHandle {
    inode: u64,
    offset: u64,
    size: u64,
    flags: u32,
}

/// EXT4 Strate state
struct Ext4Strate {
    fs: Ext4FileSystem,
    open_files: BTreeMap<u64, OpenFileHandle>,
}

impl Ext4Strate {
    fn new(fs: Ext4FileSystem) -> Self {
        Ext4Strate {
            fs,
            open_files: BTreeMap::new(),
        }
    }

    /// Handle OPEN request
    fn handle_open(&mut self, sender: u64, payload: &[u8], port_handle: u64) -> IpcMessage {
        // Kernel format: [path_len: u16][path bytes...]
        if payload.len() < 2 {
            return IpcMessage::error_reply(sender);
        }

        let path_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
        if path_len > 46 || payload.len() < 2 + path_len {
            return IpcMessage::error_reply(sender);
        }

        let path_bytes = &payload[2..2 + path_len];
        let path = match core::str::from_utf8(path_bytes) {
            Ok(p) => p,
            Err(_) => return IpcMessage::error_reply(sender),
        };

        // TODO: Actually open the file via ext4_rs
        // For now, keep a single open file per sender.
        self.open_files.insert(
            sender,
            OpenFileHandle {
                inode: 0,
                offset: 0,
                size: 0,
                flags: 0,
            },
        );

        if port_handle > u32::MAX as u64 {
            return IpcMessage::error_reply(sender);
        }

        // Success reply: msg_type=0, flags = handle to transfer.
        let mut msg = IpcMessage::new(0);
        msg.sender = sender;
        msg.flags = port_handle as u32;
        let _ = path;
        msg
    }

    /// Handle READ request
    fn handle_read(&mut self, sender: u64, payload: &[u8]) -> IpcMessage {
        // Kernel format: [count: u16]
        if payload.len() < 2 {
            return IpcMessage::error_reply(sender);
        }
        let mut count = u16::from_le_bytes([payload[0], payload[1]]) as usize;
        if count > 46 {
            count = 46;
        }

        let file = match self.open_files.get_mut(&sender) {
            Some(f) => f,
            None => return IpcMessage::error_reply(sender),
        };

        // TODO: Actually read from ext4_rs
        let read_len = 0usize.min(count);

        let mut msg = IpcMessage::new(0);
        msg.sender = sender;
        let len_bytes = (read_len as u16).to_le_bytes();
        msg.payload[0] = len_bytes[0];
        msg.payload[1] = len_bytes[1];
        let _ = file;
        msg
    }

    /// Handle WRITE request
    fn handle_write(&mut self, sender: u64, payload: &[u8]) -> core::result::Result<(), ()> {
        if payload.len() < 2 {
            return Err(());
        }
        let len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
        if payload.len() < 2 + len {
            return Err(());
        }
        let data = &payload[2..2 + len];

        let file = match self.open_files.get_mut(&sender) {
            Some(f) => f,
            None => return Err(()),
        };

        // TODO: Actually write to ext4_rs
        let _ = data;
        let _ = file;
        Ok(())
    }

    /// Handle CLOSE request
    fn handle_close(&mut self, sender: u64) -> IpcMessage {
        let _ = self.open_files.remove(&sender);
        let mut msg = IpcMessage::new(0);
        msg.sender = sender;
        msg
    }

    /// Main strate loop
    fn serve(&mut self, port_handle: u64) -> ! {
        loop {
            // Receive message
            let mut msg = IpcMessage::new(0);
            let result = unsafe {
                syscall2(
                    number::SYS_IPC_RECV,
                    port_handle as usize,
                    &mut msg as *mut IpcMessage as usize,
                )
            };

            if result.is_err() {
                continue; // Ignore errors, keep serving
            }

            // Dispatch based on opcode
            match msg.msg_type {
                OPCODE_BOOTSTRAP => {
                    let reply = IpcMessage::error_reply(msg.sender);
                    let _ = unsafe {
                        syscall1(number::SYS_IPC_REPLY, &reply as *const IpcMessage as usize)
                    };
                }
                OPCODE_OPEN => {
                    let reply = self.handle_open(msg.sender, &msg.payload, port_handle);
                    let _ = unsafe {
                        syscall1(number::SYS_IPC_REPLY, &reply as *const IpcMessage as usize)
                    };
                }
                OPCODE_READ => {
                    let reply = self.handle_read(msg.sender, &msg.payload);
                    let _ = unsafe {
                        syscall1(number::SYS_IPC_REPLY, &reply as *const IpcMessage as usize)
                    };
                }
                OPCODE_WRITE => {
                    let _ = self.handle_write(msg.sender, &msg.payload);
                }
                OPCODE_CLOSE => {
                    let reply = self.handle_close(msg.sender);
                    let _ = unsafe {
                        syscall1(number::SYS_IPC_REPLY, &reply as *const IpcMessage as usize)
                    };
                }
                _ => {
                    let reply = IpcMessage::error_reply(msg.sender);
                    let _ = unsafe {
                        syscall1(number::SYS_IPC_REPLY, &reply as *const IpcMessage as usize)
                    };
                }
            }
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
    fn new(handle: u64) -> core::result::Result<Self, BlockDeviceError> {
        let sector_count = volume_info(handle).map_err(map_sys_err)?;
        Ok(Self {
            handle,
            sector_count,
        })
    }
}

fn map_sys_err(err: Error) -> BlockDeviceError {
    match err {
        Error::Again => BlockDeviceError::NotReady,
        Error::Io => BlockDeviceError::Io,
        Error::Invalid => BlockDeviceError::InvalidOffset,
        _ => BlockDeviceError::Other,
    }
}

fn log_sys_err(prefix: &str, err: Error) {
    let msg = format!("[fs-ext4] {}: {} ({})\n", prefix, err.name(), err);
    debug_log(&msg);
}

fn validate_volume_handle(handle: u64) -> Result<u64> {
    let sectors = volume_info(handle)?;
    if sectors == 0 {
        return Err(Error::Invalid);
    }
    let mut probe = [0u8; SECTOR_SIZE];
    let _ = volume_read(handle, 0, &mut probe, 1)?;
    Ok(sectors)
}

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

    fn size(&self) -> core::result::Result<usize, BlockDeviceError> {
        Ok(self.sector_count as usize * SECTOR_SIZE)
    }
}

fn wait_for_bootstrap(port_handle: u64) -> u64 {
    debug_log("[fs-ext4] Waiting for volume bootstrap...\n");
    loop {
        let mut msg = IpcMessage::new(0);
        let result = unsafe {
            syscall2(
                number::SYS_IPC_RECV,
                port_handle as usize,
                &mut msg as *mut IpcMessage as usize,
            )
        };
        if result.is_err() {
            continue;
        }

        if msg.msg_type == OPCODE_BOOTSTRAP && msg.flags != 0 {
            let mut reply = IpcMessage::new(0);
            reply.sender = msg.sender;
            let _ =
                unsafe { syscall1(number::SYS_IPC_REPLY, &reply as *const IpcMessage as usize) };
            return msg.flags as u64;
        }

        let reply = IpcMessage::error_reply(msg.sender);
        let _ = unsafe { syscall1(number::SYS_IPC_REPLY, &reply as *const IpcMessage as usize) };
    }
}

fn try_wait_for_bootstrap(port_handle: u64, attempts: usize) -> Option<u64> {
    for _ in 0..attempts {
        let mut msg = IpcMessage::new(0);
        let result = unsafe {
            syscall2(
                number::SYS_IPC_TRY_RECV,
                port_handle as usize,
                &mut msg as *mut IpcMessage as usize,
            )
        };
        match result {
            Ok(_) => {
                if msg.msg_type == OPCODE_BOOTSTRAP && msg.flags != 0 {
                    let mut reply = IpcMessage::new(0);
                    reply.sender = msg.sender;
                    let _ = unsafe {
                        syscall1(number::SYS_IPC_REPLY, &reply as *const IpcMessage as usize)
                    };
                    return Some(msg.flags as u64);
                }
                let reply = IpcMessage::error_reply(msg.sender);
                let _ = unsafe {
                    syscall1(number::SYS_IPC_REPLY, &reply as *const IpcMessage as usize)
                };
            }
            Err(Error::Again) => {
                // EAGAIN: no message yet.
            }
            Err(err) => {
                log_sys_err("try_recv bootstrap failed", err);
            }
        }
        let _ = unsafe { syscall1(number::SYS_PROC_YIELD, 0) };
    }
    None
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(bootstrap_handle: u64) -> ! {
    // TODO: Initialize allocator (we need heap)
    // For now, this will panic since we can't allocate

    debug_log("[fs-ext4] Starting EXT4 filesystem strate\n");

    // Create IPC port
    let port_result = unsafe { syscall1(number::SYS_IPC_CREATE_PORT, 0) };

    let port_handle = match port_result {
        Ok(h) => h as u64,
        Err(_) => {
            debug_log("[fs-ext4] Failed to create IPC port\n");
            exit(1);
        }
    };

    debug_log("[fs-ext4] IPC port created\n");

    // Bind under a dedicated namespace to avoid hijacking the whole VFS root.
    let path = b"/fs/ext4";
    let bind_result = unsafe {
        syscall3(
            number::SYS_IPC_BIND_PORT,
            port_handle as usize,
            path.as_ptr() as usize,
            path.len(),
        )
    };

    if bind_result.is_err() {
        debug_log("[fs-ext4] Failed to bind port to /fs/ext4\n");
        exit(2);
    }

    debug_log("[fs-ext4] Port bound to /fs/ext4\n");

    let mut volume_handle = bootstrap_handle;
    if volume_handle == 0 {
        debug_log("[fs-ext4] Waiting for early bootstrap message...\n");
        if let Some(h) = try_wait_for_bootstrap(port_handle, 2048) {
            let msg = format!("[fs-ext4] Received bootstrap handle: {}\n", h);
            debug_log(&msg);
            volume_handle = h;
        } else if let Some(h) = discover_volume_handle_local() {
            debug_log("[fs-ext4] Bootstrap message timeout, using local discovery fallback\n");
            volume_handle = h;
        } else {
            debug_log("[fs-ext4] Bootstrap message timeout, switching to blocking wait\n");
            volume_handle = wait_for_bootstrap(port_handle);
        }
    }
    {
        let msg = format!("[fs-ext4] Volume handle ready: {}\n", volume_handle);
        debug_log(&msg);
    }

    // Mount EXT4 with retry/backoff instead of hard exit.
    let mut attempts: u64 = 0;
    loop {
        attempts = attempts.wrapping_add(1);
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
                    volume_handle = wait_for_bootstrap(port_handle);
                    let msg = format!("[fs-ext4] Refreshed volume handle: {}\n", volume_handle);
                    debug_log(&msg);
                }
                for _ in 0..2048 {
                    let _ = unsafe { syscall1(number::SYS_PROC_YIELD, 0) };
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
                    let _ = unsafe { syscall1(number::SYS_PROC_YIELD, 0) };
                }
                continue;
            }
        };

        let fs = match Ext4FileSystem::mount(device) {
            Ok(fs) => fs,
            Err(e) => {
                let msg = format!(
                    "[fs-ext4] Failed to mount EXT4 filesystem (attempt={}): {:?}\n",
                    attempts, e
                );
                debug_log(&msg);
                for _ in 0..2048 {
                    let _ = unsafe { syscall1(number::SYS_PROC_YIELD, 0) };
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
fn panic(_info: &PanicInfo) -> ! {
    debug_log("[fs-ext4] PANIC!\n");
    exit(255);
}
