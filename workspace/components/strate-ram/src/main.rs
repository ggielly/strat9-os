//! RAM Filesystem Strate Server
//!
//! Receives IPC messages from the kernel VFS and executes operations
//! on the RamFileSystem.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, sync::Arc, format};
use core::{alloc::Layout, panic::PanicInfo, sync::atomic::{AtomicUsize, Ordering}};
use strate_ram::RamFileSystem;
use strate_fs_abstraction::{VfsFileSystem, OpenFlags};
use strate_syscall::*;

// --- Simple Bump Allocator for Userspace Component ---
struct BumpAllocator;
const HEAP_SIZE: usize = 2 * 1024 * 1024; // 2 MiB
static mut HEAP: [u8; HEAP_SIZE] = [0u8; HEAP_SIZE];
static HEAP_OFFSET: AtomicUsize = AtomicUsize::new(0);

unsafe impl core::alloc::GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align();
        let size = layout.size();
        let mut offset = HEAP_OFFSET.load(Ordering::Relaxed);
        loop {
            let aligned = (offset + align - 1) & !(align - 1);
            if aligned + size > HEAP_SIZE { return core::ptr::null_mut(); }
            match HEAP_OFFSET.compare_exchange(offset, aligned + size, Ordering::SeqCst, Ordering::Relaxed) {
                Ok(_) => return (core::ptr::addr_of_mut!(HEAP) as *mut u8).add(aligned),
                Err(prev) => offset = prev,
            }
        }
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static ALLOC: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
fn oom(_: Layout) -> ! { exit(12); }

// --- IPC Protocol (shared with Kernel) ---
const OPCODE_OPEN: u32 = 0x01;
const OPCODE_READ: u32 = 0x02;
const OPCODE_WRITE: u32 = 0x03;
const OPCODE_CLOSE: u32 = 0x04;

#[repr(C, align(64))]
struct IpcMessage {
    sender: u64,
    msg_type: u32,
    flags: u32,
    payload: [u8; 48],
}

impl IpcMessage {
    fn new(msg_type: u32) -> Self {
        Self { sender: 0, msg_type, flags: 0, payload: [0u8; 48] }
    }
}

struct StrateRamServer {
    fs: RamFileSystem,
    // Maps sender ID to current open path (simplified for demo)
    open_paths: BTreeMap<u64, String>,
}

impl StrateRamServer {
    fn new() -> Self {
        Self {
            fs: RamFileSystem::new(),
            open_paths: BTreeMap::new(),
        }
    }

    fn handle_open(&mut self, sender: u64, payload: &[u8]) -> IpcMessage {
        let path_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
        let path = core::str::from_utf8(&payload[2..2+path_len]).unwrap_or("");
        
        // In a real FS, we'd return a file handle. 
        // Here we just track the path for the sender.
        self.open_paths.insert(sender, String::from(path));
        
        let mut reply = IpcMessage::new(0x80); // Success
        reply.sender = sender;
        reply
    }

    fn handle_read(&mut self, sender: u64, payload: &[u8]) -> IpcMessage {
        let mut reply = IpcMessage::new(0x80);
        reply.sender = sender;

        if let Some(path) = self.open_paths.get(&sender) {
            let mut buf = [0u8; 32];
            if let Ok(n) = self.fs.read(path, 0, &mut buf) {
                reply.payload[0..4].copy_from_slice(&(n as u32).to_le_bytes());
                reply.payload[8..8+n].copy_from_slice(&buf[..n]);
            }
        }
        reply
    }

    fn serve(&mut self, port: u64) -> ! {
        loop {
            let mut msg = IpcMessage::new(0);
            if unsafe { syscall2(number::SYS_IPC_RECV, port as usize, &mut msg as *mut _ as usize) }.is_ok() {
                let reply = match msg.msg_type {
                    OPCODE_OPEN => self.handle_open(msg.sender, &msg.payload),
                    OPCODE_READ => self.handle_read(msg.sender, &msg.payload),
                    _ => IpcMessage::new(0xFF), // Error
                };
                let _ = unsafe { syscall1(number::SYS_IPC_REPLY, &reply as *const _ as usize) };
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let port = unsafe { syscall1(number::SYS_IPC_CREATE_PORT, 0).unwrap() } as u64;
    let path = b"/ram";
    let _ = unsafe { syscall3(number::SYS_IPC_BIND_PORT, port as usize, path.as_ptr() as usize, path.len()) };

    let mut server = StrateRamServer::new();
    server.serve(port)
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! { exit(255); }
