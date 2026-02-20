//! RAM Filesystem Strate Server
//!
//! Receives IPC messages from the kernel VFS and executes operations
//! on the RamFileSystem.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use alloc::{collections::BTreeMap, string::String};
use core::{alloc::Layout, panic::PanicInfo, sync::atomic::{AtomicUsize, Ordering}};
use strate_ram::RamFileSystem;
use strate_fs_abstraction::VfsFileSystem;
use strat9_syscall::*;
use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

const HEAP_SIZE: usize = 2 * 1024 * 1024; // 2 MiB
static mut HEAP: [u8; HEAP_SIZE] = [0u8; HEAP_SIZE];

#[alloc_error_handler]
fn oom(_: Layout) -> ! {
    let _ = unsafe { syscall1(number::SYS_PROC_EXIT, 12) };
    loop {}
}

fn exit(code: usize) -> ! {
    let _ = unsafe { syscall1(number::SYS_PROC_EXIT, code) };
    loop {}
}

// --- IPC Protocol ---
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
    open_inodes: BTreeMap<u64, u64>,
}

impl StrateRamServer {
    fn new() -> Self {
        Self {
            fs: RamFileSystem::new(),
            open_inodes: BTreeMap::new(),
        }
    }

    fn handle_open(&mut self, sender: u64, payload: &[u8]) -> IpcMessage {
        let path_len = u16::from_le_bytes([payload[4], payload[5]]) as usize;
        let path_bytes = &payload[6..6+path_len.min(42)];
        let path = core::str::from_utf8(path_bytes).unwrap_or("");
        
        let mut reply = IpcMessage::new(0x80); 
        reply.sender = sender;

        match self.fs.resolve_path(path) {
            Ok(ino) => {
                self.open_inodes.insert(sender, ino);
                let info = self.fs.stat(ino).unwrap();
                
                reply.payload[0..4].copy_from_slice(&0u32.to_le_bytes()); 
                reply.payload[4..12].copy_from_slice(&ino.to_le_bytes()); 
                reply.payload[12..20].copy_from_slice(&info.size.to_le_bytes());
                let f_flags: u32 = if info.is_dir() { 1 } else { 0 };
                reply.payload[20..24].copy_from_slice(&f_flags.to_le_bytes());
            }
            Err(_) => {
                reply.msg_type = 0xFF; 
                reply.payload[0..4].copy_from_slice(&2u32.to_le_bytes()); 
            }
        }
        reply
    }

    fn handle_read(&mut self, sender: u64, payload: &[u8]) -> IpcMessage {
        let ino = u64::from_le_bytes([payload[0],payload[1],payload[2],payload[3],payload[4],payload[5],payload[6],payload[7]]);
        let offset = u64::from_le_bytes([payload[8],payload[9],payload[10],payload[11],payload[12],payload[13],payload[14],payload[15]]);
        
        let mut reply = IpcMessage::new(0x80);
        reply.sender = sender;

        let mut buf = [0u8; 32];
        match self.fs.read(ino, offset, &mut buf) {
            Ok(n) => {
                reply.payload[0..4].copy_from_slice(&0u32.to_le_bytes()); 
                reply.payload[4..8].copy_from_slice(&(n as u32).to_le_bytes()); 
                reply.payload[8..8+n].copy_from_slice(&buf[..n]);
            }
            Err(_) => {
                reply.payload[0..4].copy_from_slice(&5u32.to_le_bytes()); 
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
                    _ => {
                        let mut r = IpcMessage::new(0xFF);
                        r.sender = msg.sender;
                        r
                    }
                };
                let _ = unsafe { syscall1(number::SYS_IPC_REPLY, &reply as *const _ as usize) };
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        ALLOCATOR.lock().init(HEAP.as_mut_ptr(), HEAP_SIZE);
    }

    let port = match unsafe { syscall1(number::SYS_IPC_CREATE_PORT, 0) } {
        Ok(p) => p as u64,
        Err(_) => exit(1),
    };

    let path = b"/ram";
    let _ = unsafe { syscall3(number::SYS_IPC_BIND_PORT, port as usize, path.as_ptr() as usize, path.len()) };

    let mut server = StrateRamServer::new();
    server.serve(port)
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! { exit(255); }
