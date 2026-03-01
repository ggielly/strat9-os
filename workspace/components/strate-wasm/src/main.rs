#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::panic::PanicInfo;
use strat9_syscall::call;
use strat9_syscall::data::IpcMessage;
use talc::*;
use wasmi::{Caller, Config, Engine, Linker, Module, Store, Instance, StoreLimits, StoreLimitsBuilder};

// ---------------------------------------------------------------------------
// MEMORY MANAGEMENT (TALC + BRK)
// ---------------------------------------------------------------------------

struct BrkGrower;

impl OomHandler for BrkGrower {
    fn handle_oom(talc: &mut Talc<Self>, layout: Layout) -> Result<(), ()> {
        let current_brk = call::brk(0).map_err(|_| ())?;
        let growth = (layout.size().max(layout.align()) + 65536) & !4095;
        let new_brk = call::brk(current_brk + growth).map_err(|_| ())?;
        let actual = new_brk.saturating_sub(current_brk);
        if actual == 0 {
            return Err(());
        }
        unsafe {
            talc.claim(Span::from_base_size(current_brk as *mut u8, actual))
                .map_err(|_| ())?;
        }
        Ok(())
    }
}

#[global_allocator]
static ALLOCATOR: Talck<spin::Mutex<()>, BrkGrower> = Talck::new(Talc::new(BrkGrower));

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    let _ = call::write(1, b"[strate-wasm] Fatal: OOM\n");
    call::exit(12);
}

// ---------------------------------------------------------------------------
// UTILITIES
// ---------------------------------------------------------------------------

fn debug_log(msg: &str) {
    let _ = call::write(1, msg.as_bytes());
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    debug_log("[strate-wasm] PANIC!\n");
    call::exit(1);
}

fn extract_string(payload: &[u8], offset: usize, len: usize) -> String {
    if len == 0 || offset + len > payload.len() {
        return String::from("invalid");
    }
    let slice = &payload[offset..(offset + len)];
    let mut s = String::with_capacity(len);
    for &b in slice {
        if b.is_ascii() && !b.is_ascii_control() {
            s.push(b as char);
        } else {
            s.push('?');
        }
    }
    s
}

fn send_response(original_sender: u64, status: u32) {
    let mut msg = IpcMessage::new(0x80);
    msg.sender = original_sender;
    msg.payload[0..4].copy_from_slice(&status.to_le_bytes());
    let _ = call::ipc_reply(&msg);
}

fn read_leb_u32(bytes: &[u8], mut idx: usize) -> Option<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift = 0u32;
    for _ in 0..5 {
        let b = *bytes.get(idx)?;
        idx += 1;
        result |= ((b & 0x7f) as u32) << shift;
        if (b & 0x80) == 0 {
            return Some((result, idx));
        }
        shift += 7;
    }
    None
}

fn wasm_effective_len(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 8 {
        return None;
    }
    if bytes[0] != 0x00
        || bytes[1] != b'a'
        || bytes[2] != b's'
        || bytes[3] != b'm'
        || bytes[4] != 0x01
        || bytes[5] != 0x00
        || bytes[6] != 0x00
        || bytes[7] != 0x00
    {
        return None;
    }
    let mut i = 8usize;
    while i < bytes.len() {
        let id = bytes[i];
        if id > 12 {
            return Some(i);
        }
        i += 1;
        let (section_len, next) = read_leb_u32(bytes, i)?;
        i = next;
        let end = i.checked_add(section_len as usize)?;
        if end > bytes.len() {
            return None;
        }
        i = end;
    }
    Some(i)
}

// ---------------------------------------------------------------------------
// WASI / HOST FUNCTIONS
// ---------------------------------------------------------------------------

struct HostState {
    limits: StoreLimits,
}

fn wasi_fd_write(mut caller: Caller<'_, HostState>, fd: u32, iovs_ptr: u32, iovs_len: u32, nwritten_ptr: u32) -> u32 {
    let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory()) else { return 1; };
    if fd != 1 && fd != 2 {
        return 8; // WASI EBADF
    }
    let mut total_written: u32 = 0;
    for i in 0..iovs_len {
        let base_addr = (iovs_ptr + i * 8) as usize;
        let mut iov_desc = [0u8; 8];
        if memory.read(&caller, base_addr, &mut iov_desc).is_err() { break; }
        let buf_ptr = u32::from_le_bytes([iov_desc[0], iov_desc[1], iov_desc[2], iov_desc[3]]) as usize;
        let buf_len = u32::from_le_bytes([iov_desc[4], iov_desc[5], iov_desc[6], iov_desc[7]]) as usize;
        let mut buffer = vec![0u8; buf_len];
        if memory.read(&caller, buf_ptr, &mut buffer).is_err() { break; }
        match call::write(fd as usize, &buffer) {
            Ok(n) => total_written += n as u32,
            Err(_) => break,
        }
    }
    let _ = memory.write(&mut caller, nwritten_ptr as usize, &total_written.to_le_bytes());
    0
}

fn wasi_environ_get(_caller: Caller<'_, HostState>, _environ: u32, _environ_buf: u32) -> u32 { 0 }
fn wasi_environ_sizes_get(mut caller: Caller<'_, HostState>, count_ptr: u32, size_ptr: u32) -> u32 {
    let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory()) else { return 1; };
    let _ = memory.write(&mut caller, count_ptr as usize, &0u32.to_le_bytes());
    let _ = memory.write(&mut caller, size_ptr as usize, &0u32.to_le_bytes());
    0
}
fn wasi_proc_exit(_caller: Caller<'_, HostState>, code: u32) { call::exit(code as usize); }

// ---------------------------------------------------------------------------
// IPC PROTOCOL
// ---------------------------------------------------------------------------

const OP_WASM_LOAD_PATH: u32 = 0x100;
const OP_WASM_RUN_MAIN: u32  = 0x102;
const OP_BOOTSTRAP: u32      = 0x10;

const RESP_OK: u32  = 0x0;
const RESP_ERR_OPEN: u32 = 0x10;
const RESP_ERR_READ: u32 = 0x11;
const RESP_ERR_MODULE: u32 = 0x12;
const RESP_ERR_INSTANTIATE: u32 = 0x13;
const RESP_ERR_START: u32 = 0x14;
const RESP_ERR_NO_INSTANCE: u32 = 0x20;
const RESP_ERR_NO_ENTRY: u32 = 0x21;
const RESP_ERR_RUN: u32 = 0x22;
const RESP_ERR_TOO_LARGE: u32 = 0x23;

const MAX_WASM_SIZE: usize = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// MAIN
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    let mut config = Config::default();
    config.consume_fuel(true);

    let engine = Engine::new(&config);
    let mut linker = Linker::new(&engine);
    let limits = StoreLimitsBuilder::new().memory_size(16 * 1024 * 1024).instances(1).build();
    let mut store = Store::new(&engine, HostState { limits });
    store.limiter(|state| &mut state.limits);

    let _ = linker.define("wasi_snapshot_preview1", "fd_write", wasmi::Func::wrap(&mut store, wasi_fd_write));
    let _ = linker.define("wasi_snapshot_preview1", "proc_exit", wasmi::Func::wrap(&mut store, wasi_proc_exit));
    let _ = linker.define("wasi_snapshot_preview1", "environ_get", wasmi::Func::wrap(&mut store, wasi_environ_get));
    let _ = linker.define("wasi_snapshot_preview1", "environ_sizes_get", wasmi::Func::wrap(&mut store, wasi_environ_sizes_get));

    let mut label = String::from("default");
    let mut queued_msg: Option<IpcMessage> = None;
    
    // We need a port to bind to
    let port_h = call::ipc_create_port(0).expect("failed to create port");
    let _ = call::ipc_bind_port(port_h, b"/srv/strate-wasm/bootstrap");
    
    let mut b_msg = IpcMessage::new(0);
    if let Ok(_) = call::ipc_try_recv(port_h, &mut b_msg) {
        if b_msg.msg_type == OP_BOOTSTRAP {
            label = extract_string(&b_msg.payload, 1, b_msg.payload[0] as usize);
        } else {
            queued_msg = Some(b_msg);
        }
    }

    let final_path = format!("/srv/strate-wasm/{}", label);
    let _ = call::ipc_bind_port(port_h, final_path.as_bytes());
    debug_log("[strate-wasm] running: ");
    debug_log(&final_path);
    debug_log("\n");

    let mut current_instance: Option<Instance> = None;

    loop {
        let msg = if let Some(m) = queued_msg.take() {
            m
        } else {
            let mut m = IpcMessage::new(0);
            if call::ipc_recv(port_h, &mut m).is_err() {
                continue;
            }
            m
        };
        let src = msg.sender;
        match msg.msg_type {
            OP_WASM_LOAD_PATH => {
                let path = extract_string(&msg.payload, 1, msg.payload[0] as usize);
                let mut wasm_bytes = Vec::new();
                if let Ok(fd) = call::openat(0, &path, 0x1, 0) {
                    let mut chunk = [0u8; 4096];
                    let mut read_failed = false;
                    loop {
                        match call::read(fd as usize, &mut chunk) {
                            Ok(0) => break,
                            Ok(n) => {
                                wasm_bytes.extend_from_slice(&chunk[..n]);
                                if wasm_bytes.len() > MAX_WASM_SIZE {
                                    read_failed = true;
                                    break;
                                }
                            }
                            Err(_) => {
                                read_failed = true;
                                break;
                            }
                        }
                    }
                    let _ = call::close(fd as usize);

                    if read_failed {
                        if wasm_bytes.len() > MAX_WASM_SIZE {
                            debug_log("[strate-wasm] load error: too large\n");
                            send_response(src, RESP_ERR_TOO_LARGE);
                        } else {
                            debug_log("[strate-wasm] load error: read\n");
                            send_response(src, RESP_ERR_READ);
                        }
                        continue;
                    }

                    if wasm_bytes.is_empty() {
                        debug_log("[strate-wasm] load error: empty\n");
                        send_response(src, RESP_ERR_READ);
                        continue;
                    }

                    let trimmed_len = wasm_bytes
                        .iter()
                        .rposition(|&b| b != 0)
                        .map(|i| i + 1)
                        .unwrap_or(0);
                    if trimmed_len == 0 {
                        debug_log("[strate-wasm] load error: all-zero image\n");
                        send_response(src, RESP_ERR_MODULE);
                        continue;
                    }
                    let trimmed = &wasm_bytes[..trimmed_len];
                    let Some(effective_len) = wasm_effective_len(trimmed) else {
                        debug_log("[strate-wasm] load error: bad magic\n");
                        send_response(src, RESP_ERR_MODULE);
                        continue;
                    };
                    let module_bytes = &trimmed[..effective_len];

                    match Module::new(&engine, module_bytes) {
                        Ok(module) => match linker.instantiate(&mut store, &module) {
                            Ok(pre) => match pre.start(&mut store) {
                                Ok(inst) => {
                                    current_instance = Some(inst);
                                    send_response(src, RESP_OK);
                                }
                                Err(_) => {
                                    debug_log("[strate-wasm] load error: start\n");
                                    send_response(src, RESP_ERR_START)
                                }
                            },
                            Err(_) => {
                                debug_log("[strate-wasm] load error: instantiate\n");
                                send_response(src, RESP_ERR_INSTANTIATE)
                            }
                        },
                        Err(_) => {
                            let line = format!(
                                "[strate-wasm] load error: module parse failed (len={})\n",
                                module_bytes.len()
                            );
                            debug_log(&line);
                            send_response(src, RESP_ERR_MODULE)
                        }
                    }
                } else {
                    debug_log("[strate-wasm] load error: open\n");
                    send_response(src, RESP_ERR_OPEN);
                }
            }

            OP_WASM_RUN_MAIN => {
                if let Some(ref instance) = current_instance {
                    let _ = store.set_fuel(10_000_000);
                    if let Ok(func) = instance.get_typed_func::<(), ()>(&store, "_start") {
                        match func.call(&mut store, ()) {
                            Ok(_) => send_response(src, RESP_OK),
                            Err(_) => {
                                debug_log("[strate-wasm] run error: trap\n");
                                send_response(src, RESP_ERR_RUN)
                            }
                        }
                    } else {
                        debug_log("[strate-wasm] run error: no _start\n");
                        send_response(src, RESP_ERR_NO_ENTRY);
                    }
                } else {
                    debug_log("[strate-wasm] run error: no instance\n");
                    send_response(src, RESP_ERR_NO_INSTANCE);
                }
            }

            _ => {}
        }
    }
}
