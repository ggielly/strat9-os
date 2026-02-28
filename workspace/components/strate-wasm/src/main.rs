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
use spin::Mutex;
use strat9_syscall::call;
use strat9_syscall::data::IpcMessage;
use talc::*;
use wasmi::{Caller, Config, Engine, Linker, Module, Store, Instance, StoreLimits, StoreLimitsBuilder};

// ---------------------------------------------------------------------------
// MEMORY MANAGEMENT (TALC + BRK)
// ---------------------------------------------------------------------------

#[global_allocator]
static ALLOCATOR: Talck<spin::Mutex<()>, ErrOnOom> = Talck::new(Talc::new(ErrOnOom));

#[alloc_error_handler]
fn alloc_error(layout: Layout) -> ! {
    let mut talc = ALLOCATOR.lock();
    let current_brk = call::brk(0).expect("failed to get brk");
    let growth = (layout.size() + 8192) & !4095; 
    
    if let Ok(_new_brk) = call::brk(current_brk + growth) {
        unsafe {
            let span = Span::from_base_size(current_brk as *mut u8, growth);
            let _ = talc.claim(span);
        }
    } else {
        let _ = call::write(1, b"[strate-wasm] Fatal: OOM at brk\n");
        call::exit(12);
    }
    loop {}
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

fn send_response(target: usize, status: u32) {
    let mut msg = IpcMessage::new(0);
    msg.payload[0] = status as u8;
    let _ = call::ipc_send(target, &msg);
}

// ---------------------------------------------------------------------------
// WASI / HOST FUNCTIONS
// ---------------------------------------------------------------------------

struct HostState {
    limits: StoreLimits,
}

fn wasi_fd_write(mut caller: Caller<'_, HostState>, fd: u32, iovs_ptr: u32, iovs_len: u32, nwritten_ptr: u32) -> u32 {
    let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory()) else { return 1; };
    let mut total_written = 0;
    for i in 0..iovs_len {
        let base_addr = (iovs_ptr + i * 8) as usize;
        let mut iov_desc = [0u8; 8];
        if memory.read(&caller, base_addr, &mut iov_desc).is_err() { break; }
        let buf_ptr = u32::from_le_bytes([iov_desc[0], iov_desc[1], iov_desc[2], iov_desc[3]]) as usize;
        let buf_len = u32::from_le_bytes([iov_desc[4], iov_desc[5], iov_desc[6], iov_desc[7]]) as usize;
        let mut buffer = vec![0u8; buf_len];
        if memory.read(&caller, buf_ptr, &mut buffer).is_err() { break; }
        if fd == 1 || fd == 2 {
            let _ = call::write(1, &buffer);
            total_written += buf_len as u32;
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
const RESP_ERR: u32 = 0x1;

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
    
    // We need a port to bind to
    let port_h = call::ipc_create_port(0).expect("failed to create port");
    let _ = call::ipc_bind_port(port_h, b"/srv/strate-wasm/bootstrap");
    
    let mut b_msg = IpcMessage::new(0);
    if let Ok(_) = call::ipc_recv(port_h, &mut b_msg) {
        if b_msg.msg_type == OP_BOOTSTRAP {
            label = extract_string(&b_msg.payload, 1, b_msg.payload[0] as usize);
        }
    }

    let final_path = format!("/srv/strate-wasm/{}", label);
    let _ = call::ipc_bind_port(port_h, final_path.as_bytes());
    debug_log("[strate-wasm] running: ");
    debug_log(&final_path);
    debug_log("\n");

    let mut current_instance: Option<Instance> = None;

    loop {
        let mut msg = IpcMessage::new(0);
        match call::ipc_recv(port_h, &mut msg) {
            Ok(_) => {
                let src = msg.sender as usize;
                match msg.msg_type {
                    OP_WASM_LOAD_PATH => {
                        let path = extract_string(&msg.payload, 1, msg.payload[0] as usize);
                        let mut wasm_bytes = Vec::new();
                        if let Ok(fd) = call::openat(0, &path, 0x1, 0) {
                            let mut chunk = [0u8; 4096];
                            while let Ok(n) = call::read(fd as usize, &mut chunk) {
                                if n == 0 { break; }
                                wasm_bytes.extend_from_slice(&chunk[..n]);
                            }
                            let _ = call::close(fd as usize);

                            match Module::new(&engine, &wasm_bytes[..]) {
                                Ok(module) => match linker.instantiate(&mut store, &module) {
                                    Ok(pre) => match pre.start(&mut store) {
                                        Ok(inst) => {
                                            current_instance = Some(inst);
                                            send_response(src, RESP_OK);
                                        }
                                        Err(_) => send_response(src, RESP_ERR),
                                    },
                                    Err(_) => send_response(src, RESP_ERR),
                                },
                                Err(_) => send_response(src, RESP_ERR),
                            }
                        } else {
                            send_response(src, RESP_ERR);
                        }
                    }

                    OP_WASM_RUN_MAIN => {
                        if let Some(instance) = current_instance {
                            let _ = store.set_fuel(10_000_000);
                            if let Ok(func) = instance.get_typed_func::<(), ()>(&store, "_start") {
                                match func.call(&mut store, ()) {
                                    Ok(_) => send_response(src, RESP_OK),
                                    Err(_) => send_response(src, RESP_ERR),
                                }
                            } else {
                                send_response(src, RESP_ERR);
                            }
                        } else {
                            send_response(src, RESP_ERR);
                        }
                    }

                    _ => {}
                }
            }
            Err(_) => {}
        }
    }
}
