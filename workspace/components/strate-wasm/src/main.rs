#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::panic::PanicInfo;
use spin::Mutex;
use strat9_syscall::call;
use strat9_syscall::data::IpcMessage;
use talc::*;
use wasmi::{Caller, Config, Engine, Linker, Module, Store, Instance, TypedFunc};

// ---------------------------------------------------------------------------
// MEMORY MANAGEMENT (TALC + BRK)
// ---------------------------------------------------------------------------

static TALC_MUTEX: Mutex<Talc> = Mutex::new(Talc::new(unsafe {
    Span::from_slice(&mut [])
}));

#[global_allocator]
static ALLOCATOR: TalcRuntime = TalcRuntime::new_lock(&TALC_MUTEX);

#[alloc_error_handler]
fn alloc_error(layout: Layout) -> ! {
    let mut talc = TALC_MUTEX.lock();
    let current_brk = call::brk(0).expect("failed to get brk");
    let growth = (layout.size() + 8192) & !4095; 
    
    if let Ok(new_brk) = call::brk(current_brk + growth as u64) {
        unsafe {
            let span = Span::from_raw_parts(current_brk as *mut u8, growth);
            talc.claim(span).expect("failed to claim memory");
        }
    } else {
        debug_log("[strate-wasm] Fatal: OOM at brk\n");
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
fn panic(info: &PanicInfo) -> ! {
    debug_log("[strate-wasm] PANIC!\n");
    call::exit(1);
}

// ---------------------------------------------------------------------------
// WASI / HOST FUNCTIONS
// ---------------------------------------------------------------------------

struct HostState {
    // Per-instance state
}

/// WASI fd_write implementation (simplified)
fn wasi_fd_write(
    mut caller: Caller<'_, HostState>,
    fd: u32,
    iovs_ptr: u32,
    iovs_len: u32,
    nwritten_ptr: u32,
) -> u32 {
    let memory = caller.get_export("memory").and_then(|e| e.into_memory()).unwrap();
    let mut total_written = 0;

    for i in 0..iovs_len {
        let base_addr = (iovs_ptr + i * 8) as usize;
        let mut iov_desc = [0u8; 8];
        memory.read(&caller, base_addr, &mut iov_desc).unwrap();
        
        let buf_ptr = u32::from_le_bytes([iov_desc[0], iov_desc[1], iov_desc[2], iov_desc[3]]) as usize;
        let buf_len = u32::from_le_bytes([iov_desc[4], iov_desc[5], iov_desc[6], iov_desc[7]]) as usize;

        let mut buffer = vec![0u8; buf_len];
        memory.read(&caller, buf_ptr, &mut buffer).unwrap();

        // Redirect fd 1 (stdout) and 2 (stderr) to kernel console
        if fd == 1 || fd == 2 {
            let _ = call::write(1, &buffer);
            total_written += buf_len as u32;
        }
    }

    memory.write(&mut caller, nwritten_ptr as usize, &total_written.to_le_bytes()).unwrap();
    0 // WASI_ESUCCESS
}

fn wasi_proc_exit(_caller: Caller<'_, HostState>, code: u32) {
    debug_log("[strate-wasm] wasm requested exit\n");
    call::exit(code as usize);
}

// ---------------------------------------------------------------------------
// MODULE LOADER
// ---------------------------------------------------------------------------

fn read_wasm_file(path: &str) -> Result<Vec<u8>, &'static str> {
    let fd = call::openat(0, path, 0x1, 0).map_err(|_| "open failed")?;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    
    loop {
        match call::read(fd as usize, &mut chunk) {
            Ok(0) => break,
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            Err(_) => return Err("read failed"),
        }
    }
    let _ = call::close(fd as usize);
    Ok(buffer)
}

// ---------------------------------------------------------------------------
// IPC PROTOCOL
// ---------------------------------------------------------------------------

const OP_WASM_LOAD_PATH: u32 = 0x100;
const OP_WASM_RUN_MAIN: u32 = 0x101;
const OP_BOOTSTRAP: u32 = 0x10;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    debug_log("[strate-wasm] initialization\n");

    let engine = Engine::default();
    let mut linker = Linker::new(&engine);
    let mut store = Store::new(&engine, HostState {});

    // Register WASI subset
    linker.define("wasi_snapshot_preview1", "fd_write", wasmi::Func::wrap(&mut store, wasi_fd_write)).unwrap();
    linker.define("wasi_snapshot_preview1", "proc_exit", wasmi::Func::wrap(&mut store, wasi_proc_exit)).unwrap();

    // 1. Initial Bootstrap & Service Registration
    let mut label = String::from("default");
    let bootstrap_path = "/srv/strate-wasm/bootstrap";
    
    if let Ok(_) = call::ipc_bind_port(bootstrap_path) {
        let mut msg = IpcMessage::default();
        if let Ok(_) = call::ipc_recv(0, &mut msg) {
            if msg.payload[0] == OP_BOOTSTRAP {
                let len = msg.payload[1] as usize;
                if len > 0 && len <= 31 {
                    let mut l = String::new();
                    for i in 0..len { l.push(msg.payload[2 + i] as char); }
                    label = l;
                }
            }
        }
    }

    let service_path = format!("/srv/strate-wasm/{}", label);
    call::ipc_bind_port(&service_path).expect("failed to bind service");
    debug_log("[strate-wasm] service ready: ");
    debug_log(&service_path);
    debug_log("\n");

    // 2. Execution State
    let mut current_instance: Option<Instance> = None;

    // 3. Main IPC Loop
    loop {
        let mut msg = IpcMessage::default();
        match call::ipc_recv(0, &mut msg) {
            Ok(src) => {
                let opcode = msg.payload[0];
                match opcode {
                    OP_WASM_LOAD_PATH => {
                        // Payload[1..] = path string
                        let len = msg.payload[1] as usize;
                        let mut path = String::new();
                        for i in 0..len { path.push(msg.payload[2 + i] as char); }
                        
                        debug_log("[strate-wasm] loading ");
                        debug_log(&path);
                        debug_log("\n");

                        if let Ok(wasm_bytes) = read_wasm_file(&path) {
                            match Module::new(&engine, &wasm_bytes[..]) {
                                Ok(module) => {
                                    match linker.instantiate(&mut store, &module) {
                                        Ok(pre) => {
                                            match pre.start(&mut store) {
                                                Ok(inst) => {
                                                    current_instance = Some(inst);
                                                    debug_log("[strate-wasm] instance ready\n");
                                                }
                                                Err(_) => debug_log("[strate-wasm] start failed\n"),
                                            }
                                        }
                                        Err(_) => debug_log("[strate-wasm] instantiation failed\n"),
                                    }
                                }
                                Err(_) => debug_log("[strate-wasm] invalid wasm module\n"),
                            }
                        } else {
                            debug_log("[strate-wasm] file not found\n");
                        }
                    }

                    OP_WASM_RUN_MAIN => {
                        if let Some(instance) = current_instance {
                            debug_log("[strate-wasm] executing _start\n");
                            if let Ok(func) = instance.get_typed_func::<(), ()>(&store, "_start") {
                                if let Err(_) = func.call(&mut store, ()) {
                                    debug_log("[strate-wasm] execution error\n");
                                }
                            } else {
                                debug_log("[strate-wasm] _start not found\n");
                            }
                        } else {
                            debug_log("[strate-wasm] no module loaded\n");
                        }
                    }

                    _ => {
                        debug_log("[strate-wasm] unsupported opcode\n");
                    }
                }
            }
            Err(_) => {}
        }
    }
}
