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
use wasmi::{Caller, Config, Engine, Linker, Module, Store, Instance, TypedFunc, StoreLimits, StoreLimitsBuilder};

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
    limits: StoreLimits,
}

fn wasi_fd_write(mut caller: Caller<'_, HostState>, fd: u32, iovs_ptr: u32, iovs_len: u32, nwritten_ptr: u32) -> u32 {
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
        if fd == 1 || fd == 2 {
            let _ = call::write(1, &buffer);
            total_written += buf_len as u32;
        }
    }
    memory.write(&mut caller, nwritten_ptr as usize, &total_written.to_le_bytes()).unwrap();
    0
}

fn wasi_environ_get(mut caller: Caller<'_, HostState>, _environ: u32, _environ_buf: u32) -> u32 {
    0 // Return empty env for now
}

fn wasi_environ_sizes_get(mut caller: Caller<'_, HostState>, environ_count: u32, environ_buf_size: u32) -> u32 {
    let memory = caller.get_export("memory").and_then(|e| e.into_memory()).unwrap();
    memory.write(&mut caller, environ_count as usize, &0u32.to_le_bytes()).unwrap();
    memory.write(&mut caller, environ_buf_size as usize, &0u32.to_le_bytes()).unwrap();
    0
}

fn wasi_proc_exit(_caller: Caller<'_, HostState>, code: u32) {
    call::exit(code as usize);
}

// ---------------------------------------------------------------------------
// IPC PROTOCOL
// ---------------------------------------------------------------------------

const OP_WASM_LOAD_PATH: u32 = 0x100;
const OP_WASM_LOAD_MEM: u32  = 0x101;
const OP_WASM_RUN_MAIN: u32  = 0x102;
const OP_BOOTSTRAP: u32 = 0x10;

// ---------------------------------------------------------------------------
// MAIN
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn _start() -> ! {
    debug_log("[strate-wasm] starting wasm engine with fuel support\n");

    let mut config = Config::default();
    config.consume_fuel(true);

    let engine = Engine::new(&config);
    let mut linker = Linker::new(&engine);
    
    // Limits: Max 16MB per instance to protect the OS
    let limits = StoreLimitsBuilder::new()
        .memory_size(16 * 1024 * 1024)
        .instances(1)
        .build();

    let mut store = Store::new(&engine, HostState { limits });
    store.limiter(|state| &mut state.limits);
    store.set_fuel(1_000_000).unwrap(); // Initial fuel

    linker.define("wasi_snapshot_preview1", "fd_write", wasmi::Func::wrap(&mut store, wasi_fd_write)).unwrap();
    linker.define("wasi_snapshot_preview1", "proc_exit", wasmi::Func::wrap(&mut store, wasi_proc_exit)).unwrap();
    linker.define("wasi_snapshot_preview1", "environ_get", wasmi::Func::wrap(&mut store, wasi_environ_get)).unwrap();
    linker.define("wasi_snapshot_preview1", "environ_sizes_get", wasmi::Func::wrap(&mut store, wasi_environ_sizes_get)).unwrap();

    // 1. Label Bootstrap
    let mut label = String::from("default");
    let _ = call::ipc_bind_port("/srv/strate-wasm/bootstrap");
    let mut b_msg = IpcMessage::default();
    if let Ok(_) = call::ipc_recv(0, &mut b_msg) {
        if b_msg.payload[0] == OP_BOOTSTRAP {
            let len = b_msg.payload[1] as usize;
            let mut l = String::new();
            for i in 0..len { l.push(b_msg.payload[2 + i] as char); }
            label = l;
        }
    }

    let final_path = format!("/srv/strate-wasm/{}", label);
    call::ipc_bind_port(&final_path).unwrap();
    debug_log("[strate-wasm] listening on ");
    debug_log(&final_path);
    debug_log("\n");

    let mut current_instance: Option<Instance> = None;

    loop {
        let mut msg = IpcMessage::default();
        match call::ipc_recv(0, &mut msg) {
            Ok(_) => {
                match msg.payload[0] {
                    OP_WASM_LOAD_PATH => {
                        let len = msg.payload[1] as usize;
                        let mut path = String::new();
                        for i in 0..len { path.push(msg.payload[2 + i] as char); }
                        
                        // Simple read helper (same as before but integrated)
                        let mut wasm_bytes = Vec::new();
                        if let Ok(fd) = call::openat(0, &path, 0x1, 0) {
                            let mut chunk = [0u8; 4096];
                            while let Ok(n) = call::read(fd as usize, &mut chunk) {
                                if n == 0 { break; }
                                wasm_bytes.extend_from_slice(&chunk[..n]);
                            }
                            let _ = call::close(fd as usize);

                            if let Ok(module) = Module::new(&engine, &wasm_bytes[..]) {
                                if let Ok(pre) = linker.instantiate(&mut store, &module) {
                                    if let Ok(inst) = pre.start(&mut store) {
                                        current_instance = Some(inst);
                                        debug_log("[strate-wasm] module loaded successfully\n");
                                    }
                                }
                            }
                        }
                    }

                    OP_WASM_LOAD_MEM => {
                        // payload[1] = memory handle (capability)
                        // This allows zero-copy or direct mapping of wasm modules
                        let mem_handle = msg.payload[1];
                        debug_log("[strate-wasm] memory-handle loading not fully implemented in this version\n");
                    }

                    OP_WASM_RUN_MAIN => {
                        if let Some(instance) = current_instance {
                            store.set_fuel(10_000_000).unwrap(); // Give fuel for run
                            if let Ok(func) = instance.get_typed_func::<(), ()>(&store, "_start") {
                                let _ = func.call(&mut store, ());
                                let remaining = store.get_fuel().unwrap_or(0);
                                debug_log("[strate-wasm] execution finished\n");
                            }
                        }
                    }

                    _ => {}
                }
            }
            Err(_) => {}
        }
    }
}
