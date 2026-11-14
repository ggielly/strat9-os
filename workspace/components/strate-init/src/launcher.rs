/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! Launch paths for ELF / wasm-runtime strates and wasm applications.
//!
//! Both module sources converge on one path: a binary under `/initfs` is
//! loaded by path, any other path is read by this process and loaded as a
//! blob. A module that cannot be attached or started is unloaded immediately so
//! a failed launch does not leak the blob. `supervisor` restarts a strate from
//! the returned [`Launched::module_handle`], so the caller must keep it.

use strat9_syscall::{call, data::IpcMessage, number};

use crate::{
    fmt::{log_hex_bytes, log_u32},
    log, read_file,
};

/// A strate that was loaded and started, with the handles needed to restart it.
pub struct Launched {
    pub module_handle: usize,
    pub pid: usize,
}

/// Status reported when the wasm runtime cannot be reached.
const WASM_STATUS_CONNECT: u32 = 0xffff_0000;
/// Status reported when the `load` IPC call itself fails.
const WASM_STATUS_LOAD: u32 = 0xffff_0001;
/// Status reported when the `run` IPC call itself fails.
const WASM_STATUS_RUN: u32 = 0xffff_0002;
/// Status reported when the wasm path does not fit in the IPC framing.
const WASM_STATUS_PATH_TOO_LONG: u32 = 0xffff_0003;

/// Implements ipc call status.
fn ipc_call_status(port: usize, msg: &mut IpcMessage) -> Result<u32, &'static str> {
    call::ipc_call(port, msg).map_err(|_| "ipc_call failed")?;
    Ok(u32::from_le_bytes([
        msg.payload[0],
        msg.payload[1],
        msg.payload[2],
        msg.payload[3],
    ]))
}

/// Implements connect wasm service with exponential backoff.
fn connect_wasm_service(path: &str) -> Result<usize, &'static str> {
    let mut delay = 1;
    for _ in 0..12 {
        if let Ok(h) = call::ipc_connect(path.as_bytes()) {
            return Ok(h);
        }
        for _ in 0..delay {
            let _ = call::sched_yield();
        }
        delay = core::cmp::min(delay * 2, 256);
    }
    Err("ipc_connect timeout")
}

/// Closes an IPC port when it goes out of scope.
///
/// A failed `ipc_call` used to `?` out of [`run_wasm_app`] before the explicit
/// `handle_close`, leaking the port for the rest of the boot.
struct PortGuard(usize);

impl Drop for PortGuard {
    fn drop(&mut self) {
        let _ = call::handle_close(self.0);
    }
}

/// Implements run wasm app.
pub fn run_wasm_app(service_path: &str, wasm_path: &str) -> Result<(), u32> {
    let port = connect_wasm_service(service_path).map_err(|_| WASM_STATUS_CONNECT)?;
    // The port is released on every return path, including the early ones.
    let port = PortGuard(port);

    let bytes = wasm_path.as_bytes();
    // The path length travels in a single byte, so anything longer than 255
    // bytes cannot be framed: report it instead of sending a truncated length.
    if bytes.len() > u8::MAX as usize {
        return Err(WASM_STATUS_PATH_TOO_LONG);
    }
    let mut load = IpcMessage::new(0x100);
    let n = bytes.len();
    load.payload[0] = n as u8;
    if n > 0 {
        load.payload[1..1 + n].copy_from_slice(bytes);
    }
    let load_status = ipc_call_status(port.0, &mut load).map_err(|_| WASM_STATUS_LOAD)?;
    if load_status != 0 {
        return Err(load_status);
    }

    let mut run = IpcMessage::new(0x102);
    let run_status = ipc_call_status(port.0, &mut run).map_err(|_| WASM_STATUS_RUN)?;
    if run_status != 0 {
        return Err(run_status);
    }
    Ok(())
}

/// Loads module bytes into the kernel module registry.
fn load_module(ptr: usize, len: usize) -> Option<usize> {
    match unsafe { strat9_syscall::syscall2(number::SYS_MODULE_LOAD, ptr, len) } {
        Ok(handle) => Some(handle),
        Err(_) => None,
    }
}

/// Attaches `module_handle` to the silo and starts the strate by name.
///
/// Returns the started pid, and logs the reason on failure.
fn attach_and_start(silo_handle: usize, name: &str, module_handle: usize) -> Option<usize> {
    if let Err(e) = call::silo_attach_module(silo_handle, module_handle) {
        log("[init] silo_attach_module failed: ");
        log(e.name());
        log("\n");
        return None;
    }
    match call::silo_start_named(silo_handle, name) {
        Ok(pid) => Some(pid),
        Err(e) => {
            log("[init] silo_start failed: ");
            log(e.name());
            log("\n");
            None
        }
    }
}

/// Loads, attaches and starts one ELF (or wasm runtime) strate.
///
/// Both module sources converge here: a binary under `/initfs` is loaded by
/// path, any other path is read by this process and loaded as a blob. Only
/// the source of the bytes differs. A module that cannot be attached or
/// started is unloaded immediately, so a failed launch does not leak the
/// blob. Returns the module handle and the started pid, both needed by the
/// supervisor to restart this exact strate.
pub fn launch_module(silo_handle: usize, name: &str, binary: &str) -> Option<Launched> {
    let module_handle = if binary.starts_with("/initfs/") {
        log("[init]     module path ");
        log(binary);
        log("\n");
        match load_module(binary.as_ptr() as usize, binary.len()) {
            Some(handle) => handle,
            None => {
                log("[init] module_load failed for ");
                log(binary);
                log("\n");
                return None;
            }
        }
    } else {
        let data = match read_file(binary) {
            Ok(data) => data,
            Err(_) => {
                log("[init] failed to read binary ");
                log(binary);
                log("\n");
                return None;
            }
        };
        if data.len() < 4 {
            log("[init]     module too small size=");
            log_u32(data.len() as u32);
            log("\n");
            return None;
        }
        log("[init]     module magic ");
        log_hex_bytes(&data[..4]);
        log(" size=");
        log_u32(data.len() as u32);
        log("\n");
        match load_module(data.as_ptr() as usize, data.len()) {
            Some(handle) => handle,
            None => {
                log("[init] module_load failed for ");
                log(binary);
                log("\n");
                return None;
            }
        }
    };

    // The blob is loaded from here on: release it if the strate cannot run.
    match attach_and_start(silo_handle, name, module_handle) {
        Some(pid) => Some(Launched { module_handle, pid }),
        None => {
            let _ = call::module_unload(module_handle);
            let _ = call::handle_close(module_handle);
            None
        }
    }
}
