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

//! `/srv/init` control service.
//!
//! # Protocol
//!
//! Requests arrive on an IPC port bound at `/srv/init`. A request is a UTF-8
//! text command carried in `IpcMessage.payload`; trailing NUL padding is
//! ignored and the first whitespace-separated token is the command. The
//! request `msg_type` is `0x100`; every reply uses `0x80` and carries UTF-8
//! text (truncated to the 1008-byte payload).
//!
//! Commands:
//! * `list` — one `name pid state restarts` line per supervised strate.
//! * `status <name>` — the `list` line plus `last=<exit kind>`.
//! * `start <name>` / `stop <name>` / `restart <name>` — mutate one child.
//! * `reload` — re-read `/initfs/silo.toml`, rebuild the plan and apply the
//!   add/remove diff. A running silo whose plan changed is reconfigured in
//!   place: it is stopped, the new config and grant set are applied to the
//!   same silo handle, then its strates are restarted. Zero-downtime is not
//!   possible without task migration, so the silo is briefly down.
//! * `shutdown` — stop every child in reverse plan order, then power off.
//! * `reboot` — stop every child in reverse plan order, then reset.
//!
//! # Authorization (approximation)
//!
//! `list` and `status` are read-only and answer any sender. Mutating commands
//! are accepted only when `msg.sender` equals the pid of a supervised child
//! whose silo was configured `admin = true`. This is an approximation: the
//! kernel exposes no pid→silo query and `ipc_connect` does not check a
//! capability, so a process able to guess/reuse the admin pid could pass the
//! check. A real capability check needs a kernel pid→silo API.

use alloc::{format, string::String, vec::Vec};

use init_config::{ExitKind, PlannedSilo};
use strat9_syscall::{call, data::IpcMessage};

use crate::{
    log,
    supervisor::{self, StrateHealth, SupervisedChild},
};

/// Request message type understood by `/srv/init`.
const REQUEST_MSG_TYPE: u32 = 0x100;

/// Creates and binds the control port at `/srv/init`.
///
/// Returns `0` when the port cannot be created; the supervisor then skips the
/// control drain instead of polling an invalid handle.
pub fn init_port() -> usize {
    match call::ipc_create_port(0) {
        Ok(port) => {
            match call::ipc_bind_port(port, b"/srv/init") {
                Ok(_) => log("[init] /srv/init ready\n"),
                Err(e) => {
                    log("[init] bind /srv/init failed: ");
                    log(e.name());
                    log("\n");
                }
            }
            port
        }
        Err(e) => {
            log("[init] ipc_create_port for /srv/init failed: ");
            log(e.name());
            log("\n");
            0
        }
    }
}

/// Sends a text reply to the sender of the last received message.
fn reply(text: &str) {
    let mut msg = IpcMessage::new(IpcMessage::REPLY_MSG_TYPE);
    let bytes = text.as_bytes();
    let n = bytes.len().min(msg.payload.len());
    msg.payload[..n].copy_from_slice(&bytes[..n]);
    let _ = call::ipc_reply(&msg);
}

/// Human-readable lifecycle state for `list`/`status`.
fn state_str(child: &SupervisedChild) -> &'static str {
    if child.pid == 0 {
        "stopped"
    } else {
        match child.health {
            StrateHealth::Ready => "running",
            StrateHealth::Failed => "failed",
        }
    }
}

/// Human-readable last exit kind.
fn exit_str(kind: ExitKind) -> String {
    match kind {
        ExitKind::Normal(code) => format!("exit({})", code),
        ExitKind::Signal(signal) => format!("signal({})", signal),
        ExitKind::Stopped(signal) => format!("stopped({})", signal),
        ExitKind::Continued => String::from("continued"),
    }
}

/// True when `sender` is a supervised child from an admin silo.
fn authorized(children: &[SupervisedChild], sender: u64) -> bool {
    children.iter().any(|c| c.pid == sender && c.admin)
}

/// Unloads the module of every child owned by `silo_name`.
///
/// Errors are ignored: the silo is being torn down or reconfigured and a
/// module that is already gone is not a failure.
fn unload_modules(children: &[SupervisedChild], silo_name: &str) {
    for child in children.iter().filter(|c| c.silo == silo_name) {
        let handle = child.module_handle();
        if handle != 0 {
            let _ = call::module_unload(handle);
        }
    }
}

/// Handles one request message. Replies are sent from here.
pub fn handle(
    children: &mut Vec<SupervisedChild>,
    order: &mut Vec<String>,
    runtimes: &mut Vec<crate::SiloRuntime>,
    msg: &IpcMessage,
) {
    if msg.msg_type != REQUEST_MSG_TYPE {
        return;
    }

    let text = core::str::from_utf8(&msg.payload).unwrap_or("");
    let text = text.split('\0').next().unwrap_or("").trim();
    let mut tokens = text.split_whitespace();
    let command = tokens.next().unwrap_or("");
    let arg = tokens.next().unwrap_or("");

    // Read-only commands answer any sender.
    match command {
        "list" => {
            let mut out = String::new();
            for child in children.iter() {
                out.push_str(&format!(
                    "{} {} {} {}\n",
                    child.name,
                    child.pid,
                    state_str(child),
                    child.restart_count
                ));
            }
            reply(&out);
            return;
        }
        "status" => {
            match children.iter().find(|c| c.name == arg) {
                Some(child) => {
                    let last = child
                        .last_exit
                        .map(exit_str)
                        .unwrap_or_else(|| String::from("none"));
                    reply(&format!(
                        "{} {} {} {} last={}\n",
                        child.name,
                        child.pid,
                        state_str(child),
                        child.restart_count,
                        last
                    ));
                }
                None => reply("no such strate\n"),
            }
            return;
        }
        _ => {}
    }

    // Every remaining command mutates the boot state or the machine.
    if !authorized(children, msg.sender) {
        reply("permission denied\n");
        return;
    }

    match command {
        "start" => match supervisor::start_child(children, arg) {
            Ok(pid) => reply(&format!("started {} pid={}\n", arg, pid)),
            Err(e) => reply(&format!("start failed: {}\n", e)),
        },
        "stop" => match supervisor::stop_child(children, arg) {
            Ok(()) => reply(&format!("stopped {}\n", arg)),
            Err(e) => reply(&format!("stop failed: {}\n", e)),
        },
        "restart" => match supervisor::stop_child(children, arg) {
            Ok(()) => match supervisor::start_child(children, arg) {
                Ok(pid) => reply(&format!("restarted {} pid={}\n", arg, pid)),
                Err(e) => reply(&format!("restart failed: {}\n", e)),
            },
            Err(e) => reply(&format!("restart failed: {}\n", e)),
        },
        "reload" => {
            // Every runtime reserves its SID even when it has no live child,
            // so a new silo cannot be allocated a SID still in use.
            let reserved: Vec<u32> = runtimes.iter().map(|r| r.sid).collect();
            let plan = crate::rebuild_plan(&reserved);

            // Pass 1: classify each runtime as removed or changed. Removals are
            // applied immediately; changed silos are stopped in pass 2.
            let mut removed = 0;
            let mut changed: Vec<(usize, PlannedSilo)> = Vec::new();
            let mut i = 0;
            while i < runtimes.len() {
                let name = runtimes[i].name.clone();
                let new_def = plan
                    .silos
                    .iter()
                    .find(|s| s.name == name && !s.strates.is_empty())
                    .map(|def| {
                        let mut new_def = def.clone();
                        // The live SID wins: reconfiguration never re-keys a silo.
                        new_def.sid = runtimes[i].sid;
                        new_def
                    });

                match new_def {
                    Some(new_def) => {
                        if runtimes[i].desired != new_def {
                            changed.push((i, new_def));
                        }
                        i += 1;
                    }
                    None => {
                        // Absent from the plan, or a plan silo with no strates.
                        supervisor::stop_silo(children, &name);
                        unload_modules(children, &name);
                        children.retain(|child| child.silo != name);
                        let handle = runtimes[i].handle;
                        if let Err(e) = call::silo_destroy(handle) {
                            log("[init] silo_destroy failed: ");
                            log(e.name());
                            log(", stopping it instead\n");
                            let _ = call::silo_stop(handle);
                        }
                        let _ = call::handle_close(handle);
                        runtimes.remove(i);
                        removed += 1;
                    }
                }
            }

            // Pass 2 (reverse): stop every changed silo before any restart, so
            // dependents are down while their providers are reconfigured.
            for (idx, _) in changed.iter().rev() {
                let name = runtimes[*idx].name.clone();
                log("[init] reconfigure: ");
                log(&name);
                log(" (stopped, applying plan)\n");
                supervisor::stop_silo(children, &name);
                unload_modules(children, &name);
                children.retain(|child| child.silo != name);
            }

            // Pass 3 (forward): apply the new config and grants to the same
            // handle and restart the strates. A failure leaves the silo stopped.
            let mut reconfigured = 0;
            let mut failed = 0;
            // Runtimes whose new plan started no strate at all: destroy them
            // after the loop so the `changed` indices stay valid.
            let mut dead: Vec<usize> = Vec::new();
            for (idx, new_def) in &changed {
                let name = runtimes[*idx].name.clone();
                match crate::reconfigure_silo(runtimes[*idx].handle, new_def, children) {
                    Ok(0) => {
                        log("[init] reconfigure: ");
                        log(&name);
                        log(" started no strate, destroying it\n");
                        let handle = runtimes[*idx].handle;
                        if let Err(e) = call::silo_destroy(handle) {
                            log("[init] silo_destroy failed: ");
                            log(e.name());
                            log(", stopping it instead\n");
                            let _ = call::silo_stop(handle);
                        }
                        let _ = call::handle_close(handle);
                        dead.push(*idx);
                        failed += 1;
                    }
                    Ok(_) => {
                        runtimes[*idx].desired = new_def.clone();
                        reconfigured += 1;
                    }
                    Err(e) => {
                        log("[init] reconfigure failed: ");
                        log(&name);
                        log(" ");
                        log(e);
                        log("\n");
                        failed += 1;
                    }
                }
            }
            for idx in dead.iter().rev() {
                runtimes.remove(*idx);
            }

            // Silos in the plan with no runtime are new.
            let mut added = 0;
            for silo in &plan.silos {
                if silo.strates.is_empty() || runtimes.iter().any(|r| r.name == silo.name) {
                    continue;
                }
                let before = runtimes.len();
                crate::boot_silo(silo.clone(), children, runtimes);
                if runtimes.len() > before {
                    added += 1;
                }
            }

            *order = plan.silos.iter().map(|s| s.name.clone()).collect();
            reply(&format!(
                "reload: added={} removed={} reconfigured={} failed={}\n",
                added, removed, reconfigured, failed
            ));
        }
        "shutdown" => {
            supervisor::shutdown_all(children, order);
            reply("powering off\n");
            log("[init] shutdown complete, powering off\n");
            if let Err(e) = call::reboot(1) {
                log("[init] shutdown: reboot(1) failed: ");
                log(e.name());
                log("\n");
            }
            loop {
                supervisor::sleep_ms(1000);
            }
        }
        "reboot" => {
            supervisor::shutdown_all(children, order);
            reply("rebooting\n");
            log("[init] reboot requested, resetting\n");
            if let Err(e) = call::reboot(0) {
                log("[init] reboot: reboot(0) failed: ");
                log(e.name());
                log("\n");
            }
            loop {
                supervisor::sleep_ms(1000);
            }
        }
        "" => reply("empty command\n"),
        _ => reply("unknown command\n"),
    }
}
