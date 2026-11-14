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
//!   silo add/remove diff (running silos are not reconfigured in place).
//! * `shutdown` — stop every child in reverse plan order, then idle.
//! * `reboot` — reserved; replies that it is unsupported.
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

use init_config::ExitKind;
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

/// Handles one request message. Replies are sent from here.
pub fn handle(children: &mut Vec<SupervisedChild>, order: &mut Vec<String>, msg: &IpcMessage) {
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
            let reserved: Vec<u32> = children.iter().map(|child| child.sid).collect();
            let plan = crate::rebuild_plan(&reserved);
            let new_names: Vec<String> = plan.silos.iter().map(|s| s.name.clone()).collect();

            let mut added = 0;
            for silo in &plan.silos {
                if !order.iter().any(|name| name == &silo.name) {
                    crate::boot_silo(silo.clone(), children);
                    added += 1;
                }
            }

            let mut removed = 0;
            for name in order.iter() {
                if !new_names.iter().any(|new| new == name) {
                    supervisor::stop_silo(children, name);
                    removed += 1;
                }
            }

            // A running silo keeps its old SID, handles and strates: applying
            // changed fields in place would require a reconfigure syscall.
            log("[init] reload: running silos are not reconfigured in place\n");
            *order = new_names;
            reply(&format!("reload: added={} removed={}\n", added, removed));
        }
        "shutdown" => {
            supervisor::shutdown_all(children, order);
            reply("shutting down\n");
            log("[init] shutdown complete\n");
            loop {
                supervisor::sleep_ms(1000);
            }
        }
        "reboot" => reply("not supported (no SYS_REBOOT)\n"),
        "" => reply("empty command\n"),
        _ => reply("unknown command\n"),
    }
}
