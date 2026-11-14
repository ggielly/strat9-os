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

//! GUI audit, proof 2 - authority: peer identity, grants, blocking behaviour.
//!
//! Questions answered (see `doc/GUI_AUDIT_2026-11.md`, section "Preuve 2"):
//!
//! * A1  Can a sender forge `IpcMessage.sender`?
//! * A2  Does `sender` identify a process, or only a capability?
//! * A3  Is a grant to a nonexistent / reaped PID refused?
//! * A4  Is a grant to an exited-but-unreaped process (zombie) refused?
//! * A5  After PID reuse, does a grant addressed to the old PID reach the new
//!       process? (no incarnation check)
//! * A6  Does `SYS_POLL` actually wait / report readiness?
//! * A7  Does `ipc_send` block when the 16-slot port queue is full?

#![no_std]
#![no_main]

#[path = "gui_common.rs"]
mod common;

use common::*;
use core::panic::PanicInfo;
use strat9_syscall::{call, data::IpcMessage, error::Error, number, syscall6};

const FORGED: u64 = 0xDEAD_BEEF_CAFE_F00D;
const POLLIN: i16 = 1;
const PORT_QUEUE: usize = 16;

fn new_msg(sender: u64, tag: u32) -> IpcMessage {
    IpcMessage {
        sender,
        msg_type: tag,
        flags: 0,
        payload: [0u8; IpcMessage::PAYLOAD_CAPACITY],
    }
}

fn a1_a2_badge(ctx: &mut Ctx) {
    section(ctx, "A1/A2: sender field and port capability badge");
    let Ok(port) = call::ipc_create_port(0) else {
        check(ctx, "ipc_create_port", false, "");
        return;
    };

    // A1: forged sender must be overwritten by the kernel.
    let m = new_msg(FORGED, 1);
    if call::ipc_send(port, &m).is_err() {
        check(ctx, "self ipc_send", false, "");
        return;
    }
    let mut r = new_msg(0, 0);
    if call::ipc_recv(port, &mut r).is_err() {
        check(ctx, "self ipc_recv", false, "");
        return;
    }
    let parent_sender = r.sender;
    log("[gui_authority] info received sender=");
    log_hex(parent_sender);
    log(" parent_pid=");
    log_u64(call::getpid().unwrap_or(0) as u64);
    log("\n");
    check(ctx, "A1 kernel overwrites forged sender", parent_sender != FORGED, "");

    // A2: a forked child inherits the same capability. Same sender value?
    let child = match call::fork() {
        Ok(0) => {
            let m = new_msg(FORGED, 2);
            let _ = call::ipc_send(port, &m);
            call::exit(0)
        }
        Ok(p) => p,
        Err(_) => {
            check(ctx, "fork", false, "");
            return;
        }
    };
    let _ = reap(child);
    let mut r2 = new_msg(0, 0);
    if call::ipc_recv(port, &mut r2).is_err() {
        check(ctx, "recv child message", false, "");
        return;
    }
    gap(
        ctx,
        "A2 receiver cannot tell two processes sharing a port capability apart",
        r2.sender == parent_sender,
        "sender is the capability badge, not a process identity",
    );
}

fn a3_a5_grant(ctx: &mut Ctx) {
    section(ctx, "A3-A5: handle_grant destination checks");
    let Ok(h) = call::ipc_create_port(0) else {
        check(ctx, "ipc_create_port (handle to grant)", false, "");
        return;
    };

    // A3a: nonexistent PID.
    let r = call::handle_grant(h, 0x7fff_fff0);
    check(ctx, "A3 grant to nonexistent pid is refused", r.is_err(), "");

    // A3b: reaped child.
    let (rd, wr) = match call::pipe() {
        Ok(p) => (p.0 as usize, p.1 as usize),
        Err(_) => {
            check(ctx, "pipe", false, "");
            return;
        }
    };
    let c0 = match call::fork() {
        Ok(0) => call::exit(0),
        Ok(p) => p,
        Err(_) => {
            check(ctx, "fork", false, "");
            return;
        }
    };
    // A4: zombie (exited, not yet reaped). Give it time to exit.
    sleep_ms(100);
    let zr = call::handle_grant(h, c0);
    gap(
        ctx,
        "A4 grant to an exited-but-unreaped process succeeds",
        zr.is_ok(),
        match zr {
            Ok(_) => "handle leaked into a dead process",
            Err(e) => e.name(),
        },
    );
    let _ = reap(c0);
    let r = call::handle_grant(h, c0);
    check(ctx, "A3 grant to reaped pid is refused", r.is_err(), "");

    // A5: look for PID reuse and grant to the *old* pid.
    let mut reused = false;
    let mut leaked = false;
    for _ in 0..400 {
        match call::fork() {
            Ok(0) => {
                // Stay alive until the parent closes the pipe write end.
                let _ = call::close(wr);
                let _ = recv_u8(rd);
                call::exit(0)
            }
            Ok(pid) => {
                if pid == c0 {
                    reused = true;
                    leaked = call::handle_grant(h, c0).is_ok();
                    let _ = send_u8(wr, 0); // release the child before reaping
                    let _ = reap(pid);
                    break;
                }
                // Not reused yet: release and reap this one.
                // (The child only exits when it reads EOF/data, so feed it.)
                let _ = send_u8(wr, 0);
                let _ = reap(pid);
            }
            Err(_) => break,
        }
    }
    if reused {
        gap(
            ctx,
            "A5 grant addressed to a stale PID reaches a new process",
            leaked,
            "no incarnation check in sys_handle_grant",
        );
    } else {
        inconclusive(ctx, "A5 PID reuse", "no reuse of the reaped PID in 400 forks");
    }
}

fn a6_poll(ctx: &mut Ctx) {
    section(ctx, "A6: SYS_POLL on an empty pipe");
    let Ok((rd, _wr)) = call::pipe() else {
        check(ctx, "pipe", false, "");
        return;
    };
    // struct pollfd { i32 fd; i16 events; i16 revents; }
    let mut pfd = [0u8; 8];
    pfd[0..4].copy_from_slice(&(rd as i32).to_le_bytes());
    pfd[4..6].copy_from_slice(&POLLIN.to_le_bytes());
    // SAFETY: pfd outlives the call; nfds = 1; timeout 0 = non-blocking probe.
    let n = unsafe { syscall6(number::SYS_POLL, pfd.as_mut_ptr() as usize, 1, 0, 0, 0, 0) };
    let revents = i16::from_le_bytes([pfd[6], pfd[7]]);
    log("[gui_authority] info poll ret=");
    log_u64(n.unwrap_or(usize::MAX) as u64);
    log(" revents=");
    log_hex(revents as u64);
    log("\n");
    gap(
        ctx,
        "A6 SYS_POLL reports POLLIN on an empty pipe (no real readiness)",
        revents & POLLIN != 0,
        "stub: any valid fd is reported ready",
    );
}

fn a7_blocking_send(ctx: &mut Ctx) {
    section(ctx, "A7: ipc_send on a full port");
    let Ok(port) = call::ipc_create_port(0) else {
        check(ctx, "ipc_create_port", false, "");
        return;
    };
    let child = match call::fork() {
        Ok(0) => {
            let m = new_msg(0, 7);
            for _ in 0..(PORT_QUEUE + 4) {
                let _ = call::ipc_send(port, &m);
            }
            call::exit(0)
        }
        Ok(p) => p,
        Err(_) => {
            check(ctx, "fork", false, "");
            return;
        }
    };
    sleep_ms(300);
    let finished = try_reap(child).is_some();
    gap(
        ctx,
        "A7 ipc_send blocks the sender when the port queue is full",
        !finished,
        if finished {
            "sender completed without a receiver"
        } else {
            "sender still blocked after 300 ms"
        },
    );
    if !finished {
        // Drain so the child can finish; bounded to avoid hanging the suite.
        let mut r = new_msg(0, 0);
        for _ in 0..(PORT_QUEUE + 8) {
            match call::ipc_try_recv(port, &mut r) {
                Ok(0) | Err(Error::Again) => {
                    let _ = call::sched_yield();
                }
                _ => {}
            }
            if try_reap(child).is_some() {
                return;
            }
        }
        inconclusive(ctx, "A7 cleanup", "child still blocked after draining");
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    call::handle_panic("gui-authority", info)
}

#[no_mangle]
/// Userspace entry point.
pub extern "C" fn _start() -> ! {
    let mut ctx = Ctx::new("gui_authority");
    a1_a2_badge(&mut ctx);
    a3_a5_grant(&mut ctx);
    a6_poll(&mut ctx);
    a7_blocking_send(&mut ctx);
    call::exit(summary(&ctx))
}
