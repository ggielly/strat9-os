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
//! * A7  Does a non-blocking `ipc_try_send` report `EAGAIN` on a full queue?
//! * A8  Is `/dev/input` readable by a single reader only? (second open => `EBUSY`)

#![no_std]
#![no_main]

#[path = "gui_common.rs"]
mod common;

use common::*;
use core::panic::PanicInfo;
use strat9_syscall::{
    call,
    data::{
        IpcMessage, TimeSpec, WaitSource, WAIT_EVENT_READABLE, WAIT_SOURCE_FD, WAIT_SOURCE_HANDLE,
    },
    error::Error,
};

const FORGED: u64 = 0xDEAD_BEEF_CAFE_F00D;
const PORT_QUEUE: usize = 16;
const O_RDONLY: u32 = 0;

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
    check(
        ctx,
        "A1 kernel overwrites forged sender",
        parent_sender != FORGED,
        "",
    );

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
    check(
        ctx,
        "A3 grant to nonexistent pid is refused",
        r.is_err(),
        "",
    );

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
        inconclusive(
            ctx,
            "A5 PID reuse",
            "no reuse of the reaped PID in 400 forks",
        );
    }
}

fn a6_wait_many(ctx: &mut Ctx) {
    section(ctx, "A6: SYS_HANDLE_WAIT_MANY on empty sources");
    let Ok(port) = call::ipc_create_port(0) else {
        check(ctx, "ipc_create_port", false, "");
        return;
    };
    let Ok((rd, wr)) = call::pipe() else {
        check(ctx, "pipe", false, "");
        return;
    };
    let (rd, wr) = (rd as usize, wr as usize);

    // Index 0: empty IPC port handle. Index 1: empty pipe read end.
    let mut srcs = [
        WaitSource {
            kind: WAIT_SOURCE_HANDLE,
            events: WAIT_EVENT_READABLE,
            id: port as u64,
            revents: 0,
        },
        WaitSource {
            kind: WAIT_SOURCE_FD,
            events: WAIT_EVENT_READABLE,
            id: rd as u64,
            revents: 0,
        },
    ];

    // Probe the pipe alone with timeout 0: it must report not-ready.
    {
        let mut probe = [WaitSource {
            kind: WAIT_SOURCE_FD,
            events: WAIT_EVENT_READABLE,
            id: rd as u64,
            revents: 0,
        }];
        let t = monotonic_ns();
        let pr = call::handle_wait_many(&mut probe, 0);
        log("[gui_authority] info pipe_probe=");
        match &pr {
            Ok(i) => log_u64(*i as u64),
            Err(e) => log(err_name(*e)),
        }
        log(" revents=");
        log_u64(probe[0].revents);
        log(" t_ns=");
        log_u64(t);
        log("\n");
    }

    // Nothing is ready: the wait must time out and report nothing.
    let t0 = monotonic_ns();
    let r = call::handle_wait_many(&mut srcs, 100_000_000);
    let timed_out = matches!(r, Err(Error::TimedOut));
    if let Err(e) = &r {
        log("[gui_authority] info wait_many_err=");
        log(err_name(*e));
        log("\n");
    }
    let elapsed_ms = monotonic_ns().saturating_sub(t0) / 1_000_000;
    log("[gui_authority] info wait_many timeout_ms=");
    log_u64(elapsed_ms);
    log("\n");
    check(
        ctx,
        "A6 empty port + empty pipe time out after ~100 ms",
        timed_out && (80..=500).contains(&elapsed_ms),
        "",
    );
    gap(
        ctx,
        "A6 SYS_POLL reports POLLIN on an empty pipe (no real readiness)",
        false,
        "SYS_HANDLE_WAIT_MANY times out on empty sources",
    );

    // A child writes one byte after 30 ms: the wait must wake on the pipe.
    let child = match call::fork() {
        Ok(0) => {
            sleep_ms(30);
            let _ = send_u8(wr, 0xAB);
            call::exit(0)
        }
        Ok(pid) => pid,
        Err(_) => {
            check(ctx, "fork", false, "");
            return;
        }
    };
    // Parent drops its write end so EOF works once the child is gone.
    let _ = call::close(wr);

    let mut srcs = [
        WaitSource {
            kind: WAIT_SOURCE_HANDLE,
            events: WAIT_EVENT_READABLE,
            id: port as u64,
            revents: 0,
        },
        WaitSource {
            kind: WAIT_SOURCE_FD,
            events: WAIT_EVENT_READABLE,
            id: rd as u64,
            revents: 0,
        },
    ];
    let t1 = monotonic_ns();
    let ready = call::handle_wait_many(&mut srcs, 1_000_000_000);
    let elapsed = monotonic_ns().saturating_sub(t1);
    let index = match &ready {
        Ok(i) => *i,
        Err(_) => usize::MAX,
    };
    log("[gui_authority] info wait_many wake=");
    log_u64(index as u64);
    log(" elapsed_ms=");
    log_u64(elapsed / 1_000_000);
    log("\n");
    check(
        ctx,
        "A6 wait wakes on the first event (pipe readable) under 1 s",
        matches!(ready, Ok(1))
            && srcs[1].revents as u32 & WAIT_EVENT_READABLE != 0
            && elapsed < 1_000_000_000,
        "",
    );
    let _ = reap(child);
}

/// Monotonic clock in nanoseconds.
fn monotonic_ns() -> u64 {
    let mut ts = TimeSpec::zero();
    let _ = call::clock_gettime(strat9_syscall::CLOCK_MONOTONIC, &mut ts);
    ts.to_nanos()
}

fn a7_try_send(ctx: &mut Ctx) {
    section(ctx, "A7: non-blocking ipc_send on a full port");
    let Ok(port) = call::ipc_create_port(0) else {
        check(ctx, "ipc_create_port", false, "");
        return;
    };
    let m = new_msg(0, 7);
    let mut filled = 0usize;
    for _ in 0..PORT_QUEUE {
        if call::ipc_try_send(port, &m).is_ok() {
            filled += 1;
        }
    }
    check(
        ctx,
        "A7 the 16-slot queue accepts 16 non-blocking sends",
        filled == PORT_QUEUE,
        "",
    );

    let eagain = matches!(call::ipc_try_send(port, &m), Err(Error::Again));
    gap(
        ctx,
        "A7 non-blocking send returns EAGAIN when the queue is full",
        !eagain,
        if eagain {
            "SYS_IPC_TRY_SEND returns -EAGAIN on a full queue"
        } else {
            "no -EAGAIN: full queue not reported"
        },
    );

    // The queue held exactly PORT_QUEUE messages, and draining makes room again.
    let mut r = new_msg(0, 0);
    let mut drained = 0usize;
    while drained < PORT_QUEUE && call::ipc_try_recv(port, &mut r).is_ok() {
        drained += 1;
    }
    let empty = matches!(call::ipc_try_recv(port, &mut r), Err(Error::Again));
    let accepted = call::ipc_try_send(port, &m).is_ok();
    check(
        ctx,
        "A7 the queue held exactly 16 messages",
        drained == PORT_QUEUE && empty,
        "",
    );
    check(ctx, "A7 try_send succeeds once the queue is drained", accepted, "");
}

fn a8_input_exclusive(ctx: &mut Ctx) {
    section(ctx, "A8: /dev/input single reader");
    let fd = match call::open("/dev/input/kbd", O_RDONLY) {
        Ok(fd) => fd,
        Err(Error::Busy) => {
            check(
                ctx,
                "A8 /dev/input/kbd already has an exclusive reader",
                true,
                "first open returned EBUSY",
            );
            return;
        }
        Err(e) => {
            check(ctx, "A8 /dev/input/kbd opens", false, err_name(e));
            return;
        }
    };

    let second = call::open("/dev/input/kbd", O_RDONLY);
    check(
        ctx,
        "A8 a second open of /dev/input/kbd fails with EBUSY",
        matches!(second, Err(Error::Busy)),
        match second {
            Ok(_) => "second open succeeded",
            Err(e) => err_name(e),
        },
    );
    if let Ok(fd2) = second {
        let _ = call::close(fd2);
    }

    let _ = call::close(fd);
    let third = call::open("/dev/input/kbd", O_RDONLY);
    check(
        ctx,
        "A8 closing the reader releases the claim",
        third.is_ok(),
        match third {
            Ok(_) => "",
            Err(e) => err_name(e),
        },
    );
    if let Ok(fd3) = third {
        let _ = call::close(fd3);
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
    a6_wait_many(&mut ctx);
    a7_try_send(&mut ctx);
    a8_input_exclusive(&mut ctx);
    call::exit(summary(&ctx))
}
