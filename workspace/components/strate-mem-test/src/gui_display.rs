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

//! GUI audit, proof 3 - display ownership transfer.
//!
//! PRECONDITION: no userspace process holds `/dev/vasistas/0.0` writable
//! (boot without `strate-console` / `strate-graphical` on the display, or
//! stop them first). The binary checks `owner=kernel` in `/dev/vasistas/info`
//! and reports INCONCLUSIVE otherwise.
//!
//! It touches the first page of the framebuffer (pixel row 0) only.
//!
//! Questions answered (see `doc/GUI_AUDIT_2026-11.md`, section "Preuve 3"):
//!
//! * D1  Is a second writable open refused (EBUSY) while an owner exists?
//! * D2  Can a non-owner present (`DMG2`)? (must be refused)
//! * D3  When the owner closes, is ownership released so another process can
//!       take it and present (no stale `OWNER_PID`)?
//! * D4  After the handle is closed, can an old writable mapping still write
//!       the live (new-generation) screen?
//! * D5  Can any process open `/dev/vasistas/snapshot`?

#![no_std]
#![no_main]

#[path = "gui_common.rs"]
mod common;

use common::*;
use core::panic::PanicInfo;
use strat9_syscall::{call, error::Error, number, syscall6};

const O_RDONLY: u32 = 0;
const O_RDWR: u32 = 2;
const PROT_RW: usize = 3;
const MAP_SHARED: usize = 1;

/// `DMG2` header with zero rectangles: valid for the owner, a pure
/// permission probe for everyone else.
fn dmg2_empty() -> [u8; 8] {
    let mut p = [0u8; 8];
    p[0..4].copy_from_slice(b"DMG2");
    // count = 0, display = 0
    p
}

/// 0 = accepted, 1 = PermissionDenied, 2 = other error.
fn present_probe(damage_fd: usize) -> u8 {
    match call::write(damage_fd, &dmg2_empty()) {
        Ok(_) => 0,
        Err(Error::PermissionDenied) => 1,
        Err(_) => 2,
    }
}

/// 0 = opened, 1 = Busy (another owner), 2 = other error.
fn open_class(path: &str, flags: u32) -> u8 {
    match call::open(path, flags) {
        Ok(fd) => {
            let _ = call::close(fd);
            0
        }
        Err(Error::Busy) => 1,
        Err(_) => 2,
    }
}

fn kernel_owns_display() -> Option<bool> {
    let fd = call::open("/dev/vasistas/info", O_RDONLY).ok()?;
    let mut buf = [0u8; 512];
    let n = call::read(fd, &mut buf).ok()?;
    let _ = call::close(fd);
    let hay = &buf[..n];
    let needle = b"owner=kernel";
    Some(hay.windows(needle.len()).any(|w| w == needle))
}

/// Child body for D4: map the screen, close the handle, write through the map.
/// Exit 0 = the write survived the close; killed by a signal = mapping revoked.
fn d4_child() -> ! {
    let Ok(fd) = call::open("/dev/vasistas/0.0", O_RDWR) else {
        call::exit(10)
    };
    // SAFETY: shared mapping of one framebuffer page, written once below.
    let Ok(addr) =
        (unsafe { syscall6(number::SYS_MMAP, 0, PAGE_SIZE, PROT_RW, MAP_SHARED, fd, 0) })
    else {
        call::exit(11)
    };
    let _ = call::close(fd); // releases the ownership reference
                             // SAFETY: mapping established above; a fault here is the experiment's answer.
    unsafe { core::ptr::write_volatile(addr as *mut u8, 0x01) };
    call::exit(0)
}

fn d4(ctx: &mut Ctx) {
    section(ctx, "D4: framebuffer mapping after the handle is closed");
    let child = match call::fork() {
        Ok(0) => d4_child(),
        Ok(p) => p,
        Err(_) => {
            check(ctx, "fork", false, "");
            return;
        }
    };
    let label = "D4 an old writable mapping can write the live screen after handle close";
    match reap(child) {
        // The child wrote 0x01 through the stale mapping. Reopen the screen
        // writable (new generation) and snapshot it: the parent owns the
        // display, so the snapshot path is allowed.
        Some(Exit::Code(0)) => {
            let Ok(h) = call::open("/dev/vasistas/0.0", O_RDWR) else {
                inconclusive(ctx, "D4", "reopen failed");
                return;
            };
            let snap = call::open("/dev/vasistas/snapshot", O_RDONLY);
            let mut first = [0u8; 1];
            let n = match snap {
                Ok(fd) => {
                    let n = call::read(fd, &mut first).unwrap_or(0);
                    let _ = call::close(fd);
                    n
                }
                Err(_) => 0,
            };
            let _ = call::close(h);
            if n == 0 {
                inconclusive(ctx, "D4", "cannot snapshot the new screen");
                return;
            }
            gap(
                ctx,
                label,
                first[0] == 0x01,
                if first[0] == 0x01 {
                    "stale mapping reached the new screen"
                } else {
                    "fresh zeroed screen; stale mapping did not reach it"
                },
            );
        }
        Some(Exit::Signal(s)) => {
            gap(ctx, label, false, "write faulted");
            log("[gui_display] info signal=");
            log_u64(s as u64);
            log("\n");
        }
        Some(Exit::Code(c)) => inconclusive(
            ctx,
            "D4",
            if c == 10 {
                "open failed"
            } else {
                "mmap failed"
            },
        ),
        None => inconclusive(ctx, "D4", "reap failed"),
    }
}

fn d5(ctx: &mut Ctx) {
    section(ctx, "D5: /dev/vasistas/snapshot access");
    let child = match call::fork() {
        Ok(0) => match call::open("/dev/vasistas/snapshot", O_RDONLY) {
            Ok(fd) => {
                let _ = call::close(fd);
                call::exit(0)
            }
            Err(Error::PermissionDenied) => call::exit(1),
            Err(_) => call::exit(2),
        },
        Ok(p) => p,
        Err(_) => {
            check(ctx, "fork", false, "");
            return;
        }
    };
    let label = "D5 an arbitrary process can open the full-screen snapshot";
    match reap(child) {
        Some(Exit::Code(0)) => gap(
            ctx,
            label,
            true,
            "snapshot open succeeded without ownership",
        ),
        Some(Exit::Code(1)) => gap(ctx, label, false, "non-owner snapshot open refused"),
        Some(_) => inconclusive(ctx, "D5", "unexpected open error"),
        None => inconclusive(ctx, "D5", "reap failed"),
    }
}

/// Child body for D1-D3.
fn d123_child(to_parent: usize, from_parent: usize) -> ! {
    // The child inherited the parent's writable screen fd across fork.
    // Drop it first: otherwise it keeps the OpenFile (and the ownership
    // reference) alive, so the parent's close would never release the screen.
    if let Some(inherited) = recv_u64(from_parent) {
        let _ = call::close(inherited as usize);
    }
    // D1: a second writable open must be refused with EBUSY while the parent
    // owns the screen. `open_class` closes the handle if it unexpectedly
    // succeeded, so the child holds no ownership when D3 runs.
    let h2_class = open_class("/dev/vasistas/0.0", O_RDWR);
    let dmg = call::open("/dev/vasistas/damage", O_RDWR);
    let w1 = match dmg {
        Ok(fd) => present_probe(fd),
        Err(_) => 2,
    };
    let _ = send_u8(to_parent, h2_class);
    let _ = send_u8(to_parent, w1);
    // Wait until the parent closed its handle.
    let _ = recv_u8(from_parent);
    // D3: the owner is gone, so the kernel owns the display again and this
    // process can take ownership. Read info first, then open writable.
    let owner_kernel = kernel_owns_display().unwrap_or(false);
    let h3 = call::open("/dev/vasistas/0.0", O_RDWR);
    let w2 = match (&h3, dmg) {
        (Ok(_), Ok(fd)) => present_probe(fd),
        _ => 2,
    };
    let _ = send_u8(to_parent, owner_kernel as u8);
    let _ = send_u8(to_parent, w2);
    call::exit(0)
}

fn d123(ctx: &mut Ctx) {
    section(ctx, "D1-D3: exclusivity and presentation rights");
    let Ok(h1) = call::open("/dev/vasistas/0.0", O_RDWR) else {
        check(ctx, "open /dev/vasistas/0.0 writable", false, "");
        return;
    };
    let Ok(dmg) = call::open("/dev/vasistas/damage", O_RDWR) else {
        check(ctx, "open /dev/vasistas/damage", false, "");
        return;
    };
    check(
        ctx,
        "owner can present (DMG2, 0 rects)",
        present_probe(dmg) == 0,
        "",
    );

    let (Ok((p2c_r, p2c_w)), Ok((c2p_r, c2p_w))) = (call::pipe(), call::pipe()) else {
        check(ctx, "pipes", false, "");
        return;
    };
    let (p2c_r, p2c_w, c2p_r, c2p_w) = (
        p2c_r as usize,
        p2c_w as usize,
        c2p_r as usize,
        c2p_w as usize,
    );
    let child = match call::fork() {
        Ok(0) => {
            let _ = call::close(p2c_w);
            let _ = call::close(c2p_r);
            d123_child(c2p_w, p2c_r)
        }
        Ok(p) => p,
        Err(_) => {
            check(ctx, "fork", false, "");
            return;
        }
    };
    let _ = call::close(p2c_r);
    let _ = call::close(c2p_w);
    // Hand the inherited writable fd to the child so it can drop its copy.
    let _ = send_u64(p2c_w, h1 as u64);

    let h2_class = recv_u8(c2p_r);
    let w1 = recv_u8(c2p_r);
    gap(
        ctx,
        "D1 a second process can open the screen writable while an owner exists",
        h2_class != Some(1),
        match h2_class {
            Some(1) => "second writable open refused with EBUSY",
            Some(0) => "second writable open succeeded: ownership is shared",
            _ => "second writable open failed with an unexpected error",
        },
    );
    check(ctx, "D2 non-owner DMG2 is refused", w1 == Some(1), "");

    // Owner releases; the child should be able to take ownership in turn.
    let _ = call::close(h1);
    let _ = send_u8(p2c_w, 1);
    let owner_kernel = recv_u8(c2p_r);
    let w2 = recv_u8(c2p_r);
    gap(
        ctx,
        "D3 ownership is released on close and the next process can present",
        !(owner_kernel == Some(1) && w2 == Some(0)),
        match (owner_kernel, w2) {
            (Some(1), Some(0)) => "OWNER_PID cleared; new owner presents",
            (Some(0), _) => "OWNER_PID still set after the owner closed",
            (_, Some(1)) => "new owner cannot present: stale OWNER_PID",
            (_, Some(0)) => "new owner presents",
            _ => "unexpected result",
        },
    );
    let _ = reap(child);
    let _ = call::close(dmg);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    call::handle_panic("gui-display", info)
}

#[no_mangle]
/// Userspace entry point.
pub extern "C" fn _start() -> ! {
    let mut ctx = Ctx::new("gui_display");
    match kernel_owns_display() {
        Some(true) => {
            // D5 first: it needs a non-owner child, before D4's parent ever
            // becomes the owner. D4 then closes its writable handle before
            // returning, leaving no owner for D1-D3.
            d5(&mut ctx);
            d4(&mut ctx);
            d123(&mut ctx);
        }
        Some(false) => inconclusive(
            &mut ctx,
            "precondition",
            "a userspace process already owns the display; stop it and rerun",
        ),
        None => inconclusive(&mut ctx, "precondition", "cannot read /dev/vasistas/info"),
    }
    call::exit(summary(&ctx))
}
