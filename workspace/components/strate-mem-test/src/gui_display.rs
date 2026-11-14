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
//! PRECONDITION: no userspace process holds `/dev/display/0.0` writable
//! (boot without `strate-console` / `strate-graphical` on the display, or
//! stop them first). The binary checks `owner=kernel` in `/dev/display/info`
//! and reports INCONCLUSIVE otherwise.
//!
//! It touches the first page of the framebuffer (pixel row 0) only.
//!
//! Questions answered (see `doc/GUI_AUDIT_2026-11.md`, section "Preuve 3"):
//!
//! * D1  Is a second writable open refused while an owner exists?
//! * D2  Can a non-owner present (`DMG2`)? (must be refused)
//! * D3  When the owner closes but another writable handle remains, does
//!       presentation rights move to the remaining holder?
//! * D4  After the handle is closed, does an old writable mapping of the
//!       framebuffer still work?
//! * D5  Can any process open `/dev/display/snapshot`?

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

fn kernel_owns_display() -> Option<bool> {
    let fd = call::open("/dev/display/info", O_RDONLY).ok()?;
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
    let Ok(fd) = call::open("/dev/display/0.0", O_RDWR) else {
        call::exit(10)
    };
    // SAFETY: shared mapping of one framebuffer page, written once below.
    let Ok(addr) = (unsafe {
        syscall6(number::SYS_MMAP, 0, PAGE_SIZE, PROT_RW, MAP_SHARED, fd, 0)
    }) else {
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
    match reap(child) {
        Some(Exit::Code(0)) => gap(
            ctx,
            "D4 old writable mapping still works after handle close",
            true,
            "mapping outlives ownership; a former owner can write the screen",
        ),
        Some(Exit::Signal(s)) => {
            gap(ctx, "D4 old writable mapping still works after handle close", false, "write faulted");
            log("[gui_display] info signal=");
            log_u64(s as u64);
            log("\n");
        }
        Some(Exit::Code(c)) => {
            inconclusive(ctx, "D4", if c == 10 { "open failed" } else { "mmap failed" })
        }
        None => inconclusive(ctx, "D4", "reap failed"),
    }
}

fn d5(ctx: &mut Ctx) {
    section(ctx, "D5: /dev/display/snapshot access");
    let child = match call::fork() {
        Ok(0) => {
            let ok = call::open("/dev/display/snapshot", O_RDONLY);
            call::exit(if ok.is_ok() { 0 } else { 1 })
        }
        Ok(p) => p,
        Err(_) => {
            check(ctx, "fork", false, "");
            return;
        }
    };
    gap(
        ctx,
        "D5 an arbitrary process can open the full-screen snapshot",
        reap(child) == Some(Exit::Code(0)),
        "no ownership/capability gate in the scheme",
    );
}

/// Child body for D1-D3.
fn d123_child(to_parent: usize, from_parent: usize) -> ! {
    let h2 = call::open("/dev/display/0.0", O_RDWR);
    let dmg = call::open("/dev/display/damage", O_RDWR);
    let w1 = match dmg {
        Ok(fd) => present_probe(fd),
        Err(_) => 2,
    };
    let _ = send_u8(to_parent, h2.is_ok() as u8);
    let _ = send_u8(to_parent, w1);
    // Wait until the parent closed its handle.
    let _ = recv_u8(from_parent);
    let w2 = match dmg {
        Ok(fd) => present_probe(fd),
        Err(_) => 2,
    };
    let _ = send_u8(to_parent, w2);
    call::exit(0)
}

fn d123(ctx: &mut Ctx) {
    section(ctx, "D1-D3: exclusivity and presentation rights");
    let Ok(h1) = call::open("/dev/display/0.0", O_RDWR) else {
        check(ctx, "open /dev/display/0.0 writable", false, "");
        return;
    };
    let Ok(dmg) = call::open("/dev/display/damage", O_RDWR) else {
        check(ctx, "open /dev/display/damage", false, "");
        return;
    };
    check(ctx, "owner can present (DMG2, 0 rects)", present_probe(dmg) == 0, "");

    let (Ok((p2c_r, p2c_w)), Ok((c2p_r, c2p_w))) = (call::pipe(), call::pipe()) else {
        check(ctx, "pipes", false, "");
        return;
    };
    let (p2c_r, p2c_w, c2p_r, c2p_w) = (p2c_r as usize, p2c_w as usize, c2p_r as usize, c2p_w as usize);
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

    let h2_ok = recv_u8(c2p_r);
    let w1 = recv_u8(c2p_r);
    gap(
        ctx,
        "D1 a second process can open the screen writable while an owner exists",
        h2_ok == Some(1),
        "writable opens are reference-counted, not exclusive",
    );
    check(ctx, "D2 non-owner DMG2 is refused", w1 == Some(1), "");

    // Owner releases; the child still holds a writable handle.
    let _ = call::close(h1);
    let _ = send_u8(p2c_w, 1);
    let w2 = recv_u8(c2p_r);
    gap(
        ctx,
        "D3 presentation rights do NOT move to the remaining writable holder",
        w2 == Some(1),
        match w2 {
            Some(0) => "ownership transferred",
            Some(1) => "OWNER_PID stays the closed owner: the screen is unusable until all handles close",
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
            d4(&mut ctx);
            d5(&mut ctx);
            d123(&mut ctx);
        }
        Some(false) => inconclusive(
            &mut ctx,
            "precondition",
            "a userspace process already owns the display; stop it and rerun",
        ),
        None => inconclusive(&mut ctx, "precondition", "cannot read /dev/display/info"),
    }
    call::exit(summary(&ctx))
}
