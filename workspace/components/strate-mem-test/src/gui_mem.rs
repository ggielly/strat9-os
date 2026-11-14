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

//! GUI audit, proof 1 - memory: multi-page shared region and its lifetime.
//!
//! Questions answered (see `doc/GUI_AUDIT_2026-11.md`, section "Preuve 1"):
//!
//! * M1  Are all pages of a 5-page region shared correctly, including the
//!       first/last byte of every page, in both directions?
//! * M2  Is a fresh anonymous region zero-filled before export?
//! * M3  Can the exporter restrict what the importer may do (read-only)?
//! * M4  Can the importer re-grant the handle onward?
//! * M5  Do the pages stay alive after the exporter unmaps and closes?
//! * M6  Do the pages stay alive after the exporter process exits?
//!
//! Not covered (needs a kill primitive or memory counters): hard kill of the
//! exporter, SMP TLB shootdown, memory-pressure behaviour, accounting.

#![no_std]
#![no_main]

#[path = "gui_common.rs"]
mod common;

use common::*;
use core::panic::PanicInfo;
use strat9_syscall::{call, data::HandleInfo, number, syscall6};

const PAGES: usize = 5;
const LEN: usize = PAGES * PAGE_SIZE;
const PROT_READ: usize = 1;
const PROT_WRITE: usize = 2;
const MAP_PRIVATE: usize = 1 << 1;
const MAP_ANON: usize = 1 << 5;

/// Byte expected at `i` before anyone writes a marker (sparse seed).
fn seed(i: usize) -> u8 {
    (i as u8).wrapping_mul(7).wrapping_add((i / PAGE_SIZE) as u8)
}

fn marker_first(page: usize) -> u8 {
    0xA0 + page as u8
}
fn marker_last(page: usize) -> u8 {
    0xB0 + page as u8
}

/// Writes the seed everywhere and the boundary markers of every page.
///
/// SAFETY: caller guarantees `base..base+LEN` is a writable mapping.
unsafe fn fill(base: usize) {
    for i in 0..LEN {
        core::ptr::write_volatile((base + i) as *mut u8, seed(i));
    }
    for p in 0..PAGES {
        core::ptr::write_volatile((base + p * PAGE_SIZE) as *mut u8, marker_first(p));
        core::ptr::write_volatile((base + p * PAGE_SIZE + PAGE_SIZE - 1) as *mut u8, marker_last(p));
    }
}

/// Returns the number of mismatching bytes.
///
/// SAFETY: caller guarantees `base..base+LEN` is a readable mapping.
unsafe fn verify(base: usize) -> usize {
    let mut bad = 0;
    for i in 0..LEN {
        let page = i / PAGE_SIZE;
        let off = i % PAGE_SIZE;
        let expect = if off == 0 {
            marker_first(page)
        } else if off == PAGE_SIZE - 1 {
            marker_last(page)
        } else {
            seed(i)
        };
        if core::ptr::read_volatile((base + i) as *const u8) != expect {
            bad += 1;
        }
    }
    bad
}

fn anon_map() -> Option<usize> {
    // SAFETY: plain anonymous mapping, no aliasing.
    unsafe {
        syscall6(
            number::SYS_MMAP,
            0,
            LEN,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANON,
            0,
            0,
        )
    }
    .ok()
}

fn zero_filled(base: usize) -> bool {
    for i in 0..LEN {
        // SAFETY: freshly mapped RW region of LEN bytes.
        if unsafe { core::ptr::read_volatile((base + i) as *const u8) } != 0 {
            return false;
        }
    }
    true
}

// Child -> parent report codes.
const R_READY: u8 = 1;
const R_ACK2: u8 = 2;
const R_ACK3: u8 = 3;
const R_ACK4: u8 = 4;
// Parent -> child commands.
const C_GO2: u8 = 12;
const C_GO3: u8 = 13;
const C_GO4: u8 = 14;

/// Importer side of scenario A (parent stays alive until the end).
fn importer_a(from_parent: usize, to_parent: usize, parent_pid: usize) -> ! {
    let Some(h) = recv_u64(from_parent) else {
        call::exit(10)
    };
    let h = h as usize;
    let mut addr = 0usize;
    if call::mem_region_map(h, 0, &mut addr).is_err() {
        call::exit(11);
    }
    // SAFETY: the region was just mapped RW with LEN bytes.
    if unsafe { verify(addr) } != 0 {
        call::exit(12);
    }
    // Child-side write: first byte of page 1 changes, last byte of page 4 too.
    unsafe {
        core::ptr::write_volatile((addr + PAGE_SIZE + 1) as *mut u8, 0x5C);
        core::ptr::write_volatile((addr + LEN - 2) as *mut u8, 0x5D);
    }
    // M4: can we re-grant the handle onward?
    let regrant = call::handle_grant(h, parent_pid).is_ok();
    let mut info = HandleInfo {
        resource_type: 0,
        permissions: 0,
        resource: 0,
    };
    let _ = call::handle_info(h, &mut info);
    let _ = send_u8(to_parent, R_READY);
    let _ = send_u64(to_parent, addr as u64);
    let _ = send_u64(to_parent, info.permissions as u64);
    let _ = send_u8(to_parent, regrant as u8);

    if recv_u8(from_parent) != Some(C_GO2) {
        call::exit(20);
    }
    // Parent wrote 0x6A at page 2 offset 3.
    let seen = unsafe { core::ptr::read_volatile((addr + 2 * PAGE_SIZE + 3) as *const u8) };
    if seen != 0x6A {
        call::exit(21);
    }
    let _ = send_u8(to_parent, R_ACK2);

    if recv_u8(from_parent) != Some(C_GO3) {
        call::exit(30);
    }
    // M3: the parent made its own mapping read-only. Can we still write?
    // A fault here kills this process: the parent reads that as "restricted".
    unsafe { core::ptr::write_volatile((addr + 3 * PAGE_SIZE + 9) as *mut u8, 0xEE) };
    let _ = send_u8(to_parent, R_ACK3);

    if recv_u8(from_parent) != Some(C_GO4) {
        call::exit(40);
    }
    // M5: exporter unmapped and closed its handle; our mapping must live.
    let bad = unsafe { verify_ignoring_edits(addr) };
    let _ = send_u8(to_parent, if bad == 0 { R_ACK4 } else { 0xFF });
    call::exit(if bad == 0 { 0 } else { 41 })
}

/// Like `verify` but tolerates the bytes the participants edited on purpose.
///
/// SAFETY: caller guarantees a readable LEN-byte mapping at `base`.
unsafe fn verify_ignoring_edits(base: usize) -> usize {
    let edited = [
        PAGE_SIZE + 1,
        LEN - 2,
        2 * PAGE_SIZE + 3,
        3 * PAGE_SIZE + 9,
    ];
    let mut bad = 0;
    for i in 0..LEN {
        if edited.contains(&i) {
            continue;
        }
        let page = i / PAGE_SIZE;
        let off = i % PAGE_SIZE;
        let expect = if off == 0 {
            marker_first(page)
        } else if off == PAGE_SIZE - 1 {
            marker_last(page)
        } else {
            seed(i)
        };
        if core::ptr::read_volatile((base + i) as *const u8) != expect {
            bad += 1;
        }
    }
    bad
}

fn scenario_a(ctx: &mut Ctx) {
    section(ctx, "A: 5-page region, parent exporter, child importer");

    let Some(base) = anon_map() else {
        check(ctx, "mmap 5 pages", false, "mmap failed");
        return;
    };
    check(ctx, "mmap 5 pages", true, "");
    // M2: zero-fill before any write.
    check(ctx, "M2 fresh region is zero-filled", zero_filled(base), "");
    // SAFETY: base is a RW mapping of LEN bytes.
    unsafe { fill(base) };

    let Ok(h) = call::mem_region_export(base) else {
        check(ctx, "mem_region_export(5 pages)", false, "export failed");
        return;
    };
    check(ctx, "mem_region_export(5 pages)", true, "");

    let (Ok((p2c_r, p2c_w)), Ok((c2p_r, c2p_w))) = (call::pipe(), call::pipe()) else {
        check(ctx, "pipes", false, "pipe() failed");
        return;
    };
    let (p2c_r, p2c_w, c2p_r, c2p_w) = (p2c_r as usize, p2c_w as usize, c2p_r as usize, c2p_w as usize);
    let parent_pid = call::getpid().unwrap_or(0);

    let child = match call::fork() {
        Ok(0) => {
            let _ = call::close(p2c_w);
            let _ = call::close(c2p_r);
            importer_a(p2c_r, c2p_w, parent_pid)
        }
        Ok(pid) => pid,
        Err(_) => {
            check(ctx, "fork", false, "fork failed");
            return;
        }
    };
    let _ = call::close(p2c_r);
    let _ = call::close(c2p_w);

    // Grant by PID (the only primitive that exists today).
    let Ok(child_h) = call::handle_grant(h, child) else {
        check(ctx, "handle_grant(region, child pid)", false, "grant failed");
        return;
    };
    check(ctx, "handle_grant(region, child pid)", true, "");
    let _ = send_u64(p2c_w, child_h as u64);

    // M1 (child -> parent): child verified every byte; now see its writes.
    let ready = recv_u8(c2p_r) == Some(R_READY);
    check(ctx, "M1 child mapped and verified all 5 pages", ready, "");
    if !ready {
        let e = reap(child);
        check(ctx, "child exit", false, if e.is_some() { "child died early" } else { "reap failed" });
        return;
    }
    let child_addr = recv_u64(c2p_r).unwrap_or(0);
    let perms = recv_u64(c2p_r).unwrap_or(0);
    let regrant = recv_u8(c2p_r).unwrap_or(0) != 0;
    log("[gui_mem] info parent_va=");
    log_hex(base as u64);
    log(" child_va=");
    log_hex(child_addr);
    log(" child_handle_perms=");
    log_hex(perms);
    log("\n");
    // SAFETY: parent mapping is still RW.
    let (a, b) = unsafe {
        (
            core::ptr::read_volatile((base + PAGE_SIZE + 1) as *const u8),
            core::ptr::read_volatile((base + LEN - 2) as *const u8),
        )
    };
    check(
        ctx,
        "M1 child writes visible to parent (page 1 byte 1, page 4 byte -2)",
        a == 0x5C && b == 0x5D,
        "",
    );
    // M4
    gap(
        ctx,
        "M4 importer can re-grant a region handle onward (no grant restriction)",
        regrant,
        "handle_grant clones all permission bits",
    );

    // Parent -> child direction.
    unsafe { core::ptr::write_volatile((base + 2 * PAGE_SIZE + 3) as *mut u8, 0x6A) };
    let _ = send_u8(p2c_w, C_GO2);
    check(ctx, "M1 parent writes visible to child", recv_u8(c2p_r) == Some(R_ACK2), "");

    // M3: parent drops its own write permission; does the child still write?
    // SAFETY: SYS_MPROTECT on the parent's own mapping.
    let rc = unsafe { syscall6(number::SYS_MPROTECT, base, LEN, PROT_READ, 0, 0, 0) };
    check(ctx, "parent mprotect(READ) on exported region", rc.is_ok(), "");
    let _ = send_u8(p2c_w, C_GO3);
    let ack3 = recv_u8(c2p_r) == Some(R_ACK3);
    gap(
        ctx,
        "M3 exporter cannot make the region read-only for the importer",
        ack3,
        if ack3 {
            "child wrote after parent mprotect(READ)"
        } else {
            "child faulted: restriction effective"
        },
    );
    if !ack3 {
        let _ = reap(child);
        return;
    }
    // Restore parent write access is not needed: we unmap next.

    // M5: exporter unmaps and closes its handle; importer must keep the data.
    // SAFETY: unmapping our own mapping, no further access afterwards.
    let _ = unsafe { call::funmap(base, LEN) };
    let _ = call::handle_close(h);
    let _ = send_u8(p2c_w, C_GO4);
    let ack4 = recv_u8(c2p_r) == Some(R_ACK4);
    check(
        ctx,
        "M5 pages survive exporter munmap + handle_close (importer data intact)",
        ack4,
        "",
    );
    let exit = reap(child);
    check(ctx, "child exit code 0", exit == Some(Exit::Code(0)), "");
}

/// Scenario B: exporter exits while importer holds a mapping.
fn scenario_b(ctx: &mut Ctx) {
    section(ctx, "B: exporter process exits while importer is mapped");
    let Ok((res_r, res_w)) = call::pipe() else {
        check(ctx, "pipe", false, "pipe() failed");
        return;
    };
    let (res_r, res_w) = (res_r as usize, res_w as usize);

    let exporter = match call::fork() {
        Ok(0) => exporter_b(res_w),
        Ok(pid) => pid,
        Err(_) => {
            check(ctx, "fork exporter", false, "");
            return;
        }
    };
    let _ = call::close(res_w);
    // Result byte: 1 = importer verified all pages after exporter death.
    let result = recv_u8(res_r);
    let _ = reap(exporter);
    check(
        ctx,
        "M6 pages survive exporter process exit (importer data intact)",
        result == Some(1),
        match result {
            Some(1) => "",
            Some(_) => "importer saw corrupted/zeroed pages",
            None => "importer died or never reported",
        },
    );
}

fn exporter_b(res_w: usize) -> ! {
    let Some(base) = anon_map() else { call::exit(1) };
    // SAFETY: fresh RW mapping.
    unsafe { fill(base) };
    let Ok(h) = call::mem_region_export(base) else {
        call::exit(2)
    };
    let (Ok((p2c_r, p2c_w)), Ok((c2p_r, c2p_w))) = (call::pipe(), call::pipe()) else {
        call::exit(3)
    };
    let (p2c_r, p2c_w, c2p_r, c2p_w) = (p2c_r as usize, p2c_w as usize, c2p_r as usize, c2p_w as usize);
    let importer = match call::fork() {
        Ok(0) => {
            // Importer: must NOT keep the write end of p2c, or EOF never comes.
            let _ = call::close(p2c_w);
            let _ = call::close(c2p_r);
            let Some(hh) = recv_u64(p2c_r) else {
                call::exit(10)
            };
            let mut addr = 0usize;
            if call::mem_region_map(hh as usize, 0, &mut addr).is_err() {
                call::exit(11);
            }
            if unsafe { verify(addr) } != 0 {
                call::exit(12);
            }
            let _ = send_u8(c2p_w, 1); // mapped
            // Wait for exporter death: EOF on p2c.
            let _ = recv_u8(p2c_r);
            sleep_ms(100); // let process teardown run
            let bad = unsafe { verify(addr) };
            let _ = send_u8(res_w, if bad == 0 { 1 } else { 0 });
            call::exit(0)
        }
        Ok(pid) => pid,
        Err(_) => call::exit(4),
    };
    let _ = call::close(p2c_r);
    let _ = call::close(c2p_w);
    let Ok(ch) = call::handle_grant(h, importer) else {
        call::exit(5)
    };
    let _ = send_u64(p2c_w, ch as u64);
    if recv_u8(c2p_r) != Some(1) {
        call::exit(6);
    }
    // Die without unmapping, closing or reaping anything.
    call::exit(0)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    call::handle_panic("gui-mem", info)
}

#[no_mangle]
/// Userspace entry point.
pub extern "C" fn _start() -> ! {
    let mut ctx = Ctx::new("gui_mem");
    scenario_a(&mut ctx);
    scenario_b(&mut ctx);
    call::exit(summary(&ctx))
}
