#![no_std]
#![no_main]

use core::panic::PanicInfo;
use strat9_syscall::call;

const PAGE_SIZE: usize = 4096;

fn write_fd(fd: usize, msg: &str) {
    let _ = call::write(fd, msg.as_bytes());
}

fn log(msg: &str) {
    write_fd(1, msg);
}

fn log_err(msg: &str) {
    write_fd(2, msg);
}

fn log_u64(mut value: u64) {
    let mut buf = [0u8; 21];
    if value == 0 {
        log("0");
        return;
    }
    let mut i = buf.len();
    while value > 0 {
        i -= 1;
        buf[i] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    let s = unsafe { core::str::from_utf8_unchecked(&buf[i..]) };
    log(s);
}

fn log_hex_u64(mut value: u64) {
    let mut buf = [0u8; 16];
    for i in (0..16).rev() {
        let nibble = (value & 0xF) as u8;
        buf[i] = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
        value >>= 4;
    }
    log("0x");
    let s = unsafe { core::str::from_utf8_unchecked(&buf) };
    log(s);
}

fn section(title: &str) {
    log("\n############################################################\n");
    log("[test_mem_stressed] ");
    log(title);
    log("\n############################################################\n");
}

fn query_brk() -> usize {
    match call::brk(0) {
        Ok(v) => v,
        Err(e) => {
            log_err("[test_mem_stressed] brk(0) failed: ");
            log_err(e.name());
            log_err("\n");
            call::exit(201);
        }
    }
}

fn set_brk(new_brk: usize, ctx: &str) -> usize {
    match call::brk(new_brk) {
        Ok(v) => v,
        Err(e) => {
            log_err("[test_mem_stressed] brk(set) failed in ");
            log_err(ctx);
            log_err(": ");
            log_err(e.name());
            log_err("\n");
            call::exit(202);
        }
    }
}

fn pattern_byte(seed: u8, page: usize, pos: usize) -> u8 {
    seed.wrapping_add((page as u8).wrapping_mul(13))
        .wrapping_add(pos as u8)
}

fn touch_pages(base: usize, pages: usize, seed: u8, tag: &str) {
    log("[test_mem_stressed] touch ");
    log(tag);
    log(" base=");
    log_hex_u64(base as u64);
    log(" pages=");
    log_u64(pages as u64);
    log(" seed=");
    log_hex_u64(seed as u64);
    log("\n");

    let total = pages * PAGE_SIZE;
    let buf = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, total) };
    let marks = [0usize, 31usize, 511usize, 2047usize, 4095usize];

    for p in 0..pages {
        let page_off = p * PAGE_SIZE;
        for &m in &marks {
            buf[page_off + m] = pattern_byte(seed, p, m);
        }
    }

    for p in 0..pages {
        let page_off = p * PAGE_SIZE;
        for &m in &marks {
            let expected = pattern_byte(seed, p, m);
            let got = buf[page_off + m];
            if got != expected {
                log_err("[test_mem_stressed] verify mismatch page=");
                log_u64(p as u64);
                log_err(" mark=");
                log_u64(m as u64);
                log_err(" expected=");
                log_hex_u64(expected as u64);
                log_err(" got=");
                log_hex_u64(got as u64);
                log_err(" tag=");
                log_err(tag);
                log_err("\n");
                call::exit(203);
            }
        }
    }
}

fn stage_fixed_rounds() {
    section("Stage A: fixed-size rounds (up to 128 pages)");
    let base = query_brk();
    let rounds = [1usize, 2, 4, 8, 16, 32, 64, 128];
    for (i, pages) in rounds.iter().enumerate() {
        let target = base + pages * PAGE_SIZE;
        log("[test_mem_stressed] round=");
        log_u64(i as u64);
        log(" grow->pages=");
        log_u64(*pages as u64);
        log(" target=");
        log_hex_u64(target as u64);
        log("\n");
        let _ = set_brk(target, "stage_fixed_rounds_grow");
        touch_pages(
            base,
            *pages,
            (0x20 + i as u8).wrapping_mul(3),
            "fixed_round",
        );
        let _ = set_brk(base, "stage_fixed_rounds_shrink");
    }
}

fn stage_sawtooth_heavy() {
    section("Stage B: heavy saw-tooth (split/coalesce pressure)");
    let base = query_brk();
    let mut pages = 3usize;

    for step in 0..120usize {
        let grow = base + pages * PAGE_SIZE;
        let _ = set_brk(grow, "sawtooth_grow");
        touch_pages(base, pages, (0x60u8).wrapping_add(step as u8), "sawtooth");

        let shrink_pages = (pages / 3).max(1);
        let shrink = base + shrink_pages * PAGE_SIZE;
        let _ = set_brk(shrink, "sawtooth_shrink");

        if step % 10 == 0 {
            log("[test_mem_stressed] step=");
            log_u64(step as u64);
            log(" pages=");
            log_u64(pages as u64);
            log(" shrink_pages=");
            log_u64(shrink_pages as u64);
            log("\n");
        }

        pages = if pages >= 192 { 5 } else { pages + 7 };
        let _ = call::sched_yield();
    }

    let _ = set_brk(base, "sawtooth_end");
}

fn stage_churn_loops() {
    section("Stage C: many small/medium churn loops");
    let base = query_brk();
    for i in 0..300usize {
        let pages = 1 + ((i * 11) % 48);
        let target = base + pages * PAGE_SIZE;
        let _ = set_brk(target, "churn_grow");
        touch_pages(base, pages, (0xA0u8).wrapping_add(i as u8), "churn");
        let _ = set_brk(base, "churn_shrink");

        if i % 25 == 0 {
            log("[test_mem_stressed] churn checkpoint i=");
            log_u64(i as u64);
            log(" pages=");
            log_u64(pages as u64);
            log("\n");
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    log_err("[test_mem_stressed] PANIC\n");
    call::exit(250)
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    section("Start");
    log("[test_mem_stressed] test intensif (verbose) demarre\n");
    log("[test_mem_stressed] NOTE: binaire manuel, non lance automatiquement a l'init\n");

    let pid = call::getpid().unwrap_or(0);
    let tid = call::gettid().unwrap_or(0);
    log("[test_mem_stressed] pid=");
    log_u64(pid as u64);
    log(" tid=");
    log_u64(tid as u64);
    log("\n");

    stage_fixed_rounds();
    stage_sawtooth_heavy();
    stage_churn_loops();

    section("Done");
    log("[test_mem_stressed] SUCCESS\n");
    call::exit(0)
}
