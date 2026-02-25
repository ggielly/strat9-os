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

fn log_line(label: &str, value: u64) {
    log(label);
    log_u64(value);
    log("\n");
}

fn section(title: &str) {
    log("\n============================================================\n");
    log("[test_mem] ");
    log(title);
    log("\n============================================================\n");
}

fn query_brk() -> usize {
    match call::brk(0) {
        Ok(v) => v,
        Err(e) => {
            log_err("[test_mem] brk(0) failed: ");
            log_err(e.name());
            log_err("\n");
            call::exit(101);
        }
    }
}

fn set_brk(new_brk: usize, ctx: &str) -> usize {
    match call::brk(new_brk) {
        Ok(v) => v,
        Err(e) => {
            log_err("[test_mem] brk(set) failed in ");
            log_err(ctx);
            log_err(": ");
            log_err(e.name());
            log_err("\n");
            call::exit(102);
        }
    }
}

fn fill_and_verify_pages(base: usize, pages: usize, seed: u8, tag: &str) {
    log("[test_mem] fill_and_verify ");
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
    for p in 0..pages {
        let page_off = p * PAGE_SIZE;
        let a = seed.wrapping_add((p as u8).wrapping_mul(3));
        let b = seed.wrapping_add((p as u8).wrapping_mul(7)).wrapping_add(1);
        let c = seed.wrapping_add((p as u8).wrapping_mul(11)).wrapping_add(2);

        buf[page_off] = a;
        buf[page_off + 17] = b;
        buf[page_off + PAGE_SIZE - 1] = c;
    }

    for p in 0..pages {
        let page_off = p * PAGE_SIZE;
        let a = seed.wrapping_add((p as u8).wrapping_mul(3));
        let b = seed.wrapping_add((p as u8).wrapping_mul(7)).wrapping_add(1);
        let c = seed.wrapping_add((p as u8).wrapping_mul(11)).wrapping_add(2);

        if buf[page_off] != a || buf[page_off + 17] != b || buf[page_off + PAGE_SIZE - 1] != c {
            log_err("[test_mem] verify failed at page ");
            log_u64(p as u64);
            log_err(" in ");
            log_err(tag);
            log_err("\n");
            call::exit(103);
        }
    }

    log("[test_mem] verify OK for ");
    log(tag);
    log("\n");
}

fn single_roundtrip(case_name: &str, pages: usize, seed: u8) {
    section(case_name);
    let base = query_brk();
    let target = base + pages * PAGE_SIZE;

    log("[test_mem] base brk     = ");
    log_hex_u64(base as u64);
    log("\n[test_mem] target brk   = ");
    log_hex_u64(target as u64);
    log("\n[test_mem] grow pages   = ");
    log_u64(pages as u64);
    log("\n");

    let after_grow = set_brk(target, case_name);
    log("[test_mem] after grow   = ");
    log_hex_u64(after_grow as u64);
    log("\n");
    if after_grow < target {
        log_err("[test_mem] ERROR: brk grow returned too small value\n");
        call::exit(104);
    }

    fill_and_verify_pages(base, pages, seed, case_name);

    let after_shrink = set_brk(base, case_name);
    log("[test_mem] after shrink = ");
    log_hex_u64(after_shrink as u64);
    log("\n");
    if after_shrink > base {
        log_err("[test_mem] ERROR: brk shrink did not return near base\n");
        call::exit(105);
    }
}

fn saw_tooth_stress() {
    section("Saw-tooth stress (split/coalesce pressure)");
    let base = query_brk();
    log("[test_mem] initial base = ");
    log_hex_u64(base as u64);
    log("\n");

    let mut pages = 1usize;
    for step in 0..18usize {
        let target = base + pages * PAGE_SIZE;
        log("[test_mem] step ");
        log_u64(step as u64);
        log(": grow to ");
        log_u64(pages as u64);
        log(" pages -> ");
        log_hex_u64(target as u64);
        log("\n");
        let _ = set_brk(target, "saw_tooth_grow");
        fill_and_verify_pages(base, pages, (0x40u8).wrapping_add(step as u8), "saw_tooth");

        let back_pages = pages / 2;
        let back_target = base + back_pages * PAGE_SIZE;
        log("[test_mem] step ");
        log_u64(step as u64);
        log(": shrink to ");
        log_u64(back_pages as u64);
        log(" pages -> ");
        log_hex_u64(back_target as u64);
        log("\n");
        let _ = set_brk(back_target, "saw_tooth_shrink");

        pages = if pages >= 64 { 1 } else { pages * 2 };
        let _ = call::sched_yield();
    }

    let final_brk = set_brk(base, "saw_tooth_final");
    log("[test_mem] final brk = ");
    log_hex_u64(final_brk as u64);
    log("\n");
}

fn churn_many_small_ops() {
    section("Many small grow/shrink cycles");
    let base = query_brk();
    for i in 0..80usize {
        let pages = 1 + (i % 7);
        let target = base + pages * PAGE_SIZE;
        let _ = set_brk(target, "churn_grow");
        fill_and_verify_pages(base, pages, (0x90u8).wrapping_add(i as u8), "churn");
        let _ = set_brk(base, "churn_shrink");
        if i % 10 == 0 {
            log("[test_mem] churn checkpoint i=");
            log_u64(i as u64);
            log("\n");
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    log_err("[test_mem] PANIC\n");
    call::exit(200)
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    section("Strat9 userspace memory stress test (very verbose)");
    log("[test_mem] objectif: valider grow/shrink BRK + accès page par page\n");
    log("[test_mem] ce test est volontairement verbeux\n");

    let pid = call::getpid().unwrap_or(0);
    let tid = call::gettid().unwrap_or(0);
    log("[test_mem] pid=");
    log_u64(pid as u64);
    log(" tid=");
    log_u64(tid as u64);
    log("\n");

    single_roundtrip("Roundtrip 1 page", 1, 0x11);
    single_roundtrip("Roundtrip 2 pages", 2, 0x22);
    single_roundtrip("Roundtrip 4 pages", 4, 0x33);
    single_roundtrip("Roundtrip 8 pages", 8, 0x44);
    single_roundtrip("Roundtrip 16 pages", 16, 0x55);
    single_roundtrip("Roundtrip 32 pages", 32, 0x66);

    saw_tooth_stress();
    churn_many_small_ops();

    section("Completed successfully");
    log_line("[test_mem] exit code = ", 0);
    call::exit(0)
}
