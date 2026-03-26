#![no_std]
#![no_main]

use core::panic::PanicInfo;
use strat9_syscall::{
    call,
    data::{HandleInfo, MemoryRegionInfo},
    error::Error,
    number, syscall6,
};

const PAGE_SIZE: usize = 4096;
const REGION_PAGES: usize = 2;
const REGION_LEN: usize = PAGE_SIZE * REGION_PAGES;
const PROT_READ: usize = 1;
const PROT_WRITE: usize = 2;
const MAP_PRIVATE: usize = 1 << 1;
const MAP_ANON: usize = 1 << 5;

struct Ctx {
    pass: u64,
    fail: u64,
}

/// Write a message to a file descriptor.
fn write_fd(fd: usize, msg: &str) {
    let _ = call::write(fd, msg.as_bytes());
}

/// Write to stdout.
fn log(msg: &str) {
    write_fd(1, msg);
}

/// Write to stderr.
fn log_err(msg: &str) {
    write_fd(2, msg);
}

/// Write an unsigned integer in decimal.
fn log_u64(mut value: u64) {
    let mut buf = [0u8; 21];
    if value == 0 {
        log("0");
        return;
    }
    let mut index = buf.len();
    while value > 0 {
        index -= 1;
        buf[index] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    let text = unsafe { core::str::from_utf8_unchecked(&buf[index..]) };
    log(text);
}

/// Write an unsigned integer in hexadecimal.
fn log_hex_u64(mut value: u64) {
    let mut buf = [0u8; 16];
    for index in (0..16).rev() {
        let nibble = (value & 0xF) as u8;
        buf[index] = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
        value >>= 4;
    }
    log("0x");
    let text = unsafe { core::str::from_utf8_unchecked(&buf) };
    log(text);
}

/// Print a section banner.
fn section(title: &str) {
    log("\n============================================================\n");
    log("[test_mem_region] ");
    log(title);
    log("\n============================================================\n");
}

/// Record a successful check.
fn ok(ctx: &mut Ctx, label: &str, value: usize) {
    ctx.pass += 1;
    log("[OK] ");
    log(label);
    log(" -> ");
    log_u64(value as u64);
    log(" (");
    log_hex_u64(value as u64);
    log(")\n");
}

/// Record a failed check.
fn fail(ctx: &mut Ctx, label: &str, err: Error) {
    ctx.fail += 1;
    log_err("[FAIL] ");
    log_err(label);
    log_err(" -> ");
    log_err(err.name());
    log_err("\n");
}

/// Check a syscall result and keep the successful value.
fn check_ok(ctx: &mut Ctx, label: &str, res: core::result::Result<usize, Error>) -> Option<usize> {
    match res {
        Ok(value) => {
            ok(ctx, label, value);
            Some(value)
        }
        Err(err) => {
            fail(ctx, label, err);
            None
        }
    }
}

/// Check that a syscall fails with a specific error.
fn check_expect_err(
    ctx: &mut Ctx,
    label: &str,
    res: core::result::Result<usize, Error>,
    expected: Error,
) {
    match res {
        Ok(value) => {
            ctx.fail += 1;
            log_err("[FAIL] ");
            log_err(label);
            log_err(" -> expected ");
            log_err(expected.name());
            log_err(" got OK=");
            log_u64(value as u64);
            log_err("\n");
        }
        Err(err) => {
            if err == expected {
                ok(ctx, label, 0);
            } else {
                fail(ctx, label, err);
            }
        }
    }
}

/// Print a short memory snapshot for one mapped view.
fn dump_memory_registers(label: &str, addr: usize, len: usize) {
    let slice = unsafe { core::slice::from_raw_parts(addr as *const u8, len) };
    let mid = PAGE_SIZE;
    log("[memreg] ");
    log(label);
    log(" base=");
    log_hex_u64(addr as u64);
    log(" end=");
    log_hex_u64((addr + len) as u64);
    log(" len=");
    log_u64(len as u64);
    log(" samples={");
    log("p0[0]=");
    log_hex_u64(slice[0] as u64);
    log(", p0[17]=");
    log_hex_u64(slice[17] as u64);
    log(", p1[0]=");
    log_hex_u64(slice[mid] as u64);
    log(", p1[127]=");
    log_hex_u64(slice[mid + 127] as u64);
    log(", last=");
    log_hex_u64(slice[len - 1] as u64);
    log("}\n");
}

/// Fill the source region with a deterministic pattern.
fn seed_region(addr: usize) {
    let slice = unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, REGION_LEN) };
    for index in 0..REGION_LEN {
        let page = index / PAGE_SIZE;
        let off = index % PAGE_SIZE;
        slice[index] = (0x20u8)
            .wrapping_add((page as u8).wrapping_mul(0x31))
            .wrapping_add((off as u8).wrapping_mul(3));
    }
}

/// Verify that two mappings expose identical bytes.
fn verify_same_bytes(ctx: &mut Ctx, label: &str, left: usize, right: usize) {
    let lhs = unsafe { core::slice::from_raw_parts(left as *const u8, REGION_LEN) };
    let rhs = unsafe { core::slice::from_raw_parts(right as *const u8, REGION_LEN) };
    for index in 0..REGION_LEN {
        if lhs[index] != rhs[index] {
            ctx.fail += 1;
            log_err("[FAIL] ");
            log_err(label);
            log_err(" -> mismatch at index=");
            log_u64(index as u64);
            log_err(" left=");
            log_hex_u64(lhs[index] as u64);
            log_err(" right=");
            log_hex_u64(rhs[index] as u64);
            log_err("\n");
            return;
        }
    }
    ok(ctx, label, REGION_LEN);
}

/// Verify that a write through one alias is visible through another one.
fn verify_write_propagation(
    ctx: &mut Ctx,
    label: &str,
    writer: usize,
    reader: usize,
    offset: usize,
    value: u8,
) {
    unsafe {
        core::ptr::write_volatile((writer + offset) as *mut u8, value);
    }
    let observed = unsafe { core::ptr::read_volatile((reader + offset) as *const u8) };
    if observed == value {
        ok(ctx, label, observed as usize);
    } else {
        ctx.fail += 1;
        log_err("[FAIL] ");
        log_err(label);
        log_err(" -> expected=");
        log_hex_u64(value as u64);
        log_err(" observed=");
        log_hex_u64(observed as u64);
        log_err(" offset=");
        log_u64(offset as u64);
        log_err("\n");
    }
}

/// Print the metadata returned by handle_info.
fn log_handle_info(label: &str, info: &HandleInfo) {
    log("[handle] ");
    log(label);
    log(" type=");
    log_u64(info.resource_type as u64);
    log(" perms=");
    log_hex_u64(info.permissions as u64);
    log(" resource=");
    log_hex_u64(info.resource);
    log("\n");
}

/// Print the metadata returned by mem_region_info.
fn log_region_info(label: &str, info: &MemoryRegionInfo) {
    log("[region] ");
    log(label);
    log(" size=");
    log_u64(info.size);
    log(" page_size=");
    log_u64(info.page_size);
    log(" flags=");
    log_hex_u64(info.flags as u64);
    log("\n");
}

/// Create the anonymous source mapping used for export tests.
fn map_source_region(ctx: &mut Ctx) -> Option<usize> {
    check_ok(ctx, "mmap anon private RW 2 pages", unsafe {
        syscall6(
            number::SYS_MMAP,
            0,
            REGION_LEN,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANON,
            0,
            0,
        )
    })
}

/// Exercise invalid argument paths that should stay deterministic.
fn test_invalid_inputs(ctx: &mut Ctx, source: usize, handle: usize) {
    section("Invalid inputs");

    check_expect_err(
        ctx,
        "mem_region_export(source + 1)",
        call::mem_region_export(source + 1),
        Error::InvalidArgument,
    );

    let mut addr_out = 0usize;
    check_expect_err(
        ctx,
        "mem_region_map(handle, source + 1)",
        call::mem_region_map(handle, source + 1, &mut addr_out),
        Error::InvalidArgument,
    );

    let mut region_info = MemoryRegionInfo {
        size: 0,
        page_size: 0,
        flags: 0,
        _reserved: 0,
    };
    check_expect_err(
        ctx,
        "mem_region_info(0)",
        call::mem_region_info(0, &mut region_info),
        Error::BadHandle,
    );
}

/// Export the region and validate the returned metadata.
fn test_export_and_metadata(ctx: &mut Ctx, source: usize) -> Option<usize> {
    section("Export and metadata");

    let handle = check_ok(
        ctx,
        "mem_region_export(source)",
        call::mem_region_export(source),
    )?;

    let mut handle_info = HandleInfo {
        resource_type: 0,
        permissions: 0,
        resource: 0,
    };
    if check_ok(
        ctx,
        "handle_info(region)",
        call::handle_info(handle, &mut handle_info),
    )
    .is_some()
    {
        log_handle_info("original", &handle_info);
        if handle_info.resource_type == 1 {
            ok(
                ctx,
                "handle_info.resource_type == MemoryRegion",
                handle_info.resource_type as usize,
            );
        } else {
            ctx.fail += 1;
            log_err("[FAIL] handle_info.resource_type == MemoryRegion -> got ");
            log_u64(handle_info.resource_type as u64);
            log_err("\n");
        }
    }

    let mut region_info = MemoryRegionInfo {
        size: 0,
        page_size: 0,
        flags: 0,
        _reserved: 0,
    };
    if check_ok(
        ctx,
        "mem_region_info(region)",
        call::mem_region_info(handle, &mut region_info),
    )
    .is_some()
    {
        log_region_info("original", &region_info);
        if region_info.size == REGION_LEN as u64 {
            ok(ctx, "region_info.size", region_info.size as usize);
        } else {
            ctx.fail += 1;
            log_err("[FAIL] region_info.size -> got ");
            log_u64(region_info.size);
            log_err("\n");
        }
        if region_info.page_size == PAGE_SIZE as u64 {
            ok(ctx, "region_info.page_size", region_info.page_size as usize);
        } else {
            ctx.fail += 1;
            log_err("[FAIL] region_info.page_size -> got ");
            log_u64(region_info.page_size);
            log_err("\n");
        }
        if region_info.flags & ((PROT_READ | PROT_WRITE) as u32) == (PROT_READ | PROT_WRITE) as u32
        {
            ok(ctx, "region_info.flags has RW", region_info.flags as usize);
        } else {
            ctx.fail += 1;
            log_err("[FAIL] region_info.flags has RW -> got ");
            log_hex_u64(region_info.flags as u64);
            log_err("\n");
        }
    }

    Some(handle)
}

/// Map one handle and verify alias coherence.
fn test_mapping_alias(ctx: &mut Ctx, source: usize, handle: usize, label: &str) -> Option<usize> {
    let mut mapped_addr = 0usize;
    let size = check_ok(
        ctx,
        label,
        call::mem_region_map(handle, 0, &mut mapped_addr),
    )?;
    log("[map] ");
    log(label);
    log(" addr=");
    log_hex_u64(mapped_addr as u64);
    log(" size=");
    log_u64(size as u64);
    log("\n");
    dump_memory_registers("source", source, REGION_LEN);
    dump_memory_registers(label, mapped_addr, REGION_LEN);
    verify_same_bytes(ctx, "alias bytes match source", source, mapped_addr);
    Some(mapped_addr)
}

/// Exercise duplicate and grant lifecycles.
fn test_handle_lifecycle(ctx: &mut Ctx, source: usize, handle: usize, first_alias: usize) {
    section("Handle lifecycle");

    let dup = match check_ok(ctx, "handle_dup(region)", call::handle_dup(handle)) {
        Some(value) => value,
        None => return,
    };

    let mut dup_info = HandleInfo {
        resource_type: 0,
        permissions: 0,
        resource: 0,
    };
    if check_ok(
        ctx,
        "handle_info(dup)",
        call::handle_info(dup, &mut dup_info),
    )
    .is_some()
    {
        log_handle_info("dup", &dup_info);
    }

    let second_alias = match test_mapping_alias(ctx, source, dup, "mem_region_map(dup)") {
        Some(value) => value,
        None => return,
    };

    verify_write_propagation(
        ctx,
        "write alias1 -> source",
        first_alias,
        source,
        PAGE_SIZE + 73,
        0xD5,
    );
    verify_write_propagation(
        ctx,
        "write source -> alias2",
        source,
        second_alias,
        91,
        0x6B,
    );

    let self_pid = call::getpid().unwrap_or(0);
    let granted = match check_ok(
        ctx,
        "handle_grant(region, self)",
        call::handle_grant(handle, self_pid),
    ) {
        Some(value) => value,
        None => {
            let _ = check_ok(ctx, "handle_close(dup)", call::handle_close(dup));
            return;
        }
    };

    let third_alias = match test_mapping_alias(ctx, source, granted, "mem_region_map(granted)") {
        Some(value) => value,
        None => {
            let _ = check_ok(ctx, "handle_close(dup)", call::handle_close(dup));
            let _ = check_ok(ctx, "handle_revoke(granted)", call::handle_revoke(granted));
            return;
        }
    };

    verify_write_propagation(
        ctx,
        "write alias3 -> alias2",
        third_alias,
        second_alias,
        PAGE_SIZE * 2 - 1,
        0xA7,
    );

    let _ = check_ok(ctx, "handle_revoke(granted)", call::handle_revoke(granted));
    let mut granted_info = HandleInfo {
        resource_type: 0,
        permissions: 0,
        resource: 0,
    };
    check_expect_err(
        ctx,
        "handle_info(granted after revoke)",
        call::handle_info(granted, &mut granted_info),
        Error::BadHandle,
    );

    verify_write_propagation(
        ctx,
        "write alias2 after grant revoke -> source",
        second_alias,
        source,
        PAGE_SIZE + 255,
        0x3C,
    );

    let _ = check_ok(ctx, "handle_close(dup)", call::handle_close(dup));
    check_expect_err(
        ctx,
        "handle_info(dup after close)",
        call::handle_info(dup, &mut dup_info),
        Error::BadHandle,
    );
}

/// Run the full MemoryRegion coverage suite.
fn run_suite(ctx: &mut Ctx) {
    section("MemoryRegion public capability suite");
    log("[test_mem_region] exhaustive single-process mapping validation\n");
    log("[test_mem_region] this binary is intended for manual Chevron execution\n");

    let pid = call::getpid().unwrap_or(0);
    let tid = call::gettid().unwrap_or(0);
    log("[test_mem_region] pid=");
    log_u64(pid as u64);
    log(" tid=");
    log_u64(tid as u64);
    log(" page_size=");
    log_u64(PAGE_SIZE as u64);
    log(" region_len=");
    log_u64(REGION_LEN as u64);
    log("\n");

    let source = match map_source_region(ctx) {
        Some(value) => value,
        None => return,
    };
    seed_region(source);
    dump_memory_registers("source-seeded", source, REGION_LEN);

    let handle = match test_export_and_metadata(ctx, source) {
        Some(value) => value,
        None => return,
    };

    test_invalid_inputs(ctx, source, handle);

    let first_alias = match test_mapping_alias(ctx, source, handle, "mem_region_map(original)") {
        Some(value) => value,
        None => return,
    };

    verify_write_propagation(ctx, "write source -> alias1", source, first_alias, 17, 0xE1);
    verify_write_propagation(
        ctx,
        "write alias1 -> source",
        first_alias,
        source,
        PAGE_SIZE + 17,
        0x4D,
    );

    test_handle_lifecycle(ctx, source, handle, first_alias);

    let _ = check_ok(ctx, "handle_close(original)", call::handle_close(handle));
    let mut handle_info = HandleInfo {
        resource_type: 0,
        permissions: 0,
        resource: 0,
    };
    check_expect_err(
        ctx,
        "handle_info(original after close)",
        call::handle_info(handle, &mut handle_info),
        Error::BadHandle,
    );
}

#[panic_handler]
/// Abort the process on panic.
fn panic(_info: &PanicInfo) -> ! {
    log_err("[test_mem_region] PANIC\n");
    call::exit(250)
}

#[no_mangle]
/// Userspace entry point.
pub extern "C" fn _start() -> ! {
    let mut ctx = Ctx { pass: 0, fail: 0 };

    run_suite(&mut ctx);

    section("Summary");
    log("[summary] pass=");
    log_u64(ctx.pass);
    log(" fail=");
    log_u64(ctx.fail);
    log("\n");

    if ctx.fail == 0 {
        call::exit(0);
    } else {
        call::exit(1);
    }
}
