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

const MSG_READY: u8 = 0x10;
const MSG_STAGE1_DONE: u8 = 0x11;
const MSG_STAGE2_GO: u8 = 0x12;
const MSG_STAGE2_DONE: u8 = 0x13;

const OFF_CHILD_A: usize = 33;
const OFF_CHILD_B: usize = PAGE_SIZE + 77;
const OFF_PARENT_A: usize = 91;
const OFF_PARENT_B: usize = PAGE_SIZE + 255;
const OFF_CHILD_POST_REVOKE: usize = PAGE_SIZE + 511;

const VAL_CHILD_A: u8 = 0xC3;
const VAL_CHILD_B: u8 = 0xD7;
const VAL_PARENT_A: u8 = 0x5A;
const VAL_PARENT_B: u8 = 0x6E;
const VAL_CHILD_POST_REVOKE: u8 = 0xE9;

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
    log("[test_mem_region_proc] ");
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

/// Close a file descriptor and ignore errors.
fn close_quiet(fd: usize) {
    let _ = call::close(fd);
}

/// Write the full buffer to a file descriptor.
fn write_all(fd: usize, mut buf: &[u8]) -> Result<(), Error> {
    while !buf.is_empty() {
        match call::write(fd, buf) {
            Ok(0) => return Err(Error::Pipe),
            Ok(count) => buf = &buf[count..],
            Err(Error::Interrupted) | Err(Error::Again) => {
                let _ = call::sched_yield();
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// Read the full buffer from a file descriptor.
fn read_exact(fd: usize, mut buf: &mut [u8]) -> Result<(), Error> {
    while !buf.is_empty() {
        match call::read(fd, buf) {
            Ok(0) => return Err(Error::Pipe),
            Ok(count) => {
                let (_, tail) = buf.split_at_mut(count);
                buf = tail;
            }
            Err(Error::Interrupted) | Err(Error::Again) => {
                let _ = call::sched_yield();
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// Send a single control byte through a pipe.
fn send_u8(fd: usize, value: u8) -> Result<(), Error> {
    write_all(fd, &[value])
}

/// Receive a single control byte from a pipe.
fn recv_u8(fd: usize) -> Result<u8, Error> {
    let mut byte = [0u8; 1];
    read_exact(fd, &mut byte)?;
    Ok(byte[0])
}

/// Send a native-endian 64-bit value through a pipe.
fn send_u64(fd: usize, value: u64) -> Result<(), Error> {
    write_all(fd, &value.to_ne_bytes())
}

/// Receive a native-endian 64-bit value from a pipe.
fn recv_u64(fd: usize) -> Result<u64, Error> {
    let mut bytes = [0u8; 8];
    read_exact(fd, &mut bytes)?;
    Ok(u64::from_ne_bytes(bytes))
}

/// Return the deterministic seeded byte for one offset.
fn expected_seed(index: usize) -> u8 {
    let page = index / PAGE_SIZE;
    let off = index % PAGE_SIZE;
    (0x20u8)
        .wrapping_add((page as u8).wrapping_mul(0x31))
        .wrapping_add((off as u8).wrapping_mul(3))
}

/// Fill the region with a deterministic seed.
fn seed_region(addr: usize) {
    let slice = unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, REGION_LEN) };
    for (index, byte) in slice.iter_mut().enumerate() {
        *byte = expected_seed(index);
    }
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

/// Check one byte in the source region.
fn verify_byte(ctx: &mut Ctx, label: &str, addr: usize, offset: usize, expected: u8) {
    let observed = unsafe { core::ptr::read_volatile((addr + offset) as *const u8) };
    if observed == expected {
        ok(ctx, label, observed as usize);
    } else {
        ctx.fail += 1;
        log_err("[FAIL] ");
        log_err(label);
        log_err(" -> expected=");
        log_hex_u64(expected as u64);
        log_err(" observed=");
        log_hex_u64(observed as u64);
        log_err(" offset=");
        log_u64(offset as u64);
        log_err("\n");
    }
}

/// Log handle metadata.
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

/// Log region metadata.
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

/// Exit the child process after logging a failure.
fn child_abort(code: usize, msg: &str) -> ! {
    log_err("[child] ");
    log_err(msg);
    log_err("\n");
    call::exit(code)
}

/// Run the child-side logic of the multi-process test.
fn child_main(parent_to_child_read: usize, child_to_parent_write: usize) -> ! {
    if send_u8(child_to_parent_write, MSG_READY).is_err() {
        child_abort(60, "failed to send ready handshake");
    }

    let granted_handle = match recv_u64(parent_to_child_read) {
        Ok(value) => value as usize,
        Err(_) => child_abort(61, "failed to receive granted handle"),
    };

    let mut handle_info = HandleInfo {
        resource_type: 0,
        permissions: 0,
        resource: 0,
    };
    if call::handle_info(granted_handle, &mut handle_info).is_err() {
        child_abort(62, "handle_info(granted) failed");
    }
    if handle_info.resource_type != 1 {
        child_abort(63, "granted handle is not a MemoryRegion");
    }

    let mut region_info = MemoryRegionInfo {
        size: 0,
        page_size: 0,
        flags: 0,
        _reserved: 0,
    };
    if call::mem_region_info(granted_handle, &mut region_info).is_err() {
        child_abort(64, "mem_region_info(granted) failed");
    }
    if region_info.size != REGION_LEN as u64 || region_info.page_size != PAGE_SIZE as u64 {
        child_abort(65, "unexpected region metadata in child");
    }

    let mut mapped_addr = 0usize;
    if call::mem_region_map(granted_handle, 0, &mut mapped_addr).is_err() {
        child_abort(66, "mem_region_map(granted) failed");
    }

    let child_slice = unsafe { core::slice::from_raw_parts_mut(mapped_addr as *mut u8, REGION_LEN) };
    if child_slice[0] != expected_seed(0)
        || child_slice[17] != expected_seed(17)
        || child_slice[PAGE_SIZE] != expected_seed(PAGE_SIZE)
        || child_slice[PAGE_SIZE + 127] != expected_seed(PAGE_SIZE + 127)
    {
        child_abort(67, "seed validation failed in child mapping");
    }

    child_slice[OFF_CHILD_A] = VAL_CHILD_A;
    child_slice[OFF_CHILD_B] = VAL_CHILD_B;
    if send_u8(child_to_parent_write, MSG_STAGE1_DONE).is_err() {
        child_abort(68, "failed to send stage1 completion");
    }

    match recv_u8(parent_to_child_read) {
        Ok(MSG_STAGE2_GO) => {}
        _ => child_abort(69, "failed to receive stage2 go signal"),
    }

    if child_slice[OFF_PARENT_A] != VAL_PARENT_A || child_slice[OFF_PARENT_B] != VAL_PARENT_B {
        child_abort(70, "parent writes not visible in child mapping");
    }

    if call::handle_revoke(granted_handle).is_err() {
        child_abort(71, "handle_revoke(granted) failed");
    }
    if call::handle_info(granted_handle, &mut handle_info) != Err(Error::BadHandle) {
        child_abort(72, "granted handle still visible after revoke");
    }

    child_slice[OFF_CHILD_POST_REVOKE] = VAL_CHILD_POST_REVOKE;
    if send_u8(child_to_parent_write, MSG_STAGE2_DONE).is_err() {
        child_abort(73, "failed to send stage2 completion");
    }

    call::exit(0)
}

/// Decode a wait status and return the process exit code when it exited normally.
fn wait_exit_code(status: i32) -> Option<i32> {
    if status & 0x7f == 0 {
        Some((status >> 8) & 0xff)
    } else {
        None
    }
}

/// Run the full multi-process MemoryRegion suite.
fn run_suite(ctx: &mut Ctx) {
    section("MemoryRegion cross-process grant/revoke suite");
    log("[test_mem_region_proc] parent grants region to a real child process\n");
    log("[test_mem_region_proc] child maps, writes, revokes handle, then writes again\n");

    let (parent_to_child_read, parent_to_child_write) = match call::pipe() {
        Ok((read_fd, write_fd)) => {
            ok(ctx, "pipe(parent->child)", read_fd as usize);
            (read_fd as usize, write_fd as usize)
        }
        Err(err) => {
            fail(ctx, "pipe(parent->child)", err);
            return;
        }
    };
    let (child_to_parent_read, child_to_parent_write) = match call::pipe() {
        Ok((read_fd, write_fd)) => {
            ok(ctx, "pipe(child->parent)", read_fd as usize);
            (read_fd as usize, write_fd as usize)
        }
        Err(err) => {
            fail(ctx, "pipe(child->parent)", err);
            close_quiet(parent_to_child_read);
            close_quiet(parent_to_child_write);
            return;
        }
    };

    let child_pid = match check_ok(ctx, "fork()", call::fork()) {
        Some(value) => value,
        None => {
            close_quiet(parent_to_child_read);
            close_quiet(parent_to_child_write);
            close_quiet(child_to_parent_read);
            close_quiet(child_to_parent_write);
            return;
        }
    };

    if child_pid == 0 {
        close_quiet(parent_to_child_write);
        close_quiet(child_to_parent_read);
        child_main(parent_to_child_read, child_to_parent_write);
    }

    close_quiet(parent_to_child_read);
    close_quiet(child_to_parent_write);

    match recv_u8(child_to_parent_read) {
        Ok(MSG_READY) => ok(ctx, "child ready handshake", MSG_READY as usize),
        Ok(other) => {
            ctx.fail += 1;
            log_err("[FAIL] child ready handshake -> unexpected byte=");
            log_hex_u64(other as u64);
            log_err("\n");
            return;
        }
        Err(err) => {
            fail(ctx, "child ready handshake", err);
            return;
        }
    }

    let source = match map_source_region(ctx) {
        Some(value) => value,
        None => return,
    };
    seed_region(source);

    let handle = match check_ok(ctx, "mem_region_export(source)", call::mem_region_export(source)) {
        Some(value) => value,
        None => return,
    };

    let mut handle_info = HandleInfo {
        resource_type: 0,
        permissions: 0,
        resource: 0,
    };
    if check_ok(ctx, "handle_info(parent region)", call::handle_info(handle, &mut handle_info)).is_some() {
        log_handle_info("parent-original", &handle_info);
    }

    let mut region_info = MemoryRegionInfo {
        size: 0,
        page_size: 0,
        flags: 0,
        _reserved: 0,
    };
    if check_ok(ctx, "mem_region_info(parent region)", call::mem_region_info(handle, &mut region_info)).is_some() {
        log_region_info("parent-original", &region_info);
    }

    let granted_handle = match check_ok(
        ctx,
        "handle_grant(region, child_pid)",
        call::handle_grant(handle, child_pid),
    ) {
        Some(value) => value,
        None => return,
    };

    if let Some(value) = check_ok(ctx, "send granted handle to child", send_u64(parent_to_child_write, granted_handle as u64).map(|_| 0)) {
        let _ = value;
    } else {
        return;
    }

    match recv_u8(child_to_parent_read) {
        Ok(MSG_STAGE1_DONE) => ok(ctx, "child stage1 completion", MSG_STAGE1_DONE as usize),
        Ok(other) => {
            ctx.fail += 1;
            log_err("[FAIL] child stage1 completion -> unexpected byte=");
            log_hex_u64(other as u64);
            log_err("\n");
            return;
        }
        Err(err) => {
            fail(ctx, "child stage1 completion", err);
            return;
        }
    }

    verify_byte(ctx, "child write A visible in parent", source, OFF_CHILD_A, VAL_CHILD_A);
    verify_byte(ctx, "child write B visible in parent", source, OFF_CHILD_B, VAL_CHILD_B);

    unsafe {
        core::ptr::write_volatile((source + OFF_PARENT_A) as *mut u8, VAL_PARENT_A);
        core::ptr::write_volatile((source + OFF_PARENT_B) as *mut u8, VAL_PARENT_B);
    }
    ok(ctx, "parent wrote reply markers", VAL_PARENT_B as usize);

    if let Some(value) = check_ok(ctx, "send stage2 go", send_u8(parent_to_child_write, MSG_STAGE2_GO).map(|_| 0)) {
        let _ = value;
    } else {
        return;
    }

    match recv_u8(child_to_parent_read) {
        Ok(MSG_STAGE2_DONE) => ok(ctx, "child stage2 completion", MSG_STAGE2_DONE as usize),
        Ok(other) => {
            ctx.fail += 1;
            log_err("[FAIL] child stage2 completion -> unexpected byte=");
            log_hex_u64(other as u64);
            log_err("\n");
            return;
        }
        Err(err) => {
            fail(ctx, "child stage2 completion", err);
            return;
        }
    }

    verify_byte(
        ctx,
        "child post-revoke write visible in parent",
        source,
        OFF_CHILD_POST_REVOKE,
        VAL_CHILD_POST_REVOKE,
    );

    close_quiet(parent_to_child_write);
    close_quiet(child_to_parent_read);

    let mut status = -1i32;
    match check_ok(
        ctx,
        "waitpid(child, blocking)",
        call::waitpid_blocking(child_pid as isize, &mut status),
    ) {
        Some(_) => {
            log("[wait] child raw status=");
            log_u64(status as u64);
            log("\n");
            if wait_exit_code(status) == Some(0) {
                ok(ctx, "child exited with code 0", 0);
            } else {
                ctx.fail += 1;
                log_err("[FAIL] child exited with code 0 -> raw status=");
                log_u64(status as u64);
                log_err("\n");
            }
        }
        None => return,
    }

    let _ = check_ok(ctx, "handle_close(parent region)", call::handle_close(handle));
    check_expect_err(
        ctx,
        "handle_info(parent region after close)",
        call::handle_info(handle, &mut handle_info),
        Error::BadHandle,
    );
}

#[panic_handler]
/// Abort the process on panic.
fn panic(_info: &PanicInfo) -> ! {
    log_err("[test_mem_region_proc] PANIC\n");
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