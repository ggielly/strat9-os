#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::{
    alloc::Layout,
    arch::asm,
    panic::PanicInfo,
    sync::atomic::{AtomicUsize, Ordering},
};
use strat9_syscall::{call, error::Error, number};

alloc_freelist::define_freelist_brk_allocator!(
    pub struct BrkAllocator;
    brk = strat9_syscall::call::brk;
    heap_max = 8 * 1024 * 1024;
);

#[global_allocator]
static ALLOCATOR: BrkAllocator = BrkAllocator;

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    let _ = call::debug_log(b"[silo-test] OOM in rendezlarjan validation\n");
    call::exit(97)
}

static mut COW_SENTINEL: u64 = 0x1122_3344_5566_7788;
static mut COW_MULTI: [u8; 4096 * 4] = [0; 4096 * 4];
static mut THREAD_STACK_A: [u8; 4096 * 2] = [0; 4096 * 2];
static mut THREAD_STACK_B: [u8; 4096 * 2] = [0; 4096 * 2];
static THREAD_STARTED: AtomicUsize = AtomicUsize::new(0);
static THREAD_TID_SLOT_0: AtomicUsize = AtomicUsize::new(0);
static THREAD_TID_SLOT_1: AtomicUsize = AtomicUsize::new(0);

// ---- STEP 13 (rendezlarjan) state ----
static RZ_TID_SLOT: AtomicUsize = AtomicUsize::new(0);
static STRESS_COUNTER: AtomicUsize = AtomicUsize::new(0);
static STRESS_MUTEX: rendezlarjan::sync::Mutex = rendezlarjan::sync::Mutex::new();
const RZ_STRESS_THREADS: usize = 24;
const RZ_STRESS_INCREMENTS: usize = 50;

/// Read and parse `/thread/stats` -> (allocated_total, active).
fn read_thread_stats() -> Option<(usize, usize)> {
    let fd = call::open(
        "/thread/stats",
        strat9_syscall::flag::O_RDONLY,
    )
    .ok()?;
    let mut content = alloc::vec::Vec::new();
    let mut buf = [0u8; 128];
    loop {
        match call::read(fd, &mut buf) {
            Ok(0) => break,
            Ok(n) => content.extend_from_slice(&buf[..n]),
            Err(_) => {
                let _ = call::close(fd);
                return None;
            }
        }
    }
    let _ = call::close(fd);

    let parse_after_label = |label: &[u8]| -> Option<usize> {
        let pos = content
            .windows(label.len())
            .position(|w| w == label)?;
        let rest = &content[pos + label.len()..];
        let end = rest.iter().position(|&b| !b.is_ascii_digit()).unwrap_or(rest.len());
        if end == 0 {
            return None;
        }
        core::str::from_utf8(&rest[..end]).ok()?.parse().ok()
    };
    Some((
        parse_after_label(b"allocated ")?,
        parse_after_label(b"active ")?,
    ))
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ThreadCase {
    slot: usize,
    expected_exit: i32,
    spin_loops: usize,
}

static THREAD_CASE_A: ThreadCase = ThreadCase {
    slot: 0,
    expected_exit: 33,
    spin_loops: 64,
};

static THREAD_CASE_B: ThreadCase = ThreadCase {
    slot: 1,
    expected_exit: 44,
    spin_loops: 128,
};

/// Writes fd.
fn write_fd(fd: usize, msg: &str) {
    let _ = call::write(fd, msg.as_bytes());
}

/// Implements log.
fn log(msg: &str) {
    write_fd(1, msg);
}

/// Implements log err.
fn log_err(msg: &str) {
    write_fd(2, msg);
}

/// Implements log nl.
fn log_nl() {
    log("\n");
}

/// Implements log sep star.
fn log_sep_star() {
    log("************************************************************\n");
}

/// Implements log sep eq.
fn log_sep_eq() {
    log("============================================================\n");
}

/// Implements log section.
fn log_section(title: &str) {
    log_sep_star();
    log("[init-test] ");
    log(title);
    log_nl();
    log_sep_eq();
}

/// Implements log u64.
fn log_u64(mut value: u64) {
    let mut buf = [0u8; 21];
    if value == 0 {
        write_fd(1, "0");
        return;
    }

    let mut i = buf.len();
    while value > 0 {
        i -= 1;
        buf[i] = b'0' + (value % 10) as u8;
        value /= 10;
    }

    let s = unsafe { core::str::from_utf8_unchecked(&buf[i..]) };
    write_fd(1, s);
}

/// Implements log i64.
fn log_i64(value: i64) {
    if value < 0 {
        write_fd(1, "-");
        log_u64(value.unsigned_abs());
    } else {
        log_u64(value as u64);
    }
}

/// Implements log hex u64.
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
    write_fd(1, "0x");
    let s = unsafe { core::str::from_utf8_unchecked(&buf) };
    write_fd(1, s);
}

/// Implements log result.
fn log_result(label: &str, res: core::result::Result<usize, Error>) -> Option<usize> {
    log("[init-test] ");
    log(label);
    log(" => ");
    match res {
        Ok(v) => {
            log("OK value=");
            log_u64(v as u64);
            log(" hex=");
            log_hex_u64(v as u64);
            log_nl();
            Some(v)
        }
        Err(e) => {
            log("ERR ");
            log(e.name());
            log(" (errno=");
            log_u64(e.to_errno() as u64);
            log(")");
            log_nl();
            None
        }
    }
}

/// Implements decode wait status.
fn decode_wait_status(status: i32) {
    let exit_code = ((status >> 8) & 0xff) as u8;
    let signal = (status & 0x7f) as u8;
    log("[init-test] wait status decode: raw=");
    log_i64(status as i64);
    log(" hex=");
    log_hex_u64(status as u32 as u64);
    log(" exit_code=");
    log_u64(exit_code as u64);
    log(" signal=");
    log_u64(signal as u64);
    log_nl();
}

/// Implements raw syscall.
unsafe fn raw_syscall(nr: usize, a1: usize, a2: usize, a3: usize) -> usize {
    let mut ret = nr;
    unsafe {
        asm!(
            "syscall",
            inout("rax") ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Implements log raw ret.
fn log_raw_ret(label: &str, ret: usize) {
    log("[init-test] RAW ");
    log(label);
    log(" => dec=");
    log_u64(ret as u64);
    log(" hex=");
    log_hex_u64(ret as u64);
    if (ret as isize) < 0 {
        log(" signed=");
        log_i64(ret as isize as i64);
        if let Err(e) = Error::demux(ret) {
            log(" err=");
            log(e.name());
        }
    }
    log_nl();
}

/// Implements cow addr.
fn cow_addr() -> u64 {
    core::ptr::addr_of!(COW_SENTINEL) as u64
}

/// Implements cow read.
fn cow_read() -> u64 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(COW_SENTINEL)) }
}

/// Implements cow write.
fn cow_write(value: u64) {
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(COW_SENTINEL), value);
    }
}

/// Implements cow multi addr.
fn cow_multi_addr() -> u64 {
    core::ptr::addr_of!(COW_MULTI) as u64
}

/// Implements cow multi read.
fn cow_multi_read(offset: usize) -> u8 {
    unsafe { core::ptr::read_volatile((core::ptr::addr_of!(COW_MULTI) as *const u8).add(offset)) }
}

/// Implements cow multi write.
fn cow_multi_write(offset: usize, value: u8) {
    unsafe {
        core::ptr::write_volatile(
            (core::ptr::addr_of_mut!(COW_MULTI) as *mut u8).add(offset),
            value,
        );
    }
}

/// Implements log cow multi page snapshot.
fn log_cow_multi_page_snapshot(prefix: &str, page: usize) {
    let base = page * 4096;
    let a = cow_multi_read(base);
    let b = cow_multi_read(base + 17);
    let c = cow_multi_read(base + 4095);
    log(prefix);
    log(" page=");
    log_u64(page as u64);
    log(" first=");
    log_hex_u64(a as u64);
    log(" mid=");
    log_hex_u64(b as u64);
    log(" last=");
    log_hex_u64(c as u64);
    log_nl();
}

/// Implements exit process.
fn exit_process(code: usize) -> ! {
    call::exit(code)
}

/// Implements stack top for.
fn stack_top_for(buf: *mut u8, len: usize) -> usize {
    (buf as usize + len) & !0xFusize
}

/// Implements userspace thread entry.
extern "C" fn userspace_thread_entry(arg0: usize) -> ! {
    let case = unsafe { &*(arg0 as *const ThreadCase) };

    let tid = call::gettid().unwrap_or(0);
    if case.slot == 0 {
        THREAD_TID_SLOT_0.store(tid, Ordering::SeqCst);
    } else {
        THREAD_TID_SLOT_1.store(tid, Ordering::SeqCst);
    }
    THREAD_STARTED.fetch_add(1, Ordering::SeqCst);

    for _ in 0..case.spin_loops {
        let _ = call::sched_yield();
    }

    call::thread_exit(case.expected_exit)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    call::handle_panic("silo-test", info)
}

#[no_mangle]
/// Implements start.
pub extern "C" fn _start() -> ! {
    log_nl();
    log_sep_eq();
    log("[init-test] Strat9 first userspace init/test binary starting\n");
    log("[init-test] Goal: maximal verbosity for PID/FORK/WAIT/COW debugging\n");
    log_sep_eq();

    log_section("STEP 1/11: reading identifiers via high-level wrappers");
    let pid = log_result("getpid()", call::getpid()).unwrap_or(0);
    let ppid = log_result("getppid()", call::getppid()).unwrap_or(0);
    let tid = log_result("gettid()", call::gettid()).unwrap_or(0);
    log("[init-test] summary ids: pid=");
    log_u64(pid as u64);
    log(" ppid=");
    log_u64(ppid as u64);
    log(" tid=");
    log_u64(tid as u64);
    log_nl();

    log_section("STEP 2/11: reading identifiers via raw syscalls for cross-check");
    log_raw_ret("SYS_GETPID", unsafe {
        raw_syscall(number::SYS_GETPID, 0, 0, 0)
    });
    log_raw_ret("SYS_GETPPID", unsafe {
        raw_syscall(number::SYS_GETPPID, 0, 0, 0)
    });
    log_raw_ret("SYS_GETTID", unsafe {
        raw_syscall(number::SYS_GETTID, 0, 0, 0)
    });

    log_section("STEP 3/11: waitpid(-1, WNOHANG) before any fork (expect no child)");
    let mut status_nochild: i32 = -9999;
    log_result(
        "waitpid(-1, &status, WNOHANG)",
        call::waitpid(-1, Some(&mut status_nochild), call::WNOHANG),
    );
    log("[init-test] status buffer after nochild waitpid = ");
    log_i64(status_nochild as i64);
    log_nl();
    let raw_nochild = unsafe {
        raw_syscall(
            number::SYS_PROC_WAITPID,
            (-1isize) as usize,
            (&mut status_nochild as *mut i32) as usize,
            call::WNOHANG,
        )
    };
    log_raw_ret("SYS_PROC_WAITPID(-1, WNOHANG)", raw_nochild);

    log_section("STEP 4/11: forking first child (child should exit 42)");
    let fork_ret = call::fork();
    let child_pid = match fork_ret {
        Ok(v) => v,
        Err(e) => {
            log("[init-test] fork failed errno=");
            log_u64(e.to_errno() as u64);
            log_nl();
            exit_process(10);
        }
    };

    if child_pid == 0 {
        log("[init-test:child1] entered child branch\n");
        log_result("[child1] getpid()", call::getpid());
        log_result("[child1] getppid()", call::getppid());
        log_result("[child1] gettid()", call::gettid());
        log("[init-test:child1] doing sched_yield x2 to exercise scheduler\n");
        let _ = call::sched_yield();
        let _ = call::sched_yield();
        log("[init-test:child1] exiting with code 42\n");
        exit_process(42);
    }

    log("[init-test:parent] fork returned child_pid=");
    log_u64(child_pid as u64);
    log_nl();

    log_section("STEP 5/11: parent waits child1 (poll WNOHANG then blocking wait)");
    let mut child1_status: i32 = -1234;
    for i in 0..5usize {
        log("[init-test:parent] poll iteration ");
        log_u64(i as u64);
        log(": ");
        match call::waitpid(child_pid as isize, Some(&mut child1_status), call::WNOHANG) {
            Ok(0) => {
                log("no exit yet\n");
                let _ = call::sched_yield();
            }
            Ok(pid_done) => {
                log("reaped immediately pid=");
                log_u64(pid_done as u64);
                log_nl();
                decode_wait_status(child1_status);
                break;
            }
            Err(e) => {
                log("poll waitpid error errno=");
                log_u64(e.to_errno() as u64);
                log_nl();
                break;
            }
        }
    }
    let waited = call::waitpid_blocking(child_pid as isize, &mut child1_status);
    if let Some(done) = log_result("waitpid(child1, blocking)", waited) {
        log("[init-test:parent] blocking wait returned pid=");
        log_u64(done as u64);
        log_nl();
    }
    decode_wait_status(child1_status);

    log_section("STEP 6/11: process group/session syscalls (diagnostic only)");
    let _ = log_result("getpgrp()", call::getpgrp());
    let _ = log_result("getpgid(0)", call::getpgid(0));
    let _ = log_result("setpgid(0,0)", call::setpgid(0, 0));
    let _ = log_result("getsid(0)", call::getsid(0));
    let _ = log_result("setsid()", call::setsid());
    let _ = log_result("getsid(0) after setsid", call::getsid(0));

    log_section("STEP 7/12: userspace thread_create/thread_join validation");
    THREAD_STARTED.store(0, Ordering::SeqCst);
    THREAD_TID_SLOT_0.store(0, Ordering::SeqCst);
    THREAD_TID_SLOT_1.store(0, Ordering::SeqCst);

    let thread_entry_ptr = userspace_thread_entry as *const () as usize;
    let invalid_create = call::thread_create(thread_entry_ptr, 0x12345, 0, 0);
    log_result("thread_create(invalid stack align)", invalid_create);
    if !matches!(invalid_create, Err(Error::InvalidArgument)) {
        log("[init-test:thread] ERROR: expected EINVAL for misaligned stack\n");
        exit_process(19);
    }

    let stack_a_top = stack_top_for(
        core::ptr::addr_of_mut!(THREAD_STACK_A) as *mut u8,
        core::mem::size_of::<[u8; 4096 * 2]>(),
    );
    let stack_b_top = stack_top_for(
        core::ptr::addr_of_mut!(THREAD_STACK_B) as *mut u8,
        core::mem::size_of::<[u8; 4096 * 2]>(),
    );

    let arg_a = core::ptr::addr_of!(THREAD_CASE_A) as usize;
    let arg_b = core::ptr::addr_of!(THREAD_CASE_B) as usize;

    let tid_a = if let Some(tid_created) = log_result(
        "thread_create(thread A)",
        call::thread_create(thread_entry_ptr, stack_a_top, arg_a, 0),
    ) {
        tid_created
    } else {
        exit_process(20);
    };

    let tid_b = if let Some(tid_created) = log_result(
        "thread_create(thread B)",
        call::thread_create(thread_entry_ptr, stack_b_top, arg_b, 0),
    ) {
        tid_created
    } else {
        exit_process(21);
    };

    let mut join_status_a: i32 = -1;
    let joined_a = if let Some(joined_tid) = log_result(
        "thread_join(thread A)",
        call::thread_join(tid_a, Some(&mut join_status_a)),
    ) {
        joined_tid
    } else {
        exit_process(22);
    };
    if joined_a != tid_a {
        log("[init-test:thread] ERROR: joined tid mismatch for thread A\n");
        exit_process(23);
    }
    log("[init-test:thread] join status for A=");
    log_i64(join_status_a as i64);
    log_nl();
    if join_status_a != THREAD_CASE_A.expected_exit {
        log("[init-test:thread] ERROR: unexpected join status for thread A\n");
        exit_process(24);
    }

    let mut join_status_b: i32 = -1;
    let joined_b = if let Some(joined_tid) = log_result(
        "thread_join(thread B)",
        call::thread_join(tid_b, Some(&mut join_status_b)),
    ) {
        joined_tid
    } else {
        exit_process(25);
    };
    if joined_b != tid_b {
        log("[init-test:thread] ERROR: joined tid mismatch for thread B\n");
        exit_process(26);
    }
    log("[init-test:thread] join status for B=");
    log_i64(join_status_b as i64);
    log_nl();
    if join_status_b != THREAD_CASE_B.expected_exit {
        log("[init-test:thread] ERROR: unexpected join status for thread B\n");
        exit_process(27);
    }

    let started_count = THREAD_STARTED.load(Ordering::SeqCst);
    log("[init-test:thread] started_count=");
    log_u64(started_count as u64);
    log(" slot0_tid=");
    log_u64(THREAD_TID_SLOT_0.load(Ordering::SeqCst) as u64);
    log(" slot1_tid=");
    log_u64(THREAD_TID_SLOT_1.load(Ordering::SeqCst) as u64);
    log_nl();
    if started_count != 2
        || THREAD_TID_SLOT_0.load(Ordering::SeqCst) == 0
        || THREAD_TID_SLOT_1.load(Ordering::SeqCst) == 0
    {
        log("[init-test:thread] ERROR: not all thread start markers are set\n");
        exit_process(28);
    }

    let self_tid = call::gettid().unwrap_or(0);
    let join_self = call::thread_join(self_tid, None);
    log_result("thread_join(self)", join_self);
    if !matches!(join_self, Err(Error::InvalidArgument)) {
        log("[init-test:thread] ERROR: expected EINVAL for join(self)\n");
        exit_process(29);
    }

    let join_missing = call::thread_join(u32::MAX as usize, None);
    log_result("thread_join(nonexistent tid)", join_missing);
    if !matches!(join_missing, Err(Error::NotFound)) {
        log("[init-test:thread] ERROR: expected ENOENT for missing tid\n");
        exit_process(30);
    }

    let join_twice = call::thread_join(tid_a, None);
    log_result("thread_join(already joined thread A)", join_twice);
    if !matches!(join_twice, Err(Error::NotFound)) {
        log("[init-test:thread] ERROR: expected ENOENT for second join\n");
        exit_process(31);
    }
    log("[init-test:thread] SUCCESS: thread lifecycle + error paths validated\n");

    log_section("STEP 8/12: second fork/wait any-child path (child exits 7)");
    let second = call::fork();
    let child2_pid = match second {
        Ok(v) => v,
        Err(e) => {
            log("[init-test] second fork failed errno=");
            log_u64(e.to_errno() as u64);
            log_nl();
            exit_process(11);
        }
    };
    if child2_pid == 0 {
        log("[init-test:child2] exiting with code 7 immediately\n");
        exit_process(7);
    }
    log("[init-test:parent] second child pid=");
    log_u64(child2_pid as u64);
    log_nl();
    let mut child2_status: i32 = 0;
    let _ = log_result(
        "waitpid(-1, blocking)",
        call::waitpid_blocking(-1, &mut child2_status),
    );
    decode_wait_status(child2_status);

    log_section("STEP 9/12: targeted CoW test (single 64-bit sentinel)");
    let cow_initial = 0x1122_3344_5566_7788u64;
    let cow_child_value = 0xdead_beef_cafe_babeu64;
    let cow_parent_value = 0xa1a2_a3a4_a5a6_a7a8u64;
    cow_write(cow_initial);
    log("[init-test:cow] sentinel address=");
    log_hex_u64(cow_addr());
    log(" initial=");
    log_hex_u64(cow_read());
    log_nl();
    log("[init-test:cow] expected child write value=");
    log_hex_u64(cow_child_value);
    log(" expected parent write value=");
    log_hex_u64(cow_parent_value);
    log_nl();

    let cow_fork = call::fork();
    let cow_child_pid = match cow_fork {
        Ok(v) => v,
        Err(e) => {
            log("[init-test:cow] fork failed errno=");
            log_u64(e.to_errno() as u64);
            log_nl();
            exit_process(12);
        }
    };

    if cow_child_pid == 0 {
        log("[init-test:cow:child] entered child branch\n");
        let child_seen_before = cow_read();
        log("[init-test:cow:child] sentinel before write=");
        log_hex_u64(child_seen_before);
        log_nl();
        if child_seen_before != cow_initial {
            log("[init-test:cow:child] ERROR: unexpected initial sentinel in child\n");
            exit_process(90);
        }

        log("[init-test:cow:child] writing sentinel to child-specific value\n");
        cow_write(cow_child_value);
        let child_seen_after = cow_read();
        log("[init-test:cow:child] sentinel after write=");
        log_hex_u64(child_seen_after);
        log_nl();
        if child_seen_after != cow_child_value {
            log("[init-test:cow:child] ERROR: child write did not stick\n");
            exit_process(91);
        }

        let _ = call::sched_yield();
        let _ = call::sched_yield();
        log("[init-test:cow:child] CoW child path done, exiting code 77\n");
        exit_process(77);
    }

    log("[init-test:cow:parent] child pid=");
    log_u64(cow_child_pid as u64);
    log(" parent sees sentinel pre-wait=");
    log_hex_u64(cow_read());
    log_nl();

    let mut cow_status: i32 = -1;
    let waited_cow = call::waitpid_blocking(cow_child_pid as isize, &mut cow_status);
    let waited_cow_pid =
        if let Some(done) = log_result("[cow-parent] waitpid(cow-child, blocking)", waited_cow) {
            done
        } else {
            exit_process(13);
        };
    log("[init-test:cow:parent] wait returned pid=");
    log_u64(waited_cow_pid as u64);
    log_nl();
    decode_wait_status(cow_status);

    let cow_after_child_exit = cow_read();
    log("[init-test:cow:parent] sentinel post-child-exit=");
    log_hex_u64(cow_after_child_exit);
    log_nl();
    if cow_after_child_exit != cow_initial {
        log("[init-test:cow:parent] ERROR: parent observed child write (CoW broken)\n");
        exit_process(14);
    }

    log("[init-test:cow:parent] writing parent-specific value\n");
    cow_write(cow_parent_value);
    let cow_after_parent_write = cow_read();
    log("[init-test:cow:parent] sentinel after parent write=");
    log_hex_u64(cow_after_parent_write);
    log_nl();
    if cow_after_parent_write != cow_parent_value {
        log("[init-test:cow:parent] ERROR: parent write did not stick\n");
        exit_process(15);
    }
    log("[init-test:cow] SUCCESS: CoW isolation validated for parent/child writes\n");

    log_section("STEP 10/12: targeted CoW multi-page test (4 pages)");
    log("[init-test:cow4k] buffer address=");
    log_hex_u64(cow_multi_addr());
    log(" size=");
    log_u64((4096 * 4) as u64);
    log_nl();

    for page in 0..4usize {
        let base = page * 4096;
        cow_multi_write(base, (0x10 + page as u8));
        cow_multi_write(base + 17, (0x40 + page as u8));
        cow_multi_write(base + 4095, (0x70 + page as u8));
        log_cow_multi_page_snapshot("[init-test:cow4k:parent:init]", page);
    }

    let cow_multi_fork = call::fork();
    let cow_multi_child_pid = match cow_multi_fork {
        Ok(v) => v,
        Err(e) => {
            log("[init-test:cow4k] fork failed errno=");
            log_u64(e.to_errno() as u64);
            log_nl();
            exit_process(16);
        }
    };

    if cow_multi_child_pid == 0 {
        log_sep_star();
        log("[init-test:cow4k:child] validating inherited page fingerprints\n");
        for page in 0..4usize {
            log_cow_multi_page_snapshot("[init-test:cow4k:child:before]", page);
        }
        log("[init-test:cow4k:child] mutating all 4 pages with child-only fingerprints\n");
        for page in 0..4usize {
            let base = page * 4096;
            cow_multi_write(base, (0x91 + page as u8));
            cow_multi_write(base + 17, (0xA1 + page as u8));
            cow_multi_write(base + 4095, (0xB1 + page as u8));
            log_cow_multi_page_snapshot("[init-test:cow4k:child:after]", page);
        }
        log("[init-test:cow4k:child] exiting code 88\n");
        exit_process(88);
    }

    log("[init-test:cow4k:parent] child pid=");
    log_u64(cow_multi_child_pid as u64);
    log_nl();
    let mut cow_multi_status: i32 = -1;
    let mut waited_multi_ok = false;
    for attempt in 0..2000usize {
        let waited_multi = call::waitpid(
            cow_multi_child_pid as isize,
            Some(&mut cow_multi_status),
            call::WNOHANG,
        );
        match waited_multi {
            Ok(0) => {
                if attempt % 100 == 0 {
                    log("[init-test:cow4k:parent] waitpid WNOHANG: child still running, attempt=");
                    log_u64(attempt as u64);
                    log_nl();
                }
                let _ = call::sched_yield();
            }
            Ok(pid_done) => {
                log_result("[cow4k-parent] waitpid(cow4k-child, WNOHANG)", Ok(pid_done));
                waited_multi_ok = true;
                break;
            }
            Err(Error::Interrupted) => {
                log("[init-test:cow4k:parent] waitpid interrupted (EINTR), retry attempt=");
                log_u64((attempt + 1) as u64);
                log_nl();
                let _ = call::sched_yield();
            }
            Err(e) => {
                log_result("[cow4k-parent] waitpid(cow4k-child, WNOHANG)", Err(e));
                break;
            }
        }
    }
    if !waited_multi_ok {
        log("[init-test:cow4k:parent] ERROR: waitpid timeout after retries\n");
        exit_process(17);
    }
    decode_wait_status(cow_multi_status);

    log("[init-test:cow4k:parent] verifying parent view unchanged after child writes\n");
    for page in 0..4usize {
        let base = page * 4096;
        let v0 = cow_multi_read(base);
        let v1 = cow_multi_read(base + 17);
        let v2 = cow_multi_read(base + 4095);
        if v0 != (0x10 + page as u8) || v1 != (0x40 + page as u8) || v2 != (0x70 + page as u8) {
            log("[init-test:cow4k:parent] ERROR: parent observed child mutation page=");
            log_u64(page as u64);
            log_nl();
            exit_process(18);
        }
        log_cow_multi_page_snapshot("[init-test:cow4k:parent:verified]", page);
    }

    log("[init-test:cow4k:parent] now writing parent-only fingerprints\n");
    for page in 0..4usize {
        let base = page * 4096;
        cow_multi_write(base, (0x21 + page as u8));
        cow_multi_write(base + 17, (0x31 + page as u8));
        cow_multi_write(base + 4095, (0x41 + page as u8));
        log_cow_multi_page_snapshot("[init-test:cow4k:parent:after]", page);
    }
    log("[init-test:cow4k] SUCCESS: 4-page CoW isolation validated\n");

    log_section("STEP 11/12: raw syscall sanity check for waitpid on no child again");
    let mut st: i32 = 0;
    let raw = unsafe {
        raw_syscall(
            number::SYS_PROC_WAITPID,
            (-1isize) as usize,
            (&mut st as *mut i32) as usize,
            0,
        )
    };
    log_raw_ret("SYS_PROC_WAITPID(-1, blocking)", raw);
    log("[init-test] status buffer=");
    log_i64(st as i64);
    log_nl();

    log_section("STEP 13: rendezlarjan (/thread scheme) cross-validation");

    // ---- 13a. spawn/join + TID coherence (rendezlarjan vs raw gettid) ----
    RZ_TID_SLOT.store(0, Ordering::SeqCst);
    let spawned = rendezlarjan::Thread::spawn(|| {
        let rz_tid = rendezlarjan::thread_current();
        let raw_tid = call::gettid().unwrap_or(0) as u32;
        if rz_tid != raw_tid {
            RZ_TID_SLOT.store(usize::MAX, Ordering::SeqCst);
        } else {
            RZ_TID_SLOT.store(raw_tid as usize, Ordering::SeqCst);
        }
        // Non-zero exit path through the level-1 API.
        rendezlarjan::thread_exit(55)
    });
    let t_coherence = match spawned {
        Ok(t) => t,
        Err(e) => {
            log("[init-test:rz] ERROR: Thread::spawn failed errno=");
            log_u64(e.to_errno() as u64);
            log_nl();
            exit_process(60);
        }
    };
    let coherence_handle_tid = t_coherence.tid();
    match t_coherence.join() {
        Ok(code) if code == 55 => {}
        other => {
            log("[init-test:rz] ERROR: join exit code mismatch (want 55)\n");
            if let Err(e) = other {
                log_u64(e.to_errno() as u64);
            }
            log_nl();
            exit_process(61);
        }
    }
    let coherence_seen = RZ_TID_SLOT.load(Ordering::SeqCst);
    if coherence_seen == usize::MAX
        || coherence_seen == 0
        || coherence_seen != coherence_handle_tid as usize
    {
        log("[init-test:rz] ERROR: TID incoherent between lib/raw/handle\n");
        exit_process(62);
    }
    log("[init-test:rz] OK spawn/join coherent tid=");
    log_u64(coherence_handle_tid as u64);
    log_nl();

    // ---- 13b. Mutex stress: N threads x K increments under rendezlarjan sync ----
    STRESS_COUNTER.store(0, Ordering::SeqCst);
    let mut stress_handles = alloc::vec::Vec::new();
    for _ in 0..RZ_STRESS_THREADS {
        match rendezlarjan::Thread::spawn(|| {
            for _ in 0..RZ_STRESS_INCREMENTS {
                STRESS_MUTEX.lock();
                let v = STRESS_COUNTER.load(Ordering::Relaxed);
                STRESS_COUNTER.store(v.wrapping_add(RZ_STRESS_THREADS), Ordering::Relaxed);
                STRESS_MUTEX.unlock();
                rendezlarjan::thread_yield();
            }
        }) {
            Ok(h) => stress_handles.push(h),
            Err(e) => {
                log("[init-test:rz] ERROR: stress spawn failed errno=");
                log_u64(e.to_errno() as u64);
                log_nl();
                exit_process(63);
            }
        }
    }
    for h in stress_handles {
        if let Err(e) = h.join() {
            log("[init-test:rz] ERROR: stress join failed errno=");
            log_u64(e.to_errno() as u64);
            log_nl();
            exit_process(64);
        }
    }
    let stress_total =
        (RZ_STRESS_THREADS * RZ_STRESS_INCREMENTS * RZ_STRESS_THREADS) as usize;
    let stress_seen = STRESS_COUNTER.load(Ordering::SeqCst);
    if stress_seen != stress_total {
        log("[init-test:rz] ERROR: mutex stress lost updates want=");
        log_u64(stress_total as u64);
        log(" got=");
        log_u64(stress_seen as u64);
        log_nl();
        exit_process(65);
    }
    log("[init-test:rz] OK mutex stress sum=");
    log_u64(stress_seen as u64);
    log_nl();

    // ---- 13c. self-join via join(current()) must be EINVAL ----
    let self_join = rendezlarjan::thread_join(rendezlarjan::thread_current());
    match self_join {
        Err(Error::InvalidArgument) => {}
        other => {
            log("[init-test:rz] ERROR: expected EINVAL for self-join\n");
            if let Err(e) = other {
                log_u64(e.to_errno() as u64);
            }
            log_nl();
            exit_process(66);
        }
    }
    log("[init-test:rz] OK self-join EINVAL\n");

    // ---- 13d. thread_list includes current thread ----
    match rendezlarjan::thread_list() {
        Ok(list) => {
            let me = rendezlarjan::thread_current();
            if !list.iter().any(|info| info.tid == me) {
                log("[init-test:rz] ERROR: thread_list missing current tid\n");
                exit_process(67);
            }
            log("[init-test:rz] OK thread_list count=");
            log_u64(list.len() as u64);
            log_nl();
        }
        Err(e) => {
            log("[init-test:rz] ERROR: thread_list failed errno=");
            log_u64(e.to_errno() as u64);
            log_nl();
            exit_process(67);
        }
    }

    // ---- 13e. detach 50 threads -> kernel-owned stack counters stable ----
    let baseline = match read_thread_stats() {
        Some(s) => s,
        None => {
            log("[init-test:rz] ERROR: cannot read /thread/stats baseline\n");
            exit_process(68);
        }
    };
    for i in 0..50u32 {
        match rendezlarjan::Thread::spawn(move || {
            for _ in 0..(16 + (i % 7)) {
                rendezlarjan::thread_yield();
            }
        }) {
            Ok(h) => h.detach(),
            Err(e) => {
                log("[init-test:rz] ERROR: detach spawn failed errno=");
                log_u64(e.to_errno() as u64);
                log_nl();
                exit_process(69);
            }
        }
    }
    let mut leak_ok = false;
    for _ in 0..5000usize {
        if let Some((_, active)) = read_thread_stats() {
            if active == baseline.1 {
                leak_ok = true;
                break;
            }
        }
        let _ = call::sched_yield();
    }
    let final_stats = read_thread_stats().unwrap_or(baseline);
    log("[init-test:rz] stacks allocated=");
    log_u64(final_stats.0 as u64);
    log(" active=");
    log_u64(final_stats.1 as u64);
    log(" baseline_active=");
    log_u64(baseline.1 as u64);
    log_nl();
    if !leak_ok || final_stats.0 < baseline.0 + 50 {
        log("[init-test:rz] ERROR: kernel-owned user stack leak suspected\n");
        exit_process(70);
    }
    log("[init-test:rz] OK zero-leak proof (active back to baseline after 50 detaches)\n");

    // ---- 13f. kill EPERM across processes (fork + pipe coordination) ----
    let pipe_fds = call::pipe();
    let child_kill = call::fork();
    let kill_child_pid = match (pipe_fds, child_kill) {
        (Ok((rd, wr)), Ok(child_pid)) => {
            if child_pid == 0 {
                // Child: spawn a long-spinning thread, publish its tid.
                let _ = call::close(rd as usize);
                let target = rendezlarjan::Thread::spawn(|| {
                    for _ in 0..200_000usize {
                        let _ = call::sched_yield();
                    }
                });
                let tid = target.as_ref().map(|t| t.tid()).unwrap_or(u32::MAX);
                let _ = call::write(wr as usize, &tid.to_le_bytes());
                // Join it back (same-process kill not exercised here; the
                // thread simply finishes spinning).
                if let Ok(t) = target {
                    let _ = t.join();
                }
                log("[init-test:rz:kill-child] done, exiting 5\n");
                exit_process(5);
            }
            let _ = call::close(wr as usize);
            (rd, child_pid)
        }
        _ => {
            log("[init-test:rz] ERROR: pipe/fork for kill test failed\n");
            exit_process(71);
        }
    };
    let mut kill_target_buf = [0u8; 4];
    let mut kill_target_tid: u32 = 0;
    loop {
        match call::read(kill_child_pid.0 as usize, &mut kill_target_buf) {
            Ok(4) => {
                kill_target_tid = u32::from_le_bytes(kill_target_buf);
                break;
            }
            Ok(_) => continue,
            Err(Error::Interrupted) => continue,
            Err(_) => break,
        }
    }
    let cross_kill = rendezlarjan::thread_kill(kill_target_tid);
    match cross_kill {
        Err(Error::PermissionDenied) => {
            log("[init-test:rz] OK cross-process kill rejected with EPERM\n");
        }
        other => {
            log("[init-test:rz] ERROR: expected EPERM for cross-process kill\n");
            if let Err(e) = other {
                log("errno=");
                log_u64(e.to_errno() as u64);
                log_nl();
            }
            exit_process(72);
        }
    }
    let mut kill_child_status: i32 = -1;
    if call::waitpid_blocking(kill_child_pid.1 as isize, &mut kill_child_status).is_err() {
        log("[init-test:rz] ERROR: waitpid on kill-test child failed\n");
        exit_process(73);
    }
    decode_wait_status(kill_child_status);
    let _ = call::close(kill_child_pid.0 as usize);

    // ---- 13g. same-process kill terminates the target thread ----
    let victim = match rendezlarjan::Thread::spawn(|| {
        #[allow(clippy::empty_loop)]
        loop {
            core::hint::spin_loop();
        }
    }) {
        Ok(t) => t,
        Err(e) => {
            log("[init-test:rz] ERROR: victim spawn failed errno=");
            log_u64(e.to_errno() as u64);
            log_nl();
            exit_process(74);
        }
    };
    let victim_tid = victim.tid();
    match rendezlarjan::thread_kill(victim_tid) {
        Ok(()) => log("[init-test:rz] OK same-process kill accepted\n"),
        Err(e) => {
            log("[init-test:rz] ERROR: same-process kill failed errno=");
            log_u64(e.to_errno() as u64);
            log_nl();
            exit_process(75);
        }
    }

    log_section("STEP 12/12: completed. exiting init-test with code 0");
    log_sep_eq();
    exit_process(0)
}
