#![no_std]
#![no_main]

use core::panic::PanicInfo;
use strat9_syscall::{call, number};

// ---------------------------------------------------------------------------
// I/O helpers
// ---------------------------------------------------------------------------

fn write_str(msg: &str) {
    let _ = call::write(1, msg.as_bytes());
}

fn write_u64(mut value: u64) {
    let mut buf = [0u8; 21];
    if value == 0 {
        write_str("0");
        return;
    }
    let mut i = buf.len();
    while value > 0 {
        i -= 1;
        buf[i] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    let s = unsafe { core::str::from_utf8_unchecked(&buf[i..]) };
    write_str(s);
}

#[allow(dead_code)]
fn write_hex(mut value: u64) {
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
    write_str("0x");
    let s = unsafe { core::str::from_utf8_unchecked(&buf) };
    write_str(s);
}

// ---------------------------------------------------------------------------
// Line buffer (fixed size, no heap)
// ---------------------------------------------------------------------------

const LINE_BUF_SIZE: usize = 256;

struct LineBuf {
    buf: [u8; LINE_BUF_SIZE],
    len: usize,
}

impl LineBuf {
    const fn new() -> Self {
        LineBuf {
            buf: [0u8; LINE_BUF_SIZE],
            len: 0,
        }
    }

    fn clear(&mut self) {
        self.len = 0;
    }

    fn push(&mut self, b: u8) -> bool {
        if self.len < LINE_BUF_SIZE {
            self.buf[self.len] = b;
            self.len += 1;
            true
        } else {
            false
        }
    }

    fn pop(&mut self) -> bool {
        if self.len > 0 {
            self.len -= 1;
            true
        } else {
            false
        }
    }

    fn as_str(&self) -> &str {
        unsafe { core::str::from_utf8_unchecked(&self.buf[..self.len]) }
    }
}

// ---------------------------------------------------------------------------
// Read one line from stdin (fd 0) with echo
// ---------------------------------------------------------------------------

fn read_line(line: &mut LineBuf) {
    line.clear();
    let mut byte = [0u8; 1];
    loop {
        match call::read(0, &mut byte) {
            Ok(1) => {
                let b = byte[0];
                match b {
                    b'\n' | b'\r' => {
                        write_str("\n");
                        return;
                    }
                    0x7F | 0x08 => {
                        if line.pop() {
                            write_str("\x08 \x08");
                        }
                    }
                    0x20..=0x7E => {
                        if line.push(b) {
                            let _ = call::write(1, &byte);
                        }
                    }
                    _ => {}
                }
            }
            Ok(_) => {
                let _ = call::sched_yield();
            }
            Err(_) => {
                let _ = call::sched_yield();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Command parsing helpers
// ---------------------------------------------------------------------------

fn trim(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut start = 0;
    while start < bytes.len() && bytes[start] == b' ' {
        start += 1;
    }
    let mut end = bytes.len();
    while end > start && bytes[end - 1] == b' ' {
        end -= 1;
    }
    unsafe { core::str::from_utf8_unchecked(&bytes[start..end]) }
}

fn split_first_word(s: &str) -> (&str, &str) {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i] != b' ' {
        i += 1;
    }
    let cmd = unsafe { core::str::from_utf8_unchecked(&bytes[..i]) };
    let mut rest_start = i;
    while rest_start < bytes.len() && bytes[rest_start] == b' ' {
        rest_start += 1;
    }
    let rest = unsafe { core::str::from_utf8_unchecked(&bytes[rest_start..]) };
    (cmd, rest)
}

fn parse_usize(s: &str) -> Option<usize> {
    if s.is_empty() {
        return None;
    }
    let bytes = s.as_bytes();
    let mut value: usize = 0;
    for &b in bytes {
        if b < b'0' || b > b'9' {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((b - b'0') as usize)?;
    }
    Some(value)
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_help() {
    write_str("Available commands:\n");
    write_str("  help              - Show this help\n");
    write_str("  silos             - List known silos\n");
    write_str("  silo-create       - Create a new silo\n");
    write_str("  silo-load <path>  - Load ELF from initfs into a module\n");
    write_str("  silo-attach <silo> <mod> - Attach a module to a silo\n");
    write_str("  silo-start <id>   - Start a silo\n");
    write_str("  silo-stop <id>    - Stop a silo\n");
    write_str("  silo-kill <id>    - Force-kill a silo\n");
    write_str("  mod-load <path>   - Load a module from initfs path\n");
    write_str("  pid               - Show current PID\n");
    write_str("  exit              - Exit console-admin\n");
}

fn cmd_pid() {
    match call::getpid() {
        Ok(pid) => {
            write_str("PID: ");
            write_u64(pid as u64);
            write_str("\n");
        }
        Err(e) => {
            write_str("getpid failed: ");
            write_str(e.name());
            write_str("\n");
        }
    }
}

fn cmd_silo_create() {
    match call::silo_create(0) {
        Ok(handle) => {
            write_str("Silo created, handle=");
            write_u64(handle as u64);
            write_str("\n");
        }
        Err(e) => {
            write_str("silo_create failed: ");
            write_str(e.name());
            write_str("\n");
        }
    }
}

fn cmd_silo_start(args: &str) {
    let id_str = trim(args);
    match parse_usize(id_str) {
        Some(id) => match call::silo_start(id) {
            Ok(_) => {
                write_str("Silo ");
                write_u64(id as u64);
                write_str(" started.\n");
            }
            Err(e) => {
                write_str("silo_start failed: ");
                write_str(e.name());
                write_str("\n");
            }
        },
        None => write_str("Usage: silo-start <handle>\n"),
    }
}

fn cmd_silo_stop(args: &str) {
    let id_str = trim(args);
    match parse_usize(id_str) {
        Some(id) => match call::silo_stop(id) {
            Ok(_) => {
                write_str("Silo ");
                write_u64(id as u64);
                write_str(" stopped.\n");
            }
            Err(e) => {
                write_str("silo_stop failed: ");
                write_str(e.name());
                write_str("\n");
            }
        },
        None => write_str("Usage: silo-stop <handle>\n"),
    }
}

fn cmd_silo_kill(args: &str) {
    let id_str = trim(args);
    match parse_usize(id_str) {
        Some(id) => match call::silo_kill(id) {
            Ok(_) => {
                write_str("Silo ");
                write_u64(id as u64);
                write_str(" killed.\n");
            }
            Err(e) => {
                write_str("silo_kill failed: ");
                write_str(e.name());
                write_str("\n");
            }
        },
        None => write_str("Usage: silo-kill <handle>\n"),
    }
}

/// Load an ELF from initfs into a kernel module (blob mode).
fn cmd_mod_load(args: &str) {
    let path = trim(args);
    if path.is_empty() {
        write_str("Usage: mod-load <initfs-path>\n");
        write_str("  e.g.: mod-load /initfs/strate-fs-ramfs\n");
        return;
    }

    write_str("Opening ");
    write_str(path);
    write_str("...\n");

    let fd = match call::openat(0, path, 0x1, 0) {
        Ok(fd) => fd,
        Err(e) => {
            write_str("open failed: ");
            write_str(e.name());
            write_str("\n");
            return;
        }
    };

    // Read into a static scratch buffer (128KB max).
    // Uses a raw pointer to avoid creating references to the mutable static.
    const SCRATCH_SIZE: usize = 128 * 1024;
    static mut SCRATCH: [u8; SCRATCH_SIZE] = [0u8; SCRATCH_SIZE];
    let scratch_ptr = core::ptr::addr_of_mut!(SCRATCH) as *mut u8;
    let mut total = 0usize;

    loop {
        let remaining = SCRATCH_SIZE - total;
        if remaining == 0 {
            break;
        }
        let chunk_size = if remaining > 4096 { 4096 } else { remaining };
        let chunk = unsafe {
            core::slice::from_raw_parts_mut(scratch_ptr.add(total), chunk_size)
        };
        match call::read(fd as usize, chunk) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) => {
                write_str("read failed: ");
                write_str(e.name());
                write_str("\n");
                let _ = call::close(fd as usize);
                return;
            }
        }
    }
    let _ = call::close(fd as usize);

    write_str("Read ");
    write_u64(total as u64);
    write_str(" bytes. Loading module...\n");

    let result = unsafe {
        strat9_syscall::syscall2(
            number::SYS_MODULE_LOAD,
            scratch_ptr as usize,
            total,
        )
    };

    match result {
        Ok(handle) => {
            write_str("Module loaded, handle=");
            write_u64(handle as u64);
            write_str("\n");
        }
        Err(e) => {
            write_str("module_load failed: ");
            write_str(e.name());
            write_str("\n");
        }
    }
}

/// Load ELF + attach to new silo in one step.
fn cmd_silo_load(args: &str) {
    let path = trim(args);
    if path.is_empty() {
        write_str("Usage: silo-load <initfs-path>\n");
        return;
    }
    // Load the module first
    cmd_mod_load(path);
    // TODO: auto-attach once we store the last module handle
    write_str("Use 'silo-create' + 'silo-attach <silo> <mod>' to wire it up.\n");
}

fn cmd_silo_attach(args: &str) {
    let (silo_str, rest) = split_first_word(args);
    let (mod_str, _) = split_first_word(rest);
    match (parse_usize(silo_str), parse_usize(mod_str)) {
        (Some(silo_id), Some(mod_id)) => {
            match call::silo_attach_module(silo_id, mod_id) {
                Ok(_) => {
                    write_str("Module ");
                    write_u64(mod_id as u64);
                    write_str(" attached to silo ");
                    write_u64(silo_id as u64);
                    write_str(".\n");
                }
                Err(e) => {
                    write_str("silo_attach_module failed: ");
                    write_str(e.name());
                    write_str("\n");
                }
            }
        }
        _ => write_str("Usage: silo-attach <silo-handle> <module-handle>\n"),
    }
}

fn cmd_silos() {
    // TODO: implement silo listing via a query syscall or /proc/silos
    write_str("Silo listing not yet implemented.\n");
    write_str("(Requires a silo_list or silo_query syscall.)\n");
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

fn dispatch(line: &str) {
    let input = trim(line);
    if input.is_empty() {
        return;
    }

    let (cmd, args) = split_first_word(input);

    match cmd {
        "help" | "?" => cmd_help(),
        "pid" => cmd_pid(),
        "silos" | "silo-list" => cmd_silos(),
        "silo-create" => cmd_silo_create(),
        "silo-load" => cmd_silo_load(args),
        "silo-attach" => cmd_silo_attach(args),
        "silo-start" => cmd_silo_start(args),
        "silo-stop" => cmd_silo_stop(args),
        "silo-kill" => cmd_silo_kill(args),
        "mod-load" => cmd_mod_load(args),
        "exit" | "quit" => {
            write_str("Exiting console-admin.\n");
            call::exit(0);
        }
        _ => {
            write_str("Unknown command: ");
            write_str(cmd);
            write_str("\nType 'help' for available commands.\n");
        }
    }
}

fn prompt() {
    write_str("admin> ");
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str("[console-admin] PANIC!\n");
    call::exit(255)
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    write_str("\n");
    write_str("============================================================\n");
    write_str("[console-admin] strat9-os Console Admin Silo\n");
    write_str("[console-admin] Type 'help' for available commands.\n");
    write_str("============================================================\n");

    let mut line = LineBuf::new();
    loop {
        prompt();
        read_line(&mut line);
        dispatch(line.as_str());
    }
}
