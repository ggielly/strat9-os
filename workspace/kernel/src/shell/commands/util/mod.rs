//! Utility commands: uptime, dmesg, echo, env, whoami, grep, setenv, unsetenv
mod audit;
mod date;
mod env;
mod ntpdate;
mod watch;

use crate::{shell::ShellError, shell_println, vfs};
use alloc::string::String;

pub use audit::cmd_audit;
pub use date::cmd_date;
pub use env::{
    cmd_env, cmd_setenv, cmd_unsetenv, init_shell_env, shell_getenv, shell_setenv, shell_unsetenv,
};
pub use ntpdate::cmd_ntpdate;
pub use watch::cmd_watch;

pub fn cmd_uptime(_args: &[String]) -> Result<(), ShellError> {
    let ticks = crate::process::scheduler::ticks();
    let hz = crate::arch::x86_64::timer::TIMER_HZ;
    let total_secs = ticks / hz;
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let secs = total_secs % 60;

    let task_count = crate::process::get_all_tasks()
        .map(|t| t.len())
        .unwrap_or(0);
    let silos = crate::silo::list_silos_snapshot().len();

    shell_println!(
        "up {:02}:{:02}:{:02}  ({} ticks @ {} Hz)  {} tasks, {} silos",
        hours, minutes, secs, ticks, hz, task_count, silos
    );
    Ok(())
}

static KLOG: crate::sync::SpinLock<KernelLogBuffer> =
    crate::sync::SpinLock::new(KernelLogBuffer::new());

const KLOG_CAPACITY: usize = 256;

struct KernelLogBuffer {
    entries: [KlogEntry; KLOG_CAPACITY],
    head: usize,
    count: usize,
}

#[derive(Clone, Copy)]
struct KlogEntry {
    tick: u64,
    len: u8,
    data: [u8; 120],
}

impl KlogEntry {
    const fn empty() -> Self {
        Self { tick: 0, len: 0, data: [0; 120] }
    }
}

impl KernelLogBuffer {
    const fn new() -> Self {
        Self {
            entries: [KlogEntry::empty(); KLOG_CAPACITY],
            head: 0,
            count: 0,
        }
    }

    fn push(&mut self, msg: &str) {
        let tick = crate::process::scheduler::ticks();
        let bytes = msg.as_bytes();
        let copy_len = core::cmp::min(bytes.len(), 120);
        let idx = (self.head + self.count) % KLOG_CAPACITY;
        if self.count < KLOG_CAPACITY {
            self.count += 1;
        } else {
            self.head = (self.head + 1) % KLOG_CAPACITY;
        }
        self.entries[idx].tick = tick;
        self.entries[idx].len = copy_len as u8;
        self.entries[idx].data[..copy_len].copy_from_slice(&bytes[..copy_len]);
    }

    fn iter(&self) -> impl Iterator<Item = &KlogEntry> {
        let h = self.head;
        let c = self.count;
        (0..c).map(move |i| &self.entries[(h + i) % KLOG_CAPACITY])
    }
}

pub fn klog_write(msg: &str) {
    KLOG.lock().push(msg);
}

pub fn cmd_dmesg(args: &[String]) -> Result<(), ShellError> {
    let limit: usize = if !args.is_empty() {
        args[0].parse().unwrap_or(50)
    } else {
        50
    };

    let log = KLOG.lock();
    let entries: alloc::vec::Vec<_> = log.iter().collect();
    let start = if entries.len() > limit { entries.len() - limit } else { 0 };
    let hz = crate::arch::x86_64::timer::TIMER_HZ;

    if entries.is_empty() {
        shell_println!("(kernel log empty)");
        return Ok(());
    }

    for entry in &entries[start..] {
        let secs = entry.tick / hz;
        let cs = (entry.tick % hz) * 100 / hz;
        let text = core::str::from_utf8(&entry.data[..entry.len as usize]).unwrap_or("???");
        shell_println!("[{:>6}.{:02}] {}", secs, cs, text);
    }
    Ok(())
}


pub fn cmd_echo(args: &[String]) -> Result<(), ShellError> {
    let mut first = true;
    for arg in args {
        if !first { crate::shell_print!(" "); }
        crate::shell_print!("{}", arg);
        first = false;
    }
    shell_println!("");
    Ok(())
}


pub fn cmd_whoami(_args: &[String]) -> Result<(), ShellError> {
    if let Some(label) = crate::silo::current_task_silo_label() {
        shell_println!("silo: {}", label);
    } else {
        shell_println!("silo: kernel (no silo context)");
    }

    if let Some(task) = crate::process::current_task_clone() {
        shell_println!("task: {} (pid={}, tid={})", task.name, task.pid, task.tid);
    }

    Ok(())
}


/// Search for lines matching a pattern in a file or piped input.
///
/// Usage: `grep <pattern> [path]`
///
/// When invoked as the right-hand side of a pipe (`cmd | grep pat`),
/// reads from pipe input instead of a file.
pub fn cmd_grep(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: grep <pattern> [path]");
        return Err(ShellError::InvalidArguments);
    }
    let pattern = args[0].as_str();

    let (data, label) = if let Some(piped) = crate::shell::output::take_pipe_input() {
        (piped, String::from("(pipe)"))
    } else if args.len() >= 2 {
        let path = args[1].as_str();
        let fd = vfs::open(path, vfs::OpenFlags::READ).map_err(|_| {
            shell_println!("grep: cannot open '{}'", path);
            ShellError::ExecutionFailed
        })?;
        let d = match vfs::read_all(fd) {
            Ok(d) => d,
            Err(_) => {
                let _ = vfs::close(fd);
                shell_println!("grep: cannot read '{}'", path);
                return Err(ShellError::ExecutionFailed);
            }
        };
        let _ = vfs::close(fd);
        (d, String::from(path))
    } else {
        shell_println!("Usage: grep <pattern> <path>");
        return Err(ShellError::InvalidArguments);
    };

    let text = core::str::from_utf8(&data).unwrap_or("");
    let mut found = 0u32;
    for line in text.split('\n') {
        if line.contains(pattern) {
            shell_println!("{}", line);
            found += 1;
        }
    }
    if found == 0 {
        shell_println!("(no match in {})", label);
    }
    Ok(())
}
