//! Utility commands: uptime, dmesg, echo, env, whoami, grep, setenv, unsetenv
use crate::{shell::ShellError, shell_println, vfs};
use alloc::{collections::BTreeMap, string::String};

static SHELL_ENV: crate::sync::SpinLock<Option<BTreeMap<String, String>>> =
    crate::sync::SpinLock::new(None);

/// Initialize kernel shell environment with default values.
pub fn init_shell_env() {
    let mut map = BTreeMap::new();
    map.insert(String::from("KERNEL"), String::from("strat9"));
    map.insert(String::from("ARCH"), String::from("x86_64"));
    map.insert(String::from("SHELL"), String::from("chevron"));
    map.insert(String::from("HOME"), String::from("/"));
    map.insert(String::from("PATH"), String::from("/initfs/bin"));
    *SHELL_ENV.lock() = Some(map);
}

/// Get a shell environment variable by key.
pub fn shell_getenv(key: &str) -> Option<String> {
    SHELL_ENV
        .lock()
        .as_ref()
        .and_then(|m| m.get(key).cloned())
}

/// Set a shell environment variable.
pub fn shell_setenv(key: &str, val: &str) {
    let mut guard = SHELL_ENV.lock();
    let map = guard.get_or_insert_with(BTreeMap::new);
    map.insert(String::from(key), String::from(val));
}

/// Remove a shell environment variable.
pub fn shell_unsetenv(key: &str) {
    if let Some(map) = SHELL_ENV.lock().as_mut() {
        map.remove(key);
    }
}

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

/// Display recent audit log entries.
///
/// Usage: `audit [count]`  (default: last 30 entries)
pub fn cmd_audit(args: &[String]) -> Result<(), ShellError> {
    let count: usize = if !args.is_empty() {
        args[0].parse().unwrap_or(30)
    } else {
        30
    };

    let entries = crate::audit::recent(count);
    let hz = crate::arch::x86_64::timer::TIMER_HZ;

    if entries.is_empty() {
        shell_println!("(no audit events)");
        return Ok(());
    }

    shell_println!("{:>6} {:>8} {:>5} {:>5} {:>10} {}", "SEQ", "TIME", "PID", "SID", "CATEGORY", "MESSAGE");
    for e in &entries {
        let secs = e.tick / hz;
        let cs = (e.tick % hz) * 100 / hz;
        let cat = match e.category {
            crate::audit::AuditCategory::Silo => "silo",
            crate::audit::AuditCategory::Capability => "cap",
            crate::audit::AuditCategory::Syscall => "syscall",
            crate::audit::AuditCategory::Process => "process",
            crate::audit::AuditCategory::Security => "security",
        };
        shell_println!("{:>6} {:>5}.{:02} {:>5} {:>5} {:>10} {}",
            e.seq, secs, cs, e.pid, e.silo_id, cat, e.message);
    }
    shell_println!("({} total events since boot)", crate::audit::total_count());
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

/// Display all shell environment variables.
pub fn cmd_env(_args: &[String]) -> Result<(), ShellError> {
    if let Some(map) = SHELL_ENV.lock().as_ref() {
        for (k, v) in map.iter() {
            shell_println!("{}={}", k, v);
        }
    }

    let ticks = crate::process::scheduler::ticks();
    let hz = crate::arch::x86_64::timer::TIMER_HZ;
    shell_println!("UPTIME_SECS={}", ticks / hz);
    shell_println!("SILO_COUNT={}", crate::silo::list_silos_snapshot().len());
    shell_println!("MOUNT_COUNT={}", vfs::list_mounts().len());
    Ok(())
}

/// Set a shell environment variable: `setenv KEY=VALUE`.
pub fn cmd_setenv(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: setenv KEY=VALUE");
        return Err(ShellError::InvalidArguments);
    }
    let arg = &args[0];
    if let Some(eq_pos) = arg.find('=') {
        let key = &arg[..eq_pos];
        let val = &arg[eq_pos + 1..];
        shell_setenv(key, val);
    } else {
        shell_setenv(arg, "");
    }
    Ok(())
}

/// Remove a shell environment variable: `unsetenv KEY`.
pub fn cmd_unsetenv(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: unsetenv KEY");
        return Err(ShellError::InvalidArguments);
    }
    shell_unsetenv(&args[0]);
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

/// Display the current kernel time.
///
/// Shows uptime-based time since boot and the nanosecond timestamp
/// from the kernel clock source.
pub fn cmd_date(_args: &[String]) -> Result<(), ShellError> {
    let ns = crate::syscall::time::current_time_ns();
    let secs = ns / 1_000_000_000;
    let hours = (secs / 3600) % 24;
    let minutes = (secs % 3600) / 60;
    let s = secs % 60;
    shell_println!("Kernel time: {:02}:{:02}:{:02} ({}ns since boot)", hours, minutes, s, ns);
    Ok(())
}

/// NTP time synchronization stub.
///
/// Attempts to query an NTP server via `/net/ntp/<server>`. Currently
/// a stub that reports the kernel's internal clock until UDP support
/// is available in the network strate.
pub fn cmd_ntpdate(args: &[String]) -> Result<(), ShellError> {
    let server = args.first().map(|s| s.as_str()).unwrap_or("pool.ntp.org");
    shell_println!("ntpdate: querying {}...", server);

    let path = alloc::format!("/net/ntp/{}", server);
    match vfs::open(&path, vfs::OpenFlags::READ) {
        Ok(fd) => {
            let mut buf = [0u8; 64];
            let n = vfs::read(fd, &mut buf).unwrap_or(0);
            let _ = vfs::close(fd);
            if n > 0 {
                let s = core::str::from_utf8(&buf[..n]).unwrap_or("(invalid)");
                shell_println!("  server time: {}", s.trim());
            } else {
                shell_println!("  no response");
            }
        }
        Err(_) => {
            // TODO: implement when UDP socket support is available
            let ns = crate::syscall::time::current_time_ns();
            shell_println!("  NTP unavailable (no UDP), showing kernel clock:");
            shell_println!("  {}ns since boot", ns);
        }
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
