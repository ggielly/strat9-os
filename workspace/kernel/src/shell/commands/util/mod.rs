//! Utility commands: uptime, date, dmesg, audit, echo, env, whoami, grep,
//! setenv, unsetenv, ntpdate, watch
mod audit;
mod date;
mod dmesg;
mod echo;
mod env;
mod grep;
mod ntpdate;
#[cfg(feature = "selftest")]
mod selftest;
mod uptime;
mod watch;
mod whoami;

use crate::{
    shell::{is_interrupted, ShellError},
    shell_println, vfs,
};
use alloc::string::String;
use core::fmt::Write;

pub use audit::cmd_audit;
pub use date::cmd_date;
pub use dmesg::cmd_dmesg;
pub use echo::cmd_echo;
pub use env::{
    cmd_env, cmd_setenv, cmd_unsetenv, init_shell_env, shell_getenv, shell_setenv, shell_unsetenv,
};
pub use grep::cmd_grep;
pub use ntpdate::cmd_ntpdate;
#[cfg(feature = "selftest")]
pub use selftest::create_shell_util_test_task;
pub use uptime::cmd_uptime;
pub use watch::cmd_watch;
pub use whoami::cmd_whoami;

/// Default number of `dmesg` lines to show when no count is given.
const DEFAULT_DMESG_LINES: usize = 50;

/// Parses a positive decimal count argument for `dmesg` / `audit`.
///
/// Returns `None` for anything that is not a plain run of ASCII digits, which
/// is what makes `dmesg xyz` an error instead of a silent `unwrap_or(50)`. `0`
/// parses fine and is rejected by the callers: both commands would otherwise
/// print an empty slice and still report success.
pub(super) fn parse_count(arg: &str) -> Option<usize> {
    if arg.is_empty() || !arg.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    arg.parse().ok()
}

pub(super) fn cmd_uptime_impl(_args: &[String]) -> Result<(), ShellError> {
    let ticks = crate::process::scheduler::ticks();
    let hz = crate::arch::timer::TIMER_HZ.max(1);

    // `task_count` / `silo_count` answer this without the per-task `Arc` clone
    // and the per-silo name+label clone that the snapshot getters perform.
    // `task_count` is `try_lock`-based, so `None` means "scheduler lock was
    // contended", *not* "no tasks": reporting that as `0 tasks` would be a lie.
    let tasks = match crate::process::task_count() {
        Some(n) => alloc::format!("{}", n),
        None => String::from("?"),
    };
    let silos = crate::silo::silo_count();

    shell_println!(
        "up {}  ({} ticks @ {} Hz)  {} tasks, {} silos",
        crate::shell::output::format_uptime(ticks / hz),
        ticks,
        hz,
        tasks,
        silos
    );

    // Perf counters (TSC-based)
    let tsc_khz = crate::arch::boot_timestamp::tsc_khz();
    let stats = crate::process::scheduler::perf_counters::snapshot();
    let mut line = String::from("perf: ");
    for (i, s) in stats.iter().enumerate() {
        if i > 0 {
            line.push_str("  ");
        }
        let _ = write!(line, "{} avg={}us ({})", s.name, s.avg_us(tsc_khz), s.count);
    }
    shell_println!("{}", line);

    Ok(())
}

/// Shows the kernel's diagnostic history.
///
/// The kernel has no separate ring log: `klog_write` was the only writer of the
/// `dmesg` ring and had no callers at all, so this command could only ever
/// print "(kernel log empty)". The audit log is the structured history the
/// kernel actually keeps, so that is what this reports. Free text still goes
/// straight to the serial console via `serial_println!`.
pub(super) fn cmd_dmesg_impl(args: &[String]) -> Result<(), ShellError> {
    let limit = match args.first() {
        None => DEFAULT_DMESG_LINES,
        Some(arg) => match parse_count(arg) {
            Some(n) if n > 0 => n,
            // `dmesg 0` used to print an empty slice and report success, and
            // `dmesg abc` used to fall back to 50 through `unwrap_or`.
            _ => {
                shell_println!("dmesg: invalid count '{}' (want a positive number)", arg);
                return Err(ShellError::InvalidArguments);
            }
        },
    };

    let entries = crate::audit::recent(limit);
    if entries.is_empty() {
        shell_println!("(no kernel events recorded)");
        return Ok(());
    }

    let total = crate::audit::total_count();
    if total > entries.len() as u64 {
        shell_println!("(last {} of {} events)", entries.len(), total);
    }
    shell_println!(
        "{:>6} {:>8} {:>5} {:>5} {:<9} {}",
        "SEQ",
        "TIME",
        "PID",
        "SID",
        "CATEGORY",
        "MESSAGE"
    );
    for e in &entries {
        let (secs, cs) = crate::shell::output::format_ticks(e.tick);
        shell_println!(
            "{:>6} {:>5}.{:02} {:>5} {:>5} {:<9} {}",
            e.seq,
            secs,
            cs,
            e.pid,
            e.silo_id,
            e.category.as_str(),
            e.message
        );
    }
    Ok(())
}

/// Expands the escape sequences `echo -e` recognises.
///
/// The set is deliberately small and fixed: `\\ \n \r \t \0 \e`. Any other
/// `\X` is emitted verbatim (backslash included) so a stray backslash never
/// silently eats a character. Returns `None` when `arg` needs no expansion, so
/// the common case does not allocate.
pub(super) fn expand_escapes(arg: &str) -> Option<String> {
    if !arg.contains('\\') {
        return None;
    }
    let bytes = arg.as_bytes();
    let mut out = String::with_capacity(arg.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' || i + 1 >= bytes.len() {
            // Copy one whole UTF-8 sequence; `arg` is a `&str` so it is valid.
            let ch = arg[i..].chars().next();
            match ch {
                Some(c) => out.push(c),
                None => break,
            }
            i += ch.map_or(bytes.len(), |c| c.len_utf8());
            continue;
        }
        match bytes[i + 1] {
            b'\\' => out.push('\\'),
            b'n' => out.push('\n'),
            b'r' => out.push('\r'),
            b't' => out.push('\t'),
            b'0' => out.push('\0'),
            b'e' => out.push('\x1b'),
            other => {
                out.push('\\');
                out.push(other as char);
            }
        }
        i += 2;
    }
    Some(out)
}

/// `echo [-e] [-n] [text...]`
///
/// The tokenizer has already collapsed runs of whitespace and does not
/// understand quotes, so the caller's spacing is gone before `echo` runs; what
/// is left to do here is join the tokens, honour the two conventional flags and
/// emit the result in a single write.
pub(super) fn cmd_echo_impl(args: &[String]) -> Result<(), ShellError> {
    let mut escapes = false;
    let mut newline = true;
    let mut rest = args;
    // Flags are only recognised while they are still the first argument, so
    // `echo -n` cannot be confused with a literal `-n`.
    while let Some((first, tail)) = rest.split_first() {
        match first.as_str() {
            "-e" => {
                escapes = true;
                rest = tail;
            }
            "-n" => {
                newline = false;
                rest = tail;
            }
            _ => break,
        }
    }

    let mut out = String::new();
    for (i, arg) in rest.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        match expand_escapes(arg) {
            Some(expanded) if escapes => out.push_str(&expanded),
            _ => out.push_str(arg),
        }
    }

    if newline {
        out.push('\n');
    }
    crate::shell_print!("{}", out);
    Ok(())
}

pub(super) fn cmd_whoami_impl(_args: &[String]) -> Result<(), ShellError> {
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

/// Grep flags, parsed from the argument cluster that precedes the pattern.
#[derive(Clone, Copy, Default)]
pub(super) struct GrepOptions {
    /// `-i`: match ASCII letters case-insensitively.
    pub ignore_case: bool,
    /// `-n`: prefix each printed line with its 1-based line number.
    pub line_numbers: bool,
    /// `-v`: print the lines that do *not* match.
    pub invert: bool,
}

/// Parses the leading `-...` cluster of `args`.
///
/// Returns the flags plus the index of the first non-flag argument, or `None`
/// when a flag is not recognised, so `grep -x foo` is a diagnostic instead of a
/// search for the literal string `-x`. `--` ends flag parsing.
pub(super) fn parse_grep_options(args: &[String]) -> Option<(GrepOptions, usize)> {
    let mut opts = GrepOptions::default();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--" {
            i += 1;
            break;
        }
        // Anything that is not a flag ends option parsing.
        let cluster = match arg.strip_prefix('-') {
            Some(c) => c,
            None => break,
        };
        // A bare `-` is not a flag, it is a (useless) pattern.
        if cluster.is_empty() {
            break;
        }
        for flag in cluster.chars() {
            match flag {
                'i' => opts.ignore_case = true,
                'n' => opts.line_numbers = true,
                'v' => opts.invert = true,
                _ => return None,
            }
        }
        i += 1;
    }
    Some((opts, i))
}

/// Byte offset of the first NUL, i.e. the point where `data` stops being text.
///
/// Reported instead of quietly mangling the file; matching still proceeds on
/// the decoded text so a stray NUL does not hide a match.
pub(super) fn first_nul(data: &[u8]) -> Option<usize> {
    data.iter().position(|&b| b == 0)
}

/// Substring test that ignores ASCII case without allocating a lowercase copy.
pub(super) fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() {
        return true;
    }
    if n.len() > h.len() {
        return false;
    }
    h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

/// Feeds each line of `data` to `visit`, decoded lossily, until it returns
/// `false`.
///
/// Splitting *before* decoding is the whole point: the previous code ran
/// `str::from_utf8` over the entire file and replaced the result with `""` as
/// soon as a single byte was invalid, so one stray 0xFF anywhere in a file made
/// `grep` report "(no match)" regardless of what the file actually contained.
/// Decoding per line bounds the damage to the one line that is not UTF-8.
pub(super) fn for_each_line(data: &[u8], mut visit: impl FnMut(&str) -> bool) {
    for raw in data.split(|&b| b == b'\n') {
        let line = match raw.split_last() {
            Some((b'\r', head)) => head,
            _ => raw,
        };
        // `Cow::Borrowed` when the line is already valid UTF-8, so the common
        // case does not allocate at all.
        let decoded = String::from_utf8_lossy(line);
        if !visit(&decoded) {
            return;
        }
    }
}

/// Search for lines matching a pattern in a file or piped input.
///
/// Usage: `grep [-i] [-n] [-v] <pattern> [path]`
///
/// When invoked as the right-hand side of a pipe (`cmd | grep pat`),
/// reads from pipe input instead of a file.
///
/// Exits `Ok(())` only when at least one line was printed. "No match" is
/// reported as `Err(ExecutionFailed)` so `$?` is 1 rather than 0.
pub(super) fn cmd_grep_impl(args: &[String]) -> Result<(), ShellError> {
    let (opts, first) = match parse_grep_options(args) {
        Some(parsed) => parsed,
        None => {
            shell_println!("Usage: grep [-i] [-n] [-v] <pattern> [path]");
            shell_println!("grep: unsupported option in '{}'", args[0]);
            return Err(ShellError::InvalidArguments);
        }
    };
    let pattern = match args.get(first) {
        Some(p) => p.as_str(),
        None => {
            shell_println!("Usage: grep [-i] [-n] [-v] <pattern> [path]");
            return Err(ShellError::InvalidArguments);
        }
    };
    let path = args.get(first + 1).map(|p| p.as_str());

    let (data, label) = if let Some(piped) = crate::shell::output::take_pipe_input() {
        (piped, String::from("(pipe)"))
    } else if let Some(path) = path {
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
        shell_println!("grep: no input (need <path> or a pipe)");
        return Err(ShellError::InvalidArguments);
    };

    if let Some(offset) = first_nul(&data) {
        shell_println!(
            "grep: {} looks binary (NUL at offset {}); matching text only",
            label,
            offset
        );
    }

    let mut printed = 0u32;
    let mut line_no = 0u32;
    let mut cancelled = false;
    for_each_line(&data, |line| {
        if is_interrupted() {
            cancelled = true;
            return false;
        }
        line_no += 1;
        let hit = if opts.ignore_case {
            contains_ignore_case(line, pattern)
        } else {
            line.contains(pattern)
        };
        if hit != opts.invert {
            if opts.line_numbers {
                shell_println!("{}:{}", line_no, line);
            } else {
                shell_println!("{}", line);
            }
            printed += 1;
        }
        true
    });

    if cancelled {
        shell_println!("(grep cancelled after {} matches)", printed);
        // Ctrl+C is a non-success, and swallowing it here would leave `$?` at 0.
        return Err(ShellError::ExecutionFailed);
    }
    if printed == 0 {
        shell_println!("(no match in {})", label);
        return Err(ShellError::ExecutionFailed);
    }
    Ok(())
}
