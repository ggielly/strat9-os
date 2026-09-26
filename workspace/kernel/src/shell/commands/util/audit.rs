use super::*;
use alloc::string::String;

/// Default number of audit entries to show when no count is given.
const DEFAULT_AUDIT_ENTRIES: usize = 30;

/// Display recent audit log entries.
///
/// Usage: `audit [count]`  (default: last 30 entries)
///
/// Exits `Ok(())` on success; a malformed or zero count is `InvalidArguments`,
/// so `$?` distinguishes "the user typed nonsense" from a real failure.
pub fn cmd_audit(args: &[String]) -> Result<(), ShellError> {
    let count = match args.first() {
        None => DEFAULT_AUDIT_ENTRIES,
        Some(arg) => match super::parse_count(arg) {
            Some(n) if n > 0 => n,
            // `audit 0` used to fall through to `recent(0)`, which returns an
            // empty vector, so the command printed "(no audit events)" even when
            // the log was full. `audit abc` silently became 30.
            _ => {
                shell_println!("audit: invalid count '{}' (want a positive number)", arg);
                return Err(ShellError::InvalidArguments);
            }
        },
    };

    let entries = crate::audit::recent(count);
    let hz = crate::arch::timer::TIMER_HZ;

    if entries.is_empty() {
        shell_println!("(no audit events)");
        return Ok(());
    }

    shell_println!(
        "{:>6} {:>8} {:>5} {:>5} {:>10} {}",
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
            "{:>6} {:>5}.{:02} {:>5} {:>5} {:>10} {}",
            e.seq,
            secs,
            cs,
            e.pid,
            e.silo_id,
            e.category.as_str(),
            e.message
        );
    }
    shell_println!("({} total events since boot)", crate::audit::total_count());
    Ok(())
}
