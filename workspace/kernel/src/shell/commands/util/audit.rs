use super::*;
use alloc::string::String;

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
        let secs = e.tick / hz;
        let cs = (e.tick % hz) * 100 / hz;
        let cat = match e.category {
            crate::audit::AuditCategory::Silo => "silo",
            crate::audit::AuditCategory::Capability => "cap",
            crate::audit::AuditCategory::Syscall => "syscall",
            crate::audit::AuditCategory::Process => "process",
            crate::audit::AuditCategory::Security => "security",
        };
        shell_println!(
            "{:>6} {:>5}.{:02} {:>5} {:>5} {:>10} {}",
            e.seq,
            secs,
            cs,
            e.pid,
            e.silo_id,
            cat,
            e.message
        );
    }
    shell_println!("({} total events since boot)", crate::audit::total_count());
    Ok(())
}
