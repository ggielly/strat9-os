use super::*;

/// Execute a command repeatedly at a given interval.
///
/// Usage: `watch <seconds> <command...>`
///
/// Runs the specified command every N seconds until Ctrl+C.
pub fn cmd_watch(args: &[String]) -> Result<(), ShellError> {
    if args.len() < 2 {
        shell_println!("Usage: watch <seconds> <command...>");
        return Err(ShellError::InvalidArguments);
    }
    let interval_secs: u64 = args[0].parse().map_err(|_| {
        shell_println!("watch: invalid interval '{}'", args[0]);
        ShellError::InvalidArguments
    })?;
    if interval_secs == 0 {
        shell_println!("watch: interval must be >= 1 second");
        return Err(ShellError::InvalidArguments);
    }
    let cmd_line = args[1..].join(" ");
    let hz = crate::arch::x86_64::timer::TIMER_HZ;
    let interval_ticks = interval_secs * hz;

    shell_println!("Every {}s: {}", interval_secs, cmd_line);
    shell_println!("Press Ctrl+C to stop.\n");

    loop {
        if crate::shell::is_interrupted() {
            break;
        }
        if let Some(ch) = crate::arch::x86_64::keyboard::read_char() {
            if ch == 0x03 || ch == b'q' {
                break;
            }
        }

        crate::shell::run_line(&cmd_line);

        let start = crate::process::scheduler::ticks();
        while crate::process::scheduler::ticks() - start < interval_ticks {
            if crate::shell::is_interrupted() {
                return Ok(());
            }
            if let Some(ch) = crate::arch::x86_64::keyboard::read_char() {
                if ch == 0x03 || ch == b'q' {
                    return Ok(());
                }
            }
            crate::process::yield_task();
        }
    }
    Ok(())
}
