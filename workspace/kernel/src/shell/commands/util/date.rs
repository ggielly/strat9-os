use super::*;

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
    shell_println!(
        "Kernel time: {:02}:{:02}:{:02} ({}ns since boot)",
        hours,
        minutes,
        s,
        ns
    );
    Ok(())
}
