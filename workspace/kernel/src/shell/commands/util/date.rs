use super::*;
use crate::{
    hardware::timer::rtc::RtcDateTime,
    shell::output::{format_epoch_stamp, format_ticks, format_uptime},
};

/// Returns `true` when every field of a CMOS read is in range.
///
/// A CMOS that was never programmed - or a platform whose port I/O is a stub,
/// which is what `arch::io::{inb,outb}` are on riscv64 - reads back as zeroes
/// or 0xFF. `RtcDateTime::to_timestamp` accepts both without complaint and
/// returns an instant that looks believable, so the fields have to be checked
/// before the wall clock is believed. Month 0 or 255 is the giveaway.
pub(super) fn rtc_fields_plausible(dt: &RtcDateTime) -> bool {
    (1..=12).contains(&dt.month)
        && (1..=31).contains(&dt.day)
        && dt.hour <= 23
        && dt.minute <= 59
        && dt.second <= 60 // 60 covers the leap second
        && (2000..=2100).contains(&dt.year)
}

/// Reads the CMOS wall clock, or `None` when there is no usable one.
fn read_wall_clock() -> Option<u64> {
    if !crate::hardware::timer::rtc::is_available() {
        return None;
    }
    let dt = crate::hardware::timer::rtc::get_datetime();
    if !rtc_fields_plausible(&dt) {
        return None;
    }
    Some(dt.to_timestamp())
}

/// Display the current time.
///
/// Usage: `date`
///
/// Prints the real wall clock when the RTC yields a plausible one, and always
/// prints uptime. The two used to be conflated: the old command labelled
/// `ticks / hz` as "Kernel time" and wrapped it with `% 24`, so a machine up
/// for 30 hours reported "06:00:00" as though that were a time of day.
pub fn cmd_date(_args: &[String]) -> Result<(), ShellError> {
    // RTC first, ticks second, so the uptime shown is never older than the
    // wall clock printed above it.
    match read_wall_clock() {
        Some(unix_secs) => shell_println!("{}", format_epoch_stamp(unix_secs)),
        None => shell_println!("(no RTC: CMOS holds no plausible wall clock)"),
    }

    let ticks = crate::process::scheduler::ticks();
    let hz = crate::arch::timer::TIMER_HZ.max(1);
    let (secs, _cs) = format_ticks(ticks);
    shell_println!(
        "up {} since boot  ({} ticks @ {} Hz)",
        format_uptime(secs),
        ticks,
        hz
    );
    Ok(())
}
