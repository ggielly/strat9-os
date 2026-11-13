/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! Pure calendar and BCD arithmetic shared by the RTC implementations.
//!
//! Two very different components need the same arithmetic: the **host** CMOS
//! driver ([`crate::hardware::timer::rtc`]), which reads the real MC146818 and
//! converts its registers to and from UNIX time, and the **s9vm guest RTC
//! device model** ([`crate::s9vm::rtc`]), which does the opposite : it computes
//! the register values a guest reads from an emulated chip. Keeping one copy of
//! the Howard Hinnant civil-date algorithm and of the BCD conversions in a
//! neutral, dependency-free module guarantees the two cannot disagree about
//! leap years, month lengths or digit packing.
//!
//! Everything here is pure `core` code with no I/O and no state: it is
//! host-tested through both users.

/// Seconds in one day.
pub const SECONDS_PER_DAY: u64 = 86_400;
/// Days in one common year.
pub const DAYS_PER_YEAR: u32 = 365;
/// UNIX epoch day offset used by the civil-date algorithm.
const CIVIL_EPOCH_SHIFT: i64 = 719_468;

/// Number of days in `month` of `year` (Gregorian calendar).
///
/// `month` is `1..=12`; an out-of-range month returns 0 instead of panicking.
pub const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// True if `year` is a Gregorian leap year.
pub const fn is_leap_year(year: u32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// Converts a packed BCD byte to binary (`0x42 -> 42`).
pub const fn bcd_to_binary(bcd: u8) -> u8 {
    (bcd & 0x0F) + ((bcd >> 4) * 10)
}

/// Converts a binary value (`0..=99`) to packed BCD (`42 -> 0x42`).
///
/// Values above 99 are saturated at 99 so a corrupt register write can never
/// produce a BCD byte with a non-digit nibble.
pub const fn binary_to_bcd(value: u8) -> u8 {
    let value = if value > 99 { 99 } else { value };
    ((value / 10) << 4) | (value % 10)
}

/// Splits UNIX `seconds` into `(hour, minute, second)`.
pub const fn day_time(seconds: u64) -> (u8, u8, u8) {
    let rem = seconds % SECONDS_PER_DAY;
    (
        (rem / 3600) as u8,
        ((rem / 60) % 60) as u8,
        (rem % 60) as u8,
    )
}

/// Day of week for `days` since 1970-01-01, `0` = Sunday .. `6` = Saturday.
pub const fn weekday_from_days(days: u64) -> u8 {
    // 1970-01-01 was a Thursday.
    ((days + 4) % 7) as u8
}

/// Converts days since `1970-01-01` to a Gregorian `(year, month, day)`.
///
/// Howard Hinnant's `civil_from_days` algorithm, in unsigned arithmetic. The
/// shift to a March-based year keeps the leap-day correction uniform.
pub const fn civil_from_days(days: u64) -> (u64, u32, u32) {
    let z = days + CIVIL_EPOCH_SHIFT as u64;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month as u32, day as u32)
}

/// Converts UNIX `seconds` to a civil date-time.
///
/// Returns `(year, month, day, hour, minute, second, weekday)` where the
/// weekday is `0` = Sunday .. `6` = Saturday, matching the host RTC driver;
/// the guest RTC model adds one for its own `1` = Sunday register convention.
pub const fn civil_from_unix(seconds: u64) -> (u64, u32, u32, u8, u8, u8, u8) {
    let days = seconds / SECONDS_PER_DAY;
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = day_time(seconds);
    (
        year,
        month,
        day,
        hour,
        minute,
        second,
        weekday_from_days(days),
    )
}

/// Converts a civil date-time to UNIX seconds.
///
/// The inverse of [`civil_from_unix`]; out-of-range fields are clamped to a
/// valid date (month/day to the month's length) instead of panicking, so a
/// caller reading a partially initialised structure cannot trap the kernel.
pub fn unix_from_civil(year: i64, month: u32, day: u32, hour: u8, minute: u8, second: u8) -> u64 {
    let month = month.clamp(1, 12);
    let days_in = days_in_month(year as u32, month);
    let day = day.clamp(1, days_in.max(1)) as i64;
    let mut y = year;
    let mut m = i64::from(month);
    if m <= 2 {
        y -= 1;
        m += 12;
    }
    let days =
        365 * y + y / 4 - y / 100 + y / 400 + (153 * (m - 3) + 2) / 5 + day - 1 - CIVIL_EPOCH_SHIFT;
    let seconds = days * SECONDS_PER_DAY as i64
        + i64::from(hour.min(23)) * 3600
        + i64::from(minute.min(59)) * 60
        + i64::from(second.min(59));
    if seconds <= 0 {
        0
    } else {
        seconds as u64
    }
}
