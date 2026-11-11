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

//! L2: s9vm CMOS RTC model (real kernel code, not executed).

#[path = "../../kernel/src/s9vm/rtc.rs"]
mod rtc;

#[path = "../../kernel/src/rtc_math.rs"]
mod rtc_math;

use rtc::{
    alarm_dont_care, status_a, status_b, status_c, CmosRtc, RtcEvents, ALARM_DONT_CARE_MASK,
    DATA_PORT, INDEX_PORT, IRQ_LINE, NMI_PORT_MASK, REFERENCE_HZ, REG_CENTURY, REG_DAY,
    REG_DAY_ALARM, REG_HOURS, REG_HOURS_ALARM, REG_MINUTES, REG_MINUTES_ALARM, REG_MONTH,
    REG_SECONDS, REG_SECONDS_ALARM, REG_STATUS_A, REG_STATUS_B, REG_STATUS_C, REG_STATUS_D,
    REG_WEEKDAY, REG_YEAR,
};

/// 2026-11-11T18:00:00Z (a Wednesday).
const NOV_2026_18H: u64 = 1_794_420_000;
/// 2026-11-11T00:00:00Z.
const NOV_2026_MIDNIGHT: u64 = 1_794_355_200;
/// 2026-11-11T12:00:00Z.
const NOV_2026_NOON: u64 = 1_794_398_400;
/// 2026-11-11T23:59:59Z.
const NOV_2026_LAST_SECOND: u64 = 1_794_441_599;
/// 2024-02-28T12:00:00Z.
const FEB_2024_28TH: u64 = 1_709_121_600;
/// 2025-02-28T12:00:00Z.
const FEB_2025_28TH: u64 = 1_740_744_000;
/// 2099-12-31T23:59:59Z.
const DEC_2099_LAST_SECOND: u64 = 4_102_444_799;

/// Selects `index` and reads the data port.
fn read_reg(rtc: &mut CmosRtc, index: u8) -> u8 {
    rtc.write_index(index);
    rtc.read_data()
}

/// Selects `index` and writes the data port.
fn write_reg(rtc: &mut CmosRtc, index: u8, value: u8) {
    rtc.write_index(index);
    rtc.write_data(value);
}

/// BCD encoding of `value` (`0..=99`).
fn bcd(value: u8) -> u8 {
    (value / 10) << 4 | (value % 10)
}

#[test]
fn ports_and_constants() {
    assert_eq!(INDEX_PORT, 0x70);
    assert_eq!(DATA_PORT, 0x71);
    assert_eq!(NMI_PORT_MASK, 0x80);
    assert_eq!(IRQ_LINE, 8);
    assert!(rtc::handles_port(0x70));
    assert!(rtc::handles_port(0x71));
    for port in [0x00, 0x6F, 0x72, 0x73, 0x80, 0xFFFF] {
        assert!(!rtc::handles_port(port), "port {port:#x}");
    }
}

#[test]
fn new_is_epoch_bcd_24h_and_valid() {
    let mut clock = CmosRtc::new();
    assert_eq!(clock, CmosRtc::default());
    assert_eq!(clock.unix_time(), 0);
    assert_eq!(read_reg(&mut clock, REG_SECONDS), 0x00);
    assert_eq!(read_reg(&mut clock, REG_MINUTES), 0x00);
    assert_eq!(read_reg(&mut clock, REG_HOURS), 0x00);
    // 1970-01-01 was a Thursday: Sunday = 1.
    assert_eq!(read_reg(&mut clock, REG_WEEKDAY), bcd(5));
    assert_eq!(read_reg(&mut clock, REG_DAY), bcd(1));
    assert_eq!(read_reg(&mut clock, REG_MONTH), bcd(1));
    assert_eq!(read_reg(&mut clock, REG_YEAR), bcd(70));
    // 1970 is in the 20th century: the century register reads 19.
    assert_eq!(read_reg(&mut clock, REG_CENTURY), bcd(19));
    assert_eq!(read_reg(&mut clock, REG_STATUS_A), status_a::DEFAULT);
    assert_eq!(read_reg(&mut clock, REG_STATUS_B), status_b::DEFAULT);
    assert_eq!(
        read_reg(&mut clock, REG_STATUS_D) & status_d_valid(),
        status_d_valid()
    );
}

#[test]
fn bcd_calendar_from_known_epoch() {
    let mut clock = CmosRtc::new();
    clock.set_unix_time(NOV_2026_18H);
    assert_eq!(clock.unix_time(), NOV_2026_18H);
    assert_eq!(read_reg(&mut clock, REG_SECONDS), 0x00);
    assert_eq!(read_reg(&mut clock, REG_MINUTES), 0x00);
    assert_eq!(read_reg(&mut clock, REG_HOURS), 0x18);
    // 2026-11-11 is a Wednesday: Sunday = 1.
    assert_eq!(read_reg(&mut clock, REG_WEEKDAY), bcd(4));
    assert_eq!(read_reg(&mut clock, REG_DAY), bcd(11));
    assert_eq!(read_reg(&mut clock, REG_MONTH), bcd(11));
    assert_eq!(read_reg(&mut clock, REG_YEAR), bcd(26));
    assert_eq!(read_reg(&mut clock, REG_CENTURY), bcd(20));
}

#[test]
fn binary_mode_uses_status_b_bit_2() {
    let mut clock = CmosRtc::new();
    clock.set_unix_time(NOV_2026_18H);
    write_reg(
        &mut clock,
        REG_STATUS_B,
        status_b::HOURS_24 | status_b::BINARY,
    );
    assert_eq!(read_reg(&mut clock, REG_SECONDS), 0);
    assert_eq!(read_reg(&mut clock, REG_MINUTES), 0);
    assert_eq!(read_reg(&mut clock, REG_HOURS), 18);
    assert_eq!(read_reg(&mut clock, REG_WEEKDAY), 4);
    assert_eq!(read_reg(&mut clock, REG_DAY), 11);
    assert_eq!(read_reg(&mut clock, REG_MONTH), 11);
    assert_eq!(read_reg(&mut clock, REG_YEAR), 26);
    assert_eq!(read_reg(&mut clock, REG_CENTURY), 20);
    // Back to BCD mode: the same timestamp is BCD encoded again.
    write_reg(&mut clock, REG_STATUS_B, status_b::HOURS_24);
    assert_eq!(read_reg(&mut clock, REG_HOURS), 0x18);
    assert_eq!(read_reg(&mut clock, REG_DAY), 0x11);
}

#[test]
fn twelve_hour_mode_sets_pm_bit() {
    let mut clock = CmosRtc::new();
    // 18:00 -> 6 PM: BCD 0x06 with the PM bit.
    clock.set_unix_time(NOV_2026_18H);
    write_reg(&mut clock, REG_STATUS_B, 0x00);
    assert_eq!(read_reg(&mut clock, REG_HOURS), 0x06 | 0x80);
    // Midnight -> 12 AM: BCD 0x12 without the PM bit.
    clock.set_unix_time(NOV_2026_MIDNIGHT);
    assert_eq!(read_reg(&mut clock, REG_HOURS), bcd(12));
    // Noon -> 12 PM: BCD 0x12 with the PM bit.
    clock.set_unix_time(NOV_2026_NOON);
    assert_eq!(read_reg(&mut clock, REG_HOURS), bcd(12) | 0x80);
    // 12-hour mode in binary format still carries the PM bit.
    write_reg(&mut clock, REG_STATUS_B, status_b::BINARY);
    clock.set_unix_time(NOV_2026_18H);
    assert_eq!(read_reg(&mut clock, REG_HOURS), 6 | 0x80);
    clock.set_unix_time(NOV_2026_MIDNIGHT);
    assert_eq!(read_reg(&mut clock, REG_HOURS), 12);
}

#[test]
fn status_a_uip_always_clear() {
    let mut clock = CmosRtc::new();
    assert_eq!(read_reg(&mut clock, REG_STATUS_A), 0x26);
    // Writes keep the divider/rate field, but UIP is never observable.
    write_reg(&mut clock, REG_STATUS_A, 0x96);
    assert_eq!(read_reg(&mut clock, REG_STATUS_A), 0x16);
    assert_eq!(read_reg(&mut clock, REG_STATUS_A) & status_a::UIP, 0);
}

#[test]
fn status_c_read_clears_flags() {
    let mut clock = CmosRtc::new();
    assert_eq!(read_reg(&mut clock, REG_STATUS_C), 0);
    clock.raise_status_c(status_c::PERIODIC | status_c::ALARM | status_c::UPDATED);
    assert_eq!(
        read_reg(&mut clock, REG_STATUS_C),
        status_c::PERIODIC | status_c::ALARM | status_c::UPDATED
    );
    assert_eq!(read_reg(&mut clock, REG_STATUS_C), 0);
    // Writing status C is ignored (read-only register).
    write_reg(&mut clock, REG_STATUS_C, 0x70);
    assert_eq!(read_reg(&mut clock, REG_STATUS_C), 0);
}

#[test]
fn status_d_always_reports_valid() {
    let mut clock = CmosRtc::new();
    assert_eq!(read_reg(&mut clock, REG_STATUS_D), 0x80);
    write_reg(&mut clock, REG_STATUS_D, 0x00);
    assert_eq!(read_reg(&mut clock, REG_STATUS_D), 0x80);
}

#[test]
fn cmos_ram_is_writable_and_defaults_to_zero() {
    let mut clock = CmosRtc::new();
    assert_eq!(read_reg(&mut clock, 0x10), 0);
    assert_eq!(read_reg(&mut clock, 0x7F), 0);
    write_reg(&mut clock, 0x10, 0x5A);
    write_reg(&mut clock, 0x7F, 0xA5);
    assert_eq!(read_reg(&mut clock, 0x10), 0x5A);
    assert_eq!(read_reg(&mut clock, 0x7F), 0xA5);
    // Bytes are independent.
    assert_eq!(read_reg(&mut clock, 0x11), 0);
    assert_eq!(read_reg(&mut clock, 0x7E), 0);
}

#[test]
fn alarm_registers_are_plain_ram() {
    let mut clock = CmosRtc::new();
    write_reg(&mut clock, rtc::REG_SECONDS_ALARM, 0x42);
    write_reg(&mut clock, rtc::REG_MINUTES_ALARM, 0x59);
    write_reg(&mut clock, rtc::REG_HOURS_ALARM, 0x23);
    assert_eq!(read_reg(&mut clock, rtc::REG_SECONDS_ALARM), 0x42);
    assert_eq!(read_reg(&mut clock, rtc::REG_MINUTES_ALARM), 0x59);
    assert_eq!(read_reg(&mut clock, rtc::REG_HOURS_ALARM), 0x23);
}

#[test]
fn century_register_tracks_the_century() {
    let mut clock = CmosRtc::new();
    clock.set_unix_time(NOV_2026_18H);
    assert_eq!(read_reg(&mut clock, REG_CENTURY), 0x20);
    // 2099-12-31T23:59:59Z + 1 s = 2100-01-01T00:00:00Z (a Friday).
    clock.set_unix_time(DEC_2099_LAST_SECOND);
    clock.advance(1);
    assert_eq!(read_reg(&mut clock, REG_CENTURY), 0x21);
    assert_eq!(read_reg(&mut clock, REG_YEAR), 0x00);
    assert_eq!(read_reg(&mut clock, REG_MONTH), 0x01);
    assert_eq!(read_reg(&mut clock, REG_DAY), 0x01);
    assert_eq!(read_reg(&mut clock, REG_HOURS), 0x00);
    assert_eq!(read_reg(&mut clock, REG_WEEKDAY), bcd(6));
    // Binary mode century: 21, not 0x21.
    write_reg(
        &mut clock,
        REG_STATUS_B,
        status_b::HOURS_24 | status_b::BINARY,
    );
    assert_eq!(read_reg(&mut clock, REG_CENTURY), 21);
}

#[test]
fn status_b_set_freezes_the_guest_calendar() {
    let mut clock = CmosRtc::new();
    clock.set_unix_time(NOV_2026_18H);
    write_reg(&mut clock, REG_STATUS_B, status_b::HOURS_24 | status_b::SET);
    assert_eq!(read_reg(&mut clock, REG_HOURS), 0x18);
    assert_eq!(read_reg(&mut clock, REG_MINUTES), 0x00);
    clock.advance(3600);
    // The host clock advances, the guest-visible calendar stays frozen.
    assert_eq!(clock.unix_time(), NOV_2026_18H + 3600);
    assert_eq!(read_reg(&mut clock, REG_HOURS), 0x18);
    assert_eq!(read_reg(&mut clock, REG_MINUTES), 0x00);
    // Programming a new time while SET updates the frozen snapshot too.
    clock.set_unix_time(NOV_2026_MIDNIGHT);
    assert_eq!(read_reg(&mut clock, REG_HOURS), 0x00);
    // Clearing SET releases the freeze: the registers follow the timestamp.
    write_reg(&mut clock, REG_STATUS_B, status_b::HOURS_24);
    clock.set_unix_time(NOV_2026_18H);
    assert_eq!(read_reg(&mut clock, REG_HOURS), 0x18);
}

#[test]
fn midnight_rollover_updates_all_fields() {
    let mut clock = CmosRtc::new();
    clock.set_unix_time(NOV_2026_LAST_SECOND);
    clock.advance(1);
    assert_eq!(read_reg(&mut clock, REG_SECONDS), 0x00);
    assert_eq!(read_reg(&mut clock, REG_MINUTES), 0x00);
    assert_eq!(read_reg(&mut clock, REG_HOURS), 0x00);
    assert_eq!(read_reg(&mut clock, REG_DAY), bcd(12));
    assert_eq!(read_reg(&mut clock, REG_MONTH), bcd(11));
    assert_eq!(read_reg(&mut clock, REG_YEAR), bcd(26));
    assert_eq!(read_reg(&mut clock, REG_WEEKDAY), bcd(5));
    clock.advance(60);
    assert_eq!(read_reg(&mut clock, REG_MINUTES), 0x01);
    assert_eq!(read_reg(&mut clock, REG_SECONDS), 0x00);
}

#[test]
fn leap_year_2024_has_a_february_29th() {
    let mut clock = CmosRtc::new();
    clock.set_unix_time(FEB_2024_28TH);
    assert_eq!(read_reg(&mut clock, REG_DAY), bcd(28));
    clock.advance(86_400);
    assert_eq!(read_reg(&mut clock, REG_MONTH), bcd(2));
    assert_eq!(read_reg(&mut clock, REG_DAY), bcd(29));
    clock.advance(86_400);
    assert_eq!(read_reg(&mut clock, REG_MONTH), bcd(3));
    assert_eq!(read_reg(&mut clock, REG_DAY), bcd(1));
}

#[test]
fn non_leap_year_2025_skips_february_29th() {
    let mut clock = CmosRtc::new();
    clock.set_unix_time(FEB_2025_28TH);
    assert_eq!(read_reg(&mut clock, REG_DAY), bcd(28));
    clock.advance(86_400);
    assert_eq!(read_reg(&mut clock, REG_MONTH), bcd(3));
    assert_eq!(read_reg(&mut clock, REG_DAY), bcd(1));
    assert_eq!(read_reg(&mut clock, REG_YEAR), bcd(25));
}

#[test]
fn weekday_numbering_is_sunday_first() {
    let mut clock = CmosRtc::new();
    // 1970-01-01 (epoch) was a Thursday.
    assert_eq!(read_reg(&mut clock, REG_WEEKDAY), 5);
    // 1970-01-04 was a Sunday.
    clock.set_unix_time(3 * 86_400);
    assert_eq!(read_reg(&mut clock, REG_WEEKDAY), 1);
    // 2026-11-11 is a Wednesday.
    clock.set_unix_time(NOV_2026_18H);
    assert_eq!(read_reg(&mut clock, REG_WEEKDAY), 4);
}

#[test]
fn index_port_masks_nmi_and_register_bits() {
    let mut clock = CmosRtc::new();
    clock.set_unix_time(NOV_2026_18H);
    // Bit 7 only disables the NMI: the register index is bits 6:0.
    clock.write_index(NMI_PORT_MASK);
    assert!(clock.nmi_disabled());
    assert_eq!(clock.index(), REG_SECONDS);
    assert_eq!(clock.read_data(), 0x00);
    // The NMI flag does not gate data access; the index is masked.
    clock.write_index(NMI_PORT_MASK | REG_CENTURY);
    assert!(clock.nmi_disabled());
    assert_eq!(clock.index(), REG_CENTURY);
    assert_eq!(clock.read_data(), 0x20);
    // Clearing bit 7 re-enables the NMI.
    clock.write_index(REG_WEEKDAY);
    assert!(!clock.nmi_disabled());
    assert_eq!(clock.index(), REG_WEEKDAY);
    assert_eq!(clock.read_data(), bcd(4));
}

#[test]
fn writing_time_registers_does_not_move_the_clock() {
    let mut clock = CmosRtc::new();
    clock.set_unix_time(NOV_2026_18H);
    write_reg(&mut clock, REG_SECONDS, 0x59);
    write_reg(&mut clock, REG_HOURS, 0x23);
    write_reg(&mut clock, REG_DAY, 0x31);
    assert_eq!(read_reg(&mut clock, REG_SECONDS), 0x00);
    assert_eq!(read_reg(&mut clock, REG_HOURS), 0x18);
    assert_eq!(read_reg(&mut clock, REG_DAY), bcd(11));
    assert_eq!(clock.unix_time(), NOV_2026_18H);
}

#[test]
fn advance_saturates_at_u64_max() {
    let mut clock = CmosRtc::new();
    clock.set_unix_time(u64::MAX);
    clock.advance(1000);
    assert_eq!(clock.unix_time(), u64::MAX);
    // Reading every computed register must not panic or divide by zero.
    for index in [
        REG_SECONDS,
        REG_MINUTES,
        REG_HOURS,
        REG_WEEKDAY,
        REG_DAY,
        REG_MONTH,
        REG_YEAR,
        REG_CENTURY,
    ] {
        let _ = read_reg(&mut clock, index);
    }
}

/// Status-D valid bit helper (keeps the assertion readable).
fn status_d_valid() -> u8 {
    0x80
}

/// Programs status B with the 24-hour mode and `extra` enable bits.
fn enable_interrupts(rtc: &mut CmosRtc, extra: u8) {
    write_reg(rtc, REG_STATUS_B, status_b::HOURS_24 | extra);
}

/// Programs the four alarm bytes from the current guest-visible time.
fn program_alarm_from_now(rtc: &mut CmosRtc) {
    let seconds = read_reg(rtc, REG_SECONDS);
    let minutes = read_reg(rtc, REG_MINUTES);
    let hours = read_reg(rtc, REG_HOURS);
    let day = read_reg(rtc, REG_DAY);
    write_reg(rtc, REG_SECONDS_ALARM, seconds);
    write_reg(rtc, REG_MINUTES_ALARM, minutes);
    write_reg(rtc, REG_HOURS_ALARM, hours);
    write_reg(rtc, REG_DAY_ALARM, day);
}

#[test]
fn reference_clock_and_dont_care_convention() {
    assert_eq!(REFERENCE_HZ, 32_768);
    assert_eq!(ALARM_DONT_CARE_MASK, 0xC0);
    // Encoded values never set both top bits; the convention is unambiguous.
    assert!(!alarm_dont_care(0x00));
    assert!(!alarm_dont_care(0x59));
    assert!(!alarm_dont_care(0x92));
    assert!(!alarm_dont_care(0xBF));
    assert!(alarm_dont_care(0xC0));
    assert!(alarm_dont_care(0xFF));
}

#[test]
fn periodic_rate_decoding_for_every_rate_select() {
    let mut clock = CmosRtc::new();
    let expected: [u32; 13] = [8192, 4096, 2048, 1024, 512, 256, 128, 64, 32, 16, 8, 4, 2];
    for rate_select in 0u8..=15 {
        // Keep the divider field, replace the rate-select nibble.
        let status = 0x20 | rate_select;
        write_reg(&mut clock, REG_STATUS_A, status);
        if rate_select < 3 {
            assert_eq!(clock.periodic_rate_hz(), None, "RS={rate_select}");
        } else {
            assert_eq!(
                clock.periodic_rate_hz(),
                Some(expected[usize::from(rate_select - 3)]),
                "RS={rate_select}"
            );
        }
    }
    // The reset value selects 1024 Hz (RS = 6).
    assert_eq!(CmosRtc::new().periodic_rate_hz(), Some(1024));
}

#[test]
fn periodic_event_fires_when_the_period_crosses() {
    let mut clock = CmosRtc::new();
    enable_interrupts(&mut clock, status_b::PERIODIC_INTERRUPT);
    // RS = 6 -> 1024 Hz -> 32 reference ticks per period.
    let mut events = clock.advance_events(0, 31);
    assert!(!events.periodic);
    events = clock.advance_events(0, 1);
    assert!(events.periodic);
    assert!(!events.update_ended);
    // The phase starts a new period after the event.
    events = clock.advance_events(0, 31);
    assert!(!events.periodic);
    events = clock.advance_events(0, 1);
    assert!(events.periodic);
}

#[test]
fn periodic_fire_count_over_one_second_matches_the_rate() {
    // RS = 3 -> 8192 Hz, one period every 4 reference ticks. One full second
    // of 32768 single-tick calls must produce exactly 8192 fires.
    let mut clock = CmosRtc::new();
    write_reg(&mut clock, REG_STATUS_A, 0x23);
    assert_eq!(clock.periodic_rate_hz(), Some(8192));
    let mut fires = 0u32;
    let mut updates = 0u32;
    for _ in 0..REFERENCE_HZ {
        let events = clock.advance_events(0, 1);
        if events.periodic {
            fires += 1;
        }
        if events.update_ended {
            updates += 1;
        }
    }
    assert_eq!(fires, 8192);
    assert_eq!(updates, 1);
    assert_eq!(clock.unix_time(), 1);
}

#[test]
fn periodic_event_is_disabled_below_rate_select_three() {
    for rate_select in 0u8..3 {
        let mut clock = CmosRtc::new();
        write_reg(&mut clock, REG_STATUS_A, 0x20 | rate_select);
        enable_interrupts(&mut clock, status_b::PERIODIC_INTERRUPT);
        assert_eq!(clock.periodic_rate_hz(), None);
        let events = clock.advance_events(1, 1234);
        assert!(!events.periodic);
        assert_eq!(read_reg(&mut clock, REG_STATUS_C) & status_c::PERIODIC, 0);
    }
}

#[test]
fn status_b_decode_accessors() {
    let mut clock = CmosRtc::new();
    assert!(!clock.periodic_interrupt_enabled());
    assert!(!clock.alarm_interrupt_enabled());
    assert!(!clock.update_ended_interrupt_enabled());
    assert!(clock.hours_24_mode());
    assert!(!clock.binary_mode());
    assert!(!clock.daylight_saving_enabled());
    assert!(!clock.clock_frozen());

    write_reg(
        &mut clock,
        REG_STATUS_B,
        status_b::PERIODIC_INTERRUPT
            | status_b::ALARM_INTERRUPT
            | status_b::UPDATE_ENDED_INTERRUPT
            | status_b::BINARY
            | status_b::DAYLIGHT_SAVING,
    );
    assert!(clock.periodic_interrupt_enabled());
    assert!(clock.alarm_interrupt_enabled());
    assert!(clock.update_ended_interrupt_enabled());
    assert!(!clock.hours_24_mode());
    assert!(clock.binary_mode());
    assert!(clock.daylight_saving_enabled());
}

#[test]
fn update_ended_event_once_per_second_with_uie() {
    let mut clock = CmosRtc::new();
    enable_interrupts(&mut clock, status_b::UPDATE_ENDED_INTERRUPT);
    let events = clock.advance_events(0, 32_767);
    assert!(!events.update_ended);
    let events = clock.advance_events(0, 1);
    assert!(events.update_ended);
    assert!(clock.irq_asserted());
    // A whole second is one update event, whatever the sub-tick accounting.
    let events = clock.advance_events(1, 0);
    assert!(events.update_ended);
    let events = clock.advance_events(0, 100);
    assert!(!events.update_ended);
}

#[test]
fn update_ended_flag_set_even_without_enable_but_irq_gated() {
    let mut clock = CmosRtc::new();
    // Disable the periodic source so status C only carries the update flag.
    write_reg(&mut clock, REG_STATUS_A, 0x20);
    let events = clock.advance_events(1, 0);
    assert!(events.update_ended);
    assert!(!clock.irq_asserted());
    assert_eq!(
        read_reg(&mut clock, REG_STATUS_C),
        status_c::UPDATED,
        "the flag is latched regardless of the enable bit"
    );

    // Re-latch, then enable the interrupt: IRQF appears on the next read.
    clock.advance_events(1, 0);
    assert!(!clock.irq_asserted());
    enable_interrupts(&mut clock, status_b::UPDATE_ENDED_INTERRUPT);
    assert!(clock.irq_asserted());
    assert_eq!(
        read_reg(&mut clock, REG_STATUS_C),
        status_c::UPDATED | status_c::IRQF
    );
    assert!(!clock.irq_asserted());
}

#[test]
fn status_c_read_clears_irqf_and_flags_exactly_once() {
    let mut clock = CmosRtc::new();
    enable_interrupts(
        &mut clock,
        status_b::PERIODIC_INTERRUPT | status_b::UPDATE_ENDED_INTERRUPT,
    );
    clock.advance_events(1, 0);
    assert!(clock.irq_asserted());
    let flags = read_reg(&mut clock, REG_STATUS_C);
    assert_ne!(flags & status_c::IRQF, 0);
    assert_ne!(flags & status_c::UPDATED, 0);
    assert_ne!(flags & status_c::PERIODIC, 0);
    assert!(!clock.irq_asserted());
    assert_eq!(read_reg(&mut clock, REG_STATUS_C), 0);
    // A guest write to status C cannot set the flags back.
    write_reg(&mut clock, REG_STATUS_C, 0xFF);
    assert_eq!(read_reg(&mut clock, REG_STATUS_C), 0);
}

#[test]
fn irq_asserted_requires_flag_and_enable() {
    let mut clock = CmosRtc::new();
    clock.raise_status_c(status_c::PERIODIC | status_c::ALARM | status_c::UPDATED);
    assert!(!clock.irq_asserted());
    // Enabling the periodic interrupt alone asserts IRQF because PF is latched.
    write_reg(&mut clock, REG_STATUS_B, status_b::PERIODIC_INTERRUPT);
    assert!(clock.irq_asserted());
    assert_eq!(
        read_reg(&mut clock, REG_STATUS_C),
        status_c::PERIODIC | status_c::ALARM | status_c::UPDATED | status_c::IRQF
    );
}

#[test]
fn alarm_matches_at_the_next_second_boundary() {
    let mut clock = CmosRtc::new();
    clock.set_unix_time(NOV_2026_18H);
    // Disable the periodic source so status C only carries the alarm flag.
    write_reg(&mut clock, REG_STATUS_A, 0x20);
    // 18:00:01, 2026-11-11 encoded in the current (BCD, 24-hour) format.
    write_reg(&mut clock, REG_SECONDS_ALARM, 0x01);
    write_reg(&mut clock, REG_MINUTES_ALARM, 0x00);
    write_reg(&mut clock, REG_HOURS_ALARM, 0x18);
    write_reg(&mut clock, REG_DAY_ALARM, bcd(11));
    enable_interrupts(&mut clock, status_b::ALARM_INTERRUPT);

    let events = clock.advance_events(1, 0);
    assert!(events.alarm);
    assert!(clock.irq_asserted());
    assert_eq!(
        read_reg(&mut clock, REG_STATUS_C),
        status_c::ALARM | status_c::UPDATED | status_c::IRQF
    );
    assert!(!clock.irq_asserted());
}

#[test]
fn alarm_mismatch_and_wrong_day_do_not_fire() {
    let mut clock = CmosRtc::new();
    clock.set_unix_time(NOV_2026_18H);
    // Default alarm bytes are zero: the next second (18:00:01) does not match.
    let events = clock.advance_events(1, 0);
    assert!(!events.alarm);

    // Correct time fields but a different day of month.
    program_alarm_from_now(&mut clock);
    clock.set_unix_time(NOV_2026_18H + 1);
    write_reg(&mut clock, REG_DAY_ALARM, bcd(12));
    let events = clock.advance_events(1, 0);
    assert!(!events.alarm);
}

#[test]
fn alarm_dont_care_bytes_match_any_field() {
    let mut clock = CmosRtc::new();
    clock.set_unix_time(NOV_2026_18H);
    for register in [
        REG_SECONDS_ALARM,
        REG_MINUTES_ALARM,
        REG_HOURS_ALARM,
        REG_DAY_ALARM,
    ] {
        write_reg(&mut clock, register, 0xFF);
    }
    let events = clock.advance_events(1, 0);
    assert!(events.alarm);
    // The same values latched the flag even with AIE clear.
    assert!(!clock.irq_asserted());
    assert_eq!(
        read_reg(&mut clock, REG_STATUS_C) & status_c::ALARM,
        status_c::ALARM
    );
}

#[test]
fn alarm_accepts_hours_and_day_plus_twelve_hour_mode() {
    let mut clock = CmosRtc::new();
    clock.set_unix_time(NOV_2026_18H);
    // 12-hour mode: 18:00 displays as 6 PM (0x06 | 0x80).
    write_reg(&mut clock, REG_STATUS_B, 0x00);
    program_alarm_from_now(&mut clock);
    // Move only the seconds field to the next boundary; the hour and day bytes
    // stay in the 12-hour encoded form read from the clock.
    write_reg(&mut clock, REG_SECONDS_ALARM, 0x01);
    let events = clock.advance_events(1, 0);
    assert!(events.alarm, "12-hour encoded alarm bytes must compare");
}

#[test]
fn set_freeze_keeps_the_calendar_and_event_time() {
    let mut clock = CmosRtc::new();
    clock.set_unix_time(NOV_2026_18H);
    for register in [
        REG_SECONDS_ALARM,
        REG_MINUTES_ALARM,
        REG_HOURS_ALARM,
        REG_DAY_ALARM,
    ] {
        write_reg(&mut clock, register, 0xFF);
    }
    write_reg(&mut clock, REG_STATUS_B, status_b::HOURS_24 | status_b::SET);
    assert!(clock.clock_frozen());
    let events = clock.advance_events(3600, 0);
    assert!(events.update_ended);
    assert!(events.alarm, "the alarm compares the frozen guest time");
    // The guest-visible calendar stayed at 18:00:00.
    assert_eq!(read_reg(&mut clock, REG_HOURS), 0x18);
    assert_eq!(read_reg(&mut clock, REG_MINUTES), 0x00);
    assert_eq!(clock.unix_time(), NOV_2026_18H + 3600);
    // Clearing SET releases the freeze again.
    write_reg(&mut clock, REG_STATUS_B, status_b::HOURS_24);
    assert!(!clock.clock_frozen());
}

#[test]
fn enables_do_not_change_bcd_or_twelve_hour_formatting() {
    let mut clock = CmosRtc::new();
    clock.set_unix_time(NOV_2026_18H);
    enable_interrupts(
        &mut clock,
        status_b::PERIODIC_INTERRUPT | status_b::ALARM_INTERRUPT | status_b::UPDATE_ENDED_INTERRUPT,
    );
    assert_eq!(read_reg(&mut clock, REG_SECONDS), 0x00);
    assert_eq!(read_reg(&mut clock, REG_HOURS), 0x18);
    assert_eq!(read_reg(&mut clock, REG_DAY), bcd(11));

    // Binary + 24-hour mode still reads correctly with the enables set.
    write_reg(
        &mut clock,
        REG_STATUS_B,
        status_b::HOURS_24
            | status_b::BINARY
            | status_b::PERIODIC_INTERRUPT
            | status_b::ALARM_INTERRUPT,
    );
    assert_eq!(read_reg(&mut clock, REG_HOURS), 18);
    assert_eq!(read_reg(&mut clock, REG_DAY), 11);

    // 12-hour mode with enables reports the PM bit as before.
    write_reg(
        &mut clock,
        REG_STATUS_B,
        status_b::PERIODIC_INTERRUPT | status_b::ALARM_INTERRUPT,
    );
    assert_eq!(read_reg(&mut clock, REG_HOURS), 0x06 | 0x80);
}

#[test]
fn advance_keeps_working_and_latches_events() {
    let mut clock = CmosRtc::new();
    clock.set_unix_time(NOV_2026_18H);
    clock.advance(10);
    assert_eq!(clock.unix_time(), NOV_2026_18H + 10);
    // The historical helper still drives the event model.
    assert_eq!(
        read_reg(&mut clock, REG_STATUS_C) & status_c::UPDATED,
        status_c::UPDATED
    );
}

#[test]
fn extreme_advance_events_never_panic() {
    let mut clock = CmosRtc::new();
    let none = clock.advance_events(0, 0);
    assert_eq!(none, RtcEvents::NONE);
    assert!(!none.any());

    clock.advance_events(u64::MAX, u64::MAX);
    clock.advance_events(u64::MAX, 0);
    // The time saturates; every register must still read without panicking.
    for index in [
        REG_SECONDS,
        REG_MINUTES,
        REG_HOURS,
        REG_WEEKDAY,
        REG_DAY,
        REG_MONTH,
        REG_YEAR,
        REG_CENTURY,
        REG_STATUS_A,
        REG_STATUS_B,
        REG_STATUS_C,
        REG_STATUS_D,
    ] {
        let _ = read_reg(&mut clock, index);
    }
    let _ = clock.irq_asserted();
    let _ = clock.periodic_rate_hz();
}

#[test]
fn status_a_rate_change_resets_the_periodic_phase() {
    let mut clock = CmosRtc::new();
    // Accumulate 31 of the 32 ticks of the default 1024 Hz period.
    let _ = clock.advance_events(0, 31);
    // A status-A write restarts the divider: the phase is cleared.
    write_reg(&mut clock, REG_STATUS_A, 0x26);
    let events = clock.advance_events(0, 31);
    assert!(!events.periodic);
    let events = clock.advance_events(0, 1);
    assert!(events.periodic);
}
