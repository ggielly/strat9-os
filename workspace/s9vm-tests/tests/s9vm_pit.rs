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

//! L2: s9vm programmable interval timer (real kernel code).
//!
//! The tests program the PIT through the same command/data byte sequences a
//! guest uses, advance the model in bus ticks and check the IRQ0 pulse and the
//! read-back behaviour.

#[path = "../../kernel/src/s9vm/pit.rs"]
mod pit;

use pit::{handles_port, Pit, BASE_PORT, FREQUENCY_HZ, IRQ_LINE, PORT_COUNT};

/// Channel 0 data port offset (system timer, IRQ0).
const CH0: u32 = 0;
/// Channel 1 data port offset (legacy refresh).
const CH1: u32 = 1;
/// Channel 2 data port offset (PC speaker).
const CH2: u32 = 2;
/// Mode/command register offset.
const CMD: u32 = 3;

/// Programs a 16-bit count with the low byte first, as a guest does for a
/// lo/hi access channel.
fn write_count(pit: &mut Pit, channel: u32, count: u16) {
    pit.write(channel, count as u8);
    pit.write(channel, (count >> 8) as u8);
}

/// Latches and reads back the 16-bit counter of a lo/hi channel.
fn latch_count(pit: &mut Pit, channel: u32) -> u16 {
    // Latch command: channel selected in bits 7:6, access bits 5:4 = 00.
    pit.write(CMD, (channel as u8) << 6);
    let low = pit.read(channel) as u16;
    let high = pit.read(channel) as u16;
    low | (high << 8)
}

#[test]
fn exposes_architectural_constants_and_ports() {
    assert_eq!(BASE_PORT, 0x40);
    assert_eq!(PORT_COUNT, 4);
    assert_eq!(IRQ_LINE, 0);
    assert_eq!(FREQUENCY_HZ, 1_193_182);
    for port in BASE_PORT..BASE_PORT + PORT_COUNT {
        assert!(handles_port(port));
    }
    assert!(!handles_port(BASE_PORT - 1));
    assert!(!handles_port(BASE_PORT + PORT_COUNT));
}

#[test]
fn unprogrammed_channels_are_silent() {
    let mut pit = Pit::new();
    for offset in 0..4 {
        assert_eq!(pit.read(offset), 0);
    }
    assert!(!pit.advance(1_000_000));
    assert!(!pit.irq_level());
}

#[test]
fn mode3_programs_via_low_then_high_and_pulses_periodically() {
    let mut pit = Pit::new();
    // Channel 0, lo/hi access, mode 3 (square wave), binary.
    pit.write(CMD, 0x36);
    write_count(&mut pit, CH0, 0x1000);

    // First period: 4096 ticks.
    assert!(!pit.advance(4095));
    assert!(pit.advance(1));
    assert!(pit.irq_level());
    // The reload is automatic: a second, identical period fires again.
    assert!(!pit.advance(4095));
    assert!(pit.advance(1));
    assert!(pit.advance(4096));
}

#[test]
fn mode0_one_shot_expires_without_reload() {
    let mut pit = Pit::new();
    // Channel 0, lo/hi access, mode 0 (interrupt on terminal count), binary.
    pit.write(CMD, 0x30);
    write_count(&mut pit, CH0, 100);

    assert!(!pit.advance(99));
    assert!(pit.advance(1));
    assert!(pit.irq_level());
    // The channel stopped: no reload, no further IRQ.
    assert!(!pit.advance(1000));
    assert!(!pit.irq_level());
    assert_eq!(latch_count(&mut pit, CH0), 0);
}

#[test]
fn mode2_rate_generator_reloads_every_period() {
    let mut pit = Pit::new();
    // Channel 0, lo/hi access, mode 2 (rate generator), binary.
    pit.write(CMD, 0x34);
    write_count(&mut pit, CH0, 50);

    assert!(!pit.advance(49));
    assert!(pit.advance(1));
    assert!(pit.advance(50));
    assert!(!pit.advance(49));
    assert!(pit.advance(1));
}

#[test]
fn latch_command_captures_a_stable_count() {
    let mut pit = Pit::new();
    pit.write(CMD, 0x36);
    write_count(&mut pit, CH0, 0x1234);
    assert!(!pit.advance(0x100));

    // Latch command: bits 7:6 = 0, bits 5:4 = 00.
    pit.write(CMD, 0x00);
    assert_eq!(pit.read(CH0), 0x34);
    assert_eq!(pit.read(CH0), 0x11);
    // The latch is consumed; the next read returns the live counter, which
    // has not moved because no time elapsed since the latch.
    assert_eq!(pit.read(CH0), 0x34);
    assert_eq!(pit.read(CH0), 0x11);
}

#[test]
fn current_counter_reads_low_then_high_without_latch() {
    let mut pit = Pit::new();
    pit.write(CMD, 0x36);
    write_count(&mut pit, CH0, 0x0102);
    assert_eq!(pit.read(CH0), 0x02);
    assert_eq!(pit.read(CH0), 0x01);
    // Lo/hi readout alternates again.
    assert_eq!(pit.read(CH0), 0x02);
}

#[test]
fn channel2_counts_independently_from_channel0() {
    let mut pit = Pit::new();
    // Channel 0: rate generator, 1000 ticks.
    pit.write(CMD, 0x34);
    write_count(&mut pit, CH0, 1000);
    // Channel 2: square wave, 10 ticks (PC speaker).
    pit.write(CMD, 0xB6);
    write_count(&mut pit, CH2, 10);

    assert!(!pit.advance(5));
    assert_eq!(latch_count(&mut pit, CH0), 995);
    assert_eq!(latch_count(&mut pit, CH2), 5);
    // Channel 2 expires and reloads while channel 0 keeps counting; channel 2
    // expiry must not raise IRQ0.
    assert!(!pit.advance(5));
    assert_eq!(latch_count(&mut pit, CH2), 10);
    assert_eq!(latch_count(&mut pit, CH0), 990);
}

#[test]
fn bcd_counting_programs_and_reads_back_decimal_digits() {
    let mut pit = Pit::new();
    // Channel 0, lo/hi access, mode 2, BCD count mode.
    pit.write(CMD, 0x35);
    write_count(&mut pit, CH0, 0x0020); // BCD 20

    // A latched read returns the BCD-encoded current count.
    pit.write(CMD, 0x00);
    assert_eq!(pit.read(CH0), 0x20);
    assert_eq!(pit.read(CH0), 0x00);

    assert!(!pit.advance(19));
    assert!(pit.advance(1));
    // After the reload the counter is BCD 20 again.
    pit.write(CMD, 0x00);
    assert_eq!(pit.read(CH0), 0x20);
    assert_eq!(pit.read(CH0), 0x00);
}

#[test]
fn bcd_programming_with_invalid_digits_is_rejected() {
    let mut pit = Pit::new();
    pit.write(CMD, 0x35);
    // 0x0A is not a valid BCD digit: the programming must be refused and the
    // channel must stay silent.
    write_count(&mut pit, CH0, 0x000A);
    assert_eq!(pit.read(CH0), 0);
    assert!(!pit.advance(1000));
    assert!(!pit.irq_level());

    // A subsequent valid BCD programming is accepted.
    pit.write(CMD, 0x35);
    write_count(&mut pit, CH0, 0x0030); // BCD 30
    assert!(!pit.advance(29));
    assert!(pit.advance(1));
}

#[test]
fn read_back_command_latches_several_channels() {
    let mut pit = Pit::new();
    pit.write(CMD, 0x36);
    write_count(&mut pit, CH0, 0x0040);
    // Channel 1, lo/hi access, mode 3, binary.
    pit.write(CMD, 0x76);
    write_count(&mut pit, CH1, 0x0080);

    // Read-back command (channel 3), latch count only (bit 5), select
    // channels 0 and 1 (bits 2:1 of the select field).
    pit.write(CMD, 0xEC);
    assert_eq!(pit.read(CH0), 0x40);
    assert_eq!(pit.read(CH0), 0x00);
    assert_eq!(pit.read(CH1), 0x80);
    assert_eq!(pit.read(CH1), 0x00);
}
