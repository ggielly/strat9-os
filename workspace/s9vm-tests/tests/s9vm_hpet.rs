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

//! L2: s9vm high-precision event timer (real kernel code).
//!
//! The model is driven through its MMIO register interface exactly as a guest
//! driver does: read the capabilities, program a comparator, then advance the
//! counter and check the interrupt status. The ACPI description table is
//! checked byte by byte (signature, length, checksum, base address).

#[path = "../../kernel/src/s9vm/hpet.rs"]
mod hpet;

use hpet::{
    table_bytes, CapsId, Hpet, HpetEvents, BASE_GPA, CAPS_ID, COMPARATOR_BASE, COMPARATOR_STRIDE,
    CONFIG, CONFIG_ENABLE, CONFIG_LEGACY_ROUTE, COUNTER, FREQUENCY_HZ, IRQ_LINE, ISR, MMIO_SIZE,
    PERIOD, PERIOD_FS, REVISION, TIMER_COUNT, TIMER_INT_ENABLE, TIMER_PERIODIC,
    TIMER_64BIT_CAPABLE, TIMER_64BIT_MODE, TIMER_PERIODIC_CAPABLE, VENDOR_ID,
};

/// Offset of the configuration register of timer `index`.
fn timer_config(index: usize) -> u16 {
    COMPARATOR_BASE + index as u16 * COMPARATOR_STRIDE
}

/// Offset of the comparator register of timer `index`.
fn timer_comparator(index: usize) -> u16 {
    timer_config(index) + 0x08
}

#[test]
fn constants_are_the_architectural_values() {
    assert_eq!(BASE_GPA, 0xFED0_0000);
    assert_eq!(MMIO_SIZE, 0x400);
    assert_eq!(TIMER_COUNT, 3);
    assert_eq!(FREQUENCY_HZ, 14_318_180);
    assert_eq!(PERIOD_FS, 69_841_278);
    assert_eq!(REVISION, 1);
    assert_eq!(IRQ_LINE, 2);
    assert_eq!(CAPS_ID, 0x000);
    assert_eq!(PERIOD, 0x004);
    assert_eq!(CONFIG, 0x010);
    assert_eq!(ISR, 0x020);
    assert_eq!(COUNTER, 0x0F0);
    assert_eq!(COMPARATOR_BASE, 0x100);
    assert_eq!(COMPARATOR_STRIDE, 0x20);
}

#[test]
fn capability_register_decoding_round_trips() {
    let caps = Hpet::new().caps();
    assert_eq!(caps.revision, REVISION);
    assert_eq!(caps.timer_count as usize, TIMER_COUNT);
    assert!(caps.counter_64);
    let encoded = caps.encode();
    assert_eq!(CapsId::decode(encoded), caps);
}

#[test]
fn reset_state_is_quiet() {
    let hpet = Hpet::new();
    assert!(!hpet.enabled());
    assert!(!hpet.legacy_route());
    assert_eq!(hpet.counter(), 0);
    assert_eq!(hpet.config(), 0);
    assert_eq!(hpet.isr(), 0);
    assert!(!hpet.irq_asserted());
    for timer in 0..TIMER_COUNT {
        assert_eq!(hpet.comparator(timer), Some(0));
        // Reset configuration exposes the read-only capability bits only.
        assert_eq!(
            hpet.timer_config(timer),
            Some(TIMER_PERIODIC_CAPABLE | TIMER_64BIT_CAPABLE)
        );
    }
    assert_eq!(hpet.comparator(TIMER_COUNT), None);
    assert_eq!(hpet.timer_config(TIMER_COUNT), None);
}

#[test]
fn global_enable_and_legacy_route_bits_are_writable() {
    let mut hpet = Hpet::new();
    assert!(hpet.write(CONFIG, 4, u64::from(CONFIG_ENABLE | CONFIG_LEGACY_ROUTE)));
    assert!(hpet.enabled());
    assert!(hpet.legacy_route());
    assert!(hpet.write(CONFIG, 4, 0));
    assert!(!hpet.enabled());
    assert!(!hpet.legacy_route());
}

#[test]
fn counter_only_runs_while_enabled() {
    let mut hpet = Hpet::new();
    assert_eq!(hpet.advance_ticks(100).is_empty(), true);
    assert_eq!(hpet.counter(), 0);
    hpet.write(CONFIG, 4, u64::from(CONFIG_ENABLE));
    let events = hpet.advance_ticks(100);
    assert_eq!(events.is_empty(), true);
    assert_eq!(hpet.counter(), 100);
}

#[test]
fn counter_reads_as_two_32_bit_halves_or_one_64_bit_value() {
    let mut hpet = Hpet::new();
    hpet.write(CONFIG, 4, u64::from(CONFIG_ENABLE));
    hpet.advance_ticks(0x1_0000_0002);
    assert_eq!(hpet.read(COUNTER, 8), Some(0x1_0000_0002));
    assert_eq!(hpet.read(COUNTER, 4), Some(2));
    assert_eq!(hpet.read(COUNTER + 4, 4), Some(1));
    // The counter is read-only.
    assert!(!hpet.write(COUNTER, 8, 0));
}

#[test]
fn period_register_is_the_architectural_period() {
    let hpet = Hpet::new();
    assert_eq!(hpet.read(PERIOD, 4), Some(u64::from(PERIOD_FS)));
    assert_eq!(hpet.read(CAPS_ID, 8), Some(hpet.caps().encode()));
    assert!(!Hpet::new().write(PERIOD, 4, 0));
}

#[test]
fn capability_register_reports_the_model() {
    let hpet = Hpet::new();
    let caps = hpet.caps();
    assert_eq!(caps.revision, REVISION);
    assert_eq!(caps.timer_count as usize, TIMER_COUNT);
    assert!(caps.counter_64);
    assert!(caps.legacy_capable);
    assert_eq!(caps.vendor_id, VENDOR_ID);
    assert_eq!(caps.period_fs, PERIOD_FS);
}

#[test]
fn one_shot_timer_fires_once_then_stops() {
    let mut hpet = Hpet::new();
    hpet.write(CONFIG, 4, u64::from(CONFIG_ENABLE));
    hpet.write(timer_config(0), 4, u64::from(TIMER_INT_ENABLE));
    hpet.write(timer_comparator(0), 8, 50);
    // Not there yet.
    assert!(hpet.advance_ticks(10).is_empty());
    assert!(!hpet.irq_asserted());
    // Crossing the comparator fires the timer and sets its status bit.
    let events = hpet.advance_ticks(50);
    assert!(events.contains(0));
    assert_eq!(hpet.isr() & 1, 1);
    assert!(hpet.irq_asserted());
    // One-shot: a later advance does not fire again.
    assert!(hpet.advance_ticks(100).is_empty());
}

#[test]
fn interrupt_status_is_write_one_to_clear() {
    let mut hpet = Hpet::new();
    hpet.write(CONFIG, 4, u64::from(CONFIG_ENABLE));
    hpet.write(timer_config(1), 4, u64::from(TIMER_INT_ENABLE));
    hpet.write(timer_comparator(1), 8, 5);
    hpet.advance_ticks(10);
    assert_eq!(hpet.isr() & (1 << 1), 1 << 1);
    assert!(hpet.irq_asserted());
    assert!(hpet.write(ISR, 4, 1 << 1));
    assert_eq!(hpet.isr() & (1 << 1), 0);
    assert!(!hpet.irq_asserted());
}

#[test]
fn a_masked_timer_sets_no_interrupt_line() {
    let mut hpet = Hpet::new();
    hpet.write(CONFIG, 4, u64::from(CONFIG_ENABLE));
    // Interrupt not enabled: the status bit may latch, the line stays low.
    hpet.write(timer_comparator(2), 8, 1);
    hpet.advance_ticks(10);
    assert!(!hpet.irq_asserted());
}

#[test]
fn periodic_timer_reloads_and_fires_again() {
    let mut hpet = Hpet::new();
    hpet.write(CONFIG, 4, u64::from(CONFIG_ENABLE));
    hpet.write(
        timer_config(0),
        4,
        u64::from(TIMER_INT_ENABLE | TIMER_PERIODIC),
    );
    hpet.write(timer_comparator(0), 8, 20);
    let first = hpet.advance_ticks(20);
    assert!(first.contains(0));
    // Clear the status, then keep counting: the timer reloads at +20.
    hpet.write(ISR, 4, 1);
    let second = hpet.advance_ticks(20);
    assert!(second.contains(0));
    let comparators = hpet.comparator(0).unwrap();
    assert!(comparators >= 20);
}

#[test]
fn comparator_high_and_low_halves_compose() {
    let mut hpet = Hpet::new();
    let low = timer_comparator(0);
    hpet.write(low, 4, 0x1122_3344);
    hpet.write(low + 4, 4, 0x5566_7788);
    assert_eq!(hpet.comparator(0), Some(0x5566_7788_1122_3344));
    assert_eq!(hpet.read(low, 4), Some(0x1122_3344));
    assert_eq!(hpet.read(low + 4, 4), Some(0x5566_7788));
    assert_eq!(hpet.read(low, 8), Some(0x5566_7788_1122_3344));
}

#[test]
fn sixty_four_bit_comparator_mode_is_accepted() {
    let mut hpet = Hpet::new();
    assert!(hpet.write(
        timer_config(2),
        4,
        u64::from(TIMER_INT_ENABLE | TIMER_64BIT_MODE)
    ));
    assert_ne!(hpet.timer_config(2).unwrap() & TIMER_64BIT_MODE, 0);
}

#[test]
fn out_of_range_and_wrong_width_accesses_are_rejected() {
    let mut hpet = Hpet::new();
    assert_eq!(hpet.read(MMIO_SIZE as u16, 4), None);
    assert_eq!(hpet.read(CAPS_ID + 1, 4), None);
    assert_eq!(hpet.read(CAPS_ID, 1), None);
    assert_eq!(hpet.read(CAPS_ID, 2), None);
    assert!(!hpet.write(MMIO_SIZE as u16, 4, 0));
    assert!(!hpet.write(CAPS_ID + 2, 4, 0));
    assert!(!hpet.write(CONFIG, 1, 0));
    assert!(!hpet.write(CONFIG, 2, 0));
}

#[test]
fn read_only_registers_refuse_writes() {
    let mut hpet = Hpet::new();
    assert!(!hpet.write(CAPS_ID, 8, 0));
    assert!(!hpet.write(CONFIG, 8, u64::from(CONFIG_ENABLE)));
}

#[test]
fn handles_gpa_covers_only_the_timer_page() {
    assert!(Hpet::handles_gpa(BASE_GPA));
    assert!(Hpet::handles_gpa(BASE_GPA + 0x300));
    assert!(!Hpet::handles_gpa(BASE_GPA + MMIO_SIZE as u64));
    assert!(Hpet::handles_gpa(BASE_GPA + MMIO_SIZE as u64 - 1));
    assert!(!Hpet::handles_gpa(0xFEE0_0000));
}

#[test]
fn minimum_tick_is_a_lower_bound_derived_from_the_period() {
    let minimum = hpet::minimum_tick_from_period();
    assert!(minimum >= 1);
    // Expressed in 100 ns units, one clock period is below one unit, so the
    // architectural minimum tick (0x55) is a safe advertisement.
    assert!(hpet::TABLE_MINIMUM_TICK >= minimum);
}

#[test]
fn acpi_table_is_well_formed() {
    let table = table_bytes();
    assert_eq!(table.len(), hpet::TABLE_LEN);
    assert_eq!(&table[0..4], b"HPET");
    assert_eq!(
        u32::from_le_bytes([table[4], table[5], table[6], table[7]]) as usize,
        hpet::TABLE_LEN
    );
    assert_eq!(table[8], hpet::TABLE_REVISION);
    let sum = table.iter().fold(0u8, |acc, byte| acc.wrapping_add(*byte));
    assert_eq!(sum, 0, "ACPI checksum must make the byte sum zero");
    // Generic address structure: system memory, 64-bit registers, base page.
    assert_eq!(table[36], hpet::GAS_ADDRESS_SPACE_ID);
    assert_eq!(table[37], hpet::GAS_REGISTER_BIT_WIDTH);
    assert_eq!(table[38], hpet::GAS_REGISTER_BIT_OFFSET);
    assert_eq!(table[39], hpet::GAS_ACCESS_SIZE);
    let base = u64::from_le_bytes([
        table[40], table[41], table[42], table[43], table[44], table[45], table[46], table[47],
    ]);
    assert_eq!(base, BASE_GPA);
    let hpet_number = u16::from_le_bytes([table[48], table[49]]);
    assert_eq!(hpet_number, hpet::TABLE_HPET_NUMBER);
    let min_tick = u16::from_le_bytes([table[50], table[51]]);
    assert_eq!(min_tick, hpet::TABLE_MINIMUM_TICK);
    assert_eq!(table[52], hpet::TABLE_PAGE_PROTECTION);
}

#[test]
fn the_table_is_deterministic() {
    assert_eq!(table_bytes(), table_bytes());
}

#[test]
fn adversarial_accesses_do_not_panic() {
    let mut hpet = Hpet::new();
    hpet.write(CONFIG, 4, u64::from(CONFIG_ENABLE));
    for offset in (0..MMIO_SIZE as u16).step_by(4) {
        let _ = hpet.read(offset, 4);
        let _ = hpet.read(offset, 8);
        let _ = hpet.write(offset, 4, u64::MAX);
        let _ = hpet.write(offset, 8, u64::MAX);
    }
    let _ = hpet.advance_ticks(u64::MAX);
    let _ = hpet.advance_femtoseconds(u64::MAX);
    let _ = hpet.irq_asserted();
    assert!(hpet.read(CAPS_ID, 8).is_some());
}

#[test]
fn events_helper_reports_membership() {
    let empty = HpetEvents::empty();
    assert!(empty.is_empty());
    assert!(!empty.contains(0));
}
