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

//! L2: guest local APIC model (real kernel code, not executed).

#[path = "../../kernel/src/s9vm/apic.rs"]
mod apic;

use apic::{
    delivery, reg, shorthand, x2apic, LocalApic, TimerMode, DEFAULT_APIC_BUS_HZ, SVR_ENABLE,
    VERSION_VALUE,
};

#[test]
fn reset_state_is_architectural() {
    let apic = LocalApic::new(3);
    assert_eq!(apic.apic_id(), 3);
    assert_eq!(apic.tpr(), 0);
    assert_eq!(apic.ppr(), 0);
    assert!(apic.enabled());
    assert!(!apic.has_pending());
    assert!(!apic.in_service());
    assert_eq!(apic.mmio_read(reg::VERSION), VERSION_VALUE);
}

#[test]
fn inject_service_eoi_cycle() {
    let mut apic = LocalApic::new(0);
    apic.inject(0x21);
    assert!(apic.has_pending());
    assert_eq!(apic.pending_vector(), Some(0x21));
    assert_eq!(apic.service(), Some(0x21));
    assert!(!apic.has_pending());
    assert!(apic.in_service());
    assert_eq!(apic.ppr(), 0x20);
    apic.eoi();
    assert!(!apic.in_service());
    assert_eq!(apic.ppr(), 0);
}

#[test]
fn tpr_blocks_lower_priority_classes() {
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::TPR, 0x30);
    apic.inject(0x21); // class 2 <= 3: blocked
    assert_eq!(apic.pending_vector(), None);
    apic.inject(0x41); // class 4 > 3: deliverable
    assert_eq!(apic.pending_vector(), Some(0x41));
}

#[test]
fn isr_raises_ppr_and_blocks_same_class() {
    let mut apic = LocalApic::new(0);
    apic.inject(0x30);
    apic.inject(0x31);
    assert_eq!(apic.service(), Some(0x30));
    // Same class as the in-service vector: blocked.
    assert_eq!(apic.pending_vector(), None);
    apic.inject(0x40);
    assert_eq!(apic.pending_vector(), Some(0x40));
}

#[test]
fn disabled_spurious_register_blocks_delivery() {
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::SVR, 0);
    apic.inject(0x80);
    assert!(!apic.enabled());
    assert_eq!(apic.pending_vector(), None);
    apic.mmio_write(reg::SVR, SVR_ENABLE | 0xFF);
    assert!(apic.enabled());
    assert_eq!(apic.pending_vector(), Some(0x80));
}

#[test]
fn reserved_vectors_are_ignored() {
    let mut apic = LocalApic::new(0);
    apic.inject(0x0F);
    assert!(apic.has_pending());
    assert_eq!(apic.pending_vector(), None);
}

#[test]
fn eoi_clears_highest_in_service_first() {
    let mut apic = LocalApic::new(0);
    apic.inject(0x30);
    apic.inject(0x40);
    assert_eq!(apic.service(), Some(0x30));
    assert_eq!(apic.service(), Some(0x40));
    assert_eq!(apic.ppr(), 0x40);
    apic.eoi();
    assert_eq!(apic.ppr(), 0x30);
    apic.eoi();
    assert!(!apic.in_service());
}

#[test]
fn self_ipi_injects_vector() {
    let mut apic = LocalApic::new(0);
    let icr = (shorthand::SELF << 18) | (delivery::FIXED << 8) | 0x55;
    apic.mmio_write(reg::ICR_LOW, icr);
    assert_eq!(apic.pending_vector(), Some(0x55));
}

#[test]
fn mmio_registers_round_trip() {
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::TPR, 0xFFFF_FFFF);
    assert_eq!(apic.tpr(), 0xFF);
    apic.mmio_write(reg::LVT_TIMER, 0x0001_00AB);
    assert_eq!(apic.mmio_read(reg::LVT_TIMER), 0x0001_00AB);
    apic.mmio_write(reg::INITIAL_COUNT, 1234);
    assert_eq!(apic.mmio_read(reg::CURRENT_COUNT), 1234);
    apic.mmio_write(reg::ESR, 0x40);
    assert_eq!(apic.mmio_read(reg::ESR), 0x40);
}

#[test]
fn isr_and_irr_words_use_16_byte_stride() {
    let mut apic = LocalApic::new(0);
    apic.inject(0x40); // word 2
    assert_eq!(apic.mmio_read(reg::IRR + 2 * 16), 0x1);
    assert_eq!(apic.mmio_read(reg::IRR), 0);
    apic.service();
    assert_eq!(apic.mmio_read(reg::ISR + 2 * 16), 0x1);
}

#[test]
fn x2apic_round_trip_and_reserved() {
    let mut apic = LocalApic::new(5);
    assert_eq!(apic.x2apic_read(x2apic::ID), Some(5 << 24));
    assert_eq!(apic.x2apic_read(0x999), None);

    assert!(apic.x2apic_write(x2apic::TPR, 0x40));
    assert_eq!(apic.tpr(), 0x40);
    // Self-IPI via the x2APIC ICR.
    let icr = ((shorthand::SELF as u64) << 18) | ((delivery::FIXED as u64) << 8) | 0x60;
    assert!(apic.x2apic_write(x2apic::ICR, icr));
    assert_eq!(apic.pending_vector(), Some(0x60));
    // SELF-IPI x2APIC.
    assert!(apic.x2apic_write(x2apic::SELF_IPI, 0x70));
    assert_eq!(apic.pending_vector(), Some(0x60));
}

#[test]
fn priority_classes_follow_the_high_nibble() {
    assert_eq!(apic::priority_class(0x00), 0);
    assert_eq!(apic::priority_class(0x1F), 1);
    assert_eq!(apic::priority_class(0xF0), 0xF);
    assert_eq!(apic::priority_class(0xFF), 0xF);
}

/// Programs the LVT timer entry and then the initial count, like a guest.
fn program_timer(apic: &mut LocalApic, mode: u32, vector: u8, masked: bool, initial: u32) {
    let lvt = ((mode & 0x3) << apic::LVT_MODE_SHIFT)
        | if masked { apic::LVT_MASK } else { 0 }
        | u32::from(vector);
    apic.mmio_write(reg::LVT_TIMER, lvt);
    apic.mmio_write(reg::INITIAL_COUNT, initial);
}

#[test]
fn timer_starts_disabled_and_ignores_advance() {
    let mut apic = LocalApic::new(0);
    assert!(!apic.timer_armed());
    assert_eq!(apic.current_count(), 0);
    assert_eq!(apic.timer_mode(), TimerMode::OneShot);
    assert_eq!(apic.timer_vector(), 0);
    apic.advance(u64::MAX);
    assert!(!apic.timer_armed());
    assert!(!apic.has_pending());
}

#[test]
fn timer_programming_sequence_reports_state() {
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::DIVIDE_CONFIG, 0xB); // divide by 1
    program_timer(&mut apic, 0, 0x40, false, 10);
    assert!(apic.timer_armed());
    assert_eq!(apic.timer_mode(), TimerMode::OneShot);
    assert_eq!(apic.timer_vector(), 0x40);
    assert_eq!(apic.timer_divide(), 1);
    assert_eq!(apic.current_count(), 10);
    assert_eq!(apic.mmio_read(reg::CURRENT_COUNT), 10);
}

#[test]
fn one_shot_expires_exactly_once() {
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::DIVIDE_CONFIG, 0xB);
    program_timer(&mut apic, 0, 0x40, false, 5);
    apic.advance(4);
    assert_eq!(apic.current_count(), 1);
    assert!(!apic.has_pending());
    apic.advance(1);
    assert_eq!(apic.current_count(), 0);
    assert!(!apic.timer_armed());
    assert_eq!(apic.pending_vector(), Some(0x40));
    assert_eq!(apic.service(), Some(0x40));
    apic.eoi();
    apic.advance(1000);
    assert!(!apic.has_pending());
    assert!(!apic.timer_armed());
}

#[test]
fn divide_accumulates_sub_tick_remainders() {
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::DIVIDE_CONFIG, 0); // divide by 2
    program_timer(&mut apic, 0, 0x41, false, 10);
    apic.advance(3); // one tick, one input unit kept as remainder
    assert_eq!(apic.current_count(), 9);
    apic.advance(1); // remainder + 1 completes a second tick
    assert_eq!(apic.current_count(), 8);
    assert!(!apic.has_pending());
}

#[test]
fn periodic_reloads_and_raises_each_period() {
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::DIVIDE_CONFIG, 0xB);
    program_timer(&mut apic, 1, 0x42, false, 5);
    apic.advance(5);
    assert_eq!(apic.current_count(), 5);
    assert!(apic.timer_armed());
    assert_eq!(apic.pending_vector(), Some(0x42));
    apic.service();
    apic.eoi();
    apic.advance(4);
    assert_eq!(apic.current_count(), 1);
    assert!(!apic.has_pending());
    apic.advance(1);
    assert_eq!(apic.pending_vector(), Some(0x42));
    assert_eq!(apic.current_count(), 5);
}

#[test]
fn periodic_large_advance_wraps_count_and_raises_once() {
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::DIVIDE_CONFIG, 0xB);
    program_timer(&mut apic, 1, 0x43, false, 4);
    apic.advance(10); // 1 expiry at 4, then 6 more: 2 ticks into the next period
    assert_eq!(apic.current_count(), 2);
    assert!(apic.timer_armed());
    assert_eq!(apic.pending_vector(), Some(0x43));
}

#[test]
fn masked_one_shot_counts_but_does_not_raise() {
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::DIVIDE_CONFIG, 0xB);
    program_timer(&mut apic, 0, 0x44, true, 3);
    apic.advance(3);
    assert_eq!(apic.current_count(), 0);
    assert!(!apic.timer_armed());
    assert!(!apic.has_pending());
}

#[test]
fn masked_periodic_reloads_without_raising() {
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::DIVIDE_CONFIG, 0xB);
    program_timer(&mut apic, 1, 0x45, true, 3);
    apic.advance(3);
    assert_eq!(apic.current_count(), 3);
    assert!(apic.timer_armed());
    assert!(!apic.has_pending());
}

#[test]
fn initial_count_zero_disables_timer() {
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::DIVIDE_CONFIG, 0xB);
    program_timer(&mut apic, 1, 0x46, false, 5);
    apic.mmio_write(reg::INITIAL_COUNT, 0);
    assert!(!apic.timer_armed());
    apic.advance(100);
    assert!(!apic.has_pending());
}

#[test]
fn divide_values_scale_elapsed_cycles() {
    let cases = [
        (0xBu32, 1u32, 92u32),
        (0, 2, 96),
        (1, 4, 98),
        (2, 8, 99),
        (3, 16, 100),
        (8, 32, 100),
        (9, 64, 100),
        (10, 128, 100),
    ];
    for (config, divisor, expected) in cases {
        let mut apic = LocalApic::new(0);
        apic.mmio_write(reg::DIVIDE_CONFIG, config);
        assert_eq!(apic.timer_divide(), divisor);
        program_timer(&mut apic, 0, 0x47, false, 100);
        apic.advance(8);
        assert_eq!(apic.current_count(), expected);
    }
}

#[test]
fn divide_config_masks_reserved_bits() {
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::DIVIDE_CONFIG, 0xFFFF_FFFF);
    assert_eq!(apic.mmio_read(reg::DIVIDE_CONFIG), 0xB);
    assert_eq!(apic.timer_divide(), 1);
}

#[test]
fn current_count_reads_through_mmio_and_x2apic() {
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::DIVIDE_CONFIG, 0xB);
    program_timer(&mut apic, 0, 0x48, false, 10);
    apic.advance(3);
    assert_eq!(apic.mmio_read(reg::CURRENT_COUNT), 7);
    assert_eq!(apic.x2apic_read(x2apic::CURRENT_COUNT), Some(7));
}

#[test]
fn huge_counts_and_cycle_deltas_saturate() {
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::DIVIDE_CONFIG, 0xB);
    program_timer(&mut apic, 1, 0x49, false, u32::MAX);
    apic.advance(u64::MAX);
    assert!(apic.timer_armed());
    assert!(apic.current_count() >= 1);
    assert_eq!(apic.pending_vector(), Some(0x49));

    let mut one_shot = LocalApic::new(0);
    one_shot.mmio_write(reg::DIVIDE_CONFIG, 0);
    program_timer(&mut one_shot, 0, 0x4A, false, u32::MAX);
    one_shot.advance(u64::MAX);
    assert_eq!(one_shot.current_count(), 0);
    assert!(!one_shot.timer_armed());
}

#[test]
fn reserved_lvt_modes_are_total() {
    let mut apic = LocalApic::new(0);
    // mode 3 is reserved; mask and vector bits are set to show they are ignored.
    apic.mmio_write(reg::LVT_TIMER, 0xFFFF_FFFF);
    apic.mmio_write(reg::INITIAL_COUNT, 42);
    assert_eq!(apic.timer_mode(), TimerMode::Reserved);
    assert!(!apic.timer_armed());
    apic.advance(1000);
    assert!(!apic.timer_armed());
    assert!(!apic.has_pending());
}

#[test]
fn tsc_deadline_fires_at_deadline() {
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::LVT_TIMER, (2 << apic::LVT_MODE_SHIFT) | 0x50);
    apic.set_tsc(1000);
    apic.set_tsc_deadline(1100);
    assert!(apic.timer_armed());
    apic.advance(50);
    assert!(!apic.has_pending());
    apic.advance(49);
    assert!(!apic.has_pending());
    apic.advance(1);
    assert!(!apic.timer_armed());
    assert_eq!(apic.pending_vector(), Some(0x50));
    apic.service();
    apic.eoi();
    apic.advance(10_000);
    assert!(!apic.has_pending());
    assert!(!apic.timer_armed());
}

#[test]
fn tsc_deadline_past_fires_immediately_and_zero_disables() {
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::LVT_TIMER, (2 << apic::LVT_MODE_SHIFT) | 0x51);
    apic.set_tsc(200);
    apic.set_tsc_deadline(100);
    assert!(apic.tsc_deadline() == 100);
    assert!(!apic.timer_armed());
    assert_eq!(apic.pending_vector(), Some(0x51));
    apic.set_tsc_deadline(0);
    assert!(!apic.timer_armed());
}

#[test]
fn masked_tsc_deadline_does_not_raise() {
    let mut apic = LocalApic::new(0);
    apic.mmio_write(
        reg::LVT_TIMER,
        (2 << apic::LVT_MODE_SHIFT) | apic::LVT_MASK | 0x52,
    );
    apic.set_tsc(0);
    apic.set_tsc_deadline(10);
    apic.advance(10);
    assert!(!apic.timer_armed());
    assert!(!apic.has_pending());
}

#[test]
fn tsc_deadline_written_before_mode_is_armed_when_mode_is_selected() {
    let mut apic = LocalApic::new(0);
    apic.set_tsc(100);
    // The MSR is written while the LVT entry is still in one-shot mode.
    apic.set_tsc_deadline(150);
    assert!(!apic.timer_armed());
    // Selecting TSC-deadline mode applies the pending deadline.
    apic.mmio_write(reg::LVT_TIMER, (2 << apic::LVT_MODE_SHIFT) | 0x53);
    assert!(apic.timer_armed());
    apic.advance(50);
    assert_eq!(apic.pending_vector(), Some(0x53));
    assert!(!apic.timer_armed());
}

#[test]
fn timer_eoi_clears_the_in_service_vector() {
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::DIVIDE_CONFIG, 0xB);
    program_timer(&mut apic, 0, 0x60, false, 1);
    apic.advance(1);
    assert_eq!(apic.service(), Some(0x60));
    assert!(apic.in_service());
    apic.eoi();
    assert!(!apic.in_service());
}

#[test]
fn x2apic_timer_programming_and_count_read() {
    let mut apic = LocalApic::new(0);
    assert!(apic.x2apic_write(x2apic::DIVIDE_CONFIG, 0xB));
    assert!(apic.x2apic_write(
        x2apic::LVT_TIMER,
        u64::from((1u32 << apic::LVT_MODE_SHIFT) | 0x61)
    ));
    assert!(apic.x2apic_write(x2apic::INITIAL_COUNT, 8));
    apic.advance(3);
    assert_eq!(apic.x2apic_read(x2apic::CURRENT_COUNT), Some(5));
    apic.advance(5);
    assert_eq!(apic.pending_vector(), Some(0x61));
    assert_eq!(apic.x2apic_read(x2apic::CURRENT_COUNT), Some(8));
}

#[test]
fn default_apic_bus_frequency_is_the_documented_policy() {
    let apic = LocalApic::new(0);
    assert_eq!(apic.apic_bus_hz(), DEFAULT_APIC_BUS_HZ);
    assert_eq!(DEFAULT_APIC_BUS_HZ, 100_000_000);
}

#[test]
fn advance_tsc_scales_tsc_cycles_to_bus_ticks() {
    // 3 GHz host TSC, 100 MHz APIC bus, divide by 1.
    // 3_000_000 cycles = 1 ms = 100_000 bus ticks.
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::DIVIDE_CONFIG, 0xB);
    program_timer(&mut apic, 0, 0x70, false, 1_000_000);
    apic.advance_tsc(3_000_000, 3_000_000_000);
    assert_eq!(apic.current_count(), 900_000);
    assert!(apic.timer_armed());

    // The same number of raw APIC input ticks would have expired the timer:
    // this is exactly the unit bug the conversion fixes.
    let mut raw = LocalApic::new(0);
    raw.mmio_write(reg::DIVIDE_CONFIG, 0xB);
    program_timer(&mut raw, 0, 0x70, false, 1_000_000);
    raw.advance(3_000_000);
    assert_eq!(raw.current_count(), 0);
    assert!(!raw.timer_armed());
}

#[test]
fn advance_tsc_uses_the_configured_bus_frequency() {
    // 2.4 GHz TSC with a 24 MHz core-crystal bus: 2_400_000 cycles = 1 ms =
    // 24_000 bus ticks.
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::DIVIDE_CONFIG, 0xB);
    apic.set_apic_bus_hz(24_000_000);
    assert_eq!(apic.apic_bus_hz(), 24_000_000);
    program_timer(&mut apic, 0, 0x71, false, 1_000_000);
    apic.advance_tsc(2_400_000, 2_400_000_000);
    assert_eq!(apic.current_count(), 976_000);
}

#[test]
fn advance_tsc_carries_the_conversion_remainder() {
    // 10 TSC cycles at 3 GHz = 10/30 of a bus tick; three calls make one tick.
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::DIVIDE_CONFIG, 0xB);
    program_timer(&mut apic, 0, 0x72, false, 1_000_000);
    apic.advance_tsc(10, 3_000_000_000);
    apic.advance_tsc(10, 3_000_000_000);
    assert_eq!(apic.current_count(), 1_000_000);
    apic.advance_tsc(10, 3_000_000_000);
    assert_eq!(apic.current_count(), 999_999);
}

#[test]
fn advance_tsc_zero_inputs_are_safe() {
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::DIVIDE_CONFIG, 0xB);
    program_timer(&mut apic, 0, 0x73, false, 1_000_000);
    // Unknown TSC frequency: no conversion, no panic, no count change.
    apic.advance_tsc(1_000_000, 0);
    assert_eq!(apic.current_count(), 1_000_000);
    // Zero bus frequency: same behaviour.
    apic.set_apic_bus_hz(0);
    apic.advance_tsc(1_000_000, 3_000_000_000);
    assert_eq!(apic.current_count(), 1_000_000);
}

#[test]
fn advance_tsc_saturates_on_huge_deltas() {
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::DIVIDE_CONFIG, 0xB);
    program_timer(&mut apic, 0, 0x74, false, u32::MAX);
    // 1 Hz TSC: the product saturates instead of overflowing.
    apic.advance_tsc(u64::MAX, 1);
    assert_eq!(apic.current_count(), 0);
    assert!(!apic.timer_armed());
    assert_eq!(apic.pending_vector(), Some(0x74));
}

#[test]
fn advance_tsc_keeps_tsc_deadline_in_tsc_units() {
    // TSC-deadline mode uses absolute TSC values, never the bus conversion:
    // 1500 TSC cycles must expire a deadline of 1000 even at a slow bus.
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::LVT_TIMER, (2 << apic::LVT_MODE_SHIFT) | 0x75);
    apic.set_tsc_deadline(1000);
    apic.advance_tsc(1500, 100_000_000);
    assert!(!apic.timer_armed());
    assert_eq!(apic.pending_vector(), Some(0x75));
}
