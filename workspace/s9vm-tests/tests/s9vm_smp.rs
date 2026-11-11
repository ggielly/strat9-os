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

//! L2: s9vm guest SMP bring-up model (real kernel code).
//!
//! The tests drive the ICR decoding, the INIT/SIPI state machine, the delayed
//! de-assert/retry/completion events and the destination expansion.

#[path = "../../kernel/src/s9vm/smp.rs"]
mod smp;

use smp::{
    sipi_vector_address, sipi_vector_valid, us_to_ticks, DeliveryMode, DestinationMode, Icr,
    IpiKind, LogicalMode, Shorthand, SmpController, SmpError, SmpEventKind, TriggerMode, VCpuState,
    BSP_LAPIC_ID, DEFAULT_TSC_HZ, INIT_DEASSERT_DELAY_US, MAX_VCPUS,
    MODELLED_INIT_DEASSERT_DELAY_US, MODELLED_SIPI_MAX_RETRIES, MODELLED_SIPI_RETRY_DELAY_US,
    SIPI_MAX_ADDRESS, SIPI_MAX_RETRIES, SIPI_RETRY_DELAY_US, SIPI_VECTOR_STEP, STARTUP_DELAY_TICKS,
};

/// 1 tick per microsecond: the delays are then expressed directly in ticks.
const TSC_HZ: u64 = 1_000_000;

/// Controller with BSP + three APs.
fn controller() -> SmpController {
    SmpController::with_lapic_ids(TSC_HZ, &[0, 1, 2, 3])
}

/// INIT ICR halves for a physical destination.
fn init_icr(apic_id: u8) -> (u32, u32) {
    ((5 << 8) | (1 << 14), (apic_id as u32) << 24)
}

/// STARTUP ICR halves for a physical destination.
fn startup_icr(apic_id: u8, vector: u8) -> (u32, u32) {
    ((6 << 8) | vector as u32, (apic_id as u32) << 24)
}

/// Fixed-vector ICR halves for a physical destination.
fn fixed_icr(apic_id: u8, vector: u8) -> (u32, u32) {
    (vector as u32, (apic_id as u32) << 24)
}

/// First effect target, when present.
fn first_target(effects: &smp::Effects) -> Option<u8> {
    effects.as_slice().first().map(|effect| effect.target)
}

#[test]
fn constants_are_sane() {
    assert_eq!(SIPI_VECTOR_STEP, 0x1000);
    assert_eq!(INIT_DEASSERT_DELAY_US, 10_000);
    assert_eq!(SIPI_RETRY_DELAY_US, 200);
    assert_eq!(SIPI_MAX_RETRIES, 2);
    assert_eq!(BSP_LAPIC_ID, 0);
    assert!(MAX_VCPUS >= 8);
    assert_eq!(MAX_VCPUS * 3, smp::MAX_EVENTS);
    assert_eq!(MODELLED_INIT_DEASSERT_DELAY_US, INIT_DEASSERT_DELAY_US);
    assert_eq!(MODELLED_SIPI_RETRY_DELAY_US, SIPI_RETRY_DELAY_US);
    assert_eq!(MODELLED_SIPI_MAX_RETRIES, SIPI_MAX_RETRIES);
    assert_eq!(STARTUP_DELAY_TICKS, 1);
    assert!(DEFAULT_TSC_HZ >= 1_000_000);
}

#[test]
fn sipi_vector_addresses_stay_below_one_mib() {
    assert_eq!(sipi_vector_address(0x00), 0);
    assert_eq!(sipi_vector_address(0x01), 0x1000);
    assert_eq!(sipi_vector_address(0x7F), 0x7F000);
    assert_eq!(sipi_vector_address(0xFF), 0x0FF000);
    assert!(sipi_vector_address(0xFF) <= SIPI_MAX_ADDRESS);
    for vector in 0..=u8::MAX {
        assert!(sipi_vector_valid(vector));
        assert!(sipi_vector_address(vector) <= SIPI_MAX_ADDRESS);
    }
}

#[test]
fn converts_microseconds_to_ticks() {
    assert_eq!(us_to_ticks(1_000_000, 200), 200);
    assert_eq!(us_to_ticks(1_000_000_000, 10_000), 10_000_000);
    assert_eq!(us_to_ticks(0, 10_000), 0);
    let controller = SmpController::new(DEFAULT_TSC_HZ);
    assert_eq!(controller.ticks_for_us(1_000_000), 1_000_000_000);
    assert_eq!(controller.tsc_hz(), DEFAULT_TSC_HZ);
}

#[test]
fn icr_decodes_fixed_physical_delivery() {
    let icr = Icr::new(0x20, 0x02 << 24);
    assert_eq!(icr.vector(), 0x20);
    assert_eq!(icr.delivery_mode(), DeliveryMode::Fixed);
    assert_eq!(icr.destination_mode(), DestinationMode::Physical);
    assert_eq!(icr.destination_field(), 2);
    assert_eq!(icr.shorthand(), Shorthand::None);
    assert_eq!(icr.trigger_mode(), TriggerMode::Edge);
    assert!(!icr.level_assert());
    assert!(!icr.delivery_status_pending());
    let pending = Icr::new(0x20 | (1 << 12), 0);
    assert!(pending.delivery_status_pending());
    assert_eq!(icr.kind(), Ok(IpiKind::Fixed { vector: 0x20 }));
}

#[test]
fn icr_decodes_lowest_priority_delivery() {
    let icr = Icr::new((1 << 8) | 0x40, 0);
    assert_eq!(icr.delivery_mode(), DeliveryMode::LowestPriority);
    assert_eq!(icr.kind(), Ok(IpiKind::LowestPriority { vector: 0x40 }));
}

#[test]
fn icr_decodes_smi_and_nmi() {
    assert_eq!(Icr::new(2 << 8, 0).kind(), Ok(IpiKind::Smi));
    assert_eq!(Icr::new(4 << 8, 0).kind(), Ok(IpiKind::Nmi));
}

#[test]
fn icr_decodes_init_assert_and_deassert_levels() {
    let assert = Icr::new((5 << 8) | (1 << 14), 0);
    assert_eq!(assert.delivery_mode(), DeliveryMode::Init);
    assert_eq!(assert.trigger_mode(), TriggerMode::Edge);
    assert!(assert.level_assert());
    assert_eq!(assert.kind(), Ok(IpiKind::Init { level_assert: true }));

    // Level-triggered INIT (bit 15 set) keeps the same typed decode.
    let level = Icr::new((5 << 8) | (1 << 15) | (1 << 14), 0);
    assert_eq!(level.trigger_mode(), TriggerMode::Level);
    assert_eq!(level.kind(), Ok(IpiKind::Init { level_assert: true }));

    let deassert = Icr::new(5 << 8, 0);
    assert_eq!(
        deassert.kind(),
        Ok(IpiKind::Init {
            level_assert: false
        })
    );
}

#[test]
fn icr_decodes_startup_and_extint() {
    assert_eq!(
        Icr::new((6 << 8) | 0x08, 0).kind(),
        Ok(IpiKind::Startup { vector: 0x08 })
    );
    assert_eq!(Icr::new((7 << 8) | 0x30, 0).kind(), Ok(IpiKind::ExtInt));
}

#[test]
fn icr_rejects_reserved_delivery_mode() {
    let icr = Icr::new(3 << 8, 0);
    assert_eq!(icr.delivery_mode(), DeliveryMode::Reserved);
    assert_eq!(icr.kind(), Err(SmpError::ReservedDeliveryMode));
}

#[test]
fn icr_decodes_all_shorthands() {
    assert_eq!(Icr::new(0, 0).shorthand(), Shorthand::None);
    assert_eq!(Icr::new(1 << 18, 0).shorthand(), Shorthand::SelfOnly);
    assert_eq!(
        Icr::new(2 << 18, 0).shorthand(),
        Shorthand::AllIncludingSelf
    );
    assert_eq!(
        Icr::new(3 << 18, 0).shorthand(),
        Shorthand::AllExcludingSelf
    );
}

#[test]
fn icr_decodes_logical_destination_mode() {
    let icr = Icr::new(1 << 11, 0xAB << 24);
    assert_eq!(icr.destination_mode(), DestinationMode::Logical);
    assert_eq!(icr.destination_field(), 0xAB);
}

#[test]
fn bsp_only_controller_starts_running() {
    let controller = SmpController::new(TSC_HZ);
    assert_eq!(controller.vcpu_count(), 1);
    assert_eq!(controller.lapic_ids(), &[BSP_LAPIC_ID]);
    assert_eq!(controller.bsp_lapic_id(), BSP_LAPIC_ID);
    assert_eq!(controller.state(BSP_LAPIC_ID), Some(VCpuState::Running));
    assert!(controller.is_running(BSP_LAPIC_ID));
    assert!(controller.validate_against_madt(1));
    assert!(!controller.validate_against_madt(2));
    assert_eq!(controller.count_in_state(VCpuState::Running), 1);
}

#[test]
fn with_lapic_ids_marks_aps_offline() {
    let controller = controller();
    assert_eq!(controller.vcpu_count(), 4);
    assert_eq!(controller.lapic_ids(), &[0, 1, 2, 3]);
    assert_eq!(controller.state(0), Some(VCpuState::Running));
    assert_eq!(controller.state(1), Some(VCpuState::Offline));
    assert_eq!(controller.state(2), Some(VCpuState::Offline));
    assert_eq!(controller.state(9), None);
    assert_eq!(controller.state_at(3), Some(VCpuState::Offline));
    assert_eq!(controller.state_at(9), None);
    assert_eq!(controller.count_in_state(VCpuState::Offline), 3);
    assert!(controller.validate_against_madt(4));
    assert!(!controller.validate_against_madt(3));
}

#[test]
fn add_vcpu_rejects_duplicates_and_bounds() {
    let mut controller = SmpController::new(TSC_HZ);
    assert!(controller.add_vcpu(5));
    assert!(!controller.add_vcpu(5));
    assert_eq!(controller.vcpu_count(), 2);
    assert_eq!(controller.state(5), Some(VCpuState::Offline));

    let mut full = SmpController::new(TSC_HZ);
    for id in 1..MAX_VCPUS as u8 {
        assert!(full.add_vcpu(id), "add {id}");
    }
    assert_eq!(full.vcpu_count(), MAX_VCPUS);
    assert!(!full.add_vcpu(200));
}

#[test]
fn init_moves_target_to_wait_for_sipi() {
    let mut controller = controller();
    let (low, high) = init_icr(1);
    let effects = controller.send_ipi(0, low, high, 0);

    assert_eq!(effects.len(), 1);
    assert_eq!(effects.as_slice()[0].target, 1);
    assert_eq!(
        effects.as_slice()[0].kind,
        IpiKind::Init { level_assert: true }
    );
    assert_eq!(effects.as_slice()[0].deliver_at, 0);
    assert_eq!(controller.state(1), Some(VCpuState::WaitForSipi));
    assert_eq!(controller.last_error(), None);
}

#[test]
fn init_deassert_is_due_after_the_modeled_delay() {
    let mut controller = controller();
    controller.send_ipi(0, init_icr(1).0, init_icr(1).1, 0);

    let early = controller.advance(INIT_DEASSERT_DELAY_US - 1);
    assert!(early.is_empty());

    let due = controller.advance(INIT_DEASSERT_DELAY_US);
    assert_eq!(due.len(), 1);
    assert_eq!(due.iter().count(), 1);
    assert_eq!(due.as_slice()[0].target, 1);
    assert_eq!(due.as_slice()[0].kind, SmpEventKind::InitDeassert);
    assert_eq!(due.as_slice()[0].at, INIT_DEASSERT_DELAY_US);
    assert!(controller.advance(INIT_DEASSERT_DELAY_US * 2).is_empty());
}

#[test]
fn double_init_rearms_the_deassert_delay() {
    let mut controller = controller();
    controller.send_ipi(0, init_icr(1).0, init_icr(1).1, 0);
    controller.send_ipi(0, init_icr(1).0, init_icr(1).1, 5_000);

    assert!(controller.advance(10_000).is_empty());
    let due = controller.advance(15_000);
    assert_eq!(due.len(), 1);
    assert_eq!(due.as_slice()[0].kind, SmpEventKind::InitDeassert);
}

#[test]
fn sipi_without_init_is_ignored() {
    let mut controller = controller();
    let effects = controller.send_ipi(0, startup_icr(1, 0x08).0, startup_icr(1, 0x08).1, 0);
    assert!(effects.is_empty());
    assert_eq!(controller.last_error(), Some(SmpError::SipiWithoutInit));
    assert_eq!(controller.state(1), Some(VCpuState::Offline));
}

#[test]
fn sipi_starts_the_ap_and_runs_after_the_fetch_delay() {
    let mut controller = controller();
    controller.send_ipi(0, init_icr(1).0, init_icr(1).1, 0);
    // Consume the de-assert event first.
    controller.advance(INIT_DEASSERT_DELAY_US);

    let (low, high) = startup_icr(1, 0x08);
    let effects = controller.send_ipi(0, low, high, 10_000);
    assert_eq!(effects.len(), 1);
    assert_eq!(
        effects.as_slice()[0].kind,
        IpiKind::Startup { vector: 0x08 }
    );
    assert_eq!(controller.state(1), Some(VCpuState::Starting));
    assert_eq!(controller.sipi_vector(1), Some(0x08));

    let events = controller.advance(10_000 + STARTUP_DELAY_TICKS);
    assert_eq!(events.len(), 1);
    assert_eq!(events.as_slice()[0].kind, SmpEventKind::StartupComplete);
    assert_eq!(controller.state(1), Some(VCpuState::Running));
    assert!(controller.is_running(1));
}

#[test]
fn startup_retries_then_fails_on_a_stalled_start() {
    let mut controller = controller();
    // Delay the fetch so the retry checks happen while the vCPU is Starting.
    controller.set_startup_delay_ticks(10_000);
    let (init, sipi) = controller.bring_up_ap(1, 0x08, 0);
    assert_eq!(init.len(), 1);
    assert_eq!(sipi.len(), 1);
    assert_eq!(sipi.as_slice()[0].deliver_at, INIT_DEASSERT_DELAY_US);

    // De-assert, then retry 1 and retry 2, then failure.
    let deassert = controller.advance(INIT_DEASSERT_DELAY_US);
    assert_eq!(deassert.as_slice()[0].kind, SmpEventKind::InitDeassert);
    let retry1 = controller.advance(10_200);
    assert_eq!(
        retry1.as_slice()[0].kind,
        SmpEventKind::SipiRetry {
            vector: 0x08,
            attempt: 1
        }
    );
    assert_eq!(controller.retries(1), Some(1));
    let retry2 = controller.advance(10_400);
    assert_eq!(
        retry2.as_slice()[0].kind,
        SmpEventKind::SipiRetry {
            vector: 0x08,
            attempt: 2
        }
    );
    assert_eq!(controller.retries(1), Some(2));
    let failed = controller.advance(10_600);
    assert_eq!(failed.as_slice()[0].kind, SmpEventKind::StartupFailed);
    assert_eq!(controller.state(1), Some(VCpuState::Offline));
}

#[test]
fn retry_check_is_cancelled_once_the_ap_is_running() {
    let mut controller = controller();
    controller.bring_up_ap(1, 0x08, 0);
    controller.advance(INIT_DEASSERT_DELAY_US);
    let complete = controller.advance(10_001);
    assert_eq!(complete.as_slice()[0].kind, SmpEventKind::StartupComplete);
    // The retry deadline (10_200) no longer produces an event.
    assert!(controller.advance(10_200).is_empty());
}

#[test]
fn bring_up_ap_returns_init_and_startup_effects() {
    let mut controller = controller();
    let (init, sipi) = controller.bring_up_ap(2, 0x10, 0);

    assert_eq!(init.len(), 1);
    assert_eq!(init.as_slice()[0].target, 2);
    assert_eq!(
        init.as_slice()[0].kind,
        IpiKind::Init { level_assert: true }
    );
    assert_eq!(init.as_slice()[0].deliver_at, 0);

    assert_eq!(sipi.len(), 1);
    assert_eq!(sipi.as_slice()[0].target, 2);
    assert_eq!(sipi.as_slice()[0].kind, IpiKind::Startup { vector: 0x10 });
    assert_eq!(sipi.as_slice()[0].deliver_at, INIT_DEASSERT_DELAY_US);
    assert_eq!(controller.state(2), Some(VCpuState::Starting));

    controller.advance(INIT_DEASSERT_DELAY_US);
    controller.advance(INIT_DEASSERT_DELAY_US + STARTUP_DELAY_TICKS);
    assert_eq!(controller.state(2), Some(VCpuState::Running));
}

#[test]
fn self_shorthand_targets_only_the_sender() {
    let mut controller = controller();
    let (low, _) = fixed_icr(0, 0x30);
    let effects = controller.send_ipi(1, low | (1 << 18), 0, 0);
    assert_eq!(effects.len(), 1);
    assert_eq!(first_target(&effects), Some(1));
    assert_eq!(effects.as_slice()[0].kind, IpiKind::Fixed { vector: 0x30 });
}

#[test]
fn all_including_self_expands_to_every_vcpu() {
    let mut controller = controller();
    let (low, _) = fixed_icr(0, 0x30);
    let effects = controller.send_ipi(1, low | (2 << 18), 0, 0);
    let targets: Vec<u8> = effects.iter().map(|effect| effect.target).collect();
    assert_eq!(targets, vec![0, 1, 2, 3]);
}

#[test]
fn all_excluding_self_skips_the_sender() {
    let mut controller = controller();
    let (low, _) = fixed_icr(0, 0x30);
    let effects = controller.send_ipi(2, low | (3 << 18), 0, 0);
    let targets: Vec<u8> = effects.iter().map(|effect| effect.target).collect();
    assert_eq!(targets, vec![0, 1, 3]);
}

#[test]
fn physical_destination_filtering() {
    let mut controller = controller();
    let (low, high) = fixed_icr(2, 0x20);
    let effects = controller.send_ipi(0, low, high, 0);
    assert_eq!(effects.len(), 1);
    assert_eq!(first_target(&effects), Some(2));

    // Unknown physical destination: no effect, typed error.
    let (low, high) = fixed_icr(9, 0x20);
    let absent = controller.send_ipi(0, low, high, 0);
    assert!(absent.is_empty());
    assert_eq!(
        controller.last_error(),
        Some(SmpError::DestinationUnavailable)
    );
}

#[test]
fn logical_flat_destination_uses_an_apic_mask() {
    let mut controller = controller();
    // Logical mode, destination field bit 0 and bit 2 -> APIC ids 0 and 2.
    let low = 0x20 | (1 << 11);
    let high = 0b0101u32 << 24;
    let effects = controller.send_ipi(1, low, high, 0);
    let targets: Vec<u8> = effects.iter().map(|effect| effect.target).collect();
    assert_eq!(targets, vec![0, 2]);
}

#[test]
fn logical_cluster_mode_is_rejected() {
    let mut controller = controller();
    controller.set_logical_mode(LogicalMode::Cluster);
    assert_eq!(controller.logical_mode(), LogicalMode::Cluster);
    let low = 0x20 | (1 << 11);
    let effects = controller.send_ipi(0, low, 1 << 24, 0);
    assert!(effects.is_empty());
    assert_eq!(
        controller.last_error(),
        Some(SmpError::ClusterModeUnsupported)
    );
}

#[test]
fn lowest_priority_selects_the_lowest_apic_id() {
    let mut controller = controller();
    let low = (1 << 8) | 0x40 | (2 << 18);
    let effects = controller.send_ipi(3, low, 0, 0);
    assert_eq!(effects.len(), 1);
    assert_eq!(first_target(&effects), Some(0));
    assert_eq!(
        effects.as_slice()[0].kind,
        IpiKind::LowestPriority { vector: 0x40 }
    );
}

#[test]
fn unknown_source_is_reported() {
    let mut controller = controller();
    let (low, high) = fixed_icr(1, 0x20);
    let effects = controller.send_ipi(9, low, high, 0);
    assert!(effects.is_empty());
    assert_eq!(controller.last_error(), Some(SmpError::UnknownSource));
}

#[test]
fn init_to_self_is_ignored() {
    let mut controller = controller();
    let (low, high) = init_icr(1);
    let effects = controller.send_ipi(1, low, high, 0);
    assert!(effects.is_empty());
    assert_eq!(controller.last_error(), Some(SmpError::InitToSelf));
    assert_eq!(controller.state(1), Some(VCpuState::Offline));
}

#[test]
fn broadcast_init_skips_the_sender() {
    let mut controller = controller();
    let low = (5 << 8) | (1 << 14) | (2 << 18);
    let effects = controller.send_ipi(0, low, 0, 0);
    let targets: Vec<u8> = effects.iter().map(|effect| effect.target).collect();
    assert_eq!(targets, vec![1, 2, 3]);
    assert_eq!(controller.count_in_state(VCpuState::WaitForSipi), 3);
    assert_eq!(controller.state(0), Some(VCpuState::Running));
}

#[test]
fn state_query_and_halt_helpers() {
    let mut controller = controller();
    assert_eq!(controller.count_in_state(VCpuState::Running), 1);
    assert!(controller.set_halted(0, true));
    assert_eq!(controller.state(0), Some(VCpuState::Halted));
    assert!(!controller.set_halted(0, true));
    assert!(controller.set_halted(0, false));
    assert_eq!(controller.state(0), Some(VCpuState::Running));
    assert!(!controller.set_halted(1, true));
    assert!(!controller.set_halted(9, true));
}

#[test]
fn no_panic_on_arbitrary_icr_values() {
    let mut controller = controller();
    let patterns = [
        0u32,
        1,
        0xFF,
        0xFFFF,
        0xFFFF_FFFF,
        0x0008_0000,
        0x0010_0000,
        0xDEAD_BEEF,
        0x8000_0000,
    ];
    for &low in &patterns {
        for &high in &patterns {
            let _ = controller.send_ipi(0, low, high, 0);
            let _ = controller.advance(1_000);
        }
    }
    // Dense sweep of the low double word.
    for low in (0..=u32::MAX).step_by(0x0101_0101) {
        let _ = controller.send_ipi(1, low, 0xA5A5_A5A5, 0);
    }
}
