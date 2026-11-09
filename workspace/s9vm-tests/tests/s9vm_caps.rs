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

//! L2: decoding of s9vm hardware capabilities (real kernel code).

extern crate alloc;

#[path = "../../kernel/src/s9vm/caps.rs"]
mod caps;

use caps::{
    control_bits, ept_vpid_cap, AllowedControls, CapsError, HwCaps, MsrSnapshot,
    FEATURE_CONTROL_ENABLE_OUTSIDE_SMX, FEATURE_CONTROL_LOCKED, MSR_BASIC,
    MSR_CR0_FIXED0, MSR_CR0_FIXED1, MSR_CR4_FIXED0, MSR_CR4_FIXED1, MSR_ENTRY_CONTROLS,
    MSR_EPT_VPID_CAP, MSR_EXIT_CONTROLS, MSR_FEATURE_CONTROL, MSR_MISC, MSR_PIN_BASED,
    MSR_PRIMARY_PROC_BASED, MSR_SECONDARY_PROC_BASED, MSR_TRUE_ENTRY_CONTROLS,
    MSR_TRUE_EXIT_CONTROLS, MSR_TRUE_PIN_BASED, MSR_TRUE_PRIMARY_PROC_BASED,
};

/// Synthetic snapshot: full control over the decoded values.
fn snapshot(values: &[(u32, u64)]) -> MsrSnapshot {
    MsrSnapshot::from_reader(|msr| {
        values
            .iter()
            .find(|(key, _)| *key == msr)
            .map(|(_, value)| *value)
            .unwrap_or(0)
    })
}

fn basic_msr(revision: u32, size: u16, memory_type: u8, true_controls: bool) -> u64 {
    let mut value = revision as u64;
    value |= (size as u64) << 32;
    value |= (memory_type as u64) << 50;
    if true_controls {
        value |= 1 << 55;
    }
    value
}

#[test]
fn rejects_when_feature_control_disallows_activation() {
    let snap = snapshot(&[(MSR_FEATURE_CONTROL, FEATURE_CONTROL_LOCKED)]);
    let caps = HwCaps::from_snapshot(&snap, true);
    assert!(!caps.allowed);
    assert_eq!(caps.validate(), Err(CapsError::LockedByFirmware));
}

#[test]
fn rejects_without_cpuid_flag() {
    let snap = snapshot(&[(
        MSR_FEATURE_CONTROL,
        FEATURE_CONTROL_ENABLE_OUTSIDE_SMX | FEATURE_CONTROL_LOCKED,
    )]);
    let caps = HwCaps::from_snapshot(&snap, false);
    assert!(!caps.allowed);
}

#[test]
fn decodes_control_block_identity() {
    let snap = snapshot(&[
        (
            MSR_FEATURE_CONTROL,
            FEATURE_CONTROL_ENABLE_OUTSIDE_SMX | FEATURE_CONTROL_LOCKED,
        ),
        (MSR_BASIC, basic_msr(0x12, 4096, 6, false)),
        (MSR_SECONDARY_PROC_BASED, (u64::MAX & !0) | 0),
        (MSR_EPT_VPID_CAP, 0),
    ]);
    let caps = HwCaps::from_snapshot(&snap, true);
    assert_eq!(caps.control_block_revision, 0x12);
    assert_eq!(caps.control_block_size, 4096);
    assert_eq!(caps.control_block_memory_type, 6);
    assert!(!caps.has_true_controls);
}

#[test]
fn detects_ept_and_vpid_from_allowed_masks() {
    // Low bits = mandatory, high bits = allowed.
    let secondary = (control_bits::PROC2_ENABLE_EPT as u64)
        | ((control_bits::PROC2_ENABLE_EPT | control_bits::PROC2_ENABLE_VPID) as u64) << 32;
    let ept_vpid = ept_vpid_cap::WALK_LENGTH_4
        | ept_vpid_cap::MEMTYPE_WB
        | ept_vpid_cap::PAGE_2MB
        | ept_vpid_cap::ACCESSED_DIRTY
        | ept_vpid_cap::INVEPT;
    let snap = snapshot(&[
        (
            MSR_FEATURE_CONTROL,
            FEATURE_CONTROL_ENABLE_OUTSIDE_SMX | FEATURE_CONTROL_LOCKED,
        ),
        (MSR_BASIC, basic_msr(1, 4096, 6, false)),
        (MSR_PRIMARY_PROC_BASED, 0),
        (MSR_SECONDARY_PROC_BASED, secondary),
        (MSR_EPT_VPID_CAP, ept_vpid),
    ]);
    let caps = HwCaps::from_snapshot(&snap, true);
    assert!(caps.ept);
    assert!(caps.ept_four_levels);
    assert!(caps.vpid);
    assert!(caps.ept_2mb);
    assert!(caps.ept_wb);
    assert!(caps.ept_ad);
    assert!(!caps.ept_1gb);
    assert!(caps.can_run());
    assert_eq!(caps.validate(), Ok(()));
}

#[test]
fn ept_without_four_levels_is_unusable() {
    let secondary = ((control_bits::PROC2_ENABLE_EPT | control_bits::PROC2_ENABLE_VPID) as u64)
        << 32;
    let snap = snapshot(&[
        (
            MSR_FEATURE_CONTROL,
            FEATURE_CONTROL_ENABLE_OUTSIDE_SMX | FEATURE_CONTROL_LOCKED,
        ),
        (MSR_BASIC, basic_msr(1, 4096, 6, false)),
        (MSR_SECONDARY_PROC_BASED, secondary),
        (MSR_EPT_VPID_CAP, 0),
    ]);
    let caps = HwCaps::from_snapshot(&snap, true);
    assert!(caps.ept);
    assert!(!caps.ept_four_levels);
    assert_eq!(caps.validate(), Err(CapsError::EptUnavailable));
}

#[test]
fn true_controls_take_precedence_when_present() {
    // The base MSR forbids the controls; the TRUE MSRs allow them.
    let pin_true = (control_bits::PIN_PREEMPTION_TIMER as u64) << 32;
    let snap = snapshot(&[
        (
            MSR_FEATURE_CONTROL,
            FEATURE_CONTROL_ENABLE_OUTSIDE_SMX | FEATURE_CONTROL_LOCKED,
        ),
        (MSR_BASIC, basic_msr(1, 4096, 6, true)),
        (MSR_PIN_BASED, 0),
        (MSR_TRUE_PIN_BASED, pin_true),
        (MSR_PRIMARY_PROC_BASED, 0),
        (MSR_TRUE_PRIMARY_PROC_BASED, 0),
        (MSR_EXIT_CONTROLS, 0),
        (MSR_TRUE_EXIT_CONTROLS, 0),
        (MSR_ENTRY_CONTROLS, 0),
        (MSR_TRUE_ENTRY_CONTROLS, 0),
    ]);
    let caps = HwCaps::from_snapshot(&snap, true);
    assert!(caps.has_true_controls);
    assert!(caps.preemption_timer);
}

#[test]
fn allowed_controls_apply_and_support() {
    // Bits 0 and 1 mandatory, bits 0..3 allowed.
    let allowed = AllowedControls::from_msr(0b11 | (0b1111u64 << 32));
    assert_eq!(allowed.apply(0b1000), 0b1000 | 0b11);
    assert_eq!(allowed.apply(0b0100), 0b0100 | 0b11);
    assert!(allowed.supports(0b0100));
    assert!(!allowed.supports(0b1_0000));
    // Mandatory bits are forced even when not requested.
    assert_eq!(allowed.apply(0), 0b11);
}

#[test]
fn fixed_cr_masks_are_exposed() {
    let snap = snapshot(&[
        (
            MSR_FEATURE_CONTROL,
            FEATURE_CONTROL_ENABLE_OUTSIDE_SMX | FEATURE_CONTROL_LOCKED,
        ),
        (MSR_BASIC, basic_msr(1, 4096, 6, false)),
        (MSR_CR0_FIXED0, 0x8000_0021),
        (MSR_CR0_FIXED1, 0xFFFF_FFFF),
        (MSR_CR4_FIXED0, 0x2000),
        (MSR_CR4_FIXED1, 0xFFFF_FFFF),
        (MSR_MISC, 0),
    ]);
    let caps = HwCaps::from_snapshot(&snap, true);
    assert_eq!(caps.cr0_fixed0, 0x8000_0021);
    assert_eq!(caps.cr4_fixed0, 0x2000);
}

#[test]
fn summary_mentions_key_capabilities() {
    let snap = snapshot(&[
        (
            MSR_FEATURE_CONTROL,
            FEATURE_CONTROL_ENABLE_OUTSIDE_SMX | FEATURE_CONTROL_LOCKED,
        ),
        (MSR_BASIC, basic_msr(7, 4096, 6, false)),
    ]);
    let summary = HwCaps::from_snapshot(&snap, true).summary();
    assert!(summary.contains("rev=7"));
    assert!(summary.contains("ept="));
}

#[test]
fn vmx_capability_msr_numbers_match_intel_sdm() {
    // Regression lock: these numbers are fixed by the SDM (vol. 3C,
    // "VMX capability MSRs") and must never be shifted. A shift
    // makes the VMCS enumeration (`0x48A`) be read instead of the secondary
    // controls and makes EPT undetectable on an otherwise compatible host.
    assert_eq!(MSR_BASIC, 0x480);
    assert_eq!(MSR_PIN_BASED, 0x481);
    assert_eq!(MSR_PRIMARY_PROC_BASED, 0x482);
    assert_eq!(MSR_EXIT_CONTROLS, 0x483);
    assert_eq!(MSR_ENTRY_CONTROLS, 0x484);
    assert_eq!(MSR_MISC, 0x485);
    assert_eq!(MSR_CR0_FIXED0, 0x486);
    assert_eq!(MSR_CR0_FIXED1, 0x487);
    assert_eq!(MSR_CR4_FIXED0, 0x488);
    assert_eq!(MSR_CR4_FIXED1, 0x489);
    assert_eq!(caps::MSR_VMCS_ENUM, 0x48A);
    assert_eq!(MSR_SECONDARY_PROC_BASED, 0x48B);
    assert_eq!(MSR_EPT_VPID_CAP, 0x48C);
    assert_eq!(MSR_TRUE_PIN_BASED, 0x48D);
    assert_eq!(MSR_TRUE_PRIMARY_PROC_BASED, 0x48E);
    assert_eq!(MSR_TRUE_EXIT_CONTROLS, 0x48F);
    assert_eq!(MSR_TRUE_ENTRY_CONTROLS, 0x490);
}

#[test]
fn ept_is_read_from_0x48b_and_0x48c_only() {
    // Instrumented reader: we check that the snapshot queries the secondary
    // MSRs at 0x48B and EPT/VPID at 0x48C (and not 0x48A/0x48B).
    use core::cell::RefCell;
    let seen = RefCell::new(alloc::vec::Vec::new());
    let snapshot = MsrSnapshot::from_reader(|msr| {
        seen.borrow_mut().push(msr);
        match msr {
            0x3A => FEATURE_CONTROL_ENABLE_OUTSIDE_SMX | FEATURE_CONTROL_LOCKED,
            0x480 => basic_msr(1, 4096, 6, false),
            0x48B => ((control_bits::PROC2_ENABLE_EPT | control_bits::PROC2_ENABLE_VPID) as u64)
                << 32,
            0x48C => ept_vpid_cap::WALK_LENGTH_4 | ept_vpid_cap::MEMTYPE_WB,
            _ => 0,
        }
    });
    let caps = HwCaps::from_snapshot(&snapshot, true);
    let seen = seen.into_inner();
    assert!(seen.contains(&0x48B), "secondary controls read at 0x48B: {seen:?}");
    assert!(seen.contains(&0x48C), "EPT/VPID read at 0x48C: {seen:?}");
    assert!(!seen.contains(&0x48A), "0x48A (VMCS_ENUM) must not be read: {seen:?}");
    assert!(caps.ept);
    assert!(caps.ept_four_levels);
    assert!(caps.vpid);
    assert!(caps.can_run());
}
