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

//! L2: s9vm guest state and pre-entry validation (real kernel code).

#[path = "../../kernel/src/s9vm/guest.rs"]
mod guest;

use guest::{
    data_access_rights, long_code_access_rights, unusable_access_rights, FixedBits, GuestError,
    GuestState, Segment, AR_DEFAULT_BIG, AR_LONG_MODE, AR_UNUSABLE, CR0_PE, CR0_PG, CR4_PAE,
    CR4_PGE, CR4_VMXE, EFER_LMA, EFER_LME, EFER_NXE,
};

fn permissive() -> FixedBits {
    FixedBits::permissive()
}

#[test]
fn real_mode_state_is_valid_with_unrestricted_guest() {
    let state = GuestState::real_mode(0x1000, 0x7000);
    assert!(state.is_real_mode());
    assert!(!state.is_long_mode());
    assert_eq!(state.validate(&permissive(), true), Ok(()));
}

#[test]
fn real_mode_requires_unrestricted_guest() {
    let state = GuestState::real_mode(0x1000, 0x7000);
    assert_eq!(
        state.validate(&permissive(), false),
        Err(GuestError::RealModeRestricted)
    );
}

#[test]
fn long_mode_state_is_valid() {
    let state = GuestState::long_mode_64(0x1000_0000, 0x2000_0000, 0x3000);
    assert!(state.is_long_mode());
    assert_eq!(state.validate(&permissive(), true), Ok(()));
}

#[test]
fn long_mode_without_paging_is_rejected() {
    let mut state = GuestState::long_mode_64(0x1000, 0x2000, 0x3000);
    state.cr0 &= !CR0_PG;
    assert_eq!(
        state.validate(&permissive(), true),
        Err(GuestError::LongModeWithoutPaging)
    );
}

#[test]
fn long_mode_requires_long_code_segment() {
    let mut state = GuestState::long_mode_64(0x1000, 0x2000, 0x3000);
    state.cs.access_rights = data_access_rights(0);
    assert_eq!(
        state.validate(&permissive(), true),
        Err(GuestError::BadLongCodeSegment)
    );

    // L = 1 but D = 1: forbidden.
    let mut state = GuestState::long_mode_64(0x1000, 0x2000, 0x3000);
    state.cs.access_rights = long_code_access_rights(0) | AR_DEFAULT_BIG;
    assert_eq!(
        state.validate(&permissive(), true),
        Err(GuestError::BadLongCodeSegment)
    );
}

#[test]
fn long_mode_requires_zero_bases_and_full_limits() {
    let mut state = GuestState::long_mode_64(0x1000, 0x2000, 0x3000);
    state.ds.base = 0x1000;
    assert_eq!(
        state.validate(&permissive(), true),
        Err(GuestError::SegmentBaseNotZero)
    );

    let mut state = GuestState::long_mode_64(0x1000, 0x2000, 0x3000);
    state.ss.limit = 0xFFFF;
    assert_eq!(
        state.validate(&permissive(), true),
        Err(GuestError::SegmentLimitNotFull)
    );
}

#[test]
fn fixed_cr_bits_are_enforced() {
    // CR0: bit 0 mandatory, bit 31 forbidden.
    let caps = FixedBits::new(1 << 0, !(1 << 31), 0, u64::MAX);
    let mut state = GuestState::real_mode(0, 0x1000);
    state.cr0 = 0;
    assert_eq!(
        state.validate(&caps, true),
        Err(GuestError::Cr0RequiredBit)
    );
    let mut state = GuestState::real_mode(0, 0x1000);
    state.cr0 = 1 << 31;
    assert_eq!(state.validate(&caps, true), Err(GuestError::Cr0FixedBit));

    // CR4: bit 5 mandatory.
    let caps = FixedBits::new(0, u64::MAX, CR4_PAE, u64::MAX);
    let mut state = GuestState::real_mode(0, 0x1000);
    state.cr4 = 0;
    assert_eq!(
        state.validate(&caps, true),
        Err(GuestError::Cr4RequiredBit)
    );
}

#[test]
fn rejects_reserved_rflags_bits() {
    let mut state = GuestState::long_mode_64(0x1000, 0x2000, 0x3000);
    state.rflags = 0; // bit 1 mandatory
    assert_eq!(state.validate(&permissive(), true), Err(GuestError::BadRflags));

    let mut state = GuestState::long_mode_64(0x1000, 0x2000, 0x3000);
    state.rflags = 0x2 | (1 << 3); // bit 3 reserved
    assert_eq!(state.validate(&permissive(), true), Err(GuestError::BadRflags));

    // RF (bit 16) is a legitimate flag, not a reserved bit: it must be
    // accepted. Regression for the guest boot failure where RF=1 was rejected
    // as BadRflags (rflags=0x10206).
    let mut state = GuestState::long_mode_64(0x1000, 0x2000, 0x3000);
    state.rflags = 0x2 | (1 << 16);
    assert_eq!(state.validate(&permissive(), true), Ok(()));

    // VM (bit 17, virtual-8086) is reserved in IA-32e mode and must be
    // rejected there.
    let mut state = GuestState::long_mode_64(0x1000, 0x2000, 0x3000);
    state.rflags = 0x2 | (1 << 17);
    assert_eq!(state.validate(&permissive(), true), Err(GuestError::BadRflags));

    // First high reserved bit (bit 22): the 63:22 range must be rejected.
    let mut state = GuestState::long_mode_64(0x1000, 0x2000, 0x3000);
    state.rflags = 0x2 | (1 << 22);
    assert_eq!(state.validate(&permissive(), true), Err(GuestError::BadRflags));
}

#[test]
fn long_mode_accepts_unusable_data_segments() {
    // In IA-32e mode DS/ES are ignored by the processor and may be unusable.
    // The base/limit checks must be skipped for them: a non-zero base and a
    // non-full limit on an unusable segment must NOT be rejected.
    let unusable = Segment {
        selector: 0,
        base: 0xDEAD_BEEF,
        limit: 0x1234,
        access_rights: unusable_access_rights(),
    };
    let mut state = GuestState::long_mode_64(0x1000, 0x2000, 0x3000);
    state.ds = unusable;
    state.es = unusable;
    assert!(state.ds.is_unusable());
    assert_eq!(state.validate(&permissive(), true), Ok(()));
}

#[test]
fn rejects_non_active_activity_state() {
    let mut state = GuestState::long_mode_64(0x1000, 0x2000, 0x3000);
    state.activity_state = 1; // halted
    assert_eq!(state.validate(&permissive(), true), Err(GuestError::NotActive));
}

#[test]
fn rejects_bad_interruptibility_state() {
    let mut state = GuestState::long_mode_64(0x1000, 0x2000, 0x3000);
    state.interruptibility = 0x10;
    assert_eq!(
        state.validate(&permissive(), true),
        Err(GuestError::BadInterruptibility)
    );

    // Blocking by STI (bit 0) and by MOV-SS (bit 1) cannot both be set.
    let mut state = GuestState::long_mode_64(0x1000, 0x2000, 0x3000);
    state.rflags = 0x2 | (1 << 9); // IF = 1 so STI blocking is otherwise legal
    state.interruptibility = 0b11;
    assert_eq!(
        state.validate(&permissive(), true),
        Err(GuestError::BadInterruptibility)
    );

    // Blocking by STI requires RFLAGS.IF = 1.
    let mut state = GuestState::long_mode_64(0x1000, 0x2000, 0x3000);
    state.rflags = 0x2; // IF = 0
    state.interruptibility = 0b01;
    assert_eq!(
        state.validate(&permissive(), true),
        Err(GuestError::BadInterruptibility)
    );

    // STI blocking with IF = 1 is accepted.
    let mut state = GuestState::long_mode_64(0x1000, 0x2000, 0x3000);
    state.rflags = 0x2 | (1 << 9);
    state.interruptibility = 0b01;
    assert_eq!(state.validate(&permissive(), true), Ok(()));
}

#[test]
fn long_mode_accepts_unusable_stack_segment() {
    // In IA-32e mode SS is ignored by the processor and may be unusable.
    let mut state = GuestState::long_mode_64(0x1000, 0x2000, 0x3000);
    state.ss = Segment {
        selector: 0,
        base: 0,
        limit: 0,
        access_rights: unusable_access_rights(),
    };
    assert!(state.ss.is_unusable());
    assert_eq!(state.validate(&permissive(), true), Ok(()));

    // In protected mode (no long mode) an unusable SS is still rejected.
    let mut state = GuestState::long_mode_64(0x1000, 0x2000, 0x3000);
    state.cr0 &= !CR0_PG; // drop paging -> not long mode, still PE = 1
    state.efer &= !(EFER_LME | EFER_LMA);
    state.ss.access_rights = unusable_access_rights();
    assert!(!state.is_long_mode());
    assert!(!state.is_real_mode());
    assert_eq!(
        state.validate(&permissive(), true),
        Err(GuestError::BadStackSegment)
    );
}

#[test]
fn segment_helpers_build_expected_access_rights() {
    // Data: type 3 (read/write, accessed), S=1, P=1, DPL=0.
    assert_eq!(data_access_rights(0), 0x93);
    // 64-bit code: type B (execute/read, accessed), S=1, P=1, L=1.
    // VMCS access-rights: L = bit 13 (not bit 9), D/B = bit 14.
    assert_eq!(AR_LONG_MODE, 1 << 13);
    assert_eq!(AR_DEFAULT_BIG, 1 << 14);
    assert_eq!(long_code_access_rights(0), 0x209B);
    assert!(long_code_access_rights(0) & AR_LONG_MODE != 0);
    // Unusable.
    assert!(unusable_access_rights() & AR_UNUSABLE != 0);
    assert!(Segment::unusable().is_unusable());
}

#[test]
fn long_mode_state_has_expected_flags() {
    let state = GuestState::long_mode_64(0x1000, 0x2000, 0x3000);
    assert!(state.cr0 & CR0_PE != 0);
    assert!(state.cr0 & CR0_PG != 0);
    assert!(state.cr4 & CR4_PAE != 0);
    assert!(state.cr4 & CR4_PGE != 0);
    assert!(state.efer & EFER_LME != 0);
    assert!(state.efer & EFER_NXE != 0);
}

#[test]
fn long_mode_requires_lma_in_guest_efer_field() {
    // The "load IA32_EFER" entry control requires LMA == IA-32e mode.
    // A guest field without LMA makes the entry fail (`VMfail`).
    let mut state = GuestState::long_mode_64(0x1000, 0x2000, 0x3000);
    state.efer &= !EFER_LMA;
    assert_eq!(
        state.validate(&permissive(), true),
        Err(GuestError::LongModeWithoutLma)
    );
}

#[test]
fn long_mode_guest_efer_sets_lme_and_lma() {
    let state = GuestState::long_mode_64(0x1000, 0x2000, 0x3000);
    assert!(state.efer & EFER_LME != 0);
    assert!(state.efer & EFER_LMA != 0);
    assert!(state.efer & EFER_NXE != 0);
}
#[test]
fn long_mode_guest_cr4_has_vmxe() {
    // IA32_VMX_CR4_FIXED0 requires CR4.VMXE in the guest state.
    let state = GuestState::long_mode_64(0x1000, 0x2000, 0x3000);
    assert_ne!(state.cr4 & CR4_VMXE, 0);
    assert_ne!(state.cr4 & CR4_PAE, 0);
}


