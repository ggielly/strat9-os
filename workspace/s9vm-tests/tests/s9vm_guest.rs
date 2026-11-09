//! L2 : état invité s9vm et validation avant entrée (code noyau réel).

#[path = "../../kernel/src/s9vm/guest.rs"]
mod guest;

use guest::{
    data_access_rights, long_code_access_rights, unusable_access_rights, FixedBits, GuestError,
    GuestState, Segment, AR_DEFAULT_BIG, AR_LONG_MODE, AR_UNUSABLE, CR0_PE, CR0_PG, CR4_PAE,
    CR4_PGE, EFER_LME, EFER_NXE,
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

    // L = 1 mais D = 1 : interdit.
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
    // CR0 : bit 0 obligatoire, bit 31 interdit.
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

    // CR4 : bit 5 obligatoire.
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
    state.rflags = 0; // bit 1 obligatoire
    assert_eq!(state.validate(&permissive(), true), Err(GuestError::BadRflags));

    let mut state = GuestState::long_mode_64(0x1000, 0x2000, 0x3000);
    state.rflags = 0x2 | (1 << 3); // bit 3 réservé
    assert_eq!(state.validate(&permissive(), true), Err(GuestError::BadRflags));
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
}

#[test]
fn segment_helpers_build_expected_access_rights() {
    // Données : type 2, S=1, P=1, DPL=0.
    assert_eq!(data_access_rights(0), 0x92);
    // Code 64 bits : type A, S=1, P=1, L=1.
    assert_eq!(long_code_access_rights(0), 0x29A);
    assert!(long_code_access_rights(0) & AR_LONG_MODE != 0);
    // Inutilisable.
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
