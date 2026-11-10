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

//! L2: guest MSR shadow model, interception policy and validation.

extern crate alloc;

#[path = "../../kernel/src/s9vm/msr.rs"]
mod msr;

use msr::{
    msr_intercept_list, MsrError, MsrModel, MsrWrite, SyscallTargets, EFER_LMA, EFER_LME, EFER_NXE,
    EFER_SCE, IA32_APIC_BASE, IA32_CSTAR, IA32_EFER, IA32_FS_BASE, IA32_GS_BASE,
    IA32_KERNEL_GS_BASE, IA32_LSTAR, IA32_MISC_ENABLE, IA32_PAT, IA32_SFMASK, IA32_STAR,
    IA32_SYSENTER_CS, IA32_SYSENTER_EIP, IA32_SYSENTER_ESP, IA32_TSC_AUX,
};

const PAT_RESET: u64 = 0x0007_0406_0007_0406;
const KERNEL_STAR: u64 = (0x1B << 48) | (0x08 << 32);
const CANONICAL_HIGH: u64 = 0xFFFF_8000_0000_0000;
const NON_CANONICAL: u64 = 0x0000_8000_0000_0000;

fn model_with_efer(efer: u64, pat: u64) -> MsrModel {
    let mut model = MsrModel::new();
    model.set_efer(efer);
    model.set_pat(pat);
    model
}

#[test]
fn reset_state_has_architectural_values() {
    let model = MsrModel::new();
    assert_eq!(model.efer(), 0);
    assert_eq!(model.read(IA32_EFER), Ok(0));
    assert_eq!(model.pat(), PAT_RESET);
    assert_eq!(model.read(IA32_PAT), Ok(PAT_RESET));
    assert_eq!(model.read(IA32_STAR), Ok(0));
    assert_eq!(model.read(IA32_LSTAR), Ok(0));
    assert_eq!(model.read(IA32_CSTAR), Ok(0));
    assert_eq!(model.read(IA32_SFMASK), Ok(0));
    assert_eq!(model.read(IA32_FS_BASE), Ok(0));
    assert_eq!(model.read(IA32_GS_BASE), Ok(0));
    assert_eq!(model.read(IA32_KERNEL_GS_BASE), Ok(0));
    assert_eq!(model.read(IA32_TSC_AUX), Ok(0));
    assert_eq!(model.read(IA32_MISC_ENABLE), Ok(0));
    assert_eq!(model.read(IA32_APIC_BASE), Ok(0x0000_0000_FEE0_0900));
}

#[test]
fn efer_round_trip_and_lma_read_only() {
    let mut model = MsrModel::new();
    assert_eq!(
        model.write(IA32_EFER, EFER_SCE | EFER_LME | EFER_NXE),
        Ok(MsrWrite::Efer)
    );
    assert_eq!(model.efer(), EFER_SCE | EFER_LME | EFER_NXE);
    // The model reads back exactly what it shadows.
    assert_eq!(model.read(IA32_EFER), Ok(EFER_SCE | EFER_LME | EFER_NXE));
    // Attempting to write LMA does not change the stored LMA (currently 0).
    assert_eq!(model.write(IA32_EFER, EFER_LMA), Ok(MsrWrite::Efer));
    assert_eq!(model.read(IA32_EFER), Ok(0));
}

#[test]
fn seeded_efer_preserves_lma() {
    let mut model = model_with_efer(EFER_SCE | EFER_LME | EFER_LMA, PAT_RESET);
    assert_eq!(model.read(IA32_EFER), Ok(EFER_SCE | EFER_LME | EFER_LMA));
    // A guest write cannot clear the processor-owned LMA bit.
    assert_eq!(model.write(IA32_EFER, 0), Ok(MsrWrite::Efer));
    assert_eq!(model.read(IA32_EFER), Ok(EFER_LMA));
}

#[test]
fn efer_reserved_bits_fault() {
    let mut model = MsrModel::new();
    assert_eq!(
        model.write(IA32_EFER, 1 << 12), // SVME is not modelled
        Err(MsrError::GeneralProtection)
    );
    assert_eq!(model.read(IA32_EFER), Ok(0));
    assert_eq!(
        model.write(IA32_EFER, u64::MAX),
        Err(MsrError::GeneralProtection)
    );
}

#[test]
fn pat_validates_memory_types() {
    let mut model = MsrModel::new();
    assert_eq!(model.write(IA32_PAT, PAT_RESET), Ok(MsrWrite::Pat));
    // Memory type 2 is reserved in every PAT entry.
    let invalid = (PAT_RESET & !0xFF) | 0x2;
    assert_eq!(
        model.write(IA32_PAT, invalid),
        Err(MsrError::GeneralProtection)
    );
    // Reserved type in the highest entry.
    let invalid_high = PAT_RESET | (0x3 << 56);
    assert_eq!(
        model.write(IA32_PAT, invalid_high),
        Err(MsrError::GeneralProtection)
    );
    assert_eq!(model.pat(), PAT_RESET);
}

#[test]
fn star_round_trip_and_reserved_low_bits() {
    let mut model = MsrModel::new();
    assert_eq!(
        model.write(IA32_STAR, KERNEL_STAR),
        Ok(MsrWrite::SyscallTargets)
    );
    assert_eq!(model.read(IA32_STAR), Ok(KERNEL_STAR));
    assert_eq!(
        model.write(IA32_STAR, KERNEL_STAR | 1),
        Err(MsrError::GeneralProtection)
    );
}

#[test]
fn lstar_and_cstar_require_canonical_addresses() {
    let mut model = MsrModel::new();
    assert_eq!(
        model.write(IA32_LSTAR, CANONICAL_HIGH),
        Ok(MsrWrite::SyscallTargets)
    );
    assert_eq!(model.read(IA32_LSTAR), Ok(CANONICAL_HIGH));
    assert_eq!(
        model.write(IA32_LSTAR, NON_CANONICAL),
        Err(MsrError::GeneralProtection)
    );
    assert_eq!(
        model.write(IA32_CSTAR, CANONICAL_HIGH),
        Ok(MsrWrite::SyscallTargets)
    );
    assert_eq!(
        model.write(IA32_CSTAR, NON_CANONICAL),
        Err(MsrError::GeneralProtection)
    );
}

#[test]
fn sfmask_is_32_bit() {
    let mut model = MsrModel::new();
    assert_eq!(
        model.write(IA32_SFMASK, 0x0000_0000_0000_3F00),
        Ok(MsrWrite::SyscallTargets)
    );
    assert_eq!(model.read(IA32_SFMASK), Ok(0x3F00));
    assert_eq!(
        model.write(IA32_SFMASK, 1 << 32),
        Err(MsrError::GeneralProtection)
    );
}

#[test]
fn segment_bases_require_canonical_values() {
    let mut model = MsrModel::new();
    assert_eq!(
        model.write(IA32_FS_BASE, CANONICAL_HIGH + 0x100),
        Ok(MsrWrite::SegmentBase)
    );
    assert_eq!(model.read(IA32_FS_BASE), Ok(CANONICAL_HIGH + 0x100));
    assert_eq!(
        model.write(IA32_GS_BASE, CANONICAL_HIGH + 0x200),
        Ok(MsrWrite::SegmentBase)
    );
    assert_eq!(model.gs_base(), CANONICAL_HIGH + 0x200);
    assert_eq!(
        model.write(IA32_KERNEL_GS_BASE, CANONICAL_HIGH + 0x300),
        Ok(MsrWrite::SegmentBase)
    );
    assert_eq!(model.read(IA32_KERNEL_GS_BASE), Ok(CANONICAL_HIGH + 0x300));
    assert_eq!(
        model.write(IA32_FS_BASE, NON_CANONICAL),
        Err(MsrError::GeneralProtection)
    );
    assert_eq!(
        model.write(IA32_GS_BASE, NON_CANONICAL),
        Err(MsrError::GeneralProtection)
    );
    assert_eq!(
        model.write(IA32_KERNEL_GS_BASE, NON_CANONICAL),
        Err(MsrError::GeneralProtection)
    );
}

#[test]
fn tsc_aux_is_32_bit_and_settable() {
    let mut model = MsrModel::new();
    assert_eq!(model.write(IA32_TSC_AUX, 0xFFFF_FFFF), Ok(MsrWrite::TscAux));
    assert_eq!(model.tsc_aux(), 0xFFFF_FFFF);
    assert_eq!(
        model.write(IA32_TSC_AUX, 1 << 32),
        Err(MsrError::GeneralProtection)
    );
    assert_eq!(model.set_tsc_aux(7), Ok(()));
    assert_eq!(model.tsc_aux(), 7);
    assert_eq!(model.set_tsc_aux(1 << 32), Err(MsrError::GeneralProtection));
}

#[test]
fn misc_enable_shadow_is_ignored_for_host_state() {
    let mut model = MsrModel::new();
    assert_eq!(
        model.write(IA32_MISC_ENABLE, u64::MAX),
        Ok(MsrWrite::Ignored)
    );
    assert_eq!(model.misc_enable(), 0xFFFF_FFFF);
    assert_eq!(model.read(IA32_MISC_ENABLE), Ok(0xFFFF_FFFF));
}

#[test]
fn sysenter_state_round_trip_and_validation() {
    let mut model = MsrModel::new();
    assert_eq!(model.write(IA32_SYSENTER_CS, 0x8), Ok(MsrWrite::State));
    assert_eq!(
        model.write(IA32_SYSENTER_ESP, 0xFFFF_8000_0000_1000),
        Ok(MsrWrite::State)
    );
    assert_eq!(
        model.write(IA32_SYSENTER_EIP, 0xFFFF_8000_0000_2000),
        Ok(MsrWrite::State)
    );
    assert_eq!(model.read(IA32_SYSENTER_CS), Ok(0x8));
    assert_eq!(model.read(IA32_SYSENTER_ESP), Ok(0xFFFF_8000_0000_1000));
    assert_eq!(model.read(IA32_SYSENTER_EIP), Ok(0xFFFF_8000_0000_2000));
    assert_eq!(
        model.write(IA32_SYSENTER_CS, 1 << 32),
        Err(MsrError::GeneralProtection)
    );
    assert_eq!(
        model.write(IA32_SYSENTER_EIP, NON_CANONICAL),
        Err(MsrError::GeneralProtection)
    );
}

#[test]
fn apic_base_is_validated_and_shadowed() {
    let mut model = MsrModel::new();
    let value = 0x0000_0000_FEE0_0900;
    assert_eq!(model.write(IA32_APIC_BASE, value), Ok(MsrWrite::State));
    assert_eq!(model.apic_base(), value);
    assert_eq!(model.read(IA32_APIC_BASE), Ok(value));
    // Bit 0 is reserved in IA32_APIC_BASE.
    assert_eq!(
        model.write(IA32_APIC_BASE, value | 1),
        Err(MsrError::GeneralProtection)
    );
}

#[test]
fn unsupported_msr_is_rejected() {
    let mut model = MsrModel::new();
    assert_eq!(model.read(0x10), Err(MsrError::Unsupported));
    assert_eq!(model.write(0x10, 0), Err(MsrError::Unsupported));
    assert_eq!(model.read(0xDEAD), Err(MsrError::Unsupported));
}

#[test]
fn intercept_list_covers_security_critical_msrs() {
    let list = msr_intercept_list();
    for msr in [
        IA32_EFER,
        IA32_PAT,
        IA32_STAR,
        IA32_LSTAR,
        IA32_CSTAR,
        IA32_SFMASK,
        IA32_FS_BASE,
        IA32_GS_BASE,
        IA32_KERNEL_GS_BASE,
        IA32_TSC_AUX,
        IA32_MISC_ENABLE,
        IA32_SYSENTER_CS,
        IA32_SYSENTER_ESP,
        IA32_SYSENTER_EIP,
        IA32_APIC_BASE,
    ] {
        assert!(list.contains(&msr), "missing MSR {msr:#x}");
    }
    // Harmless read-only MSRs are not part of the model.
    assert!(!list.contains(&0x10)); // IA32_TSC
    assert!(!list.contains(&0x79));
    // No duplicate entries.
    for (index, msr) in list.iter().enumerate() {
        assert!(!list[..index].contains(msr));
    }
}

#[test]
fn model_is_deterministic() {
    let mut first = MsrModel::new();
    let mut second = MsrModel::new();
    for model in [&mut first, &mut second] {
        assert_eq!(
            model.write(IA32_EFER, EFER_SCE | EFER_LME),
            Ok(MsrWrite::Efer)
        );
        assert_eq!(
            model.write(IA32_STAR, KERNEL_STAR),
            Ok(MsrWrite::SyscallTargets)
        );
        assert_eq!(
            model.write(IA32_FS_BASE, CANONICAL_HIGH + 0x40),
            Ok(MsrWrite::SegmentBase)
        );
    }
    assert_eq!(first, second);
    assert_eq!(first.syscall_targets(), second.syscall_targets());
    for _ in 0..4 {
        assert_eq!(first.read(IA32_EFER), second.read(IA32_EFER));
    }
}

#[test]
fn seeded_state_and_accessors_agree() {
    let mut model = model_with_efer(EFER_SCE | EFER_LME, 0x0007_0406_0007_0406);
    assert_eq!(model.efer(), EFER_SCE | EFER_LME);
    assert_eq!(model.read(IA32_EFER), Ok(EFER_SCE | EFER_LME));
    assert_eq!(model.pat(), PAT_RESET);
    assert_eq!(
        model.write(IA32_STAR, KERNEL_STAR),
        Ok(MsrWrite::SyscallTargets)
    );
    assert_eq!(
        model.syscall_targets(),
        SyscallTargets {
            star: KERNEL_STAR,
            ..SyscallTargets::default()
        }
    );
}

#[test]
fn adversarial_values_never_panic() {
    let values = [
        0,
        1,
        u64::MAX,
        0x0000_8000_0000_0000,
        0xFFFF_8000_0000_0000,
        0x0007_0406_0007_0406,
        0xFFFF_FFFF_FFFF_FFFF,
    ];
    for msr in msr_intercept_list() {
        for value in values {
            let mut model = MsrModel::new();
            let _ = model.write(*msr, value);
            let _ = model.read(*msr);
        }
    }
}

#[test]
fn failed_write_does_not_change_shadow() {
    let mut model = MsrModel::new();
    assert_eq!(
        model.write(IA32_EFER, EFER_SCE | EFER_LME),
        Ok(MsrWrite::Efer)
    );
    assert_eq!(
        model.write(IA32_EFER, u64::MAX),
        Err(MsrError::GeneralProtection)
    );
    assert_eq!(model.read(IA32_EFER), Ok(EFER_SCE | EFER_LME));
    assert_eq!(model.write(IA32_PAT, 0x2), Err(MsrError::GeneralProtection));
    assert_eq!(model.read(IA32_PAT), Ok(PAT_RESET));
}

#[test]
fn syscall_targets_default_is_zero() {
    assert_eq!(SyscallTargets::default().star, 0);
    assert_eq!(SyscallTargets::default().lstar, 0);
    assert_eq!(SyscallTargets::default().cstar, 0);
    assert_eq!(SyscallTargets::default().sfmask, 0);
}
