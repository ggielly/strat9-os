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

//! L2: s9vm guest CPU description (CPUID model).
//!
//! The module under test is pure: it never touches hardware, so the same
//! source file is compiled verbatim here and exercised with host tests.

#[path = "../../kernel/src/s9vm/cpuid.rs"]
mod cpuid;
#[path = "../../kernel/src/s9vm/tsc.rs"]
mod tsc;

use cpuid::{
    extended1_ecx, extended1_edx, leaf1_ecx, leaf1_edx, CpuidPolicy, Feature, BRAND, BRAND_LEN,
    DEFAULT_LEAF1_EDX, INVARIANT_TSC_BIT, LEAF_BASE_FREQUENCY, LEAF_EXTENDED_FEATURES,
    LEAF_EXTENDED_FREQUENCY, LEAF_EXTENDED_MAX, LEAF_TSC_RATIO, MAX_BASIC_LEAF, MAX_EXTENDED_LEAF,
    VENDOR, VENDOR_LEN,
};
use tsc::TscFrequency;

/// Reassembles the 12-byte vendor string from `CPUID.0`
/// (`EBX`, `EDX`, `ECX` order).
fn vendor_string(policy: &CpuidPolicy) -> [u8; VENDOR_LEN] {
    let result = policy.leaf(0, 0);
    let mut bytes = [0u8; VENDOR_LEN];
    bytes[0..4].copy_from_slice(&result[1].to_le_bytes());
    bytes[4..8].copy_from_slice(&result[3].to_le_bytes());
    bytes[8..12].copy_from_slice(&result[2].to_le_bytes());
    bytes
}

/// Reassembles the 48-byte brand string from
/// `CPUID.0x8000_0002..=0x8000_0004`.
fn brand_string(policy: &CpuidPolicy) -> [u8; BRAND_LEN] {
    let mut bytes = [0u8; BRAND_LEN];
    for index in 0..3usize {
        let result = policy.leaf(0x8000_0002 + index as u32, 0);
        for (word_index, word) in result.iter().enumerate() {
            let offset = index * 16 + word_index * 4;
            bytes[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
        }
    }
    bytes
}

/// Decodes `CPUID.1:EAX` into `(family, model, stepping)`.
fn decode_signature(eax: u32) -> (u32, u32, u32) {
    let stepping = eax & 0x0F;
    let base_model = (eax >> 4) & 0x0F;
    let base_family = (eax >> 8) & 0x0F;
    let extended_model = (eax >> 16) & 0x0F;
    let extended_family = (eax >> 20) & 0xFF;
    let family = if base_family == 0x0F {
        base_family + extended_family
    } else {
        base_family
    };
    let model = if base_family == 0x06 || base_family == 0x0F {
        (extended_model << 4) | base_model
    } else {
        base_model
    };
    (family, model, stepping)
}

#[test]
fn default_policy_is_the_safe_profile() {
    let policy = CpuidPolicy::default();
    assert_eq!(policy, CpuidPolicy::new());
    assert_eq!(policy.max_basic_leaf, MAX_BASIC_LEAF);
    assert_eq!(policy.max_extended_leaf, MAX_EXTENDED_LEAF);
    assert_eq!(policy.cores, 1);
    assert_eq!(policy.threads, 1);
    assert_eq!(policy.leaf1_edx, DEFAULT_LEAF1_EDX);
    // No nested virtualization in the raw or effective masks.
    assert_eq!(policy.leaf1_ecx & leaf1_ecx::VMX, 0);
    assert_eq!(policy.effective_leaf1_ecx() & leaf1_ecx::VMX, 0);
    assert_eq!(policy.extended1_ecx & extended1_ecx::SVM, 0);
}

#[test]
fn vendor_string_is_twelve_synthetic_bytes() {
    assert_eq!(VENDOR.len(), 12);
    assert_eq!(&VENDOR, b"S9VMSTRAT9OS");
    // Not a real vendor: no guest may apply a real vendor's quirks.
    assert_ne!(&VENDOR, b"GenuineIntel");
    assert_ne!(&VENDOR, b"AuthenticAMD");

    let policy = CpuidPolicy::default();
    assert_eq!(vendor_string(&policy), VENDOR);
    assert_eq!(vendor_string(&policy), *b"S9VMSTRAT9OS");
}

#[test]
fn leaf_zero_advertises_vendor_and_range() {
    let policy = CpuidPolicy::default();
    let result = policy.leaf(0, 0);
    assert_eq!(result[0], MAX_BASIC_LEAF);
    // The subleaf is ignored by leaf 0.
    assert_eq!(policy.leaf(0, 1234), result);
}

#[test]
fn leaf_one_reports_family_model_stepping() {
    let policy = CpuidPolicy::default();
    let result = policy.leaf(1, 0);
    let (family, model, stepping) = decode_signature(result[0]);
    assert_eq!(family, 6);
    assert_eq!(model, cpuid::BASE_MODEL);
    assert_eq!(stepping, cpuid::BASE_STEPPING);

    // A custom signature round-trips through the architectural encoding.
    let mut custom = CpuidPolicy::new();
    custom.family = 0x17;
    custom.model = 0x31;
    custom.stepping = 0x02;
    let (family, model, stepping) = decode_signature(custom.leaf(1, 0)[0]);
    assert_eq!(family, 0x17);
    assert_eq!(model, 0x31);
    assert_eq!(stepping, 0x02);
}

#[test]
fn leaf_one_ties_logical_processors_to_topology() {
    let mut policy = CpuidPolicy::new();
    policy.cores = 4;
    policy.threads = 2;
    let ebx = policy.leaf(1, 0)[1];
    assert_eq!((ebx >> 16) & 0xFF, 8);
    assert_eq!(ebx & 0xFF, 0);
    assert_eq!((ebx >> 8) & 0xFF, 8);
    assert_eq!(policy.logical_processors(), 8);
}

#[test]
fn leaf_one_never_advertises_vmx() {
    let mut policy = CpuidPolicy::new();
    policy.set_feature(Feature::Leaf1Ecx(5));
    policy.leaf1_ecx |= leaf1_ecx::VMX;
    assert_eq!(policy.leaf(1, 0)[2] & leaf1_ecx::VMX, 0);
    assert!(!policy.has_feature(Feature::Leaf1Ecx(5)));
}

#[test]
fn leaf_one_has_x2apic_and_tsc_deadline() {
    let policy = CpuidPolicy::default();
    let ecx = policy.leaf(1, 0)[2];
    assert_ne!(ecx & leaf1_ecx::X2APIC, 0);
    assert_ne!(ecx & leaf1_ecx::TSC_DEADLINE, 0);
    // Early-boot SIMD bits a 64-bit guest expects.
    for bit in [
        leaf1_ecx::SSE3,
        leaf1_ecx::PCLMUL,
        leaf1_ecx::SSSE3,
        leaf1_ecx::SSE4_1,
        leaf1_ecx::SSE4_2,
        leaf1_ecx::POPCNT,
    ] {
        assert_ne!(ecx & bit, 0, "missing leaf 1 ECX bit {:#x}", bit);
    }
}

#[test]
fn leaf_one_edx_carries_the_early_boot_baseline() {
    let edx = CpuidPolicy::default().leaf(1, 0)[3];
    for bit in [
        leaf1_edx::FPU,
        leaf1_edx::TSC,
        leaf1_edx::MSR,
        leaf1_edx::PAE,
        leaf1_edx::CX8,
        leaf1_edx::APIC,
        leaf1_edx::SEP,
        leaf1_edx::CMOV,
        leaf1_edx::PAT,
        leaf1_edx::CLFSH,
        leaf1_edx::MMX,
        leaf1_edx::FXSR,
        leaf1_edx::SSE,
        leaf1_edx::SSE2,
    ] {
        assert_ne!(edx & bit, 0, "missing leaf 1 EDX bit {:#x}", bit);
    }
}

#[test]
fn no_hypervisor_present_bit() {
    let policy = CpuidPolicy::default();
    assert_eq!(policy.leaf(1, 0)[2] & (1 << 31), 0);
    // The 0x4000_0000 hypervisor range reads as zero when absent.
    for leaf in [0x4000_0000u32, 0x4000_0001, 0x4000_1000] {
        assert_eq!(policy.leaf(leaf, 0), [0; 4]);
    }
}

#[test]
fn extended_range_and_features() {
    let policy = CpuidPolicy::default();
    assert_eq!(
        policy.leaf(LEAF_EXTENDED_MAX, 0),
        [MAX_EXTENDED_LEAF, 0, 0, 0]
    );

    let result = policy.leaf(LEAF_EXTENDED_FEATURES, 0);
    assert_ne!(result[3] & extended1_edx::NX, 0);
    assert_ne!(result[3] & extended1_edx::LONG_MODE, 0);
    assert_ne!(result[3] & extended1_edx::SYSCALL, 0);
    assert_ne!(result[3] & extended1_edx::RDTSCP, 0);
    // SVM can never be advertised.
    assert_eq!(result[2] & extended1_ecx::SVM, 0);
}

#[test]
fn brand_string_is_the_virtual_cpu_name() {
    assert_eq!(BRAND.len(), 48);
    let policy = CpuidPolicy::default();
    let brand = brand_string(&policy);
    assert_eq!(&brand, &BRAND);
    let text = core::str::from_utf8(&brand[..16]).expect("brand prefix is ASCII");
    assert_eq!(text, "s9vm virtual CPU");
    for byte in &brand[16..] {
        assert_eq!(*byte, 0, "brand string must be zero padded");
    }
    // Subleaf is ignored by the brand leaves.
    assert_eq!(policy.leaf(0x8000_0002, 9), policy.leaf(0x8000_0002, 0));
}

#[test]
fn topology_leaf_0b_reports_one_package_one_core_one_thread() {
    let policy = CpuidPolicy::default();
    // SMT level: 1 thread, level type 1.
    assert_eq!(policy.leaf(0x0000_000B, 0), [0, 1, 1 << 8, 0]);
    // Core level: 1 logical processor, level type 2.
    assert_eq!(policy.leaf(0x0000_000B, 1), [1, 1, 2 << 8, 0]);
    // Higher subleafs terminate the enumeration with an invalid level type.
    for subleaf in 2..8 {
        assert_eq!(policy.leaf(0x0000_000B, subleaf), [0; 4]);
    }
}

#[test]
fn topology_leaf_1f_matches_leaf_0b() {
    let mut policy = CpuidPolicy::new();
    policy.cores = 2;
    policy.threads = 2;
    for subleaf in 0..4 {
        assert_eq!(
            policy.leaf(0x0000_001F, subleaf),
            policy.leaf(0x0000_000B, subleaf)
        );
    }
    assert_eq!(policy.leaf(0x0000_001F, 0), [0, 2, 1 << 8, 0]);
    assert_eq!(policy.leaf(0x0000_001F, 1), [1, 4, 2 << 8, 0]);
}

#[test]
fn topology_counts_are_configurable_and_never_zero() {
    let mut policy = CpuidPolicy::new();
    policy.cores = 3;
    policy.threads = 3;
    assert_eq!(policy.logical_processors(), 9);
    assert_eq!(policy.leaf(0x0000_000B, 0)[1], 3);
    assert_eq!(policy.leaf(0x0000_000B, 1)[1], 9);

    // Zero counts fall back to one processor instead of panicking or
    // advertising an empty machine.
    policy.cores = 0;
    policy.threads = 0;
    assert_eq!(policy.logical_processors(), 1);
    assert_eq!(policy.leaf(0x0000_000B, 0)[1], 1);
    assert_eq!(policy.leaf(0x0000_000B, 1)[1], 1);
}

#[test]
fn cache_and_xsave_leaves_are_zero() {
    let policy = CpuidPolicy::default();
    for subleaf in 0..4 {
        assert_eq!(policy.leaf(0x0000_0004, subleaf), [0; 4]);
        assert_eq!(policy.leaf(0x0000_000D, subleaf), [0; 4]);
    }
    assert_eq!(policy.leaf(0x0000_0007, 0), [0; 4]);
}

#[test]
fn address_sizes_are_advertised() {
    let result = CpuidPolicy::default().leaf(0x8000_0008, 0);
    assert_eq!(result[0] & 0xFF, cpuid::PHYSICAL_ADDRESS_BITS);
    assert_eq!((result[0] >> 8) & 0xFF, cpuid::VIRTUAL_ADDRESS_BITS);
    assert_eq!(result[1], 0);
    assert_eq!(result[2], 0);
    assert_eq!(result[3], 0);
}

#[test]
fn unknown_leaves_return_zeros() {
    let policy = CpuidPolicy::default();
    for leaf in [
        0x0000_0002u32,
        0x0000_0003,
        0x0000_0005,
        0x0000_0006,
        0x0000_0010,
        0x0000_00FF,
        0x4000_0000,
        0x7FFF_FFFF,
        0x8000_0009,
        0xDEAD_BEEF,
        0xFFFF_FFFF,
    ] {
        assert_eq!(policy.leaf(leaf, 0), [0; 4], "leaf {:#x}", leaf);
    }
}

#[test]
fn basic_leaf_range_is_enforced() {
    let mut policy = CpuidPolicy::new();
    policy.max_basic_leaf = 0x0000_000B;
    assert_eq!(policy.leaf(0, 0)[0], 0x0000_000B);
    assert_ne!(policy.leaf(0x0000_000B, 0), [0; 4]);
    // Above the advertised range: no data, even for an implemented leaf.
    assert_eq!(policy.leaf(0x0000_001F, 0), [0; 4]);
    assert_eq!(policy.leaf(0x0000_000D, 0), [0; 4]);
    // Extended leaves are independent of the basic range.
    assert_eq!(policy.leaf(0x8000_0000, 0)[0], MAX_EXTENDED_LEAF);
}

#[test]
fn extended_leaf_range_is_enforced() {
    let mut policy = CpuidPolicy::new();
    policy.max_extended_leaf = 0x8000_0001;
    assert_eq!(policy.leaf(0x8000_0000, 0)[0], 0x8000_0001);
    assert_eq!(policy.leaf(0x8000_0002, 0), [0; 4]);
    assert_eq!(policy.leaf(0x8000_0008, 0), [0; 4]);
}

#[test]
fn feature_helpers_set_and_clear_bits() {
    let mut policy = CpuidPolicy::new();
    assert!(policy.has_feature(Feature::Leaf1Edx(26)));
    policy.clear_feature(Feature::Leaf1Edx(26));
    assert!(!policy.has_feature(Feature::Leaf1Edx(26)));
    assert_eq!(policy.leaf(1, 0)[3] & leaf1_edx::SSE2, 0);
    policy.set_feature(Feature::Leaf1Edx(26));
    assert!(policy.has_feature(Feature::Leaf1Edx(26)));
    assert_ne!(policy.leaf(1, 0)[3] & leaf1_edx::SSE2, 0);

    // Out-of-range bit numbers wrap instead of panicking.
    policy.set_feature(Feature::Leaf1Ecx(255));
    assert!(policy.has_feature(Feature::Leaf1Ecx(31)));
    policy.clear_feature(Feature::Leaf1Ecx(255));
    assert!(!policy.has_feature(Feature::Leaf1Ecx(31)));
}

#[test]
fn forbidden_bits_are_filtered_even_from_raw_masks() {
    let mut policy = CpuidPolicy::new();
    policy.leaf1_ecx = u32::MAX;
    policy.extended1_ecx = u32::MAX;
    assert_eq!(policy.effective_leaf1_ecx() & leaf1_ecx::VMX, 0);
    assert_eq!(policy.effective_extended1_ecx() & extended1_ecx::SVM, 0);
    assert_eq!(policy.leaf(1, 0)[2] & leaf1_ecx::VMX, 0);
    assert_eq!(
        policy.leaf(LEAF_EXTENDED_FEATURES, 0)[2] & extended1_ecx::SVM,
        0
    );
    // Every other bit survives the filter.
    assert_eq!(
        policy.effective_leaf1_ecx(),
        u32::MAX & !cpuid::LEAF1_ECX_FORBIDDEN
    );
}

#[test]
fn replay_is_deterministic_and_total() {
    let policy = CpuidPolicy::default();
    let mut leaves: Vec<u32> = (0u32..=0x30).collect();
    leaves.extend([0x4000_0000, 0x8000_0000, 0x8000_0001, 0x8000_0002]);
    leaves.extend(0x8000_0003..=0x8000_000A);
    leaves.extend([0xDEAD_BEEF, 0xFFFF_FFFF]);
    for leaf in leaves {
        for subleaf in [0u32, 1, 2, 17, u32::MAX] {
            let first = policy.leaf(leaf, subleaf);
            assert_eq!(first, policy.leaf(leaf, subleaf));
            assert_eq!(first, CpuidPolicy::default().leaf(leaf, subleaf));
        }
    }
}

#[test]
fn tsc_ratio_leaf_publishes_policy_fields() {
    let mut policy = CpuidPolicy::new();
    policy.tsc_ratio_denominator = 5;
    policy.tsc_ratio_numerator = 12;
    policy.crystal_hz = 1_000_000_000;
    // Architectural order: EAX = denominator, EBX = numerator, ECX = crystal.
    assert_eq!(policy.leaf(LEAF_TSC_RATIO, 0), [5, 12, 1_000_000_000, 0]);
}

#[test]
fn tsc_base_frequency_leaf_publishes_mhz() {
    let mut policy = CpuidPolicy::new();
    policy.base_mhz = 2400;
    assert_eq!(policy.leaf(LEAF_BASE_FREQUENCY, 0), [2400, 0, 0, 0]);
}

#[test]
fn tsc_leaves_default_to_zero_without_host_frequency() {
    // No test in this binary publishes a host frequency in the global cache,
    // so the zero-policy fallback must read as "not published".
    let policy = CpuidPolicy::default();
    assert_eq!(policy.leaf(LEAF_TSC_RATIO, 0), [0; 4]);
    assert_eq!(policy.leaf(LEAF_BASE_FREQUENCY, 0), [0; 4]);
}

#[test]
fn tsc_leaves_can_be_filled_from_a_frequency() {
    let frequency = TscFrequency::from_hz(2_400_000_000).expect("2.4 GHz is plausible");
    let mut policy = CpuidPolicy::new();
    policy.set_tsc_frequency(frequency);

    // 2.4 GHz / 1 GHz = 12 / 5: the guest computes the exact frequency.
    assert_eq!(policy.leaf(LEAF_TSC_RATIO, 0), [5, 12, 1_000_000_000, 0]);
    assert_eq!(policy.leaf(LEAF_BASE_FREQUENCY, 0), [2400, 0, 0, 0]);

    // The published values are consistent with the helper they came from.
    let leaves = frequency.cpuid_leaves();
    assert_eq!(policy.crystal_hz, leaves.crystal_hz);
    assert_eq!(policy.tsc_ratio_numerator, leaves.ratio_numerator);
    assert_eq!(policy.tsc_ratio_denominator, leaves.ratio_denominator);
    assert_eq!(policy.base_mhz, leaves.base_mhz);
}

#[test]
fn invariant_tsc_bit_is_advertised() {
    let policy = CpuidPolicy::default();
    let result = policy.leaf(LEAF_EXTENDED_FREQUENCY, 0);
    assert_eq!(result, [0, 0, 0, INVARIANT_TSC_BIT]);
    assert_ne!(result[3] & (1 << 8), 0);
    // The CPUID model and the timing model agree on the published bit.
    assert_eq!(INVARIANT_TSC_BIT, tsc::INVARIANT_TSC_BIT);
    // No other bit is published: no power-management claims.
    assert_eq!(result[3] & !INVARIANT_TSC_BIT, 0);

    // And the leaf is reachable inside the advertised extended range.
    assert!(MAX_EXTENDED_LEAF >= LEAF_EXTENDED_FREQUENCY);
    assert_ne!(policy.leaf(LEAF_EXTENDED_FREQUENCY, 0), [0; 4]);
}

#[test]
fn tsc_leaves_are_within_the_advertised_basic_range() {
    assert!(MAX_BASIC_LEAF >= LEAF_TSC_RATIO);
    assert!(MAX_BASIC_LEAF >= LEAF_BASE_FREQUENCY);
    // Both leaves are answered even when their content is zero: a guest must
    // not depend on the range check to know they exist.
    let policy = CpuidPolicy::new();
    let mut low = CpuidPolicy::new();
    low.max_basic_leaf = LEAF_TSC_RATIO - 1;
    assert_eq!(policy.leaf(LEAF_TSC_RATIO, 0), [0; 4]);
    assert_eq!(low.leaf(LEAF_TSC_RATIO, 0), [0; 4]);
}

#[test]
fn partial_tsc_policy_falls_back() {
    // A ratio without a crystal is not usable: the guest would divide by an
    // unknown crystal, so the leaf must not publish it.
    let mut policy = CpuidPolicy::new();
    policy.tsc_ratio_denominator = 5;
    policy.tsc_ratio_numerator = 12;
    policy.crystal_hz = 0;
    assert_eq!(policy.leaf(LEAF_TSC_RATIO, 0), [0; 4]);
}
