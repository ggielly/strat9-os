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

//! L2: s9vm TSC frequency model (real kernel code).
//!
//! The module under test is pure arithmetic plus a write-once atomic cache: it
//! never touches hardware, so the same source file is compiled verbatim here.

#[path = "../../kernel/src/s9vm/tsc.rs"]
mod tsc;

use tsc::{detect, get, is_invariant, set, TscFrequency, MAX_HZ, MIN_HZ};

/// Builds a CPUID leaf array from its four register values.
const fn leaf(eax: u32, ebx: u32, ecx: u32, edx: u32) -> [u32; 4] {
    [eax, ebx, ecx, edx]
}

#[test]
fn ratio_based_frequency() {
    // 24 MHz crystal, numerator 100, denominator 1: 2.4 GHz.
    let frequency = TscFrequency::from_cpuid(leaf(1, 100, 24_000_000, 0), leaf(0, 0, 0, 0))
        .expect("ratio should be usable");
    assert_eq!(frequency.hz(), 2_400_000_000);
    assert_eq!(frequency.mhz(), 2400);
}

#[test]
fn ratio_uses_denominator() {
    // 24 MHz crystal, numerator 100, denominator 4: 600 MHz.
    let frequency = TscFrequency::from_cpuid(leaf(4, 100, 24_000_000, 0), leaf(0, 0, 0, 0))
        .expect("ratio should be usable");
    assert_eq!(frequency.hz(), 600_000_000);
}

#[test]
fn zero_denominator_falls_back_to_leaf16() {
    let frequency = TscFrequency::from_cpuid(leaf(0, 100, 24_000_000, 0), leaf(3000, 0, 0, 0))
        .expect("leaf 0x16 fallback should be used");
    assert_eq!(frequency.hz(), 3_000_000_000);
}

#[test]
fn zero_crystal_falls_back_to_leaf16() {
    let frequency = TscFrequency::from_cpuid(leaf(1, 1, 0, 0), leaf(2500, 0, 0, 0))
        .expect("leaf 0x16 fallback should be used");
    assert_eq!(frequency.hz(), 2_500_000_000);
}

#[test]
fn leaf16_only_is_accepted() {
    let frequency = TscFrequency::from_cpuid(leaf(0, 0, 0, 0), leaf(2800, 0, 0, 0))
        .expect("base frequency should be usable");
    assert_eq!(frequency.hz(), 2_800_000_000);
}

#[test]
fn no_source_returns_none() {
    assert_eq!(
        TscFrequency::from_cpuid(leaf(0, 0, 0, 0), leaf(0, 0, 0, 0)),
        None
    );
    // A ratio with a zero numerator is absent, not a zero frequency.
    assert_eq!(
        TscFrequency::from_cpuid(leaf(1, 0, 24_000_000, 0), leaf(0, 0, 0, 0)),
        None
    );
}

#[test]
fn implausible_low_is_rejected() {
    assert_eq!(TscFrequency::from_hz(MIN_HZ - 1), None);
    assert_eq!(
        TscFrequency::from_cpuid(leaf(0, 0, 0, 0), leaf(99, 0, 0, 0)),
        None
    );
}

#[test]
fn implausible_high_is_rejected() {
    assert_eq!(TscFrequency::from_hz(MAX_HZ + 1), None);
    // 10_001 MHz = 10.001 GHz, above the documented bound.
    assert_eq!(
        TscFrequency::from_cpuid(leaf(0, 0, 0, 0), leaf(10_001, 0, 0, 0)),
        None
    );
}

#[test]
fn bounds_accept_their_edges() {
    assert_eq!(
        TscFrequency::from_hz(MIN_HZ),
        TscFrequency::from_hz(100_000_000)
    );
    assert_eq!(
        TscFrequency::from_hz(MAX_HZ),
        TscFrequency::from_hz(10_000_000_000)
    );
    let low = TscFrequency::from_cpuid(leaf(0, 0, 0, 0), leaf(100, 0, 0, 0))
        .expect("100 MHz is the lowest accepted value");
    assert_eq!(low.hz(), 100_000_000);
    let high = TscFrequency::from_cpuid(leaf(0, 0, 0, 0), leaf(10_000, 0, 0, 0))
        .expect("10 GHz is the highest accepted value");
    assert_eq!(high.hz(), 10_000_000_000);
}

#[test]
fn implausible_ratio_falls_back_to_leaf16() {
    // 50 MHz from the ratio is not plausible; leaf 0x16 says 2 GHz.
    let frequency = TscFrequency::from_cpuid(leaf(1, 1, 50_000_000, 0), leaf(2000, 0, 0, 0))
        .expect("fallback should rescue an implausible ratio");
    assert_eq!(frequency.hz(), 2_000_000_000);
}

#[test]
fn mhz_truncates() {
    let frequency = TscFrequency::from_hz(2_499_999_999).expect("plausible");
    assert_eq!(frequency.mhz(), 2499);
    assert_eq!(frequency.hz(), 2_499_999_999);
}

#[test]
fn nanoseconds_round_to_nearest() {
    let one_ghz = TscFrequency::from_hz(1_000_000_000).expect("plausible");
    assert_eq!(one_ghz.nanoseconds(0), 0);
    assert_eq!(one_ghz.nanoseconds(1), 1);
    assert_eq!(one_ghz.nanoseconds(1234), 1234);

    let three_ghz = TscFrequency::from_hz(3_000_000_000).expect("plausible");
    // 0.333 ns -> 0, 0.667 ns -> 1, 1.333 ns -> 1, 1.667 ns -> 2.
    assert_eq!(three_ghz.nanoseconds(1), 0);
    assert_eq!(three_ghz.nanoseconds(2), 1);
    assert_eq!(three_ghz.nanoseconds(4), 1);
    assert_eq!(three_ghz.nanoseconds(5), 2);
}

#[test]
fn cycles_round_to_nearest() {
    let three_ghz = TscFrequency::from_hz(3_000_000_000).expect("plausible");
    assert_eq!(three_ghz.cycles(0), 0);
    assert_eq!(three_ghz.cycles(1), 3);
    assert_eq!(three_ghz.cycles(2), 6);
    assert_eq!(three_ghz.cycles(1_000_000_000), 3_000_000_000);

    let one_ghz = TscFrequency::from_hz(1_000_000_000).expect("plausible");
    assert_eq!(one_ghz.cycles(1), 1);
}

#[test]
fn conversions_saturate() {
    let slow = TscFrequency::from_hz(MIN_HZ).expect("plausible");
    assert_eq!(slow.nanoseconds(u64::MAX), u64::MAX);
    let fast = TscFrequency::from_hz(MAX_HZ).expect("plausible");
    assert_eq!(fast.cycles(u64::MAX), u64::MAX);
}

#[test]
fn invariant_flag_is_bit_eight() {
    assert!(!is_invariant(0));
    assert!(is_invariant(1 << 8));
    assert!(is_invariant(0xFFFF_FFFF));
    assert!(!is_invariant(1 << 7));
    assert!(!is_invariant(1 << 9));
}

#[test]
fn adversarial_leaves_never_panic() {
    let values = [0u32, 1, 2, 0x8000_0000, u32::MAX, u32::MAX - 1];
    for &eax in &values {
        for &ebx in &values {
            for &ecx in &values {
                let leaf15 = leaf(eax, ebx, ecx, 0);
                let leaf16 = leaf(eax, ebx, ecx, 0);
                let first = TscFrequency::from_cpuid(leaf15, leaf16);
                let second = TscFrequency::from_cpuid(leaf15, leaf16);
                assert_eq!(first, second, "detection must be deterministic");
                if let Some(frequency) = first {
                    assert!(frequency.hz() >= MIN_HZ);
                    assert!(frequency.hz() <= MAX_HZ);
                }
            }
        }
    }
}

#[test]
fn detection_helper_matches_constructor() {
    let leaf15 = leaf(1, 100, 24_000_000, 0);
    let leaf16 = leaf(3000, 0, 0, 0);
    assert_eq!(
        detect(leaf15, leaf16),
        TscFrequency::from_cpuid(leaf15, leaf16)
    );
}

#[test]
fn cache_is_write_once_and_converts() {
    // This is the only test that touches the global cache, so its state is
    // deterministic within this test binary.
    let frequency = TscFrequency::from_hz(2_900_000_000).expect("plausible");
    set(frequency);
    assert_eq!(get(), Some(frequency));
    // 1000 cycles at 2.9 GHz = 344.827... ns -> 345 ns.
    assert_eq!(tsc::cycles_to_ns(1000), Some(345));
    assert_eq!(tsc::cycles_to_ns(0), Some(0));

    // A second detection must not overwrite the first value.
    let other = TscFrequency::from_hz(1_000_000_000).expect("plausible");
    set(other);
    assert_eq!(get(), Some(frequency));
}

#[test]
fn cpuid_leaves_are_exact_for_common_frequencies() {
    // The guest computes crystal * numerator / denominator; every one of
    // these common TSC frequencies has an exact 32-bit representation.
    for hz in [
        100_000_000u64,
        1_500_000_000,
        2_400_000_000,
        2_500_000_000,
        2_900_000_000,
        3_000_000_000,
        10_000_000_000,
    ] {
        let frequency = TscFrequency::from_hz(hz).expect("plausible");
        let leaves = frequency.cpuid_leaves();
        assert_ne!(leaves.ratio_denominator, 0, "hz={}", hz);
        assert_ne!(leaves.ratio_numerator, 0, "hz={}", hz);
        assert_ne!(leaves.crystal_hz, 0, "hz={}", hz);
        let published = u128::from(leaves.crystal_hz) * u128::from(leaves.ratio_numerator)
            / u128::from(leaves.ratio_denominator);
        assert_eq!(published, u128::from(hz), "hz={} leaves={:?}", hz, leaves);
        assert_eq!(leaves.base_mhz, (hz / 1_000_000) as u32);
    }
}

#[test]
fn cpuid_leaves_publish_2_4_ghz_as_12_over_5() {
    let frequency = TscFrequency::from_hz(2_400_000_000).expect("plausible");
    let leaves = frequency.cpuid_leaves();
    assert_eq!(leaves.ratio_denominator, 5);
    assert_eq!(leaves.ratio_numerator, 12);
    assert_eq!(leaves.crystal_hz, 1_000_000_000);
    assert_eq!(leaves.base_mhz, 2400);
}

#[test]
fn cpuid_leaves_fall_back_to_megahertz_precision() {
    // 2^32 + 1: coprime with 1 GHz, so the exact numerator does not fit in
    // 32 bits. The published frequency is truncated to 4294 MHz, less than
    // 0.1 % below the real value.
    let hz = 4_294_967_297u64;
    let frequency = TscFrequency::from_hz(hz).expect("plausible");
    let leaves = frequency.cpuid_leaves();
    assert_eq!(leaves.ratio_denominator, 1);
    assert_eq!(leaves.crystal_hz, tsc::CPUID_FALLBACK_CRYSTAL_HZ);
    assert_eq!(leaves.ratio_numerator, 4294);
    assert_eq!(leaves.base_mhz, 4294);
    let published = 4_294_000_000u64;
    let error = hz - published;
    assert!(error * 1_000 < hz, "relative error must stay below 0.1 %");
}

#[test]
fn cpuid_leaves_are_total_across_the_bounds() {
    for hz in [MIN_HZ, MAX_HZ, MIN_HZ + 1, MAX_HZ - 1] {
        let frequency = TscFrequency::from_hz(hz).expect("plausible");
        let leaves = frequency.cpuid_leaves();
        assert_ne!(leaves.ratio_denominator, 0);
        assert_ne!(leaves.ratio_numerator, 0);
        assert_ne!(leaves.crystal_hz, 0);
        // The guest's computed value never exceeds the plausibility bounds by
        // more than the documented fallback precision.
        let published = u128::from(leaves.crystal_hz) * u128::from(leaves.ratio_numerator)
            / u128::from(leaves.ratio_denominator);
        assert!(published <= u128::from(MAX_HZ));
        assert!(published + 1_000_000 > u128::from(MIN_HZ));
    }
}
