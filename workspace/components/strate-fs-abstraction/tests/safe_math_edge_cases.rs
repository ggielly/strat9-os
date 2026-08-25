//! L1 — `safe_math`: exhaustive edge cases.
//!
//! These helpers guard every filesystem driver against arithmetic overflow
//! (a classic kernel-attack vector: malicious sizes/offsets from disk or
//! network). Existing in-crate tests cover the happy path; this file
//! systematically covers boundaries, overflow, and endianness.

use strate_fs_abstraction::safe_math::*;
use strate_fs_abstraction::FsError;
use strate_fs_abstraction::CheckedOps;

#[test]
fn div_ceil_exact_and_inexact() {
    assert_eq!(div_ceil(10, 5), Ok(2)); // exact
    assert_eq!(div_ceil(11, 5), Ok(3)); // inexact rounds up
    assert_eq!(div_ceil(0, 5), Ok(0));
    assert_eq!(div_ceil(1, 1), Ok(1));
    assert_eq!(div_ceil(u64::MAX - 1, 2), Ok(u64::MAX / 2)); // even value: exact
    // The naive (a+b-1)/b would overflow here; the implementation must not.
    assert_eq!(div_ceil(u64::MAX, 1), Ok(u64::MAX));
    assert_eq!(div_ceil(u64::MAX, u64::MAX), Ok(1));
    // Division by zero is an error, not a panic.
    assert_eq!(div_ceil(10, 0), Err(FsError::ArithmeticOverflow));
}

#[test]
fn saturating_div_never_panics() {
    assert_eq!(saturating_div(10, 2), 5);
    assert_eq!(saturating_div(10, 0), 0); // documented: div-by-zero → 0
    assert_eq!(saturating_div(0, 0), 0);
    assert_eq!(saturating_div(u64::MAX, 1), u64::MAX);
}

#[test]
fn align_up_boundaries() {
    for align in [1u64, 2, 4, 8, 16, 4096, 1 << 20] {
        assert_eq!(align_up(0, align), Ok(0));
        assert_eq!(align_up(1, align), Ok(align));
        assert_eq!(align_up(align, align), Ok(align));
        assert_eq!(align_up(align + 1, align), Ok(align * 2));
    }
    // Overflow must be detected: value near u64::MAX cannot be aligned up.
    assert_eq!(align_up(u64::MAX, 4096), Err(FsError::ArithmeticOverflow));
}

#[test]
fn align_up_rejects_non_power_of_two() {
    for bad_align in [0u64, 3, 5, 6, 7, 9, 12, 1000, u64::MAX] {
        assert_eq!(
            align_up(16, bad_align),
            Err(FsError::AlignmentError),
            "align {} must be rejected",
            bad_align
        );
    }
}

#[test]
fn align_down_boundaries_and_fallback() {
    for align in [1u64, 2, 4, 8, 16, 4096] {
        assert_eq!(align_down(0, align), 0);
        assert_eq!(align_down(align - 1, align), 0);
        assert_eq!(align_down(align, align), align);
        assert_eq!(align_down(3 * align - 1, align), 2 * align);
    }
    // Documented fallback: non-power-of-two alignment returns value unchanged.
    assert_eq!(align_down(123, 0), 123);
    assert_eq!(align_down(123, 3), 123);
    assert_eq!(align_down(u64::MAX, 4096), u64::MAX & !4095);
}

#[test]
fn align_up_down_are_consistent() {
    for v in [0u64, 1, 15, 16, 17, 4095, 4096, 4097] {
        let up = align_up(v, 4096).unwrap();
        let down = align_down(v, 4096);
        assert!(down <= v && v <= up);
        assert_eq!(up - down, if down == v { 0 } else { 4096 });
    }
}

// ===========================================================================
// CheckedOps trait (u64 / u32 / usize)
// ===========================================================================

macro_rules! checked_ops_suite {
    ($t:ty, $mod_name:ident) => {
        mod $mod_name {
            use super::*;

            #[test]
            fn add_detects_overflow() {
                let max = <$t>::MAX;
                assert_eq!(max.checked_add_offset(0), Ok(max));
                assert_eq!(max.checked_add_offset(1), Err(FsError::ArithmeticOverflow));
                assert_eq!((<$t>::MAX - 5).checked_add_offset(5), Ok(max));
            }

            #[test]
            fn mul_detects_overflow() {
                let four: $t = 4;
                let two: $t = 2;
                let zero: $t = 0;
                let half_max_plus_one = <$t>::MAX / 2 + 1;
                assert_eq!(four.checked_mul_size(two), Ok(four + four));
                assert_eq!(
                    half_max_plus_one.checked_mul_size(2),
                    Err(FsError::ArithmeticOverflow)
                );
                assert_eq!(zero.checked_mul_size(<$t>::MAX), Ok(zero));
            }

            #[test]
            fn sub_detects_underflow() {
                let five: $t = 5;
                let zero: $t = 0;
                let one: $t = 1;
                assert_eq!(five.checked_sub_safe(five), Ok(zero));
                assert_eq!(
                    zero.checked_sub_safe(one),
                    Err(FsError::ArithmeticOverflow)
                );
            }

            #[test]
            fn shl_rejects_bit_width_and_beyond() {
                let bits = core::mem::size_of::<$t>() as u32 * 8;
                let one: $t = 1;
                assert_eq!(one.checked_shl_safe(bits), Err(FsError::ArithmeticOverflow));
                assert_eq!(one.checked_shl_safe(bits + 1), Err(FsError::ArithmeticOverflow));
                assert_eq!(one.checked_shl_safe(bits - 1), Ok(one << (bits - 1)));
            }

            #[test]
            fn shl_detects_lost_bits() {
                let bits = core::mem::size_of::<$t>() as u32 * 8;
                // Shifting so that bits fall off must error, not silently truncate.
                let msb_only = <$t>::MAX / 2 + 1; // only MSB set
                let three: $t = 3;
                let zero: $t = 0;
                assert_eq!(msb_only.checked_shl_safe(1), Err(FsError::ArithmeticOverflow));
                assert_eq!(three.checked_shl_safe(bits - 1), Err(FsError::ArithmeticOverflow));
                // Zero shifts through anything.
                assert_eq!(zero.checked_shl_safe(bits - 1), Ok(zero));
            }
        }
    };
}

checked_ops_suite!(u64, u64_ops);
checked_ops_suite!(u32, u32_ops);
checked_ops_suite!(usize, usize_ops);

// ===========================================================================
// CheckedSliceOps: bounds + explicit endianness pinning
// ===========================================================================

#[test]
fn get_checked_bounds() {
    let buf = [0u8; 8];
    assert!(buf.get_checked(0, 8).is_ok());
    assert!(buf.get_checked(8, 0).is_ok()); // empty slice at end is legal
    assert!(buf.get_checked(0, 9).is_err());
    assert!(buf.get_checked(9, 0).is_err());
    assert!(buf.get_checked(usize::MAX, 1).is_err()); // no wraparound
}

#[test]
fn endian_reads_are_explicitly_pinned() {
    let be = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    assert_eq!(be.read_be_u16(0), Ok(0x1234));
    assert_eq!(be.read_be_u32(0), Ok(0x12345678));
    assert_eq!(be.read_be_u64(0), Ok(0x12345678_9ABCDEF0));

    let le = [0x34, 0x12, 0x78, 0x56, 0xF0, 0xDE, 0xBC, 0x9A];
    assert_eq!(le.read_le_u16(0), Ok(0x1234));
    assert_eq!(le.read_le_u32(0), Ok(0x56781234));
    assert_eq!(le.read_le_u64(0), Ok(0x9ABCDEF056781234));

    // Unaligned offsets are fine (byte-wise reads).
    let buf = [0xFF, 0x00, 0x11];
    assert_eq!(buf.read_be_u16(1), Ok(0x0011));

    // Truncated reads error instead of panicking.
    assert_eq!(buf.read_be_u32(0), Err(FsError::BufferTooSmall));
    assert_eq!(buf.read_le_u64(0), Err(FsError::BufferTooSmall));
}
