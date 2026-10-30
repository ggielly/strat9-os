//! Page Attribute Table (PAT) programming for x86_64.
//!
//! `IA32_PAT` holds eight 3-bit memory-type selectors. A 4 KiB page-table
//! entry indexes one of them with `(PAT << 2) | (PCD << 1) | PWT`, where
//! `PAT` is PTE bit 12, `PCD` bit 4 and `PWT` bit 3. Slot 0 (WB) is also the
//! type used when all three bits are clear, so leaving slot 0 as WB keeps
//! ordinary RAM mappings unchanged while slot 1 is repurposed as WC: a WC
//! leaf sets only `PWT`, i.e. index 1.
//!
//! The firmware usually programs a sane PAT, but nothing guarantees a WC
//! entry, and INIT does not reset the register on APs. We therefore program
//! the same layout explicitly on every CPU.

use super::{rdmsr, wrmsr};

/// `IA32_PAT` model-specific register.
pub const IA32_PAT_MSR: u32 = 0x277;

/// PAT layout used by the kernel.
///
/// Each selector occupies a full **byte** of the MSR (IA32_PAT is
/// `PA0` = bits 2:0, `PA1` = bits 10:8, `PA2` = bits 18:16, ...), so the
/// four low slots are `6 | (1 << 8) | (4 << 16) | (0 << 24)`.
///
/// | slot | memory type | encoding | bits  |
/// |------|-------------|----------|-------|
/// | PA0  | Write-Back  | 6        | 2:0   |
/// | PA1  | Write-Combining | 1    | 10:8  |
/// | PA2  | Write-Through | 4      | 18:16 |
/// | PA3  | Uncacheable | 0        | 26:24 |
///
/// Packing the selectors as contiguous 3-bit fields (the old `0x10E`) sets
/// reserved bits 5:3 and makes `WRMSR` raise `#GP` on real hardware/KVM
/// (QEMU-TCG happens to accept it). Slots PA4..PA7 stay UC (0).
pub const PAT_WC_VALUE: u64 = 0x0000_0000_0004_0106;

/// Mask selecting the four low PAT slots (PA0..PA3) in the low dword.
pub const PAT_WC_LOW_MASK: u32 = 0x0707_0707;
/// Low dword of [`PAT_WC_VALUE`] (selectors PA0..PA3).
pub const PAT_WC_LOW: u32 = 0x0004_0106;

/// `CPUID.01H:EDX[16]` : the CPU implements `IA32_PAT`.
///
/// `WRMSR` to `IA32_PAT` is a `#GP` when the MSR is unsupported, so it must
/// never be issued unconditionally (older QEMU CPU models mask PAT off).
#[inline]
pub fn supported() -> bool {
    let (_, _, _, edx) = super::cpuid(1, 0);
    edx & (1 << 16) != 0
}

/// Program [`PAT_WC_VALUE`] on the current CPU and verify it took effect.
///
/// Idempotent: safe to call from the BSP and from every AP. Failure is logged
/// but does not panic; callers that need WC must check [`wc_supported`].
pub fn init() {
    if !supported() {
        log::warn!("IA32_PAT: not supported by this CPU, write-combining disabled");
        return;
    }

    wrmsr(IA32_PAT_MSR, PAT_WC_VALUE);

    let current = rdmsr(IA32_PAT_MSR);
    if (current as u32) & PAT_WC_LOW_MASK != PAT_WC_LOW {
        log::warn!(
            "IA32_PAT: WC slot not accepted (wrote {:#x}, read back {:#x})",
            PAT_WC_VALUE,
            current
        );
    }
}

/// Whether the current CPU's `IA32_PAT` maps PAT slot 1 to WC.
///
/// Re-reads the MSR so the answer reflects the CPU actually executing the
/// caller rather than a cached BSP value. Returns `false` (without touching
/// the MSR) when the CPU has no PAT at all.
pub fn wc_supported() -> bool {
    if !supported() {
        return false;
    }
    let current = rdmsr(IA32_PAT_MSR);
    (current as u32) & PAT_WC_LOW_MASK == PAT_WC_LOW
}
