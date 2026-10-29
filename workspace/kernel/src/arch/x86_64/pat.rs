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
/// | slot | memory type | encoding |
/// |------|-------------|----------|
/// | PA0  | Write-Back  | 6        |
/// | PA1  | Write-Combining | 1    |
/// | PA2  | Write-Through | 4      |
/// | PA3  | Uncacheable | 0        |
///
/// low dword = `6 | (1 << 3) | (4 << 6) | (0 << 9)` = `0x10E`,
/// high dword = 0 (slots PA4..PA7 unused, encoded as UC).
pub const PAT_WC_VALUE: u64 = 0x0000_0000_0000_010E;

/// Mask selecting the four low PAT slots (PA0..PA3) in the low dword.
pub const PAT_WC_LOW_MASK: u32 = 0x7FF;
/// Low dword of [`PAT_WC_VALUE`].
pub const PAT_WC_LOW: u32 = 0x10E;

/// Program [`PAT_WC_VALUE`] on the current CPU and verify it took effect.
///
/// Idempotent: safe to call from the BSP and from every AP. Failure is logged
/// but does not panic; callers that need WC must check [`wc_supported`].
pub fn init() {
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
/// caller rather than a cached BSP value.
pub fn wc_supported() -> bool {
    let current = rdmsr(IA32_PAT_MSR);
    (current as u32) & PAT_WC_LOW_MASK == PAT_WC_LOW
}
