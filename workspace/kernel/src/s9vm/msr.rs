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

//! s9vm : modelled guest MSRs (interception policy and shadow state).
//!
//! A guest that executes `WRMSR` without interception modifies the **host**
//! MSR file. Several MSRs are per-vCPU architectural state (`IA32_EFER`,
//! `IA32_PAT`, the SYSCALL/SYSENTER targets, the FS/GS bases, `TSC_AUX`), so
//! letting the guest write them is both a host-corruption vector and a guest
//! state-modeling hole. This module keeps a per-vCPU shadow copy of those
//! MSRs and validates every write architecturally before storing it.
//!
//! # Interception policy
//!
//! [`msr_intercept_list`] is the set of MSRs that are both **modelled** and
//! intercepted on reads and writes. Each entry is either per-vCPU state or
//! host-corrupting when passed through:
//!
//! | MSR | Reason |
//! |---|---|
//! | `IA32_EFER` (`0xC000_0080`) | long-mode state, host-corrupting |
//! | `IA32_PAT` (`0x277`) | guest memory-type policy, host-corrupting |
//! | `STAR/LSTAR/CSTAR/SFMASK` (`0xC000_0081..0x84`) | syscall entry state |
//! | `FS_BASE/GS_BASE/KERNEL_GS_BASE` (`0xC000_0100..0x102`) | per-vCPU bases |
//! | `TSC_AUX` (`0xC000_0103`) | per-vCPU auxiliary TSC value |
//! | `IA32_MISC_ENABLE` (`0x1A0`) | host feature control, must not leak |
//! | `SYSENTER_CS/ESP/EIP` (`0x174..0x176`) | guest entry state, host-corrupting |
//!
//! The vCPU bitmap additionally **default-denies writes** in both MSR bitmap
//! windows (`0x0000..0x1FFF` and `0xC000_0000..0xC000_1FFF`): an unmodelled
//! `WRMSR` still exits and is reported to policy instead of reaching the host.
//! Reads of unmodelled MSRs are not intercepted (read-only information leak,
//! not host state corruption); modelled reads return the shadow value.
//!
//! # Invalid writes
//!
//! [`MsrModel::write`] returns [`MsrError::GeneralProtection`] when the value
//! violates a cheap architectural rule (reserved EFER bits, reserved PAT
//! memory types, non-canonical addresses, reserved high halves). The caller
//! chooses the policy; the s9vm emulation reports the exit to policy rather
//! than silently accepting the value or injecting #GP itself. This keeps the
//! model total and lets the policy layer decide whether a malformed guest
//! deserves a #GP, a diagnostic, or termination.

/// `IA32_PAT`.
pub const IA32_PAT: u32 = 0x277;
/// `IA32_MISC_ENABLE`.
pub const IA32_MISC_ENABLE: u32 = 0x1A0;
/// `IA32_SYSENTER_CS`.
pub const IA32_SYSENTER_CS: u32 = 0x174;
/// `IA32_SYSENTER_ESP`.
pub const IA32_SYSENTER_ESP: u32 = 0x175;
/// `IA32_SYSENTER_EIP`.
pub const IA32_SYSENTER_EIP: u32 = 0x176;
/// `IA32_APIC_BASE`.
pub const IA32_APIC_BASE: u32 = 0x1B;
/// `IA32_EFER`.
pub const IA32_EFER: u32 = 0xC000_0080;
/// `STAR`.
pub const IA32_STAR: u32 = 0xC000_0081;
/// `LSTAR`.
pub const IA32_LSTAR: u32 = 0xC000_0082;
/// `CSTAR`.
pub const IA32_CSTAR: u32 = 0xC000_0083;
/// `SFMASK`.
pub const IA32_SFMASK: u32 = 0xC000_0084;
/// `FS_BASE`.
pub const IA32_FS_BASE: u32 = 0xC000_0100;
/// `GS_BASE`.
pub const IA32_GS_BASE: u32 = 0xC000_0101;
/// `KERNEL_GS_BASE`.
pub const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;
/// `TSC_AUX`.
pub const IA32_TSC_AUX: u32 = 0xC000_0103;

/// `EFER.SCE`.
pub const EFER_SCE: u64 = 1 << 0;
/// `EFER.LME`.
pub const EFER_LME: u64 = 1 << 8;
/// `EFER.LMA` (read-only; set by the processor on entry to long mode).
pub const EFER_LMA: u64 = 1 << 10;
/// `EFER.NXE`.
pub const EFER_NXE: u64 = 1 << 11;

/// Bits a guest may write in `IA32_EFER`.
const EFER_WRITABLE: u64 = EFER_SCE | EFER_LME | EFER_NXE;
/// Reset value of `IA32_PAT` (WB/WT/WC/UC for the four entries).
const PAT_RESET: u64 = 0x0007_0406_0007_0406;
/// Valid PAT memory types: UC, WC, WT, WP, WB and UC- (2/3 are reserved).
const PAT_TYPE_VALID: [bool; 8] = [true, true, false, false, true, true, true, true];
/// Reset value of `IA32_APIC_BASE`: base `0xFEE0_0000`, BSP and enable bits.
const APIC_BASE_RESET: u64 = 0x0000_0000_FEE0_0900;
/// `IA32_APIC_BASE` bits a guest may write (base and enable/BSP/x2APIC).
const APIC_BASE_WRITABLE: u64 = 0x000F_FFFF_FFFF_FF00;

/// MSRs that are modelled and intercepted on reads and writes.
const INTERCEPT_LIST: &[u32] = &[
    IA32_PAT,
    IA32_MISC_ENABLE,
    IA32_SYSENTER_CS,
    IA32_SYSENTER_ESP,
    IA32_SYSENTER_EIP,
    IA32_APIC_BASE,
    IA32_EFER,
    IA32_STAR,
    IA32_LSTAR,
    IA32_CSTAR,
    IA32_SFMASK,
    IA32_FS_BASE,
    IA32_GS_BASE,
    IA32_KERNEL_GS_BASE,
    IA32_TSC_AUX,
];

/// The MSR whitelist used by [`crate::s9vm::vcpu`] to program the bitmap.
pub const fn msr_intercept_list() -> &'static [u32] {
    INTERCEPT_LIST
}

/// Error returned by the MSR model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsrError {
    /// The MSR is not modelled by the guest MSR model.
    Unsupported,
    /// The value violates an architectural constraint; the caller decides
    /// whether to inject #GP or report the exit to policy.
    GeneralProtection,
}

/// Effect of a successful MSR write, for the caller that maintains the guest
/// state or the control block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsrWrite {
    /// `IA32_EFER` changed: guest state must be revalidated and the control
    /// block's guest EFER field refreshed.
    Efer,
    /// `IA32_PAT` changed: the control block's guest PAT field must be
    /// refreshed.
    Pat,
    /// `STAR/LSTAR/CSTAR/SFMASK` changed.
    SyscallTargets,
    /// A segment base (`FS_BASE/GS_BASE/KERNEL_GS_BASE`) changed.
    SegmentBase,
    /// `TSC_AUX` changed.
    TscAux,
    /// Another per-vCPU MSR changed (`SYSENTER`, APIC base).
    State,
    /// The write was accepted for compatibility but has no architectural
    /// effect on the emulated guest (for example `IA32_MISC_ENABLE` bits that
    /// the model does not implement).
    Ignored,
}

/// Syscall-related `MSR` values after shadowing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyscallTargets {
    /// `STAR` value.
    pub star: u64,
    /// `LSTAR` value.
    pub lstar: u64,
    /// `CSTAR` value.
    pub cstar: u64,
    /// `SFMASK` value.
    pub sfmask: u64,
}

/// Per-vCPU shadow state of the modelled MSRs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsrModel {
    efer: u64,
    pat: u64,
    star: u64,
    lstar: u64,
    cstar: u64,
    sfmask: u64,
    fs_base: u64,
    gs_base: u64,
    kernel_gs_base: u64,
    tsc_aux: u64,
    misc_enable: u64,
    sysenter_cs: u64,
    sysenter_esp: u64,
    sysenter_eip: u64,
    apic_base: u64,
}

impl MsrModel {
    /// Creates a model with architectural reset values.
    pub const fn new() -> Self {
        Self {
            efer: 0,
            pat: PAT_RESET,
            star: 0,
            lstar: 0,
            cstar: 0,
            sfmask: 0,
            fs_base: 0,
            gs_base: 0,
            kernel_gs_base: 0,
            tsc_aux: 0,
            misc_enable: 0,
            sysenter_cs: 0,
            sysenter_esp: 0,
            sysenter_eip: 0,
            apic_base: APIC_BASE_RESET,
        }
    }

    /// Seeds the EFER shadow from the guest state (including `LMA` when the
    /// guest is already in long mode).
    pub fn set_efer(&mut self, value: u64) {
        self.efer = value;
    }

    /// Seeds the PAT shadow from the guest state.
    pub fn set_pat(&mut self, value: u64) {
        self.pat = value;
    }

    /// Seeds the segment-base shadows from the guest state.
    pub fn set_segment_bases(&mut self, fs_base: u64, gs_base: u64, kernel_gs_base: u64) {
        self.fs_base = fs_base;
        self.gs_base = gs_base;
        self.kernel_gs_base = kernel_gs_base;
    }

    /// Seeds the `SYSENTER` shadows from the guest state.
    pub fn set_sysenter(&mut self, cs: u64, esp: u64, eip: u64) {
        self.sysenter_cs = cs;
        self.sysenter_esp = esp;
        self.sysenter_eip = eip;
    }

    /// Current guest `IA32_EFER` shadow.
    pub const fn efer(&self) -> u64 {
        self.efer
    }

    /// Current guest `IA32_PAT` shadow.
    pub const fn pat(&self) -> u64 {
        self.pat
    }

    /// Current syscall-target shadows.
    pub const fn syscall_targets(&self) -> SyscallTargets {
        SyscallTargets {
            star: self.star,
            lstar: self.lstar,
            cstar: self.cstar,
            sfmask: self.sfmask,
        }
    }

    /// Current `FS_BASE` shadow.
    pub const fn fs_base(&self) -> u64 {
        self.fs_base
    }

    /// Current `GS_BASE` shadow.
    pub const fn gs_base(&self) -> u64 {
        self.gs_base
    }

    /// Current `KERNEL_GS_BASE` shadow.
    pub const fn kernel_gs_base(&self) -> u64 {
        self.kernel_gs_base
    }

    /// Current `TSC_AUX` shadow.
    pub const fn tsc_aux(&self) -> u64 {
        self.tsc_aux
    }

    /// Sets the `TSC_AUX` shadow (validated as a 32-bit value).
    pub fn set_tsc_aux(&mut self, value: u64) -> Result<(), MsrError> {
        if value >> 32 != 0 {
            return Err(MsrError::GeneralProtection);
        }
        self.tsc_aux = value;
        Ok(())
    }

    /// Current `IA32_MISC_ENABLE` shadow.
    pub const fn misc_enable(&self) -> u64 {
        self.misc_enable
    }

    /// Current `IA32_APIC_BASE` shadow.
    pub const fn apic_base(&self) -> u64 {
        self.apic_base
    }

    /// Current `SYSENTER_CS/ESP/EIP` shadows.
    pub const fn sysenter(&self) -> (u64, u64, u64) {
        (self.sysenter_cs, self.sysenter_esp, self.sysenter_eip)
    }

    /// Reads a modelled MSR from the shadow state.
    pub fn read(&self, msr: u32) -> Result<u64, MsrError> {
        let value = match msr {
            IA32_PAT => self.pat,
            IA32_MISC_ENABLE => self.misc_enable,
            IA32_SYSENTER_CS => self.sysenter_cs,
            IA32_SYSENTER_ESP => self.sysenter_esp,
            IA32_SYSENTER_EIP => self.sysenter_eip,
            IA32_APIC_BASE => self.apic_base,
            IA32_EFER => self.efer,
            IA32_STAR => self.star,
            IA32_LSTAR => self.lstar,
            IA32_CSTAR => self.cstar,
            IA32_SFMASK => self.sfmask,
            IA32_FS_BASE => self.fs_base,
            IA32_GS_BASE => self.gs_base,
            IA32_KERNEL_GS_BASE => self.kernel_gs_base,
            IA32_TSC_AUX => self.tsc_aux,
            _ => return Err(MsrError::Unsupported),
        };
        Ok(value)
    }

    /// Writes a modelled MSR after architectural validation.
    ///
    /// `EFER.LMA` is read-only: a value that tries to change it is accepted
    /// with the current LMA preserved, because the architecture defines LMA
    /// as processor-owned. Reserved EFER bits are rejected with
    /// [`MsrError::GeneralProtection`].
    pub fn write(&mut self, msr: u32, value: u64) -> Result<MsrWrite, MsrError> {
        match msr {
            IA32_EFER => {
                if value & !(EFER_WRITABLE | EFER_LMA) != 0 {
                    return Err(MsrError::GeneralProtection);
                }
                self.efer = (value & EFER_WRITABLE) | (self.efer & EFER_LMA);
                Ok(MsrWrite::Efer)
            }
            IA32_PAT => {
                if !valid_pat(value) {
                    return Err(MsrError::GeneralProtection);
                }
                self.pat = value;
                Ok(MsrWrite::Pat)
            }
            IA32_STAR => {
                // Bits 31:0 are reserved; the two selectors live in 63:32.
                if value & 0xFFFF_FFFF != 0 {
                    return Err(MsrError::GeneralProtection);
                }
                self.star = value;
                Ok(MsrWrite::SyscallTargets)
            }
            IA32_LSTAR => {
                if !is_canonical(value) {
                    return Err(MsrError::GeneralProtection);
                }
                self.lstar = value;
                Ok(MsrWrite::SyscallTargets)
            }
            IA32_CSTAR => {
                if !is_canonical(value) {
                    return Err(MsrError::GeneralProtection);
                }
                self.cstar = value;
                Ok(MsrWrite::SyscallTargets)
            }
            IA32_SFMASK => {
                if value >> 32 != 0 {
                    return Err(MsrError::GeneralProtection);
                }
                self.sfmask = value;
                Ok(MsrWrite::SyscallTargets)
            }
            IA32_FS_BASE => {
                if !is_canonical(value) {
                    return Err(MsrError::GeneralProtection);
                }
                self.fs_base = value;
                Ok(MsrWrite::SegmentBase)
            }
            IA32_GS_BASE => {
                if !is_canonical(value) {
                    return Err(MsrError::GeneralProtection);
                }
                self.gs_base = value;
                Ok(MsrWrite::SegmentBase)
            }
            IA32_KERNEL_GS_BASE => {
                if !is_canonical(value) {
                    return Err(MsrError::GeneralProtection);
                }
                self.kernel_gs_base = value;
                Ok(MsrWrite::SegmentBase)
            }
            IA32_TSC_AUX => {
                if value >> 32 != 0 {
                    return Err(MsrError::GeneralProtection);
                }
                self.tsc_aux = value;
                Ok(MsrWrite::TscAux)
            }
            IA32_MISC_ENABLE => {
                // Shadow only the low 32 bits; the model implements no host
                // feature switch, so the write is guest-local and ignored.
                self.misc_enable = value & 0xFFFF_FFFF;
                Ok(MsrWrite::Ignored)
            }
            IA32_SYSENTER_CS => {
                if value >> 32 != 0 {
                    return Err(MsrError::GeneralProtection);
                }
                self.sysenter_cs = value;
                Ok(MsrWrite::State)
            }
            IA32_SYSENTER_ESP => {
                self.sysenter_esp = value;
                Ok(MsrWrite::State)
            }
            IA32_SYSENTER_EIP => {
                if !is_canonical(value) {
                    return Err(MsrError::GeneralProtection);
                }
                self.sysenter_eip = value;
                Ok(MsrWrite::State)
            }
            IA32_APIC_BASE => {
                if value & !APIC_BASE_WRITABLE != 0 {
                    return Err(MsrError::GeneralProtection);
                }
                self.apic_base = value & APIC_BASE_WRITABLE;
                Ok(MsrWrite::State)
            }
            _ => Err(MsrError::Unsupported),
        }
    }
}

impl Default for MsrModel {
    fn default() -> Self {
        Self::new()
    }
}

/// Architectural canonicality check for a 48-bit virtual address.
pub const fn is_canonical(value: u64) -> bool {
    let upper = value >> 47;
    upper == 0 || upper == 0x1_FFFF
}

/// True if every PAT memory-type field is an architectural valid type.
fn valid_pat(value: u64) -> bool {
    for index in 0..8 {
        let memory_type = ((value >> (index * 8)) & 0x7) as usize;
        if !PAT_TYPE_VALID[memory_type] {
            return false;
        }
    }
    true
}
