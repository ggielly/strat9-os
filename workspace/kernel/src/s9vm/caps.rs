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

//! s9vm — decoding of hardware virtualization capabilities (Intel VT-x).
//!
//! This module is **pure**: it reads no MSR itself, it receives a
//! snapshot (`MsrSnapshot`) read by the kernel layer (`s9vm::mod`). It is
//! therefore compilable and testable on the host (L2 tests).
//!
//! The encoding constants come from the Intel documentation (SDM
//! vol. 3C, "VMX" chapters): MSRs `0x480`–`0x492`, `IA32_FEATURE_CONTROL`
//! (`0x3A`). No value specific to a particular hypervisor is used.

/// MSR `IA32_FEATURE_CONTROL`: lock and authorization of enabling.
pub const MSR_FEATURE_CONTROL: u32 = 0x3A;
/// `IA32_FEATURE_CONTROL` bit 0: MSR locked by the firmware.
pub const FEATURE_CONTROL_LOCKED: u64 = 1 << 0;
/// `IA32_FEATURE_CONTROL` bit 2: enabling allowed outside SMX.
pub const FEATURE_CONTROL_ENABLE_OUTSIDE_SMX: u64 = 1 << 2;

/// VT-x capability MSRs (range `0x480`–`0x492`).
pub const MSR_BASIC: u32 = 0x480;
pub const MSR_PIN_BASED: u32 = 0x481;
pub const MSR_PRIMARY_PROC_BASED: u32 = 0x482;
pub const MSR_EXIT_CONTROLS: u32 = 0x483;
pub const MSR_ENTRY_CONTROLS: u32 = 0x484;
pub const MSR_MISC: u32 = 0x485;
pub const MSR_CR0_FIXED0: u32 = 0x486;
pub const MSR_CR0_FIXED1: u32 = 0x487;
pub const MSR_CR4_FIXED0: u32 = 0x488;
pub const MSR_CR4_FIXED1: u32 = 0x489;
pub const MSR_VMCS_ENUM: u32 = 0x48A;
pub const MSR_SECONDARY_PROC_BASED: u32 = 0x48B;
pub const MSR_EPT_VPID_CAP: u32 = 0x48C;
pub const MSR_TRUE_PIN_BASED: u32 = 0x48D;
pub const MSR_TRUE_PRIMARY_PROC_BASED: u32 = 0x48E;
pub const MSR_TRUE_EXIT_CONTROLS: u32 = 0x48F;
pub const MSR_TRUE_ENTRY_CONTROLS: u32 = 0x490;

/// Bits of the `MSR_EPT_VPID_CAP` MSR that are useful to s9vm.
pub mod ept_vpid_cap {
    /// `invept` instruction available.
    pub const INVEPT: u64 = 1 << 0;
    /// 4-level EPT page walk (`PM4L`).
    pub const WALK_LENGTH_4: u64 = 1 << 6;
    /// *Uncacheable* memory type supported for EPT tables.
    pub const MEMTYPE_UC: u64 = 1 << 8;
    /// *Write-back* memory type supported for EPT tables.
    pub const MEMTYPE_WB: u64 = 1 << 14;
    /// 2 MiB pages supported in the EPT.
    pub const PAGE_2MB: u64 = 1 << 16;
    /// 1 GiB pages supported in the EPT.
    pub const PAGE_1GB: u64 = 1 << 17;
    /// *Accessed/dirty* (A/D) bits supported in the EPT.
    pub const ACCESSED_DIRTY: u64 = 1 << 21;
    /// `invvpid` with a single context.
    pub const INVVPID_SINGLE_CONTEXT: u64 = 1 << 32;
    /// `invvpid` with all contexts.
    pub const INVVPID_ALL_CONTEXT: u64 = 1 << 33;
    /// `invvpid` with an individual address.
    pub const INVVPID_INDIVIDUAL_ADDRESS: u64 = 1 << 34;
    /// `invvpid` with a single context, retaining the global entries.
    pub const INVVPID_SINGLE_CONTEXT_RETAIN_GLOBALS: u64 = 1 << 35;
}

/// Useful bits of the `MSR_PIN_BASED`, `MSR_PRIMARY_PROC_BASED`,
/// `MSR_SECONDARY_PROC_BASED` and `MSR_MISC` MSRs.
pub mod control_bits {
    /// "Pin-based" controls: exit on external interrupt.
    pub const PIN_EXTERNAL_INTERRUPT_EXITING: u32 = 1 << 0;
    /// "Pin-based" controls: exit on NMI.
    pub const PIN_NMI_EXITING: u32 = 1 << 3;
    /// "Pin-based" controls: virtual NMIs.
    pub const PIN_VIRTUAL_NMIS: u32 = 1 << 5;
    /// "Pin-based" controls: preemption timer (guest time slice).
    pub const PIN_PREEMPTION_TIMER: u32 = 1 << 6;
    /// "Pin-based" controls: posted interrupts.
    pub const PIN_POSTED_INTERRUPTS: u32 = 1 << 7;

    /// Primary controls: activate the secondary controls.
    pub const PROC_ACTIVATE_SECONDARY: u32 = 1 << 31;
    /// Primary controls: I/O bitmap.
    pub const PROC_USE_IO_BITMAPS: u32 = 1 << 25;
    /// Primary controls: MSR bitmap.
    pub const PROC_USE_MSR_BITMAPS: u32 = 1 << 28;
    /// Primary controls: exit on `hlt`.
    pub const PROC_HLT_EXITING: u32 = 1 << 7;
    /// Primary controls: exit on `rdtsc`.
    pub const PROC_RDTSC_EXITING: u32 = 1 << 12;
    /// Primary controls: exit on `mov cr`.
    pub const PROC_CR3_LOAD_EXITING: u32 = 1 << 15;

    /// Secondary controls: activate the EPT.
    pub const PROC2_ENABLE_EPT: u32 = 1 << 1;
    /// Secondary controls: virtual x2APIC mode.
    pub const PROC2_VIRTUALIZE_X2APIC: u32 = 1 << 4;
    /// Secondary controls: activate VPID.
    pub const PROC2_ENABLE_VPID: u32 = 1 << 5;
    /// Secondary controls: unrestricted guest (real mode without VM86).
    pub const PROC2_UNRESTRICTED_GUEST: u32 = 1 << 7;
    /// Secondary controls: virtualization of the APIC register.
    pub const PROC2_APIC_REGISTER_VIRT: u32 = 1 << 8;
    /// Secondary controls: virtual delivery of interrupts.
    pub const PROC2_VIRTUAL_INTERRUPT_DELIVERY: u32 = 1 << 9;
    /// Secondary controls: exit on `pause` loop (PLE).
    pub const PROC2_PAUSE_LOOP_EXITING: u32 = 1 << 10;
    /// Secondary controls: control block shadowing (nested).
    pub const PROC2_CONTROL_SHADOWING: u32 = 1 << 14;
    /// Secondary controls: `rdseed`.
    pub const PROC2_ENABLE_RDSEED: u32 = 1 << 16;
    /// Secondary controls: *page modification logging*.
    pub const PROC2_ENABLE_PML: u32 = 1 << 17;
    /// Secondary controls: XSAVES/XRSTORS.
    pub const PROC2_ENABLE_XSAVES: u32 = 1 << 20;
    /// Secondary controls: `umwait`.
    pub const PROC2_ENABLE_UMWAIT: u32 = 1 << 21;
    /// Secondary controls: `tpause`.
    pub const PROC2_ENABLE_TPAUSE: u32 = 1 << 22;
}

/// Snapshot of the MSRs needed for detection. All values are
/// raw (as read), decoding is done by [`HwCaps::from_snapshot`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MsrSnapshot {
    pub feature_control: u64,
    pub basic: u64,
    pub pin_based: u64,
    pub primary_proc_based: u64,
    pub exit_controls: u64,
    pub entry_controls: u64,
    pub misc: u64,
    pub cr0_fixed0: u64,
    pub cr0_fixed1: u64,
    pub cr4_fixed0: u64,
    pub cr4_fixed1: u64,
    pub secondary_proc_based: u64,
    pub ept_vpid_cap: u64,
    pub true_pin_based: Option<u64>,
    pub true_primary_proc_based: Option<u64>,
    pub true_exit_controls: Option<u64>,
    pub true_entry_controls: Option<u64>,
}

impl MsrSnapshot {
    /// Builds a snapshot from an MSR reader (the kernel provides
    /// an `rdmsr` reader, the tests a synthetic reader).
    pub fn from_reader<R: Fn(u32) -> u64>(read: R) -> Self {
        let mut snapshot = Self {
            feature_control: read(MSR_FEATURE_CONTROL),
            basic: read(MSR_BASIC),
            pin_based: read(MSR_PIN_BASED),
            primary_proc_based: read(MSR_PRIMARY_PROC_BASED),
            exit_controls: read(MSR_EXIT_CONTROLS),
            entry_controls: read(MSR_ENTRY_CONTROLS),
            misc: read(MSR_MISC),
            cr0_fixed0: read(MSR_CR0_FIXED0),
            cr0_fixed1: read(MSR_CR0_FIXED1),
            cr4_fixed0: read(MSR_CR4_FIXED0),
            cr4_fixed1: read(MSR_CR4_FIXED1),
            secondary_proc_based: read(MSR_SECONDARY_PROC_BASED),
            ept_vpid_cap: read(MSR_EPT_VPID_CAP),
            true_pin_based: None,
            true_primary_proc_based: None,
            true_exit_controls: None,
            true_entry_controls: None,
        };
        // The "TRUE_*" MSRs only exist if bit 55 of `MSR_BASIC` is
        // set (default controls, SDM). On older CPUs, the base
        // MSRs are authoritative.
        if snapshot.basic & (1 << 55) != 0 {
            snapshot.true_pin_based = Some(read(MSR_TRUE_PIN_BASED));
            snapshot.true_primary_proc_based = Some(read(MSR_TRUE_PRIMARY_PROC_BASED));
            snapshot.true_exit_controls = Some(read(MSR_TRUE_EXIT_CONTROLS));
            snapshot.true_entry_controls = Some(read(MSR_TRUE_ENTRY_CONTROLS));
        }
        snapshot
    }
}

/// Set of decoded capabilities, used by the `s9vm` engine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HwCaps {
    /// The firmware allows enabling (bit 2 of `IA32_FEATURE_CONTROL`).
    pub allowed: bool,
    /// MSR `IA32_FEATURE_CONTROL` locked (if it is not, it can be
    /// written once to allow enabling).
    pub feature_control_locked: bool,
    /// Control block revision identifier (bits 30:0 of `MSR_BASIC`).
    pub control_block_revision: u32,
    /// Size of the control block region in bytes (bits 44:32).
    pub control_block_size: u16,
    /// Recommended memory type for the region (bits 53:50; 6 = WB).
    pub control_block_memory_type: u8,
    /// The "TRUE_*" bits are available.
    pub has_true_controls: bool,
    /// EPT available (allowed on the secondary controls side).
    pub ept: bool,
    /// EPT with 4 walk levels.
    pub ept_four_levels: bool,
    /// EPT 2 MiB.
    pub ept_2mb: bool,
    /// EPT 1 GiB.
    pub ept_1gb: bool,
    /// EPT in write-back.
    pub ept_wb: bool,
    /// EPT with A/D bits.
    pub ept_ad: bool,
    /// `invept` available.
    pub invept: bool,
    /// VPID available.
    pub vpid: bool,
    /// `invvpid` variants available.
    pub invvpid_single_context: bool,
    pub invvpid_all_context: bool,
    pub invvpid_individual_address: bool,
    /// Unrestricted guest (16 bits without VM86).
    pub unrestricted_guest: bool,
    /// Virtual APIC (register + delivery).
    pub apic_register_virt: bool,
    pub virtual_interrupt_delivery: bool,
    /// Posted interrupts.
    pub posted_interrupts: bool,
    /// Exit on `pause` loop (PLE).
    pub pause_loop_exiting: bool,
    /// Virtualized x2APIC.
    pub virtualize_x2apic: bool,
    /// Preemption timer.
    pub preemption_timer: bool,
    /// Virtual NMIs.
    pub virtual_nmis: bool,
    /// `rdseed` allowed in the guest.
    pub rdseed: bool,

    /// "Allowed" values (low / high 32 bits) of the control MSRs, after
    /// selecting the `TRUE_*` MSRs when they exist.
    pub pin_allowed: AllowedControls,
    pub primary_proc_allowed: AllowedControls,
    pub secondary_proc_allowed: AllowedControls,
    pub exit_allowed: AllowedControls,
    pub entry_allowed: AllowedControls,

    /// Fixed CR0/CR4 masks.
    pub cr0_fixed0: u64,
    pub cr0_fixed1: u64,
    pub cr4_fixed0: u64,
    pub cr4_fixed1: u64,
}

/// Value of a control MSR: bits that must be 1 (low) and bits that may
/// be 1 (high). See SDM "VMX capability MSRs".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AllowedControls {
    /// Bits that must be 1 in the field.
    pub must_be_one: u32,
    /// Bits that may be 1 in the field.
    pub may_be_one: u32,
}

impl AllowedControls {
    /// Decodes a 64-bit control MSR value.
    pub const fn from_msr(value: u64) -> Self {
        Self {
            must_be_one: value as u32,
            may_be_one: (value >> 32) as u32,
        }
    }

    /// Builds the value to write for a desired control: the mandatory
    /// bits are forced, the forbidden bits are cleared.
    ///
    /// `value = (desired & may_be_one) | must_be_one`
    ///
    /// The relative order of `must_be_one` and `may_be_one` does not matter:
    /// the architecture guarantees that every mandatory bit is also allowed.
    pub const fn apply(self, desired: u32) -> u32 {
        (desired & self.may_be_one) | self.must_be_one
    }

    /// True if all requested bits are allowed (useful to diagnose
    /// an overly ambitious requested configuration).
    pub const fn supports(self, desired: u32) -> bool {
        (desired & !self.may_be_one) == 0
    }
}

impl HwCaps {
    /// Decodes an MSR snapshot. `cpuid_vmx` is the result of
    /// `CPUID.1:ECX[5]`; it is passed separately to keep this module pure.
    pub fn from_snapshot(snapshot: &MsrSnapshot, cpuid_vmx: bool) -> Self {
        let pin = snapshot
            .true_pin_based
            .map(AllowedControls::from_msr)
            .unwrap_or_else(|| AllowedControls::from_msr(snapshot.pin_based));
        let primary = snapshot
            .true_primary_proc_based
            .map(AllowedControls::from_msr)
            .unwrap_or_else(|| AllowedControls::from_msr(snapshot.primary_proc_based));
        let exit = snapshot
            .true_exit_controls
            .map(AllowedControls::from_msr)
            .unwrap_or_else(|| AllowedControls::from_msr(snapshot.exit_controls));
        let entry = snapshot
            .true_entry_controls
            .map(AllowedControls::from_msr)
            .unwrap_or_else(|| AllowedControls::from_msr(snapshot.entry_controls));
        let secondary = AllowedControls::from_msr(snapshot.secondary_proc_based);
        let ept_vpid = snapshot.ept_vpid_cap;

        let _ = cpuid_vmx; // The CPUID presence is checked by the caller.

        Self {
            allowed: snapshot.feature_control & FEATURE_CONTROL_ENABLE_OUTSIDE_SMX != 0
                && cpuid_vmx,
            feature_control_locked: snapshot.feature_control & FEATURE_CONTROL_LOCKED != 0,
            control_block_revision: (snapshot.basic & 0x7FFF_FFFF) as u32,
            control_block_size: ((snapshot.basic >> 32) & 0x1FFF) as u16,
            control_block_memory_type: ((snapshot.basic >> 50) & 0xF) as u8,
            has_true_controls: snapshot.true_pin_based.is_some(),
            ept: cpuid_vmx && secondary.supports(control_bits::PROC2_ENABLE_EPT),
            ept_four_levels: secondary.supports(control_bits::PROC2_ENABLE_EPT)
                && ept_vpid & ept_vpid_cap::WALK_LENGTH_4 != 0,
            ept_2mb: ept_vpid & ept_vpid_cap::PAGE_2MB != 0,
            ept_1gb: ept_vpid & ept_vpid_cap::PAGE_1GB != 0,
            ept_wb: ept_vpid & ept_vpid_cap::MEMTYPE_WB != 0,
            ept_ad: ept_vpid & ept_vpid_cap::ACCESSED_DIRTY != 0,
            invept: ept_vpid & ept_vpid_cap::INVEPT != 0,
            vpid: secondary.supports(control_bits::PROC2_ENABLE_VPID),
            invvpid_single_context: ept_vpid & ept_vpid_cap::INVVPID_SINGLE_CONTEXT != 0,
            invvpid_all_context: ept_vpid & ept_vpid_cap::INVVPID_ALL_CONTEXT != 0,
            invvpid_individual_address: ept_vpid
                & ept_vpid_cap::INVVPID_INDIVIDUAL_ADDRESS
                != 0,
            unrestricted_guest: secondary.supports(control_bits::PROC2_UNRESTRICTED_GUEST),
            apic_register_virt: secondary.supports(control_bits::PROC2_APIC_REGISTER_VIRT),
            virtual_interrupt_delivery: secondary
                .supports(control_bits::PROC2_VIRTUAL_INTERRUPT_DELIVERY),
            posted_interrupts: pin.supports(control_bits::PIN_POSTED_INTERRUPTS),
            pause_loop_exiting: secondary.supports(control_bits::PROC2_PAUSE_LOOP_EXITING),
            virtualize_x2apic: secondary.supports(control_bits::PROC2_VIRTUALIZE_X2APIC),
            preemption_timer: pin.supports(control_bits::PIN_PREEMPTION_TIMER),
            virtual_nmis: pin.supports(control_bits::PIN_VIRTUAL_NMIS),
            rdseed: secondary.supports(control_bits::PROC2_ENABLE_RDSEED),
            pin_allowed: pin,
            primary_proc_allowed: primary,
            secondary_proc_allowed: secondary,
            exit_allowed: exit,
            entry_allowed: entry,
            cr0_fixed0: snapshot.cr0_fixed0,
            cr0_fixed1: snapshot.cr0_fixed1,
            cr4_fixed0: snapshot.cr4_fixed0,
            cr4_fixed1: snapshot.cr4_fixed1,
        }
    }

    /// True if the platform can host the s9vm engine with EPT and VPID.
    pub const fn can_run(&self) -> bool {
        self.allowed && self.ept && self.ept_four_levels
    }

    /// Readable summary (one line) for boot logs.
    pub fn summary(&self) -> alloc::string::String {
        use alloc::format;
        format!(
            "allowed={} rev={} cb={}B ept={} 2mb={} 1gb={} ad={} vpid={} ug={} apicv={} pi={} ple={} x2apic={} ptimer={} cr0fix={:#x}/{:#x} cr4fix={:#x}/{:#x}",
            self.allowed,
            self.control_block_revision,
            self.control_block_size,
            self.ept,
            self.ept_2mb,
            self.ept_1gb,
            self.ept_ad,
            self.vpid,
            self.unrestricted_guest,
            self.apic_register_virt && self.virtual_interrupt_delivery,
            self.posted_interrupts,
            self.pause_loop_exiting,
            self.virtualize_x2apic,
            self.preemption_timer,
            self.cr0_fixed0,
            self.cr0_fixed1,
            self.cr4_fixed0,
            self.cr4_fixed1
        )
    }
}

/// Detection errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapsError {
    /// The CPU does not expose VT-x (CPUID.1:ECX[5] = 0).
    NotSupported,
    /// The firmware forbids enabling and the MSR is locked.
    LockedByFirmware,
    /// EPT absent or not usable in 4 levels.
    EptUnavailable,
}

impl HwCaps {
    /// Checks the enabling conditions and returns an explicit error.
    pub fn validate(&self) -> Result<(), CapsError> {
        if !self.allowed {
            return Err(if self.feature_control_locked {
                CapsError::LockedByFirmware
            } else {
                CapsError::NotSupported
            });
        }
        if !self.ept || !self.ept_four_levels {
            return Err(CapsError::EptUnavailable);
        }
        Ok(())
    }
}
