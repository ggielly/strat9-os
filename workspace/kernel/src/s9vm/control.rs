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

//! s9vm — processor control block (guest/host state structure).
//!
//! This module provides:
//! - field encoding (16, 32, 64 bits and "natural") according to the SDM;
//! - the assembler primitives `vmptrld`, `vmclear`, `vmptrst`, `vmread`,
//!   `vmwrite` (Intel instruction names, unrelated to a commercial
//!   hypervisor);
//! - the building of the enabling value (`EPTP`) and the computation of the
//!   controls from the "allowed" masks.
//!
//! The module depends only on `core`: it is testable on the host (L2 tests).
//! The assembler calls must be made with local interrupts
//! disabled and a control block loaded on the current CPU.

use core::arch::asm;

/// Weight of the fields according to bits 14:13 of the encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldWidth {
    Bits16,
    Bits64,
    Bits32,
    Natural,
}

impl FieldWidth {
    /// Decodes the width of a field from its encoding.
    pub const fn of(field: u32) -> Self {
        match (field >> 13) & 0b11 {
            0 => Self::Bits16,
            1 => Self::Bits64,
            2 => Self::Bits32,
            _ => Self::Natural,
        }
    }
}

/// Field encodings that are useful to the s9vm foundation. The width is deduced
/// by [`FieldWidth::of`]; these constants are checked by the L2 tests.
pub mod field {
    // --- 16-bit control fields ---
    pub const VIRTUAL_PROCESSOR_ID: u32 = 0x0000;
    pub const POSTED_INTERRUPT_NOTIFICATION: u32 = 0x0002;
    pub const EPT_INDEX: u32 = 0x0004;

    // --- 16-bit guest selectors ---
    pub const GUEST_ES_SELECTOR: u32 = 0x0800;
    pub const GUEST_CS_SELECTOR: u32 = 0x0802;
    pub const GUEST_SS_SELECTOR: u32 = 0x0804;
    pub const GUEST_DS_SELECTOR: u32 = 0x0806;
    pub const GUEST_FS_SELECTOR: u32 = 0x0808;
    pub const GUEST_GS_SELECTOR: u32 = 0x080A;
    pub const GUEST_LDTR_SELECTOR: u32 = 0x080C;
    pub const GUEST_TR_SELECTOR: u32 = 0x080E;

    // --- 32-bit guest limits ---
    pub const GUEST_ES_LIMIT: u32 = 0x4800;
    pub const GUEST_CS_LIMIT: u32 = 0x4802;
    pub const GUEST_SS_LIMIT: u32 = 0x4804;
    pub const GUEST_DS_LIMIT: u32 = 0x4806;
    pub const GUEST_FS_LIMIT: u32 = 0x4808;
    pub const GUEST_GS_LIMIT: u32 = 0x480A;
    pub const GUEST_LDTR_LIMIT: u32 = 0x480C;
    pub const GUEST_TR_LIMIT: u32 = 0x480E;
    pub const GUEST_GDTR_LIMIT: u32 = 0x4810;
    pub const GUEST_IDTR_LIMIT: u32 = 0x4812;

    // --- 32-bit guest access rights ---
    pub const GUEST_ES_ACCESS_RIGHTS: u32 = 0x4814;
    pub const GUEST_CS_ACCESS_RIGHTS: u32 = 0x4816;
    pub const GUEST_SS_ACCESS_RIGHTS: u32 = 0x4818;
    pub const GUEST_DS_ACCESS_RIGHTS: u32 = 0x481A;
    pub const GUEST_FS_ACCESS_RIGHTS: u32 = 0x481C;
    pub const GUEST_GS_ACCESS_RIGHTS: u32 = 0x481E;
    pub const GUEST_LDTR_ACCESS_RIGHTS: u32 = 0x4820;
    pub const GUEST_TR_ACCESS_RIGHTS: u32 = 0x4822;
    pub const GUEST_INTERRUPTIBILITY_INFO: u32 = 0x4824;
    pub const GUEST_ACTIVITY_STATE: u32 = 0x4826;
    pub const GUEST_SMSTATE: u32 = 0x4828;
    pub const GUEST_SYSENTER_CS: u32 = 0x482A;

    // --- 16-bit host selectors ---
    pub const HOST_ES_SELECTOR: u32 = 0x0C00;
    pub const HOST_CS_SELECTOR: u32 = 0x0C02;
    pub const HOST_SS_SELECTOR: u32 = 0x0C04;
    pub const HOST_DS_SELECTOR: u32 = 0x0C06;
    pub const HOST_FS_SELECTOR: u32 = 0x0C08;
    pub const HOST_GS_SELECTOR: u32 = 0x0C0A;
    pub const HOST_TR_SELECTOR: u32 = 0x0C0C;

    // --- Structure addresses (64 bits) ---
    pub const IO_BITMAP_A: u32 = 0x2000;
    pub const IO_BITMAP_B: u32 = 0x2002;
    pub const MSR_BITMAP: u32 = 0x2004;
    pub const EXIT_MSR_STORE_ADDRESS: u32 = 0x2006;
    pub const EXIT_MSR_LOAD_ADDRESS: u32 = 0x2008;
    pub const ENTRY_MSR_LOAD_ADDRESS: u32 = 0x200A;
    pub const PML_ADDRESS: u32 = 0x200E;
    pub const TSC_OFFSET: u32 = 0x2010;
    pub const VIRTUAL_APIC_ADDRESS: u32 = 0x2012;
    pub const APIC_ACCESS_ADDRESS: u32 = 0x2014;
    pub const POSTED_INTERRUPT_DESCRIPTOR: u32 = 0x2016;
    pub const EPT_POINTER: u32 = 0x201A;
    pub const EPT_POINTER_LIST: u32 = 0x2024;
    pub const CONTROL_READ_BITMAP: u32 = 0x2026;
    pub const CONTROL_WRITE_BITMAP: u32 = 0x2028;
    pub const VIRTUAL_EXCEPTION_INFO: u32 = 0x202A;

    // --- 32-bit control fields ---
    pub const PIN_BASED_CONTROLS: u32 = 0x4000;
    /// Value of the VMX preemption timer (32 bits).
    pub const VMX_PREEMPTION_TIMER: u32 = 0x482E;
    pub const PRIMARY_PROC_BASED_CONTROLS: u32 = 0x4002;
    pub const EXCEPTION_BITMAP: u32 = 0x4004;
    pub const PAGE_FAULT_ERROR_CODE_MASK: u32 = 0x4006;
    pub const PAGE_FAULT_ERROR_CODE_MATCH: u32 = 0x4008;
    pub const CR3_TARGET_COUNT: u32 = 0x400A;
    /// CR0 bits controlled by the host (0 = guest keeps its value).
    pub const CR0_GUEST_HOST_MASK: u32 = 0x6000;
    /// CR4 bits controlled by the host.
    pub const CR4_GUEST_HOST_MASK: u32 = 0x6002;
    /// Value guest reads back for CR0.
    pub const CR0_READ_SHADOW: u32 = 0x6004;
    /// Value guest reads back for CR4.
    pub const CR4_READ_SHADOW: u32 = 0x6006;
    pub const EXIT_CONTROLS: u32 = 0x400C;
    pub const EXIT_MSR_STORE_COUNT: u32 = 0x400E;
    pub const EXIT_MSR_LOAD_COUNT: u32 = 0x4010;
    pub const ENTRY_CONTROLS: u32 = 0x4012;
    pub const ENTRY_MSR_LOAD_COUNT: u32 = 0x4014;
    pub const ENTRY_INTERRUPT_INFO: u32 = 0x4016;
    pub const ENTRY_EXCEPTION_ERROR_CODE: u32 = 0x4018;
    pub const ENTRY_INSTRUCTION_LENGTH: u32 = 0x401A;
    pub const TPR_THRESHOLD: u32 = 0x401C;
    pub const SECONDARY_PROC_BASED_CONTROLS: u32 = 0x401E;
    pub const PLE_GAP: u32 = 0x4020;
    pub const PLE_WINDOW: u32 = 0x4022;

    // --- Exit information (32 bits, read-only) ---
    pub const INSTRUCTION_ERROR: u32 = 0x4400;
    pub const EXIT_REASON: u32 = 0x4402;
    pub const EXIT_INTERRUPT_INFO: u32 = 0x4404;
    pub const EXIT_INTERRUPT_ERROR_CODE: u32 = 0x4406;
    pub const IDT_VECTORING_INFO: u32 = 0x4408;
    pub const IDT_VECTORING_ERROR_CODE: u32 = 0x440A;
    pub const EXIT_INSTRUCTION_LENGTH: u32 = 0x440C;
    pub const EXIT_INSTRUCTION_INFO: u32 = 0x440E;

    // --- 64-bit guest state ---
    pub const GUEST_VMCS_LINK_POINTER: u32 = 0x2800;
    pub const GUEST_DEBUGCTL: u32 = 0x2802;
    pub const GUEST_PAT: u32 = 0x2804;
    pub const GUEST_EFER: u32 = 0x2806;
    pub const GUEST_PERF_GLOBAL_CTRL: u32 = 0x2808;
    pub const GUEST_PDPTE0: u32 = 0x280A;
    pub const GUEST_PDPTE1: u32 = 0x280C;
    pub const GUEST_PDPTE2: u32 = 0x280E;
    pub const GUEST_PDPTE3: u32 = 0x2810;
    pub const GUEST_IA32_XSS: u32 = 0x2816;

    // --- 64-bit host state ---
    pub const HOST_PAT: u32 = 0x2C00;
    pub const HOST_EFER: u32 = 0x2C02;
    pub const HOST_PERF_GLOBAL_CTRL: u32 = 0x2C04;

    // --- Guest "natural" state (full width) ---
    pub const GUEST_CR0: u32 = 0x6800;
    pub const GUEST_CR3: u32 = 0x6802;
    pub const GUEST_CR4: u32 = 0x6804;
    pub const GUEST_ES_BASE: u32 = 0x6806;
    pub const GUEST_CS_BASE: u32 = 0x6808;
    pub const GUEST_SS_BASE: u32 = 0x680A;
    pub const GUEST_DS_BASE: u32 = 0x680C;
    pub const GUEST_FS_BASE: u32 = 0x680E;
    pub const GUEST_GS_BASE: u32 = 0x6810;
    pub const GUEST_LDTR_BASE: u32 = 0x6812;
    pub const GUEST_TR_BASE: u32 = 0x6814;
    pub const GUEST_GDTR_BASE: u32 = 0x6816;
    pub const GUEST_IDTR_BASE: u32 = 0x6818;
    pub const GUEST_DR7: u32 = 0x681A;
    pub const GUEST_RSP: u32 = 0x681C;
    pub const GUEST_RIP: u32 = 0x681E;
    pub const GUEST_RFLAGS: u32 = 0x6820;
    pub const GUEST_PENDING_DEBUG_EXCEPTIONS: u32 = 0x6822;
    pub const GUEST_SYSENTER_ESP: u32 = 0x6824;
    pub const GUEST_SYSENTER_EIP: u32 = 0x6826;

    // --- Host "natural" state ---
    pub const HOST_CR0: u32 = 0x6C00;
    pub const HOST_CR3: u32 = 0x6C02;
    pub const HOST_CR4: u32 = 0x6C04;
    pub const HOST_FS_BASE: u32 = 0x6C06;
    pub const HOST_GS_BASE: u32 = 0x6C08;
    pub const HOST_TR_BASE: u32 = 0x6C0A;
    pub const HOST_GDTR_BASE: u32 = 0x6C0C;
    pub const HOST_IDTR_BASE: u32 = 0x6C0E;
    /// Host code selector for `sysenter` (32-bit field, `0x4C00`).
    pub const HOST_SYSENTER_CS: u32 = 0x4C00;
    pub const HOST_SYSENTER_ESP: u32 = 0x6C10;
    pub const HOST_SYSENTER_EIP: u32 = 0x6C12;
    pub const HOST_RSP: u32 = 0x6C14;
    pub const HOST_RIP: u32 = 0x6C16;

    // --- Miscellaneous ---
    pub const GUEST_PHYSICAL_ADDRESS: u32 = 0x2400;
    pub const EXIT_QUALIFICATION: u32 = 0x6400;
}

/// Errors of the control block primitives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlError {
    /// The instruction reported a failure (CF = 1).
    Failed,
    /// The block is not loaded on this CPU.
    NotLoaded,
    /// The region is misaligned or too small.
    BadRegion,
    /// The CPU is not in VT-x root mode (enabling absent).
    NotEnabled,
}

/// Scope of a control block: a physical region aligned on 4 KiB.
#[derive(Debug)]
pub struct ControlBlock {
    /// Physical address of the region (4 KiB aligned).
    phys: u64,
    /// Revision identifier expected in the first 4 bytes.
    revision: u32,
    /// Loaded on the current CPU (via `vmptrld`).
    loaded: bool,
}

impl ControlBlock {
    /// Creates a control block descriptor.
    ///
    /// # Safety
    /// `phys` must designate a 4 KiB aligned region, exclusively
    /// reserved for this control block, located in RAM accessible by
    /// the CPU. No access is made here.
    pub const unsafe fn new(phys: u64, revision: u32) -> Self {
        Self {
            phys,
            revision,
            loaded: false,
        }
    }

    /// Physical address of the region.
    pub const fn phys(&self) -> u64 {
        self.phys
    }

    /// Revision encoded in the region.
    pub const fn revision(&self) -> u32 {
        self.revision
    }

    /// True if the block is loaded on the current CPU.
    pub const fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Initializes the first 4 bytes of the region with the revision
    /// identifier. `region_virt` is the virtual address (HHDM) of the region.
    ///
    /// # Safety
    /// `region_virt` must be a valid, aligned address, covering at least
    /// 4 bytes, and not used by another object.
    pub unsafe fn prepare_region(&self, region_virt: *mut u8) {
        // The whole 4 KiB region must be zeroed before use: every VMCS field
        // that is not written explicitly (masks, read shadows, MSR load
        // counts, SMM/CET/PDPTE fields...) must read as 0. Garbage in the
        // CR0/CR4 guest/host masks, for example, makes the host hypervisor
        // merge guest control registers incorrectly and the processor then
        // rejects the entry with "invalid guest state".
        //
        // SAFETY: parameter contract; the region is a private, 4 KiB-aligned
        // frame owned by this control block.
        unsafe {
            core::ptr::write_bytes(region_virt, 0, 4096);
            core::ptr::write_volatile(region_virt as *mut u32, self.revision);
        }
    }

    /// Decodes the base of a 64-bit TSS descriptor (16 bytes).
    ///
    /// In long mode, the base of a TSS is split into four pieces:
    /// `base[15:0]` in bytes 2-3, `base[23:16]` in byte 4,
    /// `base[31:24]` in byte 7 and `base[63:32]` in bytes 8-11.
    ///
    /// This function is pure so that it is testable on the host: an incorrect
    /// shift produces a non-canonical address, which the processor rejects at
    /// guest entry time (`VMfail(8)`, invalid host-state).
    pub const fn decode_tss_base(descriptor_low: u64, descriptor_upper: u32) -> u64 {
        let base_low = (descriptor_low >> 16) & 0xFFFF;
        let base_mid = (descriptor_low >> 32) & 0xFF;
        let base_high = (descriptor_low >> 56) & 0xFF;
        let base_upper = descriptor_upper as u64;
        base_low | (base_mid << 16) | (base_high << 24) | (base_upper << 32)
    }

    /// Loads the control block on the current CPU (`vmptrld`).
    ///
    /// # Safety
    /// - the CPU must be in VT-x root mode (prior enabling);
    /// - `self.phys` must be an initialized region, exclusively
    ///   reserved;
    /// - the block must not be loaded on another CPU.
    pub unsafe fn load(&mut self) -> Result<(), ControlError> {
        let phys = self.phys;
        let fail: u8;
        // SAFETY: the memory operand is a 4 KiB aligned physical address
        // provided by the caller. `vmptrld` reads 8 bytes.
        unsafe {
            asm!(
                "vmptrld qword ptr [{addr}]",
                "setc {fail}",
                addr = in(reg) &phys,
                fail = out(reg_byte) fail,
                options(nostack, preserves_flags)
            );
        }
        if fail != 0 {
            return Err(ControlError::Failed);
        }
        self.loaded = true;
        Ok(())
    }

    /// Unloads the control block (`vmclear`).
    ///
    /// # Safety
    /// The block must be the one loaded on the current CPU, or not be
    /// loaded at all; the caller guarantees that no guest is active.
    pub unsafe fn clear(&mut self) -> Result<(), ControlError> {
        let phys = self.phys;
        let fail: u8;
        // SAFETY: same contract as `load`.
        unsafe {
            asm!(
                "vmclear qword ptr [{addr}]",
                "setc {fail}",
                addr = in(reg) &phys,
                fail = out(reg_byte) fail,
                options(nostack, preserves_flags)
            );
        }
        if fail != 0 {
            return Err(ControlError::Failed);
        }
        self.loaded = false;
        Ok(())
    }

    /// Retrieves the physical address of the currently loaded block (`vmptrst`).
    ///
    /// # Safety
    /// The CPU must be in VT-x root mode.
    pub unsafe fn current_phys(&self) -> Result<u64, ControlError> {
        let mut phys: u64 = 0;
        let fail: u8;
        // SAFETY: `vmptrst` writes 8 bytes into `phys`, a local variable.
        unsafe {
            asm!(
                "vmptrst qword ptr [{addr}]",
                "setc {fail}",
                addr = in(reg) &mut phys,
                fail = out(reg_byte) fail,
                options(nostack)
            );
        }
        if fail != 0 {
            return Err(ControlError::Failed);
        }
        Ok(phys)
    }

    /// Reads a 16-bit field.
    ///
    /// # Safety
    /// - the block must be loaded on the current CPU;
    /// - `field` must be a valid 16-bit encoding.
    pub unsafe fn read_u16(&self, field: u32) -> Result<u16, ControlError> {
        // SAFETY: method contract.
        unsafe { self.read_raw(field).map(|v| v as u16) }
    }

    /// Reads a 32-bit field.
    ///
    /// # Safety
    /// See [`Self::read_u16`]; `field` must be a 32-bit encoding.
    pub unsafe fn read_u32(&self, field: u32) -> Result<u32, ControlError> {
        // SAFETY: method contract.
        unsafe { self.read_raw(field).map(|v| v as u32) }
    }

    /// Reads a 64-bit or "natural" field (both are read as 64 bits).
    ///
    /// # Safety
    /// See [`Self::read_u16`].
    pub unsafe fn read_u64(&self, field: u32) -> Result<u64, ControlError> {
        // SAFETY: method contract.
        unsafe { self.read_raw(field) }
    }

    /// Reads a "natural" field (pointer, RSP/RIP, CR0/CR3/CR4…).
    ///
    /// # Safety
    /// See [`Self::read_u16`].
    pub unsafe fn read_natural(&self, field: u32) -> Result<u64, ControlError> {
        // SAFETY: method contract.
        unsafe { self.read_raw(field) }
    }

    /// Writes a 16-bit field.
    ///
    /// # Safety
    /// - the block must be loaded on the current CPU;
    /// - `field` must be a valid 16-bit encoding;
    /// - the value must respect the architecture constraints (otherwise
    ///   `VMLAUNCH` will fail and the diagnostic will be difficult).
    pub unsafe fn write_u16(&self, field: u32, value: u16) -> Result<(), ControlError> {
        // SAFETY: method contract.
        unsafe { self.write_raw(field, value as u64) }
    }

    /// Writes a 32-bit field.
    ///
    /// # Safety
    /// See [`Self::write_u16`].
    pub unsafe fn write_u32(&self, field: u32, value: u32) -> Result<(), ControlError> {
        // SAFETY: method contract.
        unsafe { self.write_raw(field, value as u64) }
    }

    /// Writes a 64-bit or "natural" field.
    ///
    /// # Safety
    /// See [`Self::write_u16`].
    pub unsafe fn write_u64(&self, field: u32, value: u64) -> Result<(), ControlError> {
        // SAFETY: method contract.
        unsafe { self.write_raw(field, value) }
    }

    /// Writes a "natural" field.
    ///
    /// # Safety
    /// See [`Self::write_u16`].
    pub unsafe fn write_natural(&self, field: u32, value: u64) -> Result<(), ControlError> {
        // SAFETY: method contract.
        unsafe { self.write_raw(field, value) }
    }

    unsafe fn read_raw(&self, field: u32) -> Result<u64, ControlError> {
        if !self.loaded {
            return Err(ControlError::NotLoaded);
        }
        let value: u64;
        let fail: u8;
        // SAFETY: the block is loaded (checked) and `field` comes from the caller.
        unsafe {
            asm!(
                "vmread {value}, {field}",
                "setc {fail}",
                value = out(reg) value,
                field = in(reg) field as u64,
                fail = out(reg_byte) fail,
                options(nostack, preserves_flags)
            );
        }
        if fail != 0 {
            return Err(ControlError::Failed);
        }
        Ok(value)
    }

    unsafe fn write_raw(&self, field: u32, value: u64) -> Result<(), ControlError> {
        if !self.loaded {
            return Err(ControlError::NotLoaded);
        }
        let fail: u8;
        // SAFETY: the block is loaded (checked).
        unsafe {
            asm!(
                "vmwrite {field}, {value}",
                "setc {fail}",
                field = in(reg) field as u64,
                value = in(reg) value,
                fail = out(reg_byte) fail,
                options(nostack, preserves_flags)
            );
        }
        if fail != 0 {
            return Err(ControlError::Failed);
        }
        Ok(())
    }
}

/// Control block revision identifier from `MSR_BASIC`.
pub const fn revision_from_basic(basic: u64) -> u32 {
    (basic & 0x7FFF_FFFF) as u32
}

/// Minimum size of the control block region (bytes), from
/// `MSR_BASIC` bits 44:32.
pub const fn region_size_from_basic(basic: u64) -> u16 {
    ((basic >> 32) & 0x1FFF) as u16
}

/// Builds the enabling value of the second-level translation (`EPTP`):
/// memory type, walk length, A/D and root address.
///
/// Format (SDM): bits 2:0 = memory type (6 = WB), bits 5:3 = walk
/// length minus 1 (3 for 4 levels), bit 6 = A/D, bits 51:12 = physical
/// address of the root (PML4).
pub const fn make_eptp(root_phys: u64, memory_type: u8, four_levels: bool, ad: bool) -> u64 {
    let mut value = (memory_type as u64) & 0x7;
    if four_levels {
        value |= 3 << 3;
    }
    if ad {
        value |= 1 << 6;
    }
    value | (root_phys & 0x000F_FFFF_FFFF_F000)
}

/// Invalidates the second-level translations for a given context
/// (`invept` type 1, single context). Does nothing if the CPU has no `invept`.
///
/// # Safety
/// The CPU must be in VT-x root mode and the second-level translation must no
/// longer be used by an active guest.
pub unsafe fn invalidate_second_level(eptp: u64) {
    let descriptor = [eptp, 0u64];
    // SAFETY: `invept` reads 16 bytes from memory (local descriptor).
    unsafe {
        asm!(
            "invept {kind}, [{descriptor}]",
            kind = in(reg) 1u64,
            descriptor = in(reg) &descriptor,
            options(nostack)
        );
    }
}

/// Invalidates all second-level translations (`invept` type 2).
///
/// # Safety
/// See [`invalidate_second_level`].
pub unsafe fn invalidate_second_level_all() {
    let descriptor = [0u64, 0u64];
    // SAFETY: `invept` type 2 ignores the descriptor, but the memory operand
    // must be valid (16 bytes read).
    unsafe {
        asm!(
            "invept {kind}, [{descriptor}]",
            kind = in(reg) 2u64,
            descriptor = in(reg) &descriptor,
            options(nostack)
        );
    }
}

