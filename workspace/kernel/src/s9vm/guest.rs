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

//! s9vm — guest state and validation before entry.
//!
//! **Pure** module: it describes the state of a guest processor (general
//! registers, control registers, segments, system tables) and checks the
//! invariants that the hardware will require anyway, but with a diagnostic
//! usable on the kernel side. Testable on the host (L2 tests).
//!
//! The rules come from the Intel SDM (vol. 3C, "VM entry" chapter
//! and "checking and loading guest state"). No constant specific to a
//! particular hypervisor.

/// Bit `CR0.PE` (protection enable).
pub const CR0_PE: u64 = 1 << 0;
/// Bit `CR0.MP`.
pub const CR0_MP: u64 = 1 << 1;
/// Bit `CR0.EM`.
pub const CR0_EM: u64 = 1 << 2;
/// Bit `CR0.TS`.
pub const CR0_TS: u64 = 1 << 3;
/// Bit `CR0.NE`.
pub const CR0_NE: u64 = 1 << 5;
/// Bit `CR0.WP`.
pub const CR0_WP: u64 = 1 << 16;
/// Bit `CR0.PG` (paging enable).
pub const CR0_PG: u64 = 1 << 31;

/// Bit `CR4.PAE`.
pub const CR4_PAE: u64 = 1 << 5;
/// Bit `CR4.VMXE`.
///
/// `IA32_VMX_CR4_FIXED0` imposes this bit in CR4 as long as the VMX operation is
/// active, including in the guest state: omitting it causes an entry
/// failure (`VM entry with invalid guest state`).
pub const CR4_VMXE: u64 = 1 << 13;
/// Bit `CR4.PGE`.
pub const CR4_PGE: u64 = 1 << 7;
/// Bit `CR4.OSFXSR`.
pub const CR4_OSFXSR: u64 = 1 << 9;
/// Bit `CR4.OSXMMEXCPT`.
pub const CR4_OSXMMEXCPT: u64 = 1 << 10;
/// Bit `CR4.OSXSAVE`.
pub const CR4_OSXSAVE: u64 = 1 << 18;
/// Bit `CR4.SMEP`.
pub const CR4_SMEP: u64 = 1 << 20;
/// Bit `CR4.SMAP`.
pub const CR4_SMAP: u64 = 1 << 21;

/// Bit `EFER.SCE`.
pub const EFER_SCE: u64 = 1 << 0;
/// Bit `EFER.LME` (long mode enable).
pub const EFER_LME: u64 = 1 << 8;
/// Bit `EFER.LMA` (long mode active — set by the CPU, not by the host).
pub const EFER_LMA: u64 = 1 << 10;
/// Bit `EFER.NXE`.
pub const EFER_NXE: u64 = 1 << 11;

/// "Unusable segment" bit of the guest access rights (VMCS: bit 16).
pub const AR_UNUSABLE: u32 = 1 << 16;
/// "L" bit (long mode) of the `CS` access rights.
pub const AR_LONG_MODE: u32 = 1 << 13;
/// "D/B" bit of the access rights.
pub const AR_DEFAULT_BIG: u32 = 1 << 14;
/// "Present" bit.
pub const AR_PRESENT: u32 = 0x80;
/// "Code or data" bit (1 = code/data, 0 = system).
pub const AR_CODE_DATA: u32 = 0x10;
/// "Granularity" bit (G, bit 15): the limit is scaled by 4 KiB. Mandatory
/// when `limit[31:20] != 0` (e.g. a flat `0xFFFF_FFFF` limit).
pub const AR_GRANULARITY: u32 = 1 << 15;

/// Access rights of a read/write data segment, kernel (DPL 0).
///
/// Type 3 = read/write **accessed**. The accessed bit (bit 0 of the type) is
/// mandatory on every usable SS/DS/ES at VM entry — type 2 is refused with
/// "invalid guest state".
pub const fn data_access_rights(dpl: u8) -> u32 {
    0x3 | AR_CODE_DATA | AR_PRESENT | (((dpl as u32) & 3) << 5)
}

/// Access rights of a 64-bit executable/readable code segment.
///
/// Type 0xB = execute/read **accessed**. CS must be an accessed code type
/// (9/11/13/15) at VM entry; type 0xA is refused.
pub const fn long_code_access_rights(dpl: u8) -> u32 {
    0xB | AR_CODE_DATA | AR_PRESENT | AR_LONG_MODE | (((dpl as u32) & 3) << 5)
}

/// Access rights of a 32-bit executable/readable code segment.
pub const fn protected_code_access_rights(dpl: u8) -> u32 {
    0xB | AR_CODE_DATA | AR_PRESENT | AR_DEFAULT_BIG | (((dpl as u32) & 3) << 5)
}

/// "Unusable" access rights (segment not loaded).
pub const fn unusable_access_rights() -> u32 {
    AR_UNUSABLE
}

/// Code selector the 64-bit boot protocol requires (`__BOOT_CS`).
pub const BOOT_CS_SELECTOR: u16 = 0x10;
/// Data selector the 64-bit boot protocol requires (`__BOOT_DS`).
pub const BOOT_DS_SELECTOR: u16 = 0x18;

/// GDT the loader installs before entering a 64-bit boot-protocol kernel.
///
/// Three entries, all flat: the null descriptor, the 4 GiB executable/readable
/// 64-bit code descriptor at selector `0x10`, and the 4 GiB read/write data
/// descriptor at selector `0x18`. The encodings are the conventional ones
/// (`0x00AF_9A00_0000_FFFF` and `0x00CF_9200_0000_FFFF`): present, DPL 0,
/// code/data, code has `L = 1`, both have `G = 1`.
pub const BOOT_GDT: [u64; 3] = [
    0,
    0x00AF_9A00_0000_FFFF,
    0x00CF_9200_0000_FFFF,
];
/// Byte limit of [`BOOT_GDT`].
pub const BOOT_GDT_LIMIT: u32 = (BOOT_GDT.len() * 8 - 1) as u32;

/// Little-endian bytes of [`BOOT_GDT`], ready to copy to guest memory.
pub const fn boot_gdt_bytes() -> [u8; 24] {
    let mut bytes = [0u8; 24];
    let mut entry = 0;
    while entry < BOOT_GDT.len() {
        let value = BOOT_GDT[entry].to_le_bytes();
        let mut index = 0;
        while index < 8 {
            bytes[entry * 8 + index] = value[index];
            index += 1;
        }
        entry += 1;
    }
    bytes
}

/// Segment descriptor as stored in the control block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    /// Selector (16 bits).
    pub selector: u16,
    /// Base (ignored in long mode except for FS/GS).
    pub base: u64,
    /// Limit.
    pub limit: u32,
    /// Access rights in the control block format.
    pub access_rights: u32,
}

impl Segment {
    /// Unusable segment (all fields zero).
    pub const fn unusable() -> Self {
        Self {
            selector: 0,
            base: 0,
            limit: 0,
            access_rights: AR_UNUSABLE,
        }
    }

    /// True if the segment is marked unusable.
    pub const fn is_unusable(&self) -> bool {
        self.access_rights & AR_UNUSABLE != 0
    }

    /// True if the segment is a long-mode code segment (L = 1).
    pub const fn is_long_code(&self) -> bool {
        self.access_rights & AR_CODE_DATA != 0 && self.access_rights & AR_LONG_MODE != 0
    }
}

/// Complete state of a guest processor, ready to be loaded into the control
/// block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestState {
    // General-purpose registers (rsp is a separate field).
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,

    /// Instruction pointer.
    pub rip: u64,
    /// Stack pointer.
    pub rsp: u64,
    /// Flags.
    pub rflags: u64,

    /// Control registers.
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    /// `IA32_EFER`.
    pub efer: u64,
    /// `DR7`.
    pub dr7: u64,
    /// `IA32_PAT` (0 if unused).
    pub pat: u64,

    /// Segments.
    pub es: Segment,
    pub cs: Segment,
    pub ss: Segment,
    pub ds: Segment,
    pub fs: Segment,
    pub gs: Segment,
    pub ldtr: Segment,
    pub tr: Segment,

    /// System tables.
    pub gdtr_base: u64,
    pub gdtr_limit: u32,
    pub idtr_base: u64,
    pub idtr_limit: u32,

    /// MSR SYSENTER.
    pub sysenter_cs: u32,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,

    /// Pending debug exceptions.
    pub pending_debug_exceptions: u64,
    /// Interruptibility state (STI/MOV-SS/SMI/NMI bits).
    pub interruptibility: u32,
    /// Activity state (0 = active).
    pub activity_state: u32,
}

impl GuestState {
    /// Basic 16-bit real-mode state, for a minimal guest.
    ///
    /// No paging, no protected-mode segment: intended for the smoke tests
    /// of the engine (the guest executes a few instructions then exits).
    pub const fn real_mode(entry: u64, stack_top: u64) -> Self {
        Self {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: entry,
            rsp: stack_top,
            rflags: 0x2,
            cr0: 0,
            cr3: 0,
            cr4: 0,
            efer: 0,
            dr7: 0x400,
            pat: 0x0007_0406_0007_0406,
            es: Segment {
                selector: 0,
                base: 0,
                limit: 0xFFFF,
                access_rights: data_access_rights(0),
            },
            cs: Segment {
                selector: 0,
                base: 0,
                limit: 0xFFFF,
                access_rights: protected_code_access_rights(0),
            },
            ss: Segment {
                selector: 0,
                base: 0,
                limit: 0xFFFF,
                access_rights: data_access_rights(0),
            },
            ds: Segment {
                selector: 0,
                base: 0,
                limit: 0xFFFF,
                access_rights: data_access_rights(0),
            },
            fs: Segment::unusable(),
            gs: Segment::unusable(),
            ldtr: Segment::unusable(),
            tr: Segment {
                selector: 0,
                base: 0,
                limit: 0xFFFF,
                access_rights: 0x8B, // type 0xB (busy 32-bit TSS), present
            },
            gdtr_base: 0,
            gdtr_limit: 0,
            idtr_base: 0,
            idtr_limit: 0,
            sysenter_cs: 0,
            sysenter_esp: 0,
            sysenter_eip: 0,
            pending_debug_exceptions: 0,
            interruptibility: 0,
            activity_state: 0,
        }
    }

    /// Basic 64-bit long mode state (paging enabled, CS.L = 1).
    pub const fn long_mode_64(entry: u64, stack_top: u64, cr3: u64) -> Self {
        let mut state = Self::real_mode(entry, stack_top);
        state.cr0 = CR0_PE | CR0_MP | CR0_NE | CR0_PG | CR0_WP;
        state.cr3 = cr3;
        state.cr4 = CR4_PAE | CR4_PGE | CR4_OSFXSR | CR4_OSXMMEXCPT | CR4_VMXE;
        state.efer = EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE;
        // Flat 4 GiB segments: limit 0xFFFF_FFFF forces G = 1. TR is inherited
        // from `real_mode` (type 0xB, present) and must stay usable: VMX never
        // allows an unusable TR, unlike LDTR.
        state.cs = Segment {
            selector: 0x8,
            base: 0,
            limit: 0xFFFF_FFFF,
            access_rights: long_code_access_rights(0) | AR_GRANULARITY,
        };
        state.ss = Segment {
            selector: 0x10,
            base: 0,
            limit: 0xFFFF_FFFF,
            access_rights: data_access_rights(0) | AR_DEFAULT_BIG | AR_GRANULARITY,
        };
        state.ds = state.ss;
        state.es = state.ss;
        state.fs = Segment::unusable();
        state.gs = Segment::unusable();
        state
    }

    /// True if the state requests 64-bit long mode.
    pub const fn is_long_mode(&self) -> bool {
        (self.cr0 & CR0_PG) != 0 && (self.efer & EFER_LME) != 0
    }

    /// Entry state required by the 64-bit boot protocol.
    ///
    /// The protocol enters the kernel in 64-bit mode with paging enabled, an
    /// identity mapping covering the loaded image and the boot objects, a GDT
    /// whose selectors are `__BOOT_CS(0x10)` and `__BOOT_DS(0x18)`, interrupts
    /// disabled, and `%rsi` holding the boot parameter page address. The kernel
    /// installs its own descriptor tables immediately, but the first
    /// instructions run with the loader's segments, so the control block must
    /// carry them: this constructor is the only difference from
    /// [`Self::long_mode_64`], which keeps the engine's historical `CS=0x08`
    /// and `SS=0x10` layout for the s9vm guest kernel.
    ///
    /// `gdt_base`/`gdt_limit` describe the table in guest memory returned by
    /// [`boot_gdt_bytes`]; `boot_params_gpa` is the boot parameter page.
    pub const fn boot_protocol_64(
        entry: u64,
        stack_top: u64,
        cr3: u64,
        boot_params_gpa: u64,
        gdt_base: u64,
        gdt_limit: u32,
    ) -> Self {
        let mut state = Self::long_mode_64(entry, stack_top, cr3);
        // %rsi carries the boot parameter page to the kernel entry point.
        state.rsi = boot_params_gpa;
        // Interrupts are disabled at entry (the kernel enables them when its
        // IDT is installed).
        state.rflags = 0x2;
        state.cs = Segment {
            selector: 0x10,
            base: 0,
            limit: 0xFFFF_FFFF,
            access_rights: long_code_access_rights(0) | AR_GRANULARITY,
        };
        let data = Segment {
            selector: 0x18,
            base: 0,
            limit: 0xFFFF_FFFF,
            access_rights: data_access_rights(0) | AR_DEFAULT_BIG | AR_GRANULARITY,
        };
        state.ds = data;
        state.es = data;
        state.ss = data;
        state.gdtr_base = gdt_base;
        state.gdtr_limit = gdt_limit;
        state.idtr_base = 0;
        state.idtr_limit = 0;
        state
    }

    /// True if the state is in real mode (PE = 0).
    pub const fn is_real_mode(&self) -> bool {
        (self.cr0 & CR0_PE) == 0
    }

    /// Imports the architectural state a policy register block cannot carry.
    ///
    /// The ABI register block describes the general-purpose registers, RIP,
    /// RSP, RFLAGS, CR0/CR3/CR4 and EFER of a vCPU; it has no room for the
    /// descriptor tables, the segment registers or the MSRs a guest loads for
    /// itself from inside the world. The kernel therefore rebuilds the guest
    /// state from that block at the start of every `RUN`, which would reset
    /// the tables and segments to their boot defaults and make the next
    /// interrupt or far control transfer fault.
    ///
    /// `source` is the state read back from the processor (the control block
    /// keeps it across VM exits). Only the fields the policy cannot express
    /// are copied: everything the caller sets keeps the value it already has.
    pub fn import_system_state(&mut self, source: &Self) {
        // A policy change of execution mode invalidates the segment/table
        // snapshot (the constructors provide the matching defaults); only
        // import the hardware state when the mode is unchanged.
        if self.is_long_mode() != source.is_long_mode() {
            return;
        }
        // Segment registers: a guest can reload them from its own GDT (selector
        // and, in long mode, the cached limit/access rights follow).
        self.es = source.es;
        self.cs = source.cs;
        self.ss = source.ss;
        self.ds = source.ds;
        self.fs = source.fs;
        self.gs = source.gs;
        self.ldtr = source.ldtr;
        self.tr = source.tr;
        // Descriptor tables: the bases and limits the guest installed.
        self.gdtr_base = source.gdtr_base;
        self.gdtr_limit = source.gdtr_limit;
        self.idtr_base = source.idtr_base;
        self.idtr_limit = source.idtr_limit;
        // State the guest may write through an intercepted MSR: the replay
        // updates the shadow and the control block, so the processor value is
        // authoritative here.
        self.pat = source.pat;
        self.dr7 = source.dr7;
        self.sysenter_cs = source.sysenter_cs;
        self.sysenter_esp = source.sysenter_esp;
        self.sysenter_eip = source.sysenter_eip;
    }

    /// Builds a guest state from an ABI register block.
    ///
    /// Long mode is selected if `EFER.LME` and `CR0.PG` are both
    /// set; otherwise the base state is real mode. The segments are
    /// initialized accordingly; the registers provided by the caller
    /// (CR0/CR3/CR4/EFER/RIP/RSP/RFLAGS and GPRs) override the default
    /// values. The final consistency is checked by [`Self::validate`].
    pub fn from_abi_regs(regs: &strat9_abi::vmm::VmmRegs) -> Self {
        let long_mode = (regs.efer & EFER_LME) != 0 && (regs.cr0 & CR0_PG) != 0;
        let mut state = if long_mode {
            Self::long_mode_64(regs.rip, regs.rsp, regs.cr3)
        } else {
            Self::real_mode(regs.rip, regs.rsp)
        };
        state.rax = regs.rax;
        state.rbx = regs.rbx;
        state.rcx = regs.rcx;
        state.rdx = regs.rdx;
        state.rsi = regs.rsi;
        state.rdi = regs.rdi;
        state.rbp = regs.rbp;
        state.r8 = regs.r8;
        state.r9 = regs.r9;
        state.r10 = regs.r10;
        state.r11 = regs.r11;
        state.r12 = regs.r12;
        state.r13 = regs.r13;
        state.r14 = regs.r14;
        state.r15 = regs.r15;
        state.rip = regs.rip;
        state.rsp = regs.rsp;
        state.rflags = regs.rflags;
        state.cr0 = regs.cr0;
        state.cr3 = regs.cr3;
        state.cr4 = regs.cr4;
        state.efer = regs.efer;
        state
    }
}

/// Guest state validation error, usable in logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestError {
    /// A forbidden CR0 bit is set.
    Cr0FixedBit,
    /// A mandatory CR0 bit is missing.
    Cr0RequiredBit,
    /// A forbidden CR4 bit is set.
    Cr4FixedBit,
    /// A mandatory CR4 bit is missing.
    Cr4RequiredBit,
    /// Long mode requested without paging (`CR0.PG` absent).
    LongModeWithoutPaging,
    /// Long mode requested without `EFER.LMA` in the guest field (the
    /// "load IA32_EFER" entry control requires `LMA == IA-32e mode guest`).
    LongModeWithoutLma,
    /// Real mode without "unrestricted guest".
    RealModeRestricted,
    /// In long mode, `CS.L` must be 1 and `CS.D` must be 0.
    BadLongCodeSegment,
    /// In long mode, the CS/SS/DS/ES bases must be zero.
    SegmentBaseNotZero,
    /// In long mode, the CS/SS/DS/ES limits must be 0xFFFF_FFFF.
    SegmentLimitNotFull,
    /// `RFLAGS` contains a reserved combination.
    BadRflags,
    /// Invalid interruptibility state.
    BadInterruptibility,
    /// Non-active activity state.
    NotActive,
    /// Invalid stack segment.
    BadStackSegment,
}

impl GuestState {
    /// Validates the state before a guest entry.
    ///
    /// `cr0_fixed0`/`cr0_fixed1` and `cr4_fixed0`/`cr4_fixed1` are the fixed-mask
    /// MSRs read at boot. `unrestricted_guest` indicates whether real
    /// mode without VM86 is available.
    pub fn validate(&self, caps: &FixedBits, unrestricted_guest: bool) -> Result<(), GuestError> {
        // CR0: the fixed bits are imposed by the architecture.
        if self.cr0 & !caps.cr0_fixed1 != 0 {
            return Err(GuestError::Cr0FixedBit);
        }
        if self.cr0 & caps.cr0_fixed0 != caps.cr0_fixed0 {
            return Err(GuestError::Cr0RequiredBit);
        }
        if self.cr4 & !caps.cr4_fixed1 != 0 {
            return Err(GuestError::Cr4FixedBit);
        }
        if self.cr4 & caps.cr4_fixed0 != caps.cr4_fixed0 {
            return Err(GuestError::Cr4RequiredBit);
        }

        // Real mode (PE = 0): requires the unrestricted guest.
        if self.is_real_mode() && !unrestricted_guest {
            return Err(GuestError::RealModeRestricted);
        }

        // Long mode: EFER.LME requests paging, and CS must be in long mode.
        if self.efer & EFER_LME != 0 {
            if self.cr0 & CR0_PG == 0 {
                return Err(GuestError::LongModeWithoutPaging);
            }
            // The guest `IA32_EFER` field is loaded ("load IA32_EFER" entry
            // control): the processor requires that LMA reflects the
            // IA-32e mode of the entry. Omitting LMA causes a `VMfail`.
            if self.efer & EFER_LMA == 0 {
                return Err(GuestError::LongModeWithoutLma);
            }
            if !self.cs.is_long_code() || self.cs.access_rights & AR_DEFAULT_BIG != 0 {
                return Err(GuestError::BadLongCodeSegment);
            }
            // In IA-32e mode the base/limit checks only apply to usable
            // segments: the processor ignores DS/ES/SS entirely, and a guest
            // may legitimately leave them unusable. Skipping them avoids a
            // spurious SegmentLimitNotFull. CS is always usable here (its
            // long-code check above would have rejected an unusable CS).
            for segment in [self.cs, self.ss, self.ds, self.es] {
                if segment.is_unusable() {
                    continue;
                }
                if segment.base != 0 {
                    return Err(GuestError::SegmentBaseNotZero);
                }
                if segment.limit != 0xFFFF_FFFF {
                    return Err(GuestError::SegmentLimitNotFull);
                }
            }
        }

        // RFLAGS: bit 1 mandatory, reserved bits clear.
        if self.rflags & 0x2 == 0 {
            return Err(GuestError::BadRflags);
        }
        // Architectural reserved bits (SDM Vol. 3 §27.3.1.4): bits 3, 5, 15 and
        // 63:22 must be zero. RF (bit 16) is a legitimate flag and must NOT be
        // rejected; VM (bit 17) is checked separately because it is only
        // reserved conditionally.
        // `!0x003F_FFFF` is bits 63:22 (0x003F_FFFF = bits 21:0).
        const RFLAGS_RESERVED: u64 = (1 << 3) | (1 << 5) | (1 << 15) | !0x003F_FFFF;
        if self.rflags & RFLAGS_RESERVED != 0 {
            return Err(GuestError::BadRflags);
        }
        // VM (bit 17, virtual-8086) must be clear when entering IA-32e mode or
        // when CR0.PE = 0; otherwise the processor rejects the entry.
        const RFLAGS_VM: u64 = 1 << 17;
        if self.rflags & RFLAGS_VM != 0 && (self.is_long_mode() || self.is_real_mode()) {
            return Err(GuestError::BadRflags);
        }

        // Interruptibility (SDM Vol. 3 §27.3.1.5): only bits 0-3 are defined.
        if self.interruptibility & !0xF != 0 {
            return Err(GuestError::BadInterruptibility);
        }
        // Blocking by STI (bit 0) and blocking by MOV-SS (bit 1) are mutually
        // exclusive: the processor rejects an entry with both set.
        const STI_BLOCKING: u32 = 1 << 0;
        const MOV_SS_BLOCKING: u32 = 1 << 1;
        if self.interruptibility & STI_BLOCKING != 0 && self.interruptibility & MOV_SS_BLOCKING != 0
        {
            return Err(GuestError::BadInterruptibility);
        }
        // Blocking by STI requires interrupts to be enabled (RFLAGS.IF = 1);
        // otherwise there is nothing for STI to have deferred.
        const RFLAGS_IF: u64 = 1 << 9;
        if self.interruptibility & STI_BLOCKING != 0 && self.rflags & RFLAGS_IF == 0 {
            return Err(GuestError::BadInterruptibility);
        }

        // Activity: only the "active" state (0) is accepted for entry.
        if self.activity_state != 0 {
            return Err(GuestError::NotActive);
        }

        // Stack: in protected/real mode SS must be usable, since RSP is pushed
        // through it. In IA-32e (long) mode the processor ignores SS, so a
        // guest may legitimately leave it unusable.
        if !self.is_long_mode() && self.ss.is_unusable() {
            return Err(GuestError::BadStackSegment);
        }

        Ok(())
    }
}

/// Fixed CR0/CR4 masks, extracted from the capability MSRs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedBits {
    pub cr0_fixed0: u64,
    pub cr0_fixed1: u64,
    pub cr4_fixed0: u64,
    pub cr4_fixed1: u64,
}

impl FixedBits {
    /// Builds from the raw masks.
    pub const fn new(cr0_fixed0: u64, cr0_fixed1: u64, cr4_fixed0: u64, cr4_fixed1: u64) -> Self {
        Self {
            cr0_fixed0,
            cr0_fixed1,
            cr4_fixed0,
            cr4_fixed1,
        }
    }

    /// Permissive masks (synthetic tests, or a CPU whose MSRs are
    /// `0`/`u64::MAX`).
    pub const fn permissive() -> Self {
        Self {
            cr0_fixed0: 0,
            cr0_fixed1: u64::MAX,
            cr4_fixed0: 0,
            cr4_fixed1: u64::MAX,
        }
    }
}
