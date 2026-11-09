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

/// Access rights of a read/write data segment, kernel (DPL 0).
pub const fn data_access_rights(dpl: u8) -> u32 {
    0x2 | AR_CODE_DATA | AR_PRESENT | (((dpl as u32) & 3) << 5)
}

/// Access rights of a 64-bit executable/readable code segment.
pub const fn long_code_access_rights(dpl: u8) -> u32 {
    0xA | AR_CODE_DATA | AR_PRESENT | AR_LONG_MODE | (((dpl as u32) & 3) << 5)
}

/// Access rights of a 32-bit executable/readable code segment.
pub const fn protected_code_access_rights(dpl: u8) -> u32 {
    0xA | AR_CODE_DATA | AR_PRESENT | AR_DEFAULT_BIG | (((dpl as u32) & 3) << 5)
}

/// "Unusable" access rights (segment not loaded).
pub const fn unusable_access_rights() -> u32 {
    AR_UNUSABLE
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
        state.cs = Segment {
            selector: 0x8,
            base: 0,
            limit: 0xFFFF_FFFF,
            access_rights: long_code_access_rights(0),
        };
        state.ss = Segment {
            selector: 0x10,
            base: 0,
            limit: 0xFFFF_FFFF,
            access_rights: data_access_rights(0),
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

    /// True if the state is in real mode (PE = 0).
    pub const fn is_real_mode(&self) -> bool {
        (self.cr0 & CR0_PE) == 0
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
            for segment in [self.cs, self.ss, self.ds, self.es] {
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
        const RFLAGS_RESERVED: u64 = (1 << 3) | (1 << 5) | (1 << 15) | (1 << 16) | (1 << 17);
        if self.rflags & RFLAGS_RESERVED != 0 {
            return Err(GuestError::BadRflags);
        }

        // Interruptibility: only bits 0-3 are defined.
        if self.interruptibility & !0xF != 0 {
            return Err(GuestError::BadInterruptibility);
        }

        // Activity: only the "active" state (0) is accepted for entry.
        if self.activity_state != 0 {
            return Err(GuestError::NotActive);
        }

        // Stack: SS must be usable if RSP is used.
        if self.ss.is_unusable() {
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

