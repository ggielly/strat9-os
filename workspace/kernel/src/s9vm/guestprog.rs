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

//! s9vm : guest program builder (tiny assembler for in-kernel test payloads).
//!
//! The guest payloads of the smoke tests used to be hand-written byte arrays.
//! One of them encoded `mov dx, 0xE9` as `BA E9 00`, which in 64-bit mode is
//! `mov edx, 0x00E9` and consumed the following bytes: the guest ran into the
//! zero-filled tail of its page and triple-faulted on hardware. This module
//! makes that class of mistake impossible: a typed assembler emits the real
//! encoding of every supported instruction and **validates every argument**
//! instead of truncating it.
//!
//! [`GuestProgram::validate_with_decoder`] closes the loop on the host: it
//! re-decodes each emitted instruction with the kernel's own
//! [`decode`][super::decode] module and checks the encoded length, so a
//! hand-patched byte (or a regression in an encoder) is caught on the build
//! machine rather than at boot.
//!
//! # Supported instructions
//!
//! | Method | Encoding | Notes |
//! |---|---|---|
//! | [`GuestProgram::mov_imm8`] | `B0+rb ib` (+`REX.B`) | 8-bit immediate |
//! | [`GuestProgram::mov_imm16`] | `66 B8+rw iw` (+`REX.B`) | 16-bit immediate, historical `BA` trap |
//! | [`GuestProgram::mov_imm32`] | `B8+rd id` (+`REX.B`) | 32-bit immediate, zero-extends |
//! | [`GuestProgram::mov_imm64`] | `REX.W B8+ro io` | full 64-bit immediate |
//! | [`GuestProgram::mov_byte_to_abs`] | `A2 moffs64` | `AL` only (moffs) |
//! | [`GuestProgram::mov_dword_to_abs`] | `A3 moffs64` | `EAX` only |
//! | [`GuestProgram::mov_qword_to_abs`] | `REX.W A3 moffs64` | `RAX` only |
//! | [`GuestProgram::mov_byte_from_abs`] | `A0 moffs64` | `AL` only |
//! | [`GuestProgram::mov_dword_from_abs`] | `A1 moffs64` | `EAX` only |
//! | [`GuestProgram::mov_qword_from_abs`] | `REX.W A1 moffs64` | `RAX` only |
//! | [`GuestProgram::mov_abs_to_reg64`] | `REX.W 8B /r [disp32]` | any register, 32-bit absolute address |
//! | [`GuestProgram::mov_abs_to_reg32`] | `8B /r [disp32]` | 32-bit load, zero-extends |
//! | [`GuestProgram::mov_qword_from_ptr`] | `REX.W 8B /r` | `mov r64, [base]` |
//! | [`GuestProgram::mov_dword_to_ptr`] | `89 /r` | `mov [base], src`, register-indirect |
//! | [`GuestProgram::mov_qword_regs`] | `REX.W 89 /r` | register-to-register move |
//! | [`GuestProgram::cmp_qword_regs`] | `REX.W 39 /r` | `cmp left, right` (64-bit) |
//! | [`GuestProgram::cmp_dword_imm32`] | `81 /7 id` | `cmp r/m32, imm32` |
//! | [`GuestProgram::cmp_byte_imm8`] | `80 /7 ib` | `cmp r/m8, imm8` |
//! | [`GuestProgram::add_qword_imm8`] | `REX.W 83 /0 ib` | sign-extended immediate |
//! | [`GuestProgram::add_byte_ptr_to_accumulator`] | `02 /r` | `add AL, byte [base]` |
//! | [`GuestProgram::out_imm8_port`] | `E6 ib` | `AL` only, port `0..=255` |
//! | [`GuestProgram::in_imm8_port`] | `E4 ib` | `AL` only, port `0..=255` |
//! | [`GuestProgram::hlt`] | `F4` | |
//! | [`GuestProgram::cli`] / [`GuestProgram::sti`] | `FA` / `FB` | |
//! | [`GuestProgram::nop`] | `90` | |
//! | [`GuestProgram::jmp_short`] | `EB cb` | signed 8-bit displacement |
//! | [`GuestProgram::je_short`] / [`GuestProgram::jne_short`] | `74 cb` / `75 cb` | signed 8-bit displacement |
//! | [`GuestProgram::jb_short`] | `72 cb` | signed 8-bit displacement |
//! | [`GuestProgram::loop_short`] | `E2 cb` | signed 8-bit displacement |
//!
//! Forward branches are emitted with the `*_placeholder` methods and resolved
//! once their target offset is known ([`GuestProgram::resolve_short_branch`]);
//! the displacement is range-checked, never guessed.
//!
//! The `moffs` and `in`/`out` immediate-port forms are deliberately limited to
//! the accumulator, which is what the architecture defines: passing another
//! register returns [`GuestProgError::AccumulatorRequired`] instead of silently
//! emitting a different instruction.
//!
//! # Validation
//!
//! Every method returns [`Result`]: a register index out of `0..=15`, a short
//! jump displacement outside `-128..=127`, an immediate-port number above 255,
//! a `mov_abs_to_reg64` address above `u32::MAX`, or a program exceeding
//! [`MAX_PROGRAM_BYTES`] is reported as a typed error. Nothing is truncated and
//! no user-provided value can panic the builder.
//!
//! [`GuestProgram::validate_with_decoder`] walks the emitted instruction
//! records. Instructions inside the decoder's supported subset must decode to
//! exactly the emitted length; the instructions the decoder deliberately does
//! not model (`hlt`, `cli`/`sti`, `nop`, short jumps, `cmp`, arithmetic) are
//! skipped by their recorded length. The final `hlt` is therefore tolerated by
//! design.
//!
//! # Composed payloads
//!
//! [`guestos`] builds the guest-OS bootstrap payload of the `guestos` selftest
//! phase from a [`guestos::GuestOsLayout`]. That payload is the first real user
//! of the assembler: it validates the boot-parameter block and discovers the
//! ACPI RSDP entirely guest-side.
//!
//! # Integration note
//!
//! Payloads are built at run time into a `Vec<u8>`; the current `const`
//! payloads of [`super::guestcode`] cannot switch to it verbatim (a `const`
//! evaluable builder would be needed). The loader and SMP payloads : and the
//! success/failure tails of the ACPI payload : are fully expressible with this
//! API today.

use alloc::vec::Vec;

use super::decode::decode;

/// Maximum size of a guest program built by [`GuestProgram`].
///
/// Test payloads live in one 4 KiB guest code page; refusing to grow past it
/// turns an overflowing payload into a build-time test failure instead of a
/// guest that runs off the end of its page.
pub const MAX_PROGRAM_BYTES: usize = 4096;

/// Reason a [`GuestProgram`] operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestProgError {
    /// Register index outside `0..=15`.
    InvalidRegister(u8),
    /// Short-jump displacement outside `-128..=127`.
    DisplacementOutOfRange(i32),
    /// Immediate-port number above `255`.
    PortOutOfRange(u16),
    /// Absolute address too large for the encoding used (`u32::MAX` for the
    /// `disp32` form).
    AddressOutOfRange(u64),
    /// The instruction only exists for the `RAX`/`EAX`/`AX`/`AL` accumulator,
    /// but another register was supplied.
    AccumulatorRequired(u8),
    /// The program would exceed [`MAX_PROGRAM_BYTES`].
    ProgramTooLong,
    /// A composed payload describes an inconsistent guest layout (alignment,
    /// or an ACPI/scan window that does not contain the firmware image).
    InvalidLayout,
    /// A [`BranchPatch`] handle does not point at an unpatched short branch
    /// (offset out of range or wrong opcode).
    InvalidBranch(usize),
    /// The target of a resolved short branch is outside `-128..=127` bytes of
    /// the instruction.
    BranchTargetOutOfRange,
    /// The decoder rejected the bytes of the instruction at this offset.
    DecodeFailed(usize),
    /// The decoder accepted the instruction but with another length.
    LengthMismatch {
        /// Offset of the instruction in the program.
        offset: usize,
        /// Length recorded by the assembler.
        expected: u8,
        /// Length decoded from the emitted bytes.
        decoded: u8,
    },
}

impl GuestProgError {
    /// Human-readable name of the error (diagnostics).
    pub const fn name(self) -> &'static str {
        match self {
            GuestProgError::InvalidRegister(_) => "invalid-register",
            GuestProgError::DisplacementOutOfRange(_) => "displacement-out-of-range",
            GuestProgError::PortOutOfRange(_) => "port-out-of-range",
            GuestProgError::AddressOutOfRange(_) => "address-out-of-range",
            GuestProgError::AccumulatorRequired(_) => "accumulator-required",
            GuestProgError::ProgramTooLong => "program-too-long",
            GuestProgError::InvalidLayout => "invalid-layout",
            GuestProgError::InvalidBranch(_) => "invalid-branch",
            GuestProgError::BranchTargetOutOfRange => "branch-target-out-of-range",
            GuestProgError::DecodeFailed(_) => "decode-failed",
            GuestProgError::LengthMismatch { .. } => "length-mismatch",
        }
    }
}

/// General-purpose register of a guest program (`0 = RAX … 15 = R15`).
///
/// The value is a newtype rather than a bare `u8` so a builder cannot silently
/// accept an out-of-range index. Prefer the associated constants:
/// `Reg::RAX`, `Reg::RCX`, … `Reg::R15`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reg(u8);

impl Reg {
    /// `RAX`, the accumulator required by the `moffs` and immediate-port forms.
    pub const RAX: Reg = Reg(0);
    /// `RCX`.
    pub const RCX: Reg = Reg(1);
    /// `RDX`.
    pub const RDX: Reg = Reg(2);
    /// `RBX`.
    pub const RBX: Reg = Reg(3);
    /// `RSP`.
    pub const RSP: Reg = Reg(4);
    /// `RBP`.
    pub const RBP: Reg = Reg(5);
    /// `RSI`.
    pub const RSI: Reg = Reg(6);
    /// `RDI`.
    pub const RDI: Reg = Reg(7);
    /// `R8`.
    pub const R8: Reg = Reg(8);
    /// `R9`.
    pub const R9: Reg = Reg(9);
    /// `R10`.
    pub const R10: Reg = Reg(10);
    /// `R11`.
    pub const R11: Reg = Reg(11);
    /// `R12`.
    pub const R12: Reg = Reg(12);
    /// `R13`.
    pub const R13: Reg = Reg(13);
    /// `R14`.
    pub const R14: Reg = Reg(14);
    /// `R15`.
    pub const R15: Reg = Reg(15);

    /// Builds a register from its architectural index (`0..=15`).
    pub const fn new(index: u8) -> Result<Self, GuestProgError> {
        if index < 16 {
            Ok(Reg(index))
        } else {
            Err(GuestProgError::InvalidRegister(index))
        }
    }

    /// Architectural index (`0 = RAX … 15 = R15`).
    pub const fn index(self) -> u8 {
        self.0
    }

    /// True for `R8..=R15`, whose encodings need `REX.B`/`REX.R`.
    const fn needs_rex(self) -> bool {
        self.0 >= 8
    }

    /// Low three bits of the architectural index (the part encoded without
    /// `REX`).
    const fn low(self) -> u8 {
        self.0 & 0x7
    }

    /// Encodes the register, or reports that the instruction needs the
    /// accumulator.
    const fn accumulator(self) -> Result<Self, GuestProgError> {
        if self.0 == Reg::RAX.0 {
            Ok(self)
        } else {
            Err(GuestProgError::AccumulatorRequired(self.0))
        }
    }
}

/// One emitted instruction, kept so validation can walk the program without
/// re-parsing the byte stream.
#[derive(Debug, Clone, Copy)]
struct Entry {
    /// Offset of the instruction in the program.
    offset: usize,
    /// Encoded length in bytes (all supported encodings are shorter than 16).
    length: u8,
    /// True when the kernel decoder is expected to understand the encoding.
    decodable: bool,
}

/// Opaque handle to a short branch whose displacement is resolved later.
///
/// Only the placeholder emitters construct a `BranchPatch`, so a caller cannot
/// forge one; [`GuestProgram::resolve_short_branch`] still validates the
/// offset, the opcode and the target range before writing the displacement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BranchPatch {
    /// Offset of the 2-byte branch instruction in the program.
    offset: usize,
}

impl BranchPatch {
    /// Offset of the branch instruction in the program.
    pub const fn offset(self) -> usize {
        self.offset
    }
}

/// Typed assembler for an x86-64 guest payload.
///
/// Build a program with the `mov_*`/control-flow methods, then read
/// [`GuestProgram::emit_bytes`] to get the machine code. Every builder method
/// returns [`Result`] and validates its arguments; the byte buffer never
/// exceeds [`MAX_PROGRAM_BYTES`].
#[derive(Debug, Default, Clone)]
pub struct GuestProgram {
    /// Encoded instruction bytes.
    bytes: Vec<u8>,
    /// Instruction records, in emission order.
    entries: Vec<Entry>,
}

impl GuestProgram {
    /// Creates an empty program.
    pub const fn new() -> Self {
        // `Vec::new` is const, so the builder can back a `static` if needed.
        Self {
            bytes: Vec::new(),
            entries: Vec::new(),
        }
    }

    /// Encoded program bytes.
    pub fn emit_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Mutable view of the encoded program.
    ///
    /// Intended for adversarial validation tests and diagnostics: the assembler
    /// cannot track manual edits, so a caller that patches a byte must re-run
    /// [`GuestProgram::validate_with_decoder`], which detects any corruption
    /// that changes the decoded structure or length.
    pub fn emit_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Current program length in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// True when no instruction has been emitted.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Number of emitted instructions.
    pub fn instruction_count(&self) -> usize {
        self.entries.len()
    }

    /// Offset at which the next instruction will be emitted.
    pub fn offset(&self) -> usize {
        self.bytes.len()
    }

    /// Discards every emitted instruction.
    pub fn clear(&mut self) {
        self.bytes.clear();
        self.entries.clear();
    }

    /// `mov r8, imm8` (`B0+rb ib`).
    pub fn mov_imm8(&mut self, register: Reg, value: u8) -> Result<(), GuestProgError> {
        let mut buffer = [0u8; 3];
        let mut length = 0usize;
        if let Some(rex) = rex_byte(false, false, false, register.needs_rex()) {
            buffer[length] = rex;
            length += 1;
        }
        buffer[length] = 0xB0 + register.low();
        length += 1;
        buffer[length] = value;
        length += 1;
        self.emit(&buffer[..length], true)
    }

    /// `mov r16, imm16` (`66 B8+rw iw`).
    ///
    /// This is the form a hand-written payload got wrong with `BA` (which is
    /// `mov r32, imm32` in 64-bit mode); the assembler always emits the `66`
    /// operand-size prefix.
    pub fn mov_imm16(&mut self, register: Reg, value: u16) -> Result<(), GuestProgError> {
        let mut buffer = [0u8; 5];
        let mut length = 0usize;
        buffer[length] = 0x66;
        length += 1;
        if let Some(rex) = rex_byte(false, false, false, register.needs_rex()) {
            buffer[length] = rex;
            length += 1;
        }
        buffer[length] = 0xB8 + register.low();
        length += 1;
        buffer[length..length + 2].copy_from_slice(&value.to_le_bytes());
        length += 2;
        self.emit(&buffer[..length], true)
    }

    /// `mov r32, imm32` (`B8+rd id`). The 32-bit write zero-extends.
    pub fn mov_imm32(&mut self, register: Reg, value: u32) -> Result<(), GuestProgError> {
        let mut buffer = [0u8; 6];
        let mut length = 0usize;
        if let Some(rex) = rex_byte(false, false, false, register.needs_rex()) {
            buffer[length] = rex;
            length += 1;
        }
        buffer[length] = 0xB8 + register.low();
        length += 1;
        buffer[length..length + 4].copy_from_slice(&value.to_le_bytes());
        length += 4;
        self.emit(&buffer[..length], true)
    }

    /// `mov r64, imm64` (`REX.W B8+ro io`).
    pub fn mov_imm64(&mut self, register: Reg, value: u64) -> Result<(), GuestProgError> {
        let mut buffer = [0u8; 10];
        let mut length = 0usize;
        // REX.W is mandatory for the 64-bit immediate form.
        if let Some(rex) = rex_byte(true, false, false, register.needs_rex()) {
            buffer[length] = rex;
            length += 1;
        }
        buffer[length] = 0xB8 + register.low();
        length += 1;
        buffer[length..length + 8].copy_from_slice(&value.to_le_bytes());
        length += 8;
        self.emit(&buffer[..length], true)
    }

    /// `mov moffs64, AL` (`A2`), writing one byte to an absolute address.
    pub fn mov_byte_to_abs(&mut self, address: u64, source: Reg) -> Result<(), GuestProgError> {
        self.emit_moffs(0xA2, None, address, source)
    }

    /// `mov moffs64, EAX` (`A3`), writing four bytes to an absolute address.
    pub fn mov_dword_to_abs(&mut self, address: u64, source: Reg) -> Result<(), GuestProgError> {
        self.emit_moffs(0xA3, None, address, source)
    }

    /// `mov moffs64, RAX` (`REX.W A3`), writing eight bytes to an absolute
    /// address.
    pub fn mov_qword_to_abs(&mut self, address: u64, source: Reg) -> Result<(), GuestProgError> {
        self.emit_moffs(0xA3, Some(0x48), address, source)
    }

    /// `mov AL, moffs64` (`A0`), reading one byte from an absolute address.
    pub fn mov_byte_from_abs(
        &mut self,
        address: u64,
        destination: Reg,
    ) -> Result<(), GuestProgError> {
        self.emit_moffs(0xA0, None, address, destination)
    }

    /// `mov EAX, moffs64` (`A1`), reading four bytes from an absolute address.
    pub fn mov_dword_from_abs(
        &mut self,
        address: u64,
        destination: Reg,
    ) -> Result<(), GuestProgError> {
        self.emit_moffs(0xA1, None, address, destination)
    }

    /// `mov RAX, moffs64` (`REX.W A1`), reading eight bytes from an absolute
    /// address.
    pub fn mov_qword_from_abs(
        &mut self,
        address: u64,
        destination: Reg,
    ) -> Result<(), GuestProgError> {
        self.emit_moffs(0xA1, Some(0x48), address, destination)
    }

    /// `mov r64, [disp32]` (`REX.W 8B /r` with a SIB absolute base).
    ///
    /// Loads an arbitrary register from a zero-extended 32-bit absolute
    /// address; this is the scanning-loop form (the `moffs` forms only reach
    /// the accumulator). `address` must fit in 32 bits.
    pub fn mov_abs_to_reg64(
        &mut self,
        address: u64,
        destination: Reg,
    ) -> Result<(), GuestProgError> {
        let address =
            u32::try_from(address).map_err(|_| GuestProgError::AddressOutOfRange(address))?;
        let mut buffer = [0u8; 8];
        let mut length = 0usize;
        if let Some(rex) = rex_byte(true, destination.needs_rex(), false, false) {
            buffer[length] = rex;
            length += 1;
        }
        buffer[length] = 0x8B;
        length += 1;
        // mod = 00, reg = destination, rm = 100 (SIB follows).
        buffer[length] = (destination.low() << 3) | 0x04;
        length += 1;
        // SIB: scale 1, no index, base 101 = absolute disp32.
        buffer[length] = 0x25;
        length += 1;
        buffer[length..length + 4].copy_from_slice(&address.to_le_bytes());
        length += 4;
        self.emit(&buffer[..length], true)
    }

    /// `mov r32, [disp32]` (REX.R `8B /r` with a SIB absolute base).
    ///
    /// Loads the low 32 bits of an arbitrary register from a zero-extended
    /// 32-bit absolute address; the write zero-extends. This is the scalar
    /// companion of [`GuestProgram::mov_abs_to_reg64`], used to read the
    /// 32-bit fields of the boot-parameter block.
    pub fn mov_abs_to_reg32(
        &mut self,
        address: u64,
        destination: Reg,
    ) -> Result<(), GuestProgError> {
        let address =
            u32::try_from(address).map_err(|_| GuestProgError::AddressOutOfRange(address))?;
        let mut buffer = [0u8; 8];
        let mut length = 0usize;
        if let Some(rex) = rex_byte(false, destination.needs_rex(), false, false) {
            buffer[length] = rex;
            length += 1;
        }
        buffer[length] = 0x8B;
        length += 1;
        buffer[length] = (destination.low() << 3) | 0x04;
        length += 1;
        buffer[length] = 0x25;
        length += 1;
        buffer[length..length + 4].copy_from_slice(&address.to_le_bytes());
        length += 4;
        self.emit(&buffer[..length], true)
    }

    /// `mov r64, [base]` (REX.W `8B /r`), a register-indirect 64-bit load.
    ///
    /// Used by scanning loops, which walk a pointer instead of reloading a
    /// fixed absolute address. `RSP`/`R12` bases get a SIB byte and
    /// `RBP`/`R13` bases a zero displacement, exactly like the store form.
    pub fn mov_qword_from_ptr(
        &mut self,
        base: Reg,
        destination: Reg,
    ) -> Result<(), GuestProgError> {
        self.emit_ptr_operand(0x8B, true, destination, base, &[], true)
    }

    /// `mov [base], src` (`89 /r`), a register-indirect 32-bit store.
    ///
    /// Used by the device payloads to program virtio transport registers.
    pub fn mov_dword_to_ptr(&mut self, base: Reg, source: Reg) -> Result<(), GuestProgError> {
        self.emit_ptr_operand(0x89, false, source, base, &[], true)
    }

    /// `mov r64, r64` (REX.W `89 /r`), a register-to-register move.
    pub fn mov_qword_regs(&mut self, destination: Reg, source: Reg) -> Result<(), GuestProgError> {
        let mut buffer = [0u8; 3];
        let mut length = 0usize;
        if let Some(rex) = rex_byte(true, source.needs_rex(), false, destination.needs_rex()) {
            buffer[length] = rex;
            length += 1;
        }
        buffer[length] = 0x89;
        length += 1;
        buffer[length] = 0xC0 | (source.low() << 3) | destination.low();
        length += 1;
        self.emit(&buffer[..length], false)
    }

    /// `cmp left, right` for 64-bit registers (REX.W `39 /r`).
    ///
    /// The condition flags describe `left - right`; use the short-branch
    /// emitters (`je`, `jne`, `jb`, …) to act on them.
    pub fn cmp_qword_regs(&mut self, left: Reg, right: Reg) -> Result<(), GuestProgError> {
        let mut buffer = [0u8; 3];
        let mut length = 0usize;
        if let Some(rex) = rex_byte(true, right.needs_rex(), false, left.needs_rex()) {
            buffer[length] = rex;
            length += 1;
        }
        buffer[length] = 0x39;
        length += 1;
        buffer[length] = 0xC0 | (right.low() << 3) | left.low();
        length += 1;
        self.emit(&buffer[..length], false)
    }

    /// `cmp r/m32, imm32` (`81 /7 id`).
    pub fn cmp_dword_imm32(&mut self, register: Reg, value: u32) -> Result<(), GuestProgError> {
        let mut buffer = [0u8; 7];
        let mut length = 0usize;
        if let Some(rex) = rex_byte(false, false, false, register.needs_rex()) {
            buffer[length] = rex;
            length += 1;
        }
        buffer[length] = 0x81;
        length += 1;
        buffer[length] = 0xF8 | register.low();
        length += 1;
        buffer[length..length + 4].copy_from_slice(&value.to_le_bytes());
        length += 4;
        self.emit(&buffer[..length], false)
    }

    /// `add r64, imm8` (REX.W `83 /0 ib`), the immediate is sign-extended.
    pub fn add_qword_imm8(&mut self, register: Reg, value: i8) -> Result<(), GuestProgError> {
        let mut buffer = [0u8; 4];
        let mut length = 0usize;
        if let Some(rex) = rex_byte(true, false, false, register.needs_rex()) {
            buffer[length] = rex;
            length += 1;
        }
        buffer[length] = 0x83;
        length += 1;
        buffer[length] = 0xC0 | register.low();
        length += 1;
        buffer[length] = value as u8;
        length += 1;
        self.emit(&buffer[..length], false)
    }

    /// `add AL, byte [base]` (`02 /r`), used to sum the RSDP checksum.
    pub fn add_byte_ptr_to_accumulator(&mut self, base: Reg) -> Result<(), GuestProgError> {
        self.emit_ptr_operand(0x02, false, Reg::RAX, base, &[], false)
    }

    /// `out imm8, AL` (`E6 ib`).
    ///
    /// `port` must fit in one byte (the immediate-port form); use a `DX` form
    /// for larger ports. Only `AL` is architecturally encodable.
    pub fn out_imm8_port(&mut self, port: u16, source: Reg) -> Result<(), GuestProgError> {
        source.accumulator()?;
        let port = u8::try_from(port).map_err(|_| GuestProgError::PortOutOfRange(port))?;
        self.emit(&[0xE6, port], true)
    }

    /// `in AL, imm8` (`E4 ib`). The value is read into `AL`.
    pub fn in_imm8_port(&mut self, port: u16, destination: Reg) -> Result<(), GuestProgError> {
        destination.accumulator()?;
        let port = u8::try_from(port).map_err(|_| GuestProgError::PortOutOfRange(port))?;
        self.emit(&[0xE4, port], true)
    }

    /// `hlt` (`F4`).
    pub fn hlt(&mut self) -> Result<(), GuestProgError> {
        self.emit(&[0xF4], false)
    }

    /// `cli` (`FA`).
    pub fn cli(&mut self) -> Result<(), GuestProgError> {
        self.emit(&[0xFA], false)
    }

    /// `sti` (`FB`).
    pub fn sti(&mut self) -> Result<(), GuestProgError> {
        self.emit(&[0xFB], false)
    }

    /// `nop` (`90`).
    pub fn nop(&mut self) -> Result<(), GuestProgError> {
        self.emit(&[0x90], false)
    }

    /// `jmp rel8` (`EB cb`), displacement relative to the next instruction.
    pub fn jmp_short(&mut self, displacement: i32) -> Result<(), GuestProgError> {
        self.emit_short_branch(0xEB, displacement)
    }

    /// `je rel8` (`74 cb`), displacement relative to the next instruction.
    pub fn je_short(&mut self, displacement: i32) -> Result<(), GuestProgError> {
        self.emit_short_branch(0x74, displacement)
    }

    /// `jne rel8` (`75 cb`), displacement relative to the next instruction.
    pub fn jne_short(&mut self, displacement: i32) -> Result<(), GuestProgError> {
        self.emit_short_branch(0x75, displacement)
    }

    /// `jb rel8` (`72 cb`), displacement relative to the next instruction.
    pub fn jb_short(&mut self, displacement: i32) -> Result<(), GuestProgError> {
        self.emit_short_branch(0x72, displacement)
    }

    /// `loop rel8` (`E2 cb`), displacement relative to the next instruction.
    pub fn loop_short(&mut self, displacement: i32) -> Result<(), GuestProgError> {
        self.emit_short_branch(0xE2, displacement)
    }

    /// Emits a forward `je rel8` whose displacement is filled in later by
    /// [`GuestProgram::resolve_short_branch`].
    ///
    /// Forward branches appear in real payloads (a failure stub emitted after
    /// the check that jumps over it): the target is not known when the branch
    /// is emitted, so it is recorded as a handle instead of being guessed.
    pub fn je_short_placeholder(&mut self) -> Result<BranchPatch, GuestProgError> {
        self.emit_branch_placeholder(0x74)
    }

    /// Emits a forward `jne rel8` whose displacement is filled in later by
    /// [`GuestProgram::resolve_short_branch`].
    pub fn jne_short_placeholder(&mut self) -> Result<BranchPatch, GuestProgError> {
        self.emit_branch_placeholder(0x75)
    }

    /// Fills in the displacement of a branch emitted with a placeholder.
    ///
    /// `target` is the program offset the branch must reach; it may be before
    /// or after the branch, as long as the signed 8-bit displacement fits.
    /// Lengths never change, so the offsets recorded by the assembler and by
    /// [`GuestProgram::validate_with_decoder`] stay valid.
    pub fn resolve_short_branch(
        &mut self,
        patch: BranchPatch,
        target: usize,
    ) -> Result<(), GuestProgError> {
        let instruction_end = patch
            .offset
            .checked_add(2)
            .ok_or(GuestProgError::InvalidBranch(patch.offset))?;
        if instruction_end > self.bytes.len() {
            return Err(GuestProgError::InvalidBranch(patch.offset));
        }
        let opcode = *self
            .bytes
            .get(patch.offset)
            .ok_or(GuestProgError::InvalidBranch(patch.offset))?;
        if !matches!(opcode, 0x74 | 0x75) {
            return Err(GuestProgError::InvalidBranch(patch.offset));
        }
        let displacement = i64::try_from(target)
            .map_err(|_| GuestProgError::BranchTargetOutOfRange)?
            - i64::try_from(instruction_end).map_err(|_| GuestProgError::BranchTargetOutOfRange)?;
        let displacement =
            i8::try_from(displacement).map_err(|_| GuestProgError::BranchTargetOutOfRange)?;
        if let Some(slot) = self.bytes.get_mut(patch.offset + 1) {
            *slot = displacement as u8;
        }
        Ok(())
    }

    /// `cmp r/m8, imm8` (`80 /7 ib`).
    pub fn cmp_byte_imm8(&mut self, register: Reg, value: u8) -> Result<(), GuestProgError> {
        let mut buffer = [0u8; 4];
        let mut length = 0usize;
        if let Some(rex) = rex_byte(false, false, false, register.needs_rex()) {
            buffer[length] = rex;
            length += 1;
        }
        buffer[length] = 0x80;
        length += 1;
        // mod = 11 (register operand), reg = 111 (/7), rm = register.
        buffer[length] = 0xF8 | register.low();
        length += 1;
        buffer[length] = value;
        length += 1;
        self.emit(&buffer[..length], false)
    }

    /// Re-decodes every emitted instruction with the kernel decoder.
    ///
    /// For each instruction the decoder supports, the decoded length must equal
    /// the emitted length; any decode failure or mismatch is a
    /// [`GuestProgError`]. Instructions outside the decoder's subset (`hlt`,
    /// `cli`/`sti`, `nop`, short jumps and `cmp`) are skipped by their recorded
    /// length : this is what lets a payload end with `hlt`. An empty program is
    /// valid.
    pub fn validate_with_decoder(&self) -> Result<(), GuestProgError> {
        let mut rip = 0u64;
        for entry in &self.entries {
            let end = entry
                .offset
                .checked_add(usize::from(entry.length))
                .ok_or(GuestProgError::DecodeFailed(entry.offset))?;
            let bytes = self
                .bytes
                .get(entry.offset..end)
                .ok_or(GuestProgError::DecodeFailed(entry.offset))?;
            let decoded = decode(bytes, rip, |_| 0);
            if entry.decodable {
                let decoded = decoded.map_err(|_| GuestProgError::DecodeFailed(entry.offset))?;
                let decoded_length = decoded.instruction_length(rip);
                if decoded_length != entry.length {
                    return Err(GuestProgError::LengthMismatch {
                        offset: entry.offset,
                        expected: entry.length,
                        decoded: decoded_length,
                    });
                }
            }
            rip = rip.wrapping_add(u64::from(entry.length));
        }
        Ok(())
    }

    /// Appends one encoded instruction and records it for validation.
    fn emit(&mut self, bytes: &[u8], decodable: bool) -> Result<(), GuestProgError> {
        let length = u8::try_from(bytes.len()).map_err(|_| GuestProgError::ProgramTooLong)?;
        let end = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(GuestProgError::ProgramTooLong)?;
        if end > MAX_PROGRAM_BYTES {
            return Err(GuestProgError::ProgramTooLong);
        }
        let offset = self.bytes.len();
        self.bytes.extend_from_slice(bytes);
        self.entries.push(Entry {
            offset,
            length,
            decodable,
        });
        Ok(())
    }

    /// Emits one `moffs` instruction after checking the accumulator operand.
    fn emit_moffs(
        &mut self,
        opcode: u8,
        rex: Option<u8>,
        address: u64,
        register: Reg,
    ) -> Result<(), GuestProgError> {
        register.accumulator()?;
        let mut buffer = [0u8; 10];
        let mut length = 0usize;
        if let Some(rex) = rex {
            buffer[length] = rex;
            length += 1;
        }
        buffer[length] = opcode;
        length += 1;
        buffer[length..length + 8].copy_from_slice(&address.to_le_bytes());
        length += 8;
        self.emit(&buffer[..length], true)
    }

    /// Emits an instruction with a register-indirect memory operand `[base]`.
    ///
    /// `reg_field` is the ModRM register operand (source for stores, destination
    /// for loads); `immediate` is appended after the addressing bytes. The
    /// `RSP`/`R12` base needs a SIB byte and the `RBP`/`R13` base needs a zero
    /// `disp8` to avoid the `mod = 00` RIP-relative meaning.
    fn emit_ptr_operand(
        &mut self,
        opcode: u8,
        rex_w: bool,
        reg_field: Reg,
        base: Reg,
        immediate: &[u8],
        decodable: bool,
    ) -> Result<(), GuestProgError> {
        let mut buffer = [0u8; 16];
        let mut length = 0usize;
        if let Some(rex) = rex_byte(rex_w, reg_field.needs_rex(), false, base.needs_rex()) {
            buffer[length] = rex;
            length += 1;
        }
        buffer[length] = opcode;
        length += 1;
        if base.low() == 4 {
            // Base 100 selects RSP (or R12 via REX.B); index 100 = no index.
            buffer[length] = (reg_field.low() << 3) | 0x04;
            length += 1;
            buffer[length] = 0x24;
            length += 1;
        } else if base.low() == 5 {
            // `RBP`/`R13` with mod = 00 would be RIP-relative: use mod = 01.
            buffer[length] = 0x40 | (reg_field.low() << 3) | base.low();
            length += 1;
            buffer[length] = 0x00;
            length += 1;
        } else {
            buffer[length] = (reg_field.low() << 3) | base.low();
            length += 1;
        }
        if length + immediate.len() > buffer.len() {
            return Err(GuestProgError::ProgramTooLong);
        }
        buffer[length..length + immediate.len()].copy_from_slice(immediate);
        length += immediate.len();
        self.emit(&buffer[..length], decodable)
    }

    /// Emits a 2-byte short branch with a placeholder displacement.
    fn emit_branch_placeholder(&mut self, opcode: u8) -> Result<BranchPatch, GuestProgError> {
        let offset = self.offset();
        self.emit(&[opcode, 0x00], false)?;
        Ok(BranchPatch { offset })
    }

    /// Emits a short branch after validating its signed 8-bit displacement.
    fn emit_short_branch(&mut self, opcode: u8, displacement: i32) -> Result<(), GuestProgError> {
        let displacement = i8::try_from(displacement)
            .map_err(|_| GuestProgError::DisplacementOutOfRange(displacement))?;
        self.emit(&[opcode, displacement as u8], false)
    }
}

/// Builds a `REX` prefix, or `None` when the bare `0x40` prefix would be a
/// no-op.
const fn rex_byte(w: bool, r: bool, x: bool, b: bool) -> Option<u8> {
    let byte = 0x40 | ((w as u8) << 3) | ((r as u8) << 2) | ((x as u8) << 1) | (b as u8);
    if byte == 0x40 {
        None
    } else {
        Some(byte)
    }
}

/// Guest-OS bootstrap payload: validate the hand-off block and find ACPI.
///
/// This is the payload of the `guestos` selftest phase. It behaves like the
/// first stage of a real operating system: it reads the boot-parameter block
/// written by [`crate::s9vm::vm::write_boot_params`], checks that the fields a
/// kernel needs are populated, scans the legacy BIOS window for the ACPI RSDP,
/// validates the ACPI 1.0 checksum, then reports through the debug port.
///
/// The payload is **built at run time with the typed assembler** rather than
/// stored as a hand-written byte array: every instruction is encoded by the
/// methods above (no `BA`/`MOV DX` class of mistake) and the whole program is
/// re-decoded by [`GuestProgram::validate_with_decoder`] in the host tests.
///
/// # What it validates
///
/// 1. magic: the 64-bit value at [`bootparams::OFF_MAGIC`] is
///    [`bootparams::MAGIC`];
/// 2. counts: `cmdline_len`, `memory_count` and `module_count` are non-zero
///    (the phase stores a command line and one module first);
/// 3. RSDP field: `rsdp_gpa` equals the address the firmware image was written
///    to;
/// 4. RSDP scan: the 8-byte `RSD PTR ` signature is found, on a 16-byte
///    boundary, inside the configured window, and the address found is the
///    `rsdp_gpa` field value;
/// 5. checksum: the 20 bytes of the ACPI 1.0 RSDP sum to zero modulo 256.
///
/// # Reported bytes
///
/// Success: [`PASS_MARKER`], [`STATUS_OK`], then the low byte of `cmdline_len`
/// and of `memory_count`, then `hlt`. Failure: [`FAIL_MARKER`], the failing
/// [`failure_step`] code, then `hlt`. The phase's exit loop collects these bytes
/// and independently decodes the same block on the kernel side.
pub mod guestos {
    use super::{GuestProgError, GuestProgram, Reg};
    // `guestos` is nested one level below the assembler module: the boot
    // parameter and payload modules are its siblings.
    use super::super::{bootparams, guestcode::DEBUG_PORT};

    /// Byte written on the debug port when every validation passed.
    pub const PASS_MARKER: u8 = b'O';
    /// Byte written on the debug port when a validation failed.
    pub const FAIL_MARKER: u8 = b'F';
    /// Status byte reported after [`PASS_MARKER`]: the number of validations.
    pub const STATUS_OK: u8 = 5;
    /// ACPI 1.0 RSDP checksum covers the first 20 bytes of the table.
    pub const RSDP_CHECKSUM_LEN: u32 = 20;
    /// RSDP entries are searched on 16-byte boundaries.
    pub const RSDP_SCAN_STRIDE: u64 = 16;
    /// RSDP signature: the ASCII bytes `RSD PTR ` (trailing space).
    pub const RSDP_SIGNATURE: [u8; 8] = *b"RSD PTR ";
    /// Encoded length of one failure stub: marker, step, `hlt`.
    pub const FAIL_STUB_LEN: usize = 9;
    /// Alignment of a boot-parameter block in guest memory (one page).
    pub const BOOT_PARAMS_ALIGN: u64 = 4096;
    /// Alignment of the RSDP and of every scan candidate.
    pub const RSDP_ALIGN: u64 = 16;

    /// Failure codes reported after [`FAIL_MARKER`].
    pub mod failure_step {
        /// The boot-parameter magic is wrong.
        pub const MAGIC: u8 = 1;
        /// A bookkeeping count (`cmdline_len`, memory or module count) is zero.
        pub const COUNTS: u8 = 2;
        /// The `rsdp_gpa` field does not point at the firmware image.
        pub const RSDP_FIELD: u8 = 3;
        /// The RSDP signature was not found or not at the advertised address.
        pub const RSDP_SCAN: u8 = 4;
        /// The ACPI 1.0 checksum of the RSDP is invalid.
        pub const CHECKSUM: u8 = 5;
        /// Every defined failure code.
        pub const ALL: [u8; 5] = [MAGIC, COUNTS, RSDP_FIELD, RSDP_SCAN, CHECKSUM];
    }

    /// Guest-physical layout the payload is built for.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct GuestOsLayout {
        /// Page-aligned address of the 1024-byte boot-parameter block.
        pub boot_params_gpa: u64,
        /// Address the firmware image (and its RSDP) was written to.
        pub acpi_gpa: u64,
        /// First candidate address of the RSDP scan (16-byte aligned).
        pub scan_start_gpa: u64,
        /// End of the RSDP scan, exclusive.
        pub scan_end_gpa: u64,
    }

    impl GuestOsLayout {
        /// Checks that the layout can be encoded by this payload.
        ///
        /// The boot-parameter block must be page aligned and reachable with a
        /// 32-bit absolute address (the 32-bit field loads use `disp32`); the
        /// RSDP must be 16-byte aligned and inside a non-empty, 16-byte aligned
        /// scan window.
        pub fn validate(&self) -> Result<(), GuestProgError> {
            let block_end = self
                .boot_params_gpa
                .checked_add(bootparams::SIZE as u64)
                .ok_or(GuestProgError::InvalidLayout)?;
            if self.boot_params_gpa % BOOT_PARAMS_ALIGN != 0
                || block_end > u64::from(u32::MAX)
                || self.acpi_gpa % RSDP_ALIGN != 0
                || self.scan_start_gpa % RSDP_ALIGN != 0
                || self.scan_start_gpa >= self.scan_end_gpa
                || (self.scan_end_gpa - self.scan_start_gpa) % RSDP_SCAN_STRIDE != 0
                || self.acpi_gpa < self.scan_start_gpa
                || self.acpi_gpa >= self.scan_end_gpa
            {
                return Err(GuestProgError::InvalidLayout);
            }
            Ok(())
        }
    }

    /// Builds the guest-OS bootstrap payload for `layout`.
    pub fn build_payload(layout: &GuestOsLayout) -> Result<GuestProgram, GuestProgError> {
        layout.validate()?;
        let mut program = GuestProgram::new();
        let base = layout.boot_params_gpa;

        // 1. The boot-parameter block starts with the expected magic value.
        program.mov_abs_to_reg64(base + bootparams::OFF_MAGIC as u64, Reg::RAX)?;
        program.mov_imm64(Reg::RDX, bootparams::MAGIC)?;
        program.cmp_qword_regs(Reg::RAX, Reg::RDX)?;
        guard(&mut program, true, failure_step::MAGIC)?;

        // 2. The hand-off fields a kernel reads first must be populated.
        for offset in [
            bootparams::OFF_CMDLINE_LEN,
            bootparams::OFF_MEMORY_COUNT,
            bootparams::OFF_MODULE_COUNT,
        ] {
            program.mov_abs_to_reg32(base + offset as u64, Reg::RAX)?;
            program.cmp_dword_imm32(Reg::RAX, 0)?;
            guard(&mut program, false, failure_step::COUNTS)?;
        }

        // 3. The RSDP field points at the firmware image.
        program.mov_abs_to_reg64(base + bootparams::OFF_RSDP_GPA as u64, Reg::RSI)?;
        program.mov_imm64(Reg::RCX, layout.acpi_gpa)?;
        program.cmp_qword_regs(Reg::RSI, Reg::RCX)?;
        guard(&mut program, true, failure_step::RSDP_FIELD)?;

        // 4. Scan the legacy window for the RSDP signature.
        program.mov_imm64(Reg::RBX, layout.scan_start_gpa)?;
        program.mov_imm64(Reg::R8, layout.scan_end_gpa)?;
        program.mov_imm64(Reg::RDX, u64::from_le_bytes(RSDP_SIGNATURE))?;
        let scan = program.offset();
        program.mov_qword_from_ptr(Reg::RBX, Reg::RAX)?;
        program.cmp_qword_regs(Reg::RAX, Reg::RDX)?;
        let found = program.je_short_placeholder()?;
        program.add_qword_imm8(Reg::RBX, RSDP_SCAN_STRIDE as i8)?;
        program.cmp_qword_regs(Reg::RBX, Reg::R8)?;
        let back = backward_displacement(&program, scan)?;
        program.jb_short(back)?;
        emit_fail_stub(&mut program, failure_step::RSDP_SCAN)?;
        program.resolve_short_branch(found, program.offset())?;

        // The discovered address must be the one the block advertises.
        program.cmp_qword_regs(Reg::RBX, Reg::RSI)?;
        guard(&mut program, true, failure_step::RSDP_SCAN)?;

        // 5. ACPI 1.0 checksum: the first 20 bytes sum to zero modulo 256.
        program.mov_qword_regs(Reg::RDX, Reg::RBX)?;
        program.mov_imm32(Reg::RAX, 0)?;
        program.mov_imm32(Reg::RCX, RSDP_CHECKSUM_LEN)?;
        let sum = program.offset();
        program.add_byte_ptr_to_accumulator(Reg::RDX)?;
        program.add_qword_imm8(Reg::RDX, 1)?;
        let back = backward_displacement(&program, sum)?;
        program.loop_short(back)?;
        program.cmp_byte_imm8(Reg::RAX, 0)?;
        guard(&mut program, true, failure_step::CHECKSUM)?;

        // Report: marker, status, cmdline length, memory count; then halt.
        emit_debug_byte(&mut program, PASS_MARKER)?;
        emit_debug_byte(&mut program, STATUS_OK)?;
        for offset in [bootparams::OFF_CMDLINE_LEN, bootparams::OFF_MEMORY_COUNT] {
            program.mov_abs_to_reg32(base + offset as u64, Reg::RAX)?;
            program.out_imm8_port(DEBUG_PORT, Reg::RAX)?;
        }
        program.hlt()?;
        Ok(program)
    }

    /// Emits a conditional failure guard.
    ///
    /// `jump_when_equal` selects the branch used to jump over the failure stub:
    /// `je` when an equal comparison means success, `jne` when a non-equal
    /// comparison means success. Falling through the branch executes the stub.
    fn guard(
        program: &mut GuestProgram,
        jump_when_equal: bool,
        step: u8,
    ) -> Result<(), GuestProgError> {
        let patch = if jump_when_equal {
            program.je_short_placeholder()?
        } else {
            program.jne_short_placeholder()?
        };
        let start = program.offset();
        emit_fail_stub(program, step)?;
        if program.offset() - start != FAIL_STUB_LEN {
            return Err(GuestProgError::InvalidLayout);
        }
        program.resolve_short_branch(patch, program.offset())
    }

    /// Emits a failure stub: [`FAIL_MARKER`], the step code, then `hlt`.
    fn emit_fail_stub(program: &mut GuestProgram, step: u8) -> Result<(), GuestProgError> {
        emit_debug_byte(program, FAIL_MARKER)?;
        emit_debug_byte(program, step)?;
        program.hlt()
    }

    /// Writes one byte on the debug port through `AL`.
    fn emit_debug_byte(program: &mut GuestProgram, byte: u8) -> Result<(), GuestProgError> {
        program.mov_imm8(Reg::RAX, byte)?;
        program.out_imm8_port(DEBUG_PORT, Reg::RAX)
    }

    /// Displacement of the short branch emitted next towards `target`.
    fn backward_displacement(program: &GuestProgram, target: usize) -> Result<i32, GuestProgError> {
        let next = program
            .offset()
            .checked_add(2)
            .ok_or(GuestProgError::BranchTargetOutOfRange)?;
        let delta = i64::try_from(target).map_err(|_| GuestProgError::BranchTargetOutOfRange)?
            - i64::try_from(next).map_err(|_| GuestProgError::BranchTargetOutOfRange)?;
        i32::try_from(delta).map_err(|_| GuestProgError::BranchTargetOutOfRange)
    }
}
