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

//! s9vm : minimal x86-64 instruction decoder for exit emulation.
//!
//! When a guest exit is a fault that must be emulated (MMIO, EPT violation,
//! port I/O), the kernel needs three pieces of information: the access width,
//! the direction (read/write), and : for MMIO : the effective address and the
//! destination/source general-purpose register. This module decodes just
//! enough x86-64 to answer those questions for the forms a device model
//! actually sees:
//!
//! - `mov r8, r/m8`, `mov r16/r32/r64, r/m8/16/32/64`,
//!   `mov r/m8, r8`, `mov r/m16/32/64, r` (opcodes `0x8A/0x8B/0x88/0x89`);
//! - `mov r8, imm8` and `mov r16/32/64, imm16/32/64` (opcodes `0xB0..0xBF`);
//! - `mov r/m8, imm8`, `mov r/m16/32/64, imm16/32/64` (`0xC6/0xC7`, `/0`);
//! - `mov AL/AX/EAX/RAX, moffs` and `mov moffs, AL/AX/EAX/RAX`
//!   (`0xA0..0xA3`), with a 64-bit offset, or a 32-bit offset under `0x67`;
//! - `movzx`/`movsx` register from memory (`0x0F 0xB6/0xB7/0xBE/0xBF`);
//! - `in`/`out` with an immediate port (`0xE4..0xE7`) or `DX` (`0xEC..0xEF`);
//! - `rdmsr`/`wrmsr` (`0x0F 0x30/0x32`).
//!
//! Prefix handling: `0x66` selects a 16-bit operand, `0x67` selects 32-bit
//! addressing (the effective address is zero-extended), segment prefixes are
//! consumed and ignored, and `LOCK`/`REP`/`REPNE` are rejected with
//! [`DecodeError::Unsupported`] because none of the supported forms uses them.
//! `REX.W/R/X/B` is honoured where architectural.
//!
//! ModRM addressing supports `mod = 00/01/10`, SIB with scale/base/index,
//! absolute `disp32` (SIB base 5 or `rm = 5` in 32-bit addressing),
//! RIP-relative `disp32` (`mod = 00, rm = 101` in 64-bit addressing), signed
//! `disp8`, and `disp32` with the correct sign. `mod = 11` forms that are not
//! plain register moves are reported as unsupported rather than mis-decoded.
//!
//! It is deliberately pure: no memory access, no hardware. The caller supplies
//! a register reader and the instruction bytes; the decoder returns the
//! effective address and the next RIP, or a typed error. Decoding never
//! panics: every read is bounds-checked through [`slice::get`] and a truncated
//! instruction yields [`DecodeError::Truncated`]. Every result is testable on
//! the host, which is why this logic lives apart from the virtual-machine
//! monitor.

use alloc::string::String;

/// Longest possible x86 instruction.
pub const MAX_INSTRUCTION: usize = 15;

/// Reason a sequence could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The byte slice ends before the instruction does.
    Truncated,
    /// A prefix or opcode outside the supported subset.
    Unsupported,
    /// A ModRM/SIB combination that cannot be formed.
    BadEncoding,
}

/// How a memory operand narrower than the destination register is widened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Extension {
    /// No widening: the memory width is the register width.
    None,
    /// `movzx`: the destination is zero-extended.
    Zero,
    /// `movsx`: the destination is sign-extended.
    Sign,
}

/// A guest memory access decoded from an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryAccess {
    /// Effective linear address of the access.
    pub address: u64,
    /// Access width in bytes (1, 2, 4 or 8).
    pub size: u8,
    /// True for a write (`mov r/m, r` or `mov r/m, imm`), false for a read.
    pub write: bool,
    /// General-purpose register involved (0 = RAX … 15 = R15).
    pub register: u8,
    /// Width in bytes written to/read from `register` (1, 2, 4 or 8).
    ///
    /// For plain `mov` this equals [`Self::size`]; for `movzx`/`movsx` it is
    /// the destination operand size while `size` remains the memory width.
    /// Zero marks a read-only probe (`test`/`cmp` with a memory operand): the
    /// value is consumed by the instruction itself and must not be written back
    /// to any register.
    pub register_size: u8,
    /// Immediate source for `mov r/m, imm`; `None` for register transfers.
    ///
    /// When this is `Some`, the caller must use the immediate value instead of
    /// reading `register`. The value is already truncated to the operand width
    /// and, for the 64-bit `C7` form, sign-extended from `imm32`.
    pub immediate: Option<u64>,
    /// Widening applied when `register` is updated.
    pub extension: Extension,
    /// Value of RIP after the instruction (faulting exits restart here).
    pub next_rip: u64,
}

/// A guest port access decoded from an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortAccess {
    /// Port number.
    pub port: u16,
    /// Access width in bytes: 1, 2 or 4.
    pub size: u8,
    /// True for `out`, false for `in`.
    pub write: bool,
    /// Register holding the value: AL/AX/EAX (0) for `in`/`out`.
    pub register: u8,
    /// Value of RIP after the instruction.
    pub next_rip: u64,
}

/// An MSR access decoded from an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsrAccess {
    /// True for `wrmsr` (`0x0F 0x30`), false for `rdmsr` (`0x0F 0x32`).
    pub write: bool,
    /// Value of RIP after the instruction.
    pub next_rip: u64,
}

/// A register-only move decoded from an instruction.
///
/// These forms cannot cause a device exit, but decoding them keeps the
/// instruction-length accounting total and lets a caller skip over them when
/// replaying a block of instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterAccess {
    /// Destination general-purpose register (0 = RAX … 15 = R15).
    pub register: u8,
    /// Operand width in bytes: 1, 2, 4 or 8.
    pub size: u8,
    /// Immediate value written to the register, zero-extended to `u64`.
    ///
    /// The 64-bit `REX.W` form of `mov r64, imm64` carries a full 64-bit
    /// value; the other forms carry a value already truncated to `size`.
    pub value: u64,
    /// Value of RIP after the instruction.
    pub next_rip: u64,
}

/// Result of decoding one instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decoded {
    Memory(MemoryAccess),
    Port(PortAccess),
    Msr(MsrAccess),
    Register(RegisterAccess),
}

impl Decoded {
    /// RIP after the instruction, whichever kind was decoded.
    pub const fn next_rip(self) -> u64 {
        match self {
            Decoded::Memory(access) => access.next_rip,
            Decoded::Port(access) => access.next_rip,
            Decoded::Msr(access) => access.next_rip,
            Decoded::Register(access) => access.next_rip,
        }
    }

    /// Instruction length in bytes: `next_rip - rip`.
    pub const fn instruction_length(self, rip: u64) -> u8 {
        self.next_rip().wrapping_sub(rip) as u8
    }
}

/// Prefixes decoded before the opcode.
struct Prefixes {
    /// `0x66`: 16-bit operand size unless overridden by `REX.W`.
    operand_size_override: bool,
    /// `0x67`: 32-bit addressing in 64-bit mode.
    address_size_override: bool,
    /// Last `REX` byte, or zero when absent.
    rex: u8,
    /// Index of the first opcode byte.
    opcode_index: usize,
}

/// Parses legacy and `REX` prefixes.
///
/// Segment prefixes are ignored (the emulation only needs the linear address),
/// while `LOCK`/`REP`/`REPNE` are rejected: no supported form uses them.
fn parse_prefixes(bytes: &[u8]) -> Result<Prefixes, DecodeError> {
    let mut index = 0usize;
    let mut operand_size_override = false;
    let mut address_size_override = false;
    let mut rex = 0u8;

    loop {
        match bytes.get(index).copied() {
            Some(0x66) => {
                operand_size_override = true;
                index += 1;
            }
            Some(0x67) => {
                address_size_override = true;
                index += 1;
            }
            Some(0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65) => {
                // Segment override: consumed and ignored.
                index += 1;
            }
            Some(0xF0 | 0xF2 | 0xF3) => return Err(DecodeError::Unsupported),
            Some(0x40..=0x4F) => {
                rex = bytes[index];
                index += 1;
                break;
            }
            Some(_) => break,
            None => return Err(DecodeError::Truncated),
        }
    }

    Ok(Prefixes {
        operand_size_override,
        address_size_override,
        rex,
        opcode_index: index,
    })
}

/// Operand width in bytes for a general instruction.
const fn operand_size(byte_sized: bool, rex: u8, operand_size_override: bool) -> u8 {
    if byte_sized {
        1
    } else if rex & 0x08 != 0 {
        8
    } else if operand_size_override {
        2
    } else {
        4
    }
}

/// Addresses of a ModRM operand, resolved before the instruction length is
/// known.
enum ModRmOperand {
    Memory { address: u64, reg: u8 },
    Register { rm: u8, reg: u8 },
}

/// Decodes one instruction.
///
/// `bytes` starts at the instruction; `rip` is its linear address (used for
/// RIP-relative addressing and the returned next RIP); `register` returns the
/// current value of a general-purpose register (0 = RAX … 15 = R15).
pub fn decode<F>(bytes: &[u8], rip: u64, register: F) -> Result<Decoded, DecodeError>
where
    F: Fn(u8) -> u64,
{
    let prefixes = parse_prefixes(bytes)?;
    let rex = prefixes.rex;
    let mut index = prefixes.opcode_index;

    let opcode = *bytes.get(index).ok_or(DecodeError::Truncated)?;
    index += 1;

    match opcode {
        // mov r, r/m  (0x8A byte, 0x8B word/dword/qword)
        0x8A | 0x8B => {
            let size = operand_size(opcode == 0x8A, rex, prefixes.operand_size_override);
            let (operand, next) = decode_modrm(
                bytes,
                index,
                rip,
                rex,
                prefixes.address_size_override,
                0,
                &register,
            )?;
            let ModRmOperand::Memory { address, reg } = operand else {
                return Err(DecodeError::Unsupported);
            };
            Ok(Decoded::Memory(MemoryAccess {
                address,
                size,
                write: false,
                register: reg,
                register_size: size,
                immediate: None,
                extension: Extension::None,
                next_rip: rip.wrapping_add(next as u64),
            }))
        }
        // mov r/m, r  (0x88 byte, 0x89 word/dword/qword)
        0x88 | 0x89 => {
            let size = operand_size(opcode == 0x88, rex, prefixes.operand_size_override);
            let (operand, next) = decode_modrm(
                bytes,
                index,
                rip,
                rex,
                prefixes.address_size_override,
                0,
                &register,
            )?;
            let ModRmOperand::Memory { address, reg } = operand else {
                return Err(DecodeError::Unsupported);
            };
            Ok(Decoded::Memory(MemoryAccess {
                address,
                size,
                write: true,
                register: reg,
                register_size: size,
                immediate: None,
                extension: Extension::None,
                next_rip: rip.wrapping_add(next as u64),
            }))
        }
        // mov r8, imm8
        0xB0..=0xB7 => {
            let value = u64::from(read_u8(bytes, &mut index)?);
            Ok(register_move(opcode & 0x7, rex, 1, value, rip, index))
        }
        // mov r16/r32/r64, imm16/32/64
        0xB8..=0xBF => {
            let size = operand_size(false, rex, prefixes.operand_size_override);
            let value = read_immediate(bytes, &mut index, size)?;
            Ok(register_move(opcode & 0x7, rex, size, value, rip, index))
        }
        // mov AL/AX/EAX/RAX, moffs
        0xA0..=0xA1 => {
            let size = if opcode == 0xA0 {
                1
            } else {
                operand_size(false, rex, prefixes.operand_size_override)
            };
            let address = read_moffs(bytes, &mut index, prefixes.address_size_override)?;
            Ok(Decoded::Memory(MemoryAccess {
                address,
                size,
                write: false,
                register: 0,
                register_size: size,
                immediate: None,
                extension: Extension::None,
                next_rip: rip.wrapping_add(index as u64),
            }))
        }
        // mov moffs, AL/AX/EAX/RAX
        0xA2..=0xA3 => {
            let size = if opcode == 0xA2 {
                1
            } else {
                operand_size(false, rex, prefixes.operand_size_override)
            };
            let address = read_moffs(bytes, &mut index, prefixes.address_size_override)?;
            Ok(Decoded::Memory(MemoryAccess {
                address,
                size,
                write: true,
                register: 0,
                register_size: size,
                immediate: None,
                extension: Extension::None,
                next_rip: rip.wrapping_add(index as u64),
            }))
        }
        // mov r/m8, imm8
        0xC6 => {
            // One immediate byte follows the ModRM/SIB/displacement; include
            // it in the RIP-relative base address.
            let (operand, after_modrm) = decode_modrm(
                bytes,
                index,
                rip,
                rex,
                prefixes.address_size_override,
                1,
                &register,
            )?;
            index = after_modrm;
            let value = u64::from(read_u8(bytes, &mut index)?);
            decode_immediate_move(operand, 1, value, rip, index)
        }
        // mov r/m16/r32/r64, imm16/32/64 (imm32 sign-extended under REX.W)
        0xC7 => {
            let size = operand_size(false, rex, prefixes.operand_size_override);
            let immediate_size = if size == 8 { 4 } else { size };
            let (operand, after_modrm) = decode_modrm(
                bytes,
                index,
                rip,
                rex,
                prefixes.address_size_override,
                usize::from(immediate_size),
                &register,
            )?;
            index = after_modrm;
            let value = if size == 8 {
                // REX.W: imm32 is sign-extended to 64 bits.
                read_u32(bytes, &mut index)? as i32 as i64 as u64
            } else {
                read_immediate(bytes, &mut index, size)?
            };
            decode_immediate_move(operand, size, value, rip, index)
        }
        // test r/m8, r8 / test r/m, r (0x84/0x85): read-only memory probe
        0x84 | 0x85 => {
            let size = operand_size(opcode == 0x84, rex, prefixes.operand_size_override);
            let (operand, next) = decode_modrm(
                bytes,
                index,
                rip,
                rex,
                prefixes.address_size_override,
                0,
                &register,
            )?;
            decode_read_only_memory(operand, size, None, rip, next)
        }
        // cmp r/m8, r8 / cmp r/m, r (0x38/0x39): read-only memory probe
        0x38 | 0x39 => {
            let size = operand_size(opcode == 0x38, rex, prefixes.operand_size_override);
            let (operand, next) = decode_modrm(
                bytes,
                index,
                rip,
                rex,
                prefixes.address_size_override,
                0,
                &register,
            )?;
            decode_read_only_memory(operand, size, None, rip, next)
        }
        // cmp r8, r/m8 / cmp r, r/m (0x3A/0x3B): the memory operand is the
        // source, so the access is a read-only probe as well.
        0x3A | 0x3B => {
            let size = operand_size(opcode == 0x3A, rex, prefixes.operand_size_override);
            let (operand, next) = decode_modrm(
                bytes,
                index,
                rip,
                rex,
                prefixes.address_size_override,
                0,
                &register,
            )?;
            decode_read_only_memory(operand, size, None, rip, next)
        }
        // test r/m, imm (0xF6 /0 byte, 0xF7 /0 word/dword/qword): read-only
        0xF6 | 0xF7 => {
            let size = operand_size(opcode == 0xF6, rex, prefixes.operand_size_override);
            let immediate_size = if size == 8 { 4 } else { size };
            let (operand, mut after_modrm) = decode_modrm(
                bytes,
                index,
                rip,
                rex,
                prefixes.address_size_override,
                usize::from(immediate_size),
                &register,
            )?;
            if !matches!(operand, ModRmOperand::Memory { reg: 0, .. }) {
                return Err(DecodeError::Unsupported);
            }
            let value = if size == 8 {
                u64::from(read_u32(bytes, &mut after_modrm)?)
            } else {
                read_immediate(bytes, &mut after_modrm, size)?
            };
            decode_read_only_memory(operand, size, Some(value), rip, after_modrm)
        }
        // cmp r/m, imm: 0x80 (/7, imm8), 0x81 (/7, imm16/32) and 0x83 (/7,
        // imm8 sign-extended). Only the read-only CMP form is modeled.
        0x80 | 0x81 | 0x83 => {
            let size = operand_size(opcode == 0x80, rex, prefixes.operand_size_override);
            let immediate_size = if opcode == 0x83 {
                1
            } else if opcode == 0x80 {
                1
            } else if size == 8 {
                4
            } else {
                size
            };
            let (operand, mut after_modrm) = decode_modrm(
                bytes,
                index,
                rip,
                rex,
                prefixes.address_size_override,
                usize::from(immediate_size),
                &register,
            )?;
            if !matches!(operand, ModRmOperand::Memory { reg: 7, .. }) {
                return Err(DecodeError::Unsupported);
            }
            let value = if opcode == 0x83 || opcode == 0x80 {
                u64::from(read_u8(bytes, &mut after_modrm)?)
            } else {
                read_immediate(bytes, &mut after_modrm, size)?
            };
            decode_read_only_memory(operand, size, Some(value), rip, after_modrm)
        }
        // in al/ax/eax, imm8
        0xE4 | 0xE5 => {
            let port = u16::from(read_u8(bytes, &mut index)?);
            let size = if opcode == 0xE4 {
                1
            } else if prefixes.operand_size_override {
                2
            } else {
                4
            };
            Ok(Decoded::Port(PortAccess {
                port,
                size,
                write: false,
                register: 0,
                next_rip: rip.wrapping_add(index as u64),
            }))
        }
        // out imm8, al/ax/eax
        0xE6 | 0xE7 => {
            let port = u16::from(read_u8(bytes, &mut index)?);
            let size = if opcode == 0xE6 {
                1
            } else if prefixes.operand_size_override {
                2
            } else {
                4
            };
            Ok(Decoded::Port(PortAccess {
                port,
                size,
                write: true,
                register: 0,
                next_rip: rip.wrapping_add(index as u64),
            }))
        }
        // in al/ax/eax, dx
        0xEC | 0xED => {
            let size = if opcode == 0xEC {
                1
            } else if prefixes.operand_size_override {
                2
            } else {
                4
            };
            Ok(Decoded::Port(PortAccess {
                port: register(2) as u16,
                size,
                write: false,
                register: 0,
                next_rip: rip.wrapping_add(index as u64),
            }))
        }
        // out dx, al/ax/eax
        0xEE | 0xEF => {
            let size = if opcode == 0xEE {
                1
            } else if prefixes.operand_size_override {
                2
            } else {
                4
            };
            Ok(Decoded::Port(PortAccess {
                port: register(2) as u16,
                size,
                write: true,
                register: 0,
                next_rip: rip.wrapping_add(index as u64),
            }))
        }
        // Two-byte opcodes: movzx/movsx and the MSR accesses.
        0x0F => {
            let second = *bytes.get(index).ok_or(DecodeError::Truncated)?;
            index += 1;
            match second {
                0x30 => Ok(Decoded::Msr(MsrAccess {
                    write: true,
                    next_rip: rip.wrapping_add(index as u64),
                })),
                0x32 => Ok(Decoded::Msr(MsrAccess {
                    write: false,
                    next_rip: rip.wrapping_add(index as u64),
                })),
                0xB6 | 0xB7 | 0xBE | 0xBF => {
                    let (operand, next) = decode_modrm(
                        bytes,
                        index,
                        rip,
                        rex,
                        prefixes.address_size_override,
                        0,
                        &register,
                    )?;
                    let ModRmOperand::Memory { address, reg } = operand else {
                        return Err(DecodeError::Unsupported);
                    };
                    let source_size = if matches!(second, 0xB6 | 0xBE) { 1 } else { 2 };
                    let destination_size = operand_size(false, rex, prefixes.operand_size_override);
                    let extension = if matches!(second, 0xB6 | 0xB7) {
                        Extension::Zero
                    } else {
                        Extension::Sign
                    };
                    Ok(Decoded::Memory(MemoryAccess {
                        address,
                        size: source_size,
                        write: false,
                        register: reg,
                        register_size: destination_size,
                        immediate: None,
                        extension,
                        next_rip: rip.wrapping_add(next as u64),
                    }))
                }
                _ => Err(DecodeError::Unsupported),
            }
        }
        _ => Err(DecodeError::Unsupported),
    }
}

/// Builds a register-only move result.
fn register_move(
    register_low: u8,
    rex: u8,
    size: u8,
    value: u64,
    rip: u64,
    index: usize,
) -> Decoded {
    Decoded::Register(RegisterAccess {
        register: register_low | ((rex & 0x01) << 3),
        size,
        value,
        next_rip: rip.wrapping_add(index as u64),
    })
}

/// Builds a read-only memory probe (`test`/`cmp` with a memory operand).
///
/// Such an instruction reads the device register but has no destination to
/// write the value to: `register_size` is 0 so the replay path performs the
/// device read and discards the result. A register-form probe cannot target a
/// device page and is reported as unsupported.
fn decode_read_only_memory(
    operand: ModRmOperand,
    size: u8,
    immediate: Option<u64>,
    rip: u64,
    index: usize,
) -> Result<Decoded, DecodeError> {
    match operand {
        ModRmOperand::Memory { address, .. } => Ok(Decoded::Memory(MemoryAccess {
            address,
            size,
            write: false,
            register: 0,
            register_size: 0,
            immediate,
            extension: Extension::None,
            next_rip: rip.wrapping_add(index as u64),
        })),
        ModRmOperand::Register { .. } => Err(DecodeError::Unsupported),
    }
}

/// Builds a `mov r/m, imm` result once the ModRM operand and immediate are known.
fn decode_immediate_move(
    operand: ModRmOperand,
    size: u8,
    value: u64,
    rip: u64,
    index: usize,
) -> Result<Decoded, DecodeError> {
    match operand {
        ModRmOperand::Memory { address, reg } => {
            // C6/C7 only define group 0 (register field 000).
            if reg != 0 {
                return Err(DecodeError::Unsupported);
            }
            Ok(Decoded::Memory(MemoryAccess {
                address,
                size,
                write: true,
                register: 0,
                register_size: size,
                immediate: Some(value),
                extension: Extension::None,
                next_rip: rip.wrapping_add(index as u64),
            }))
        }
        ModRmOperand::Register { rm, reg } => {
            if reg != 0 {
                return Err(DecodeError::Unsupported);
            }
            Ok(Decoded::Register(RegisterAccess {
                register: rm,
                size,
                value,
                next_rip: rip.wrapping_add(index as u64),
            }))
        }
    }
}

/// Decodes the ModRM byte (and optional SIB/displacement) of an instruction.
///
/// Returns the resolved operand and the index of the first byte after the
/// ModRM/SIB/displacement fields. `trailing_bytes` is the number of immediate
/// bytes that will follow; it only affects RIP-relative addressing, where the
/// address is relative to the end of the whole instruction.
fn decode_modrm<F>(
    bytes: &[u8],
    mut index: usize,
    rip: u64,
    rex: u8,
    address_size_override: bool,
    trailing_bytes: usize,
    register: &F,
) -> Result<(ModRmOperand, usize), DecodeError>
where
    F: Fn(u8) -> u64,
{
    let modrm = *bytes.get(index).ok_or(DecodeError::Truncated)?;
    index += 1;
    let mode = modrm >> 6;
    let reg_field = ((modrm >> 3) & 0x7) | ((rex & 0x04) << 1);
    let rm_low = modrm & 0x7;
    let rm_field = rm_low | ((rex & 0x01) << 3);

    // Register-only form (mod = 11): callers decide whether it is supported.
    if mode == 0b11 {
        return Ok((
            ModRmOperand::Register {
                rm: rm_field,
                reg: reg_field,
            },
            index,
        ));
    }

    let mut address = 0u64;
    let mut base_register: Option<u8> = None;
    let mut index_register: Option<u8> = None;
    let mut scale = 1u64;
    let mut displacement: i64 = 0;

    if rm_low == 4 {
        // SIB byte.
        let sib = *bytes.get(index).ok_or(DecodeError::Truncated)?;
        index += 1;
        scale = 1u64 << (sib >> 6);
        let sib_index = (sib >> 3) & 0x7;
        // In 64-bit mode, index 100b without REX.X means "no index"; with
        // REX.X it selects R12. The same applies with 32-bit addressing.
        index_register = if sib_index == 4 && (rex & 0x02) == 0 {
            None
        } else {
            Some(sib_index | ((rex & 0x02) << 2))
        };
        let sib_base = sib & 0x7;
        match mode {
            0b00 if sib_base == 0b101 => {
                // No base, disp32 absolute (never RIP-relative).
                displacement = read_i32(bytes, &mut index)? as i64;
            }
            _ => {
                base_register = Some(sib_base | ((rex & 0x01) << 3));
            }
        }
    } else if mode == 0b00 && rm_low == 0b101 {
        if address_size_override {
            // 32-bit addressing: disp32 is an absolute address.
            address = u64::from(read_u32(bytes, &mut index)?);
        } else {
            // RIP-relative disp32, relative to the end of the instruction.
            let disp = read_i32(bytes, &mut index)? as i64;
            let next = index
                .checked_add(trailing_bytes)
                .ok_or(DecodeError::Truncated)?;
            address = rip.wrapping_add(next as u64).wrapping_add(disp as u64);
        }
    } else {
        base_register = Some(rm_field);
    }

    let register_value = |register_index: u8| -> u64 {
        let value = register(register_index);
        if address_size_override {
            value & 0xFFFF_FFFF
        } else {
            value
        }
    };

    if let Some(base) = base_register {
        address = address.wrapping_add(register_value(base));
    }
    if let Some(index_register) = index_register {
        address = address.wrapping_add(register_value(index_register).wrapping_mul(scale));
    }

    match mode {
        0b01 => displacement = read_i8(bytes, &mut index)? as i64,
        0b10 => displacement = read_i32(bytes, &mut index)? as i64,
        _ => {}
    }
    address = address.wrapping_add(displacement as u64);

    if address_size_override {
        // 32-bit addressing zero-extends the computed address.
        address &= 0xFFFF_FFFF;
    }

    Ok((
        ModRmOperand::Memory {
            address,
            reg: reg_field,
        },
        index,
    ))
}

/// Reads the address of a `moffs` operand.
fn read_moffs(
    bytes: &[u8],
    index: &mut usize,
    address_size_override: bool,
) -> Result<u64, DecodeError> {
    if address_size_override {
        Ok(u64::from(read_u32(bytes, index)?))
    } else {
        read_u64(bytes, index)
    }
}

/// Reads an immediate of `size` bytes, zero-extended to `u64`.
fn read_immediate(bytes: &[u8], index: &mut usize, size: u8) -> Result<u64, DecodeError> {
    match size {
        1 => Ok(u64::from(read_u8(bytes, index)?)),
        2 => Ok(u64::from(read_u16(bytes, index)?)),
        4 => Ok(u64::from(read_u32(bytes, index)?)),
        8 => read_u64(bytes, index),
        _ => Err(DecodeError::BadEncoding),
    }
}

fn read_u8(bytes: &[u8], index: &mut usize) -> Result<u8, DecodeError> {
    let value = *bytes.get(*index).ok_or(DecodeError::Truncated)?;
    *index += 1;
    Ok(value)
}

fn read_u16(bytes: &[u8], index: &mut usize) -> Result<u16, DecodeError> {
    let end = index.checked_add(2).ok_or(DecodeError::Truncated)?;
    let slice = bytes.get(*index..end).ok_or(DecodeError::Truncated)?;
    *index = end;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], index: &mut usize) -> Result<u32, DecodeError> {
    let end = index.checked_add(4).ok_or(DecodeError::Truncated)?;
    let slice = bytes.get(*index..end).ok_or(DecodeError::Truncated)?;
    *index = end;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64(bytes: &[u8], index: &mut usize) -> Result<u64, DecodeError> {
    let end = index.checked_add(8).ok_or(DecodeError::Truncated)?;
    let slice = bytes.get(*index..end).ok_or(DecodeError::Truncated)?;
    *index = end;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn read_i8(bytes: &[u8], index: &mut usize) -> Result<i8, DecodeError> {
    Ok(read_u8(bytes, index)? as i8)
}

fn read_i32(bytes: &[u8], index: &mut usize) -> Result<i32, DecodeError> {
    Ok(read_u32(bytes, index)? as i32)
}

/// Human-readable name of a decode error (diagnostics).
pub fn error_name(error: DecodeError) -> &'static str {
    match error {
        DecodeError::Truncated => "truncated",
        DecodeError::Unsupported => "unsupported",
        DecodeError::BadEncoding => "bad-encoding",
    }
}

impl Decoded {
    /// Builds a diagnostic string (used by the exit diagnostics).
    pub fn describe(self) -> String {
        match self {
            Decoded::Memory(access) => alloc::format!(
                "mem {} size={} reg={} next={:#x}",
                if access.write { "write" } else { "read" },
                access.size,
                access.register,
                access.next_rip
            ),
            Decoded::Port(access) => alloc::format!(
                "port {} size={} reg={} next={:#x}",
                if access.write { "out" } else { "in" },
                access.size,
                access.register,
                access.next_rip
            ),
            Decoded::Msr(access) => alloc::format!(
                "msr {} next={:#x}",
                if access.write { "write" } else { "read" },
                access.next_rip
            ),
            Decoded::Register(access) => alloc::format!(
                "reg r{} size={} value={:#x} next={:#x}",
                access.register,
                access.size,
                access.value,
                access.next_rip
            ),
        }
    }
}
