//! s9vm — minimal x86-64 instruction decoder for exit emulation.
//!
//! When a guest exit is a fault that must be emulated (MMIO, EPT violation,
//! port I/O), the kernel needs three pieces of information: the access width,
//! the direction (read/write), and — for MMIO — the effective address and the
//! destination/source general-purpose register. This module decodes just
//! enough x86-64 to answer those questions for the forms a device model
//! actually sees:
//!
//! - `mov r8, r/m8`, `mov r16/r32/r64, r/m`, `mov r/m8, r8`,
//!   `mov r/m16/r32/r64, r` (opcodes `0x8A/0x8B/0x88/0x89`);
//! - ModRM addressing with `mod = 00/01/10`, SIB byte, absolute `disp32`, and
//!   RIP-relative `disp32` (`mod = 00, rm = 101`);
//! - `in`/`out` with an immediate port (`0xE4..0xE7`) or `DX` (`0xEC..0xEF`).
//!
//! It is deliberately pure: no memory access, no hardware. The caller supplies
//! a register reader and the instruction bytes; the decoder returns the
//! effective address and the next RIP, or an error for unsupported forms.
//! Every result is testable on the host, which is why this logic lives apart
//! from the virtual-machine monitor.

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

/// A guest memory access decoded from an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryAccess {
    /// Effective linear address of the access.
    pub address: u64,
    /// Access width in bytes (1, 2, 4 or 8).
    pub size: u8,
    /// True for a write (`mov r/m, r`), false for a read (`mov r, r/m`).
    pub write: bool,
    /// General-purpose register involved (0 = RAX … 15 = R15).
    pub register: u8,
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

/// Result of decoding one instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decoded {
    Memory(MemoryAccess),
    Port(PortAccess),
}

impl Decoded {
    /// RIP after the instruction, whichever kind was decoded.
    pub const fn next_rip(self) -> u64 {
        match self {
            Decoded::Memory(access) => access.next_rip,
            Decoded::Port(access) => access.next_rip,
        }
    }
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
    let mut index = 0usize;
    let mut operand_size_override = false;
    let mut rex: u8 = 0;

    // Legacy prefixes we care about: 0x66 selects a 16-bit operand.
    while index < bytes.len() {
        match bytes[index] {
            0x66 => {
                operand_size_override = true;
                index += 1;
            }
            0x67 => {
                // 32-bit addressing in a 64-bit guest: unsupported.
                return Err(DecodeError::Unsupported);
            }
            0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 => {
                return Err(DecodeError::Unsupported);
            }
            0x40..=0x4F => {
                rex = bytes[index];
                index += 1;
                break;
            }
            _ => break,
        }
    }

    let opcode = *bytes.get(index).ok_or(DecodeError::Truncated)?;
    index += 1;

    match opcode {
        // mov r, r/m  (0x8A byte, 0x8B word/dword/qword)
        0x8A | 0x8B => {
            let size = if opcode == 0x8A {
                1
            } else if rex & 0x08 != 0 {
                8
            } else if operand_size_override {
                2
            } else {
                4
            };
            let (address, register, next) = decode_modrm(bytes, index, rip, rex, &register)?;
            Ok(Decoded::Memory(MemoryAccess {
                address,
                size,
                write: false,
                register,
                next_rip: next,
            }))
        }
        // mov r/m, r  (0x88 byte, 0x89 word/dword/qword)
        0x88 | 0x89 => {
            let size = if opcode == 0x88 {
                1
            } else if rex & 0x08 != 0 {
                8
            } else if operand_size_override {
                2
            } else {
                4
            };
            let (address, register, next) = decode_modrm(bytes, index, rip, rex, &register)?;
            Ok(Decoded::Memory(MemoryAccess {
                address,
                size,
                write: true,
                register,
                next_rip: next,
            }))
        }
        // in al/ax/eax, imm8
        0xE4 | 0xE5 => {
            let port = *bytes.get(index).ok_or(DecodeError::Truncated)? as u16;
            index += 1;
            let size = if opcode == 0xE4 { 1 } else { 2 };
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
            let port = *bytes.get(index).ok_or(DecodeError::Truncated)? as u16;
            index += 1;
            let size = if opcode == 0xE6 { 1 } else { 2 };
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
            let size = if opcode == 0xEC { 1 } else { 4 };
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
            let size = if opcode == 0xEE { 1 } else { 4 };
            Ok(Decoded::Port(PortAccess {
                port: register(2) as u16,
                size,
                write: true,
                register: 0,
                next_rip: rip.wrapping_add(index as u64),
            }))
        }
        _ => Err(DecodeError::Unsupported),
    }
}

/// Decodes the ModRM byte (and optional SIB/displacement) of a `mov`.
///
/// Returns (effective address, register index, next RIP).
fn decode_modrm<F>(
    bytes: &[u8],
    mut index: usize,
    rip: u64,
    rex: u8,
    register: &F,
) -> Result<(u64, u8, u64), DecodeError>
where
    F: Fn(u8) -> u64,
{
    let modrm = *bytes.get(index).ok_or(DecodeError::Truncated)?;
    index += 1;
    let mode = modrm >> 6;
    let reg_field = ((modrm >> 3) & 0x7) | ((rex & 0x04) << 1);
    let rm_low = modrm & 0x7;
    let rm_field = rm_low | ((rex & 0x01) << 3);

    // Register-only form (mod = 11): not a memory access.
    if mode == 0b11 {
        return Err(DecodeError::Unsupported);
    }

    let mut address = 0u64;
    let mut base_register: Option<u8> = None;
    let mut index_register: Option<u8> = None;
    let mut scale = 1u64;
    let mut displacement: i64 = 0;

    if rm_low == 4 {
        // SIB byte (the low three bits select SIB regardless of REX.B).
        let sib = *bytes.get(index).ok_or(DecodeError::Truncated)?;
        index += 1;
        scale = 1u64 << (sib >> 6);
        let sib_index = (sib >> 3) & 0x7;
        // In 64-bit mode only index 100b with REX.X = 0 means "no index";
        // with REX.X = 1 it selects R12.
        index_register = if sib_index == 4 && (rex & 0x02) == 0 {
            None
        } else {
            Some(sib_index | ((rex & 0x02) << 2))
        };
        let sib_base = sib & 0x7;
        match mode {
            0b00 if sib_base == 0b101 => {
                // No base, disp32 absolute.
                displacement = read_i32(bytes, &mut index)? as i64;
            }
            _ => {
                base_register = Some(sib_base | ((rex & 0x01) << 3));
            }
        }
    } else if mode == 0b00 && rm_low == 0b101 {
        // RIP-relative disp32.
        let disp = read_i32(bytes, &mut index)? as i64;
        address = rip.wrapping_add(index as u64).wrapping_add(disp as u64);
    } else {
        base_register = Some(rm_field);
    }

    if let Some(base) = base_register {
        address = address.wrapping_add(register(base));
    }
    if let Some(index_register) = index_register {
        address = address.wrapping_add(register(index_register).wrapping_mul(scale));
    }

    match mode {
        0b01 => displacement = read_i8(bytes, &mut index)? as i64,
        0b10 => displacement = read_i32(bytes, &mut index)? as i64,
        _ => {}
    }
    address = address.wrapping_add(displacement as u64);

    Ok((address, reg_field, rip.wrapping_add(index as u64)))
}

fn read_i8(bytes: &[u8], index: &mut usize) -> Result<i8, DecodeError> {
    let value = *bytes.get(*index).ok_or(DecodeError::Truncated)? as i8;
    *index += 1;
    Ok(value)
}

fn read_i32(bytes: &[u8], index: &mut usize) -> Result<i32, DecodeError> {
    let end = *index + 4;
    let slice = bytes.get(*index..end).ok_or(DecodeError::Truncated)?;
    *index = end;
    Ok(i32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
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
        }
    }
}
