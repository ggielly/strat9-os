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

//! L2: s9vm guest program builder (typed assembler for test payloads).
//!
//! The module under test is pure, so it is compiled here together with the
//! kernel decoder it validates against.

extern crate alloc;

#[path = "../../kernel/src/s9vm/decode.rs"]
mod decode;
#[path = "../../kernel/src/s9vm/guestprog.rs"]
mod guestprog;

use guestprog::{GuestProgError, GuestProgram, MAX_PROGRAM_BYTES, Reg};

#[test]
fn new_program_is_empty_and_valid() {
    let program = GuestProgram::new();
    assert!(program.is_empty());
    assert_eq!(program.len(), 0);
    assert_eq!(program.offset(), 0);
    assert_eq!(program.instruction_count(), 0);
    assert!(program.emit_bytes().is_empty());
    assert_eq!(program.validate_with_decoder(), Ok(()));
}

#[test]
fn mov_imm8_encodes_opcode_and_rex() {
    let mut program = GuestProgram::new();
    program.mov_imm8(Reg::RAX, b'A').unwrap();
    assert_eq!(program.emit_bytes(), &[0xB0, b'A']);

    program.clear();
    program.mov_imm8(Reg::R8, 0x7F).unwrap();
    assert_eq!(program.emit_bytes(), &[0x41, 0xB0, 0x7F]);
    assert_eq!(program.validate_with_decoder(), Ok(()));
}

#[test]
fn mov_imm16_always_sets_the_operand_size_prefix() {
    // The historical payload encoded `mov dx, 0xE9` as `BA E9 00`, which is
    // `mov r32, imm32` in 64-bit mode and consumed the following bytes.
    let mut program = GuestProgram::new();
    program.mov_imm16(Reg::RDX, 0x0100).unwrap();
    assert_eq!(program.emit_bytes(), &[0x66, 0xBA, 0x00, 0x01]);
    assert_ne!(program.emit_bytes()[0], 0xBA);

    program.clear();
    program.mov_imm16(Reg::R9, 0x1234).unwrap();
    assert_eq!(program.emit_bytes(), &[0x66, 0x41, 0xB9, 0x34, 0x12]);
    assert_eq!(program.validate_with_decoder(), Ok(()));
}

#[test]
fn mov_imm32_encodes_a_zero_extending_move() {
    let mut program = GuestProgram::new();
    program.mov_imm32(Reg::RAX, 0xFEB0_0070).unwrap();
    assert_eq!(program.emit_bytes(), &[0xB8, 0x70, 0x00, 0xB0, 0xFE]);

    program.clear();
    program.mov_imm32(Reg::R15, 0xDEAD_BEEF).unwrap();
    assert_eq!(program.emit_bytes(), &[0x41, 0xBF, 0xEF, 0xBE, 0xAD, 0xDE]);
    assert_eq!(program.validate_with_decoder(), Ok(()));
}

#[test]
fn mov_imm64_encodes_rex_w_and_eight_immediate_bytes() {
    let mut program = GuestProgram::new();
    program.mov_imm64(Reg::RAX, 0x1122_3344_5566_7788).unwrap();
    assert_eq!(
        program.emit_bytes(),
        &[0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
    );

    program.clear();
    program.mov_imm64(Reg::R15, 0x0102_0304_0506_0708).unwrap();
    assert_eq!(
        program.emit_bytes(),
        &[0x49, 0xBF, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
    );
    assert_eq!(program.validate_with_decoder(), Ok(()));
}

#[test]
fn moffs_stores_use_the_64_bit_absolute_address() {
    let mut program = GuestProgram::new();
    program.mov_byte_to_abs(0x0001_4000, Reg::RAX).unwrap();
    assert_eq!(
        program.emit_bytes(),
        &[0xA2, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]
    );

    program.clear();
    program.mov_dword_to_abs(0x0001_4000, Reg::RAX).unwrap();
    assert_eq!(
        program.emit_bytes(),
        &[0xA3, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]
    );

    program.clear();
    program.mov_qword_to_abs(0x0001_4000, Reg::RAX).unwrap();
    assert_eq!(
        program.emit_bytes(),
        &[0x48, 0xA3, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
    assert_eq!(program.validate_with_decoder(), Ok(()));
}

#[test]
fn moffs_loads_use_the_64_bit_absolute_address() {
    let mut program = GuestProgram::new();
    program.mov_byte_from_abs(0x0000_7400, Reg::RAX).unwrap();
    assert_eq!(
        program.emit_bytes(),
        &[0xA0, 0x00, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );

    program.clear();
    program.mov_dword_from_abs(0x0000_7400, Reg::RAX).unwrap();
    assert_eq!(program.emit_bytes()[0], 0xA1);

    program.clear();
    program.mov_qword_from_abs(0x0000_7400, Reg::RAX).unwrap();
    assert_eq!(program.emit_bytes()[0..2], [0x48, 0xA1]);
    assert_eq!(program.emit_bytes().len(), 10);
    assert_eq!(program.validate_with_decoder(), Ok(()));
}

#[test]
fn mov_abs_to_reg64_uses_a_sib_absolute_address() {
    let mut program = GuestProgram::new();
    program.mov_abs_to_reg64(0x000E_0000, Reg::RAX).unwrap();
    assert_eq!(
        program.emit_bytes(),
        &[0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x0E, 0x00]
    );

    program.clear();
    program.mov_abs_to_reg64(0x000E_0000, Reg::R8).unwrap();
    assert_eq!(
        program.emit_bytes(),
        &[0x4C, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x0E, 0x00]
    );
    assert_eq!(program.validate_with_decoder(), Ok(()));
}

#[test]
fn mov_abs_to_reg64_rejects_an_address_above_32_bits() {
    let mut program = GuestProgram::new();
    assert_eq!(
        program.mov_abs_to_reg64(0x1_0000_0000, Reg::RAX),
        Err(GuestProgError::AddressOutOfRange(0x1_0000_0000))
    );
    assert_eq!(program.len(), 0);
}

#[test]
fn mov_dword_to_ptr_encodes_register_indirect_stores() {
    let mut program = GuestProgram::new();
    program.mov_dword_to_ptr(Reg::RAX, Reg::RCX).unwrap();
    assert_eq!(program.emit_bytes(), &[0x89, 0x08]);

    program.clear();
    // RBP/R13 as a base needs a zero disp8 with mod = 01.
    program.mov_dword_to_ptr(Reg::RBP, Reg::RCX).unwrap();
    assert_eq!(program.emit_bytes(), &[0x89, 0x4D, 0x00]);

    program.clear();
    // RSP/R12 as a base needs a SIB byte.
    program.mov_dword_to_ptr(Reg::RSP, Reg::RCX).unwrap();
    assert_eq!(program.emit_bytes(), &[0x89, 0x0C, 0x24]);
    assert_eq!(program.validate_with_decoder(), Ok(()));
}

#[test]
fn port_instructions_encode_the_immediate_port() {
    let mut program = GuestProgram::new();
    program.out_imm8_port(0xE9, Reg::RAX).unwrap();
    assert_eq!(program.emit_bytes(), &[0xE6, 0xE9]);

    program.clear();
    program.in_imm8_port(0x60, Reg::RAX).unwrap();
    assert_eq!(program.emit_bytes(), &[0xE4, 0x60]);
    assert_eq!(program.validate_with_decoder(), Ok(()));
}

#[test]
fn control_and_halt_instructions_are_single_bytes() {
    let mut program = GuestProgram::new();
    program.hlt().unwrap();
    assert_eq!(program.emit_bytes(), &[0xF4]);
    program.clear();
    program.cli().unwrap();
    assert_eq!(program.emit_bytes(), &[0xFA]);
    program.clear();
    program.sti().unwrap();
    assert_eq!(program.emit_bytes(), &[0xFB]);
    program.clear();
    program.nop().unwrap();
    assert_eq!(program.emit_bytes(), &[0x90]);
}

#[test]
fn short_branches_validate_the_signed_displacement() {
    let mut program = GuestProgram::new();
    program.jmp_short(-2).unwrap();
    assert_eq!(program.emit_bytes(), &[0xEB, 0xFE]);
    program.clear();
    program.je_short(0x7F).unwrap();
    assert_eq!(program.emit_bytes(), &[0x74, 0x7F]);
    program.clear();
    program.loop_short(-128).unwrap();
    assert_eq!(program.emit_bytes(), &[0xE2, 0x80]);

    assert_eq!(
        program.jmp_short(128),
        Err(GuestProgError::DisplacementOutOfRange(128))
    );
    assert_eq!(
        program.je_short(-129),
        Err(GuestProgError::DisplacementOutOfRange(-129))
    );
}

#[test]
fn backward_loop_uses_the_emitted_offsets() {
    let mut program = GuestProgram::new();
    program.mov_imm8(Reg::RCX, 3).unwrap();
    let start = program.offset();
    program.nop().unwrap();
    let end = program.offset();
    let displacement = start as i32 - end as i32 - 2;
    program.loop_short(displacement).unwrap();
    assert_eq!(program.emit_bytes()[end], 0xE2);
    assert_eq!(program.emit_bytes()[end + 1], displacement as u8);
    assert_eq!(program.validate_with_decoder(), Ok(()));
}

#[test]
fn cmp_byte_imm8_encodes_group_seven() {
    let mut program = GuestProgram::new();
    program.cmp_byte_imm8(Reg::RAX, 0xFF).unwrap();
    assert_eq!(program.emit_bytes(), &[0x80, 0xF8, 0xFF]);

    program.clear();
    program.cmp_byte_imm8(Reg::R8, 0x02).unwrap();
    assert_eq!(program.emit_bytes(), &[0x41, 0x80, 0xF8, 0x02]);
}

#[test]
fn composed_loader_payload_is_exact_and_decodable() {
    let mut program = GuestProgram::new();
    program.mov_imm8(Reg::RAX, b'A').unwrap();
    program.out_imm8_port(0xE9, Reg::RAX).unwrap();
    program.hlt().unwrap();

    assert_eq!(program.emit_bytes(), &[0xB0, b'A', 0xE6, 0xE9, 0xF4]);
    assert_eq!(program.len(), 5);
    assert_eq!(program.instruction_count(), 3);
    assert_eq!(program.validate_with_decoder(), Ok(()));
}

#[test]
fn validation_skips_instructions_outside_the_decoder_subset() {
    let mut program = GuestProgram::new();
    program.nop().unwrap();
    program.jmp_short(-2).unwrap();
    program.je_short(0).unwrap();
    program.loop_short(-1).unwrap();
    program.cmp_byte_imm8(Reg::RAX, 0).unwrap();
    program.cli().unwrap();
    program.sti().unwrap();
    program.hlt().unwrap();
    assert_eq!(program.validate_with_decoder(), Ok(()));
}

#[test]
fn validation_rejects_a_patched_port_opcode() {
    let mut program = GuestProgram::new();
    program.mov_imm8(Reg::RAX, b'A').unwrap();
    program.out_imm8_port(0xE9, Reg::RAX).unwrap();
    program.hlt().unwrap();
    assert_eq!(program.validate_with_decoder(), Ok(()));

    // Replace `out 0xE9, al` (`E6`) with `BA`, the historical triple-fault
    // encoding (`mov r32, imm32`).
    program.emit_bytes_mut()[2] = 0xBA;
    assert_eq!(
        program.validate_with_decoder(),
        Err(GuestProgError::DecodeFailed(2))
    );
}

#[test]
fn validation_rejects_a_patched_immediate_move() {
    let mut program = GuestProgram::new();
    program.mov_imm8(Reg::RAX, b'L').unwrap();
    program.hlt().unwrap();
    // `B0` (mov r8, imm8) patched to `B8` (mov r32, imm32): the recorded
    // length no longer matches the decoded instruction.
    program.emit_bytes_mut()[0] = 0xB8;
    assert_eq!(
        program.validate_with_decoder(),
        Err(GuestProgError::DecodeFailed(0))
    );
}

#[test]
fn invalid_register_indices_are_reported() {
    assert_eq!(Reg::new(0), Ok(Reg::RAX));
    assert_eq!(Reg::new(15), Ok(Reg::R15));
    assert_eq!(Reg::new(16), Err(GuestProgError::InvalidRegister(16)));
    assert_eq!(
        Reg::new(u8::MAX),
        Err(GuestProgError::InvalidRegister(u8::MAX))
    );
    assert_eq!(Reg::RAX.index(), 0);
    assert_eq!(Reg::R15.index(), 15);
}

#[test]
fn accumulator_only_forms_reject_other_registers() {
    let mut program = GuestProgram::new();
    assert_eq!(
        program.mov_byte_to_abs(0, Reg::RCX),
        Err(GuestProgError::AccumulatorRequired(1))
    );
    assert_eq!(
        program.mov_qword_from_abs(0, Reg::RDX),
        Err(GuestProgError::AccumulatorRequired(2))
    );
    assert_eq!(
        program.out_imm8_port(0xE9, Reg::RBX),
        Err(GuestProgError::AccumulatorRequired(3))
    );
    assert_eq!(
        program.in_imm8_port(0x60, Reg::RSI),
        Err(GuestProgError::AccumulatorRequired(6))
    );
    assert_eq!(program.len(), 0);
}

#[test]
fn immediate_ports_above_one_byte_are_rejected() {
    let mut program = GuestProgram::new();
    assert_eq!(
        program.out_imm8_port(0x100, Reg::RAX),
        Err(GuestProgError::PortOutOfRange(0x100))
    );
    assert_eq!(
        program.in_imm8_port(0xFFFF, Reg::RAX),
        Err(GuestProgError::PortOutOfRange(0xFFFF))
    );
    assert_eq!(program.len(), 0);
}

#[test]
fn program_is_bounded_by_one_guest_page() {
    assert_eq!(MAX_PROGRAM_BYTES, 4096);

    let mut program = GuestProgram::new();
    for _ in 0..MAX_PROGRAM_BYTES {
        program.nop().unwrap();
    }
    assert_eq!(program.len(), MAX_PROGRAM_BYTES);
    assert_eq!(program.instruction_count(), MAX_PROGRAM_BYTES);
    assert_eq!(program.nop(), Err(GuestProgError::ProgramTooLong));
    // The failed emission left the program untouched.
    assert_eq!(program.len(), MAX_PROGRAM_BYTES);
    assert_eq!(program.instruction_count(), MAX_PROGRAM_BYTES);
}

#[test]
fn clear_resets_the_program() {
    let mut program = GuestProgram::new();
    program.mov_imm8(Reg::RAX, 1).unwrap();
    program.hlt().unwrap();
    assert_eq!(program.instruction_count(), 2);
    program.clear();
    assert!(program.is_empty());
    assert_eq!(program.instruction_count(), 0);
    assert_eq!(program.validate_with_decoder(), Ok(()));
}

#[test]
fn error_names_are_stable() {
    assert_eq!(
        GuestProgError::InvalidRegister(16).name(),
        "invalid-register"
    );
    assert_eq!(
        GuestProgError::DisplacementOutOfRange(200).name(),
        "displacement-out-of-range"
    );
    assert_eq!(
        GuestProgError::PortOutOfRange(300).name(),
        "port-out-of-range"
    );
    assert_eq!(
        GuestProgError::AddressOutOfRange(u64::MAX).name(),
        "address-out-of-range"
    );
    assert_eq!(
        GuestProgError::AccumulatorRequired(1).name(),
        "accumulator-required"
    );
    assert_eq!(GuestProgError::ProgramTooLong.name(), "program-too-long");
    assert_eq!(GuestProgError::DecodeFailed(3).name(), "decode-failed");
    assert_eq!(
        GuestProgError::LengthMismatch {
            offset: 1,
            expected: 2,
            decoded: 3,
        }
        .name(),
        "length-mismatch"
    );
}
