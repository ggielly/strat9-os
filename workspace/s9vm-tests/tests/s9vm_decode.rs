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

//! L2: minimal x86-64 instruction decoder used for exit emulation.

extern crate alloc;

#[path = "../../kernel/src/s9vm/decode.rs"]
mod decode;

use decode::{decode, DecodeError, Decoded, Extension};

fn regs() -> [u64; 16] {
    let mut values = [0u64; 16];
    values[0] = 0x1111;
    values[1] = 0x2222;
    values[2] = 0x3F8;
    values[3] = 0x1000;
    values[5] = 0x2000;
    values[4] = 0x3000;
    values[6] = 0x5000;
    values[8] = 0x4000;
    values[12] = 0x6000;
    values[13] = 0x7000;
    values
}

fn decode_with(bytes: &[u8], rip: u64) -> Result<Decoded, DecodeError> {
    let values = regs();
    decode(bytes, rip, |index| values[index as usize])
}

fn decode_with_regs(bytes: &[u8], rip: u64, values: &[u64; 16]) -> Result<Decoded, DecodeError> {
    decode(bytes, rip, |index| values[index as usize])
}

fn memory(decoded: Decoded) -> decode::MemoryAccess {
    match decoded {
        Decoded::Memory(access) => access,
        _ => panic!("expected memory access"),
    }
}

fn register(decoded: Decoded) -> decode::RegisterAccess {
    match decoded {
        Decoded::Register(access) => access,
        _ => panic!("expected register-only move"),
    }
}

#[test]
fn decodes_mov_register_from_base_plus_disp8() {
    let access = memory(decode_with(&[0x48, 0x8B, 0x43, 0x10], 0x3000).unwrap());
    assert_eq!(access.address, 0x1010);
    assert_eq!(access.size, 8);
    assert!(!access.write);
    assert_eq!(access.register, 0);
    assert_eq!(access.register_size, 8);
    assert_eq!(access.immediate, None);
    assert_eq!(access.extension, Extension::None);
    assert_eq!(access.next_rip, 0x3004);
}

#[test]
fn decodes_mov_rip_relative_write() {
    let access = memory(decode_with(&[0x89, 0x05, 0x20, 0x00, 0x00, 0x00], 0x3000).unwrap());
    assert_eq!(access.address, 0x3026);
    assert_eq!(access.size, 4);
    assert!(access.write);
    assert_eq!(access.register, 0);
    assert_eq!(access.next_rip, 0x3006);
}

#[test]
fn decodes_rex_extension_registers() {
    // 4D 8B 08: mov r9, [r8]
    let access = memory(decode_with(&[0x4D, 0x8B, 0x08], 0x100).unwrap());
    assert_eq!(access.register, 9);
    assert_eq!(access.address, 0x4000);
    assert_eq!(access.size, 8);
}

#[test]
fn decodes_sixteen_bit_operand_override() {
    // 66 8B 06: mov ax, [rsi]
    let access = memory(decode_with(&[0x66, 0x8B, 0x06], 0x100).unwrap());
    assert_eq!(access.size, 2);
    assert_eq!(access.address, 0x5000);
}

#[test]
fn decodes_sib_with_base_and_disp8() {
    // 49 8B 44 24 08: mov rax, [r12 + 8]
    let access = memory(decode_with(&[0x49, 0x8B, 0x44, 0x24, 0x08], 0x100).unwrap());
    assert_eq!(access.address, 0x6008);
    assert_eq!(access.size, 8);
}

#[test]
fn decodes_absolute_sib_disp32() {
    // 8B 04 25 00 20 00 00: mov eax, [0x2000]
    let access = memory(decode_with(&[0x8B, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00], 0x100).unwrap());
    assert_eq!(access.address, 0x2000);
    assert_eq!(access.size, 4);
}

#[test]
fn decodes_sib_with_rsp_base_and_no_index() {
    // 8B 04 24: mov eax, [rsp]
    let access = memory(decode_with(&[0x8B, 0x04, 0x24], 0x100).unwrap());
    assert_eq!(access.address, 0x3000);
    assert_eq!(access.size, 4);
}

#[test]
fn decodes_sib_with_r12_index() {
    // 42 8B 04 24: mov eax, [rsp + r12]
    let access = memory(decode_with(&[0x42, 0x8B, 0x04, 0x24], 0x100).unwrap());
    assert_eq!(access.address, 0x9000);
    assert_eq!(access.size, 4);
}

#[test]
fn decodes_sib_scaled_index_and_absolute_base() {
    // 8B 04 6D 00 10 00 00: mov eax, [rbp * 2 + 0x1000]
    let access = memory(decode_with(&[0x8B, 0x04, 0x6D, 0x00, 0x10, 0x00, 0x00], 0x100).unwrap());
    assert_eq!(access.address, 0x5000);
    assert_eq!(access.size, 4);
}

#[test]
fn decodes_negative_disp8() {
    // 8B 43 F0: mov eax, [rbx - 16]
    let access = memory(decode_with(&[0x8B, 0x43, 0xF0], 0x100).unwrap());
    assert_eq!(access.address, 0x0FF0);
}

#[test]
fn decodes_negative_disp32() {
    // 8B 83 00 FF FF FF: mov eax, [rbx - 256]
    let access = memory(decode_with(&[0x8B, 0x83, 0x00, 0xFF, 0xFF, 0xFF], 0x100).unwrap());
    assert_eq!(access.address, 0x0F00);
}

#[test]
fn decodes_rbp_base_disp8() {
    // 8B 45 F0: mov eax, [rbp - 16]
    let access = memory(decode_with(&[0x8B, 0x45, 0xF0], 0x100).unwrap());
    assert_eq!(access.address, 0x1FF0);
}

#[test]
fn decodes_r13_base_disp32() {
    // 41 8B 85 00 00 00 00: mov eax, [r13]
    let access = memory(decode_with(&[0x41, 0x8B, 0x85, 0x00, 0x00, 0x00, 0x00], 0x100).unwrap());
    assert_eq!(access.address, 0x7000);
    assert_eq!(access.size, 4);
}

#[test]
fn decodes_negative_rip_relative_disp() {
    // 8B 05 F0 FF FF FF at 0x3000: mov eax, [rip - 16]
    let access = memory(decode_with(&[0x8B, 0x05, 0xF0, 0xFF, 0xFF, 0xFF], 0x3000).unwrap());
    assert_eq!(access.address, 0x2FF6);
    assert_eq!(access.next_rip, 0x3006);
}

#[test]
fn rex_b_does_not_turn_rip_relative_into_r13() {
    // 41 8B 05 00 00 00 00: REX.B is ignored for mod=00 rm=101, still RIP-relative.
    let access = memory(decode_with(&[0x41, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00], 0x3000).unwrap());
    assert_eq!(access.address, 0x3007);
    assert_eq!(access.next_rip, 0x3007);
}

#[test]
fn rex_b_does_not_turn_sib_base_5_into_r13() {
    // 41 8B 04 25 00 20 00 00: SIB base=5 is no-base disp32, even with REX.B.
    let access =
        memory(decode_with(&[0x41, 0x8B, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00], 0x100).unwrap());
    assert_eq!(access.address, 0x2000);
    assert_eq!(access.size, 4);
}

#[test]
fn decodes_address_size_override_modrm() {
    // 67 8B 43 10: mov eax, [ebx + 0x10], with high bits of RBX ignored.
    let mut values = regs();
    values[3] = 0x1_0000_1000;
    let access = memory(decode_with_regs(&[0x67, 0x8B, 0x43, 0x10], 0x100, &values).unwrap());
    assert_eq!(access.address, 0x1010);
    assert_eq!(access.size, 4);
}

#[test]
fn decodes_address_size_override_absolute_disp32() {
    // 67 8B 05 00 20 00 00: 32-bit addressing makes rm=5 absolute, not RIP-relative.
    let access = memory(decode_with(&[0x67, 0x8B, 0x05, 0x00, 0x20, 0x00, 0x00], 0x3000).unwrap());
    assert_eq!(access.address, 0x2000);
    assert_eq!(access.size, 4);
}

#[test]
fn decodes_segment_prefix_as_ignored() {
    // 64 8B 43 10: segment override is consumed and ignored.
    let access = memory(decode_with(&[0x64, 0x8B, 0x43, 0x10], 0x100).unwrap());
    assert_eq!(access.address, 0x1010);
    assert_eq!(access.size, 4);
}

#[test]
fn decodes_combined_prefixes_in_any_order() {
    // 64 66 67 8B 43 10: segment ignored, 16-bit operand, 32-bit address.
    let access = memory(decode_with(&[0x64, 0x66, 0x67, 0x8B, 0x43, 0x10], 0x100).unwrap());
    assert_eq!(access.address, 0x1010);
    assert_eq!(access.size, 2);
}

#[test]
fn decodes_mov_immediate_to_byte_register() {
    // B0 7F: mov al, 0x7F
    let access = register(decode_with(&[0xB0, 0x7F], 0x100).unwrap());
    assert_eq!(access.register, 0);
    assert_eq!(access.size, 1);
    assert_eq!(access.value, 0x7F);
    assert_eq!(access.next_rip, 0x102);
}

#[test]
fn decodes_mov_immediate_to_extended_byte_register() {
    // 41 B0 7F: mov r8b, 0x7F
    let access = register(decode_with(&[0x41, 0xB0, 0x7F], 0x100).unwrap());
    assert_eq!(access.register, 8);
    assert_eq!(access.size, 1);
    assert_eq!(access.value, 0x7F);
}

#[test]
fn decodes_mov_immediate_to_word_register() {
    // 66 B8 34 12: mov ax, 0x1234
    let access = register(decode_with(&[0x66, 0xB8, 0x34, 0x12], 0x100).unwrap());
    assert_eq!(access.register, 0);
    assert_eq!(access.size, 2);
    assert_eq!(access.value, 0x1234);
}

#[test]
fn decodes_mov_immediate_to_dword_register() {
    // B9 78 56 34 12: mov ecx, 0x12345678
    let access = register(decode_with(&[0xB9, 0x78, 0x56, 0x34, 0x12], 0x100).unwrap());
    assert_eq!(access.register, 1);
    assert_eq!(access.size, 4);
    assert_eq!(access.value, 0x1234_5678);
}

#[test]
fn decodes_mov_immediate_to_qword_register() {
    // 49 BA 88 77 66 55 44 33 22 11: mov r10, 0x1122334455667788
    let access = register(
        decode_with(
            &[0x49, 0xBA, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
            0x100,
        )
        .unwrap(),
    );
    assert_eq!(access.register, 10);
    assert_eq!(access.size, 8);
    assert_eq!(access.value, 0x1122_3344_5566_7788);
    assert_eq!(access.next_rip, 0x10A);
}

#[test]
fn decodes_mov_immediate_to_extended_dword_register() {
    // 41 BF EF CD AB 89: mov r15d, 0x89ABCDEF
    let access = register(decode_with(&[0x41, 0xBF, 0xEF, 0xCD, 0xAB, 0x89], 0x100).unwrap());
    assert_eq!(access.register, 15);
    assert_eq!(access.size, 4);
    assert_eq!(access.value, 0x89AB_CDEF);
}

#[test]
fn decodes_mov_immediate_to_memory_byte() {
    // C6 03 7F: mov byte ptr [rbx], 0x7F
    let access = memory(decode_with(&[0xC6, 0x03, 0x7F], 0x100).unwrap());
    assert_eq!(access.address, 0x1000);
    assert_eq!(access.size, 1);
    assert!(access.write);
    assert_eq!(access.immediate, Some(0x7F));
    assert_eq!(access.next_rip, 0x103);
}

#[test]
fn decodes_mov_immediate_to_memory_dword() {
    // C7 03 78 56 34 12: mov dword ptr [rbx], 0x12345678
    let access = memory(decode_with(&[0xC7, 0x03, 0x78, 0x56, 0x34, 0x12], 0x100).unwrap());
    assert_eq!(access.address, 0x1000);
    assert_eq!(access.size, 4);
    assert!(access.write);
    assert_eq!(access.immediate, Some(0x1234_5678));
    assert_eq!(access.next_rip, 0x106);
}

#[test]
fn decodes_mov_immediate_to_memory_qword_sign_extended() {
    // 48 C7 03 FE FF FF FF: mov qword ptr [rbx], -2
    let access = memory(decode_with(&[0x48, 0xC7, 0x03, 0xFE, 0xFF, 0xFF, 0xFF], 0x100).unwrap());
    assert_eq!(access.address, 0x1000);
    assert_eq!(access.size, 8);
    assert!(access.write);
    assert_eq!(access.immediate, Some(0xFFFF_FFFF_FFFF_FFFE));
    assert_eq!(access.next_rip, 0x107);
}

#[test]
fn decodes_mov_immediate_to_memory_word_with_operand_override() {
    // 66 C7 03 34 12: mov word ptr [rbx], 0x1234
    let access = memory(decode_with(&[0x66, 0xC7, 0x03, 0x34, 0x12], 0x100).unwrap());
    assert_eq!(access.size, 2);
    assert_eq!(access.immediate, Some(0x1234));
    assert_eq!(access.next_rip, 0x105);
}

#[test]
fn rex_w_wins_over_operand_override_for_c7() {
    // 66 48 C7 03 FE FF FF FF: REX.W selects a 64-bit store, imm32 sign-extended.
    let access =
        memory(decode_with(&[0x66, 0x48, 0xC7, 0x03, 0xFE, 0xFF, 0xFF, 0xFF], 0x100).unwrap());
    assert_eq!(access.size, 8);
    assert_eq!(access.immediate, Some(0xFFFF_FFFF_FFFF_FFFE));
}

#[test]
fn decodes_mov_immediate_to_memory_rip_relative() {
    // C7 05 00 00 00 00 78 56 34 12: RIP-relative address includes the immediate.
    let access = memory(
        decode_with(
            &[0xC7, 0x05, 0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12],
            0x3000,
        )
        .unwrap(),
    );
    assert_eq!(access.address, 0x300A);
    assert_eq!(access.size, 4);
    assert_eq!(access.next_rip, 0x300A);
}

#[test]
fn decodes_mov_immediate_to_memory_byte_rip_relative() {
    // C6 05 00 00 00 00 7F
    let access = memory(decode_with(&[0xC6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x7F], 0x3000).unwrap());
    assert_eq!(access.address, 0x3007);
    assert_eq!(access.size, 1);
    assert_eq!(access.next_rip, 0x3007);
}

#[test]
fn decodes_mov_immediate_to_register_via_c7() {
    // C7 C0 01 00 00 00: mov eax, 1
    let access = register(decode_with(&[0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00], 0x100).unwrap());
    assert_eq!(access.register, 0);
    assert_eq!(access.size, 4);
    assert_eq!(access.value, 1);
    assert_eq!(access.next_rip, 0x106);
}

#[test]
fn decodes_c7_register_form_with_rex_b() {
    // 41 C7 C0 01 00 00 00: mov r8d, 1
    let access = register(decode_with(&[0x41, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00], 0x100).unwrap());
    assert_eq!(access.register, 8);
    assert_eq!(access.size, 4);
    assert_eq!(access.value, 1);
    assert_eq!(access.next_rip, 0x107);
}

#[test]
fn rejects_mov_immediate_with_nonzero_group() {
    // C6 C8 01: group 1, not mov.
    assert_eq!(
        decode_with(&[0xC6, 0xC8, 0x01], 0),
        Err(DecodeError::Unsupported)
    );
    // C7 0B 01 00 00 00: memory form with group 1.
    assert_eq!(
        decode_with(&[0xC7, 0x0B, 0x01, 0x00, 0x00, 0x00], 0),
        Err(DecodeError::Unsupported)
    );
}

#[test]
fn decodes_moffs_read_byte() {
    // A0 00 20 00 00 00 00 00 00: mov al, [0x2000]
    let access = memory(
        decode_with(
            &[0xA0, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            0x100,
        )
        .unwrap(),
    );
    assert_eq!(access.address, 0x2000);
    assert_eq!(access.size, 1);
    assert!(!access.write);
    assert_eq!(access.next_rip, 0x109);
}

#[test]
fn decodes_moffs_write_byte() {
    // A2 00 20 00 00 00 00 00 00: mov [0x2000], al
    let access = memory(
        decode_with(
            &[0xA2, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            0x100,
        )
        .unwrap(),
    );
    assert_eq!(access.address, 0x2000);
    assert_eq!(access.size, 1);
    assert!(access.write);
}

#[test]
fn decodes_moffs_qword_with_rex_w() {
    // 48 A1 00 20 00 00 00 00 00 00: mov rax, [0x2000]
    let access = memory(
        decode_with(
            &[0x48, 0xA1, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            0x100,
        )
        .unwrap(),
    );
    assert_eq!(access.address, 0x2000);
    assert_eq!(access.size, 8);
}

#[test]
fn decodes_moffs_qword_write_with_rex_w() {
    // 48 A3 00 20 00 00 00 00 00 00: mov [0x2000], rax
    let access = memory(
        decode_with(
            &[0x48, 0xA3, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            0x100,
        )
        .unwrap(),
    );
    assert_eq!(access.address, 0x2000);
    assert_eq!(access.size, 8);
    assert!(access.write);
}

#[test]
fn decodes_moffs_with_address_size_override() {
    // 67 A1 00 20 00 00: 32-bit moffs.
    let access = memory(decode_with(&[0x67, 0xA1, 0x00, 0x20, 0x00, 0x00], 0x100).unwrap());
    assert_eq!(access.address, 0x2000);
    assert_eq!(access.size, 4);
    assert_eq!(access.next_rip, 0x106);
}

#[test]
fn decodes_mov_byte_transfers() {
    // 88 03: mov [rbx], al
    let write = memory(decode_with(&[0x88, 0x03], 0x100).unwrap());
    assert!(write.write);
    assert_eq!(write.size, 1);
    assert_eq!(write.address, 0x1000);
    // 8A 03: mov al, [rbx]
    let read = memory(decode_with(&[0x8A, 0x03], 0x100).unwrap());
    assert!(!read.write);
    assert_eq!(read.size, 1);
    assert_eq!(read.address, 0x1000);
}

#[test]
fn decodes_movzx_byte() {
    // 0F B6 03: movzx eax, byte ptr [rbx]
    let access = memory(decode_with(&[0x0F, 0xB6, 0x03], 0x100).unwrap());
    assert_eq!(access.address, 0x1000);
    assert_eq!(access.size, 1);
    assert_eq!(access.register, 0);
    assert_eq!(access.register_size, 4);
    assert_eq!(access.extension, Extension::Zero);
}

#[test]
fn decodes_movzx_word_with_operand_override() {
    // 66 0F B7 03: movzx ax, word ptr [rbx]
    let access = memory(decode_with(&[0x66, 0x0F, 0xB7, 0x03], 0x100).unwrap());
    assert_eq!(access.size, 2);
    assert_eq!(access.register_size, 2);
    assert_eq!(access.extension, Extension::Zero);
}

#[test]
fn decodes_movsx_byte() {
    // 0F BE 03: movsx eax, byte ptr [rbx]
    let access = memory(decode_with(&[0x0F, 0xBE, 0x03], 0x100).unwrap());
    assert_eq!(access.size, 1);
    assert_eq!(access.register_size, 4);
    assert_eq!(access.extension, Extension::Sign);
}

#[test]
fn decodes_movsx_word_to_qword() {
    // 48 0F BF 03: movsx rax, word ptr [rbx]
    let access = memory(decode_with(&[0x48, 0x0F, 0xBF, 0x03], 0x100).unwrap());
    assert_eq!(access.size, 2);
    assert_eq!(access.register_size, 8);
    assert_eq!(access.extension, Extension::Sign);
}

#[test]
fn rejects_register_only_movzx() {
    // 0F B6 C0: movzx eax, al has no memory operand.
    assert_eq!(
        decode_with(&[0x0F, 0xB6, 0xC0], 0),
        Err(DecodeError::Unsupported)
    );
}

#[test]
fn rejects_lock_and_rep_prefixes() {
    assert_eq!(
        decode_with(&[0xF0, 0x8B, 0x43, 0x10], 0),
        Err(DecodeError::Unsupported)
    );
    assert_eq!(
        decode_with(&[0xF3, 0x8B, 0x43, 0x10], 0),
        Err(DecodeError::Unsupported)
    );
}

#[test]
fn decodes_in_al_immediate_port() {
    let decoded = decode_with(&[0xE4, 0x60], 0x3000).unwrap();
    match decoded {
        Decoded::Port(access) => {
            assert_eq!(access.port, 0x60);
            assert_eq!(access.size, 1);
            assert!(!access.write);
            assert_eq!(access.next_rip, 0x3002);
        }
        _ => panic!("expected port access"),
    }
}

#[test]
fn decodes_out_immediate_port() {
    let decoded = decode_with(&[0xE6, 0xE9], 0x3000).unwrap();
    match decoded {
        Decoded::Port(access) => {
            assert_eq!(access.port, 0xE9);
            assert_eq!(access.size, 1);
            assert!(access.write);
            assert_eq!(access.next_rip, 0x3002);
        }
        _ => panic!("expected port access"),
    }
}

#[test]
fn decodes_out_word_immediate_port() {
    // 66 E7 21: out 0x21, ax (the 0x66 prefix is required for 16-bit).
    let decoded = decode_with(&[0x66, 0xE7, 0x21], 0x0).unwrap();
    match decoded {
        Decoded::Port(access) => {
            assert_eq!(access.port, 0x21);
            assert_eq!(access.size, 2);
            assert!(access.write);
            assert_eq!(access.next_rip, 0x3);
        }
        _ => panic!("expected port access"),
    }
}

#[test]
fn decodes_out_dword_immediate_port_by_default() {
    // E7 21: out 0x21, eax
    let decoded = decode_with(&[0xE7, 0x21], 0x0).unwrap();
    match decoded {
        Decoded::Port(access) => {
            assert_eq!(access.size, 4);
            assert!(access.write);
        }
        _ => panic!("expected port access"),
    }
}

#[test]
fn decodes_in_eax_from_dx() {
    let decoded = decode_with(&[0xED], 0x1234).unwrap();
    match decoded {
        Decoded::Port(access) => {
            assert_eq!(access.port, 0x3F8);
            assert_eq!(access.size, 4);
            assert!(!access.write);
            assert_eq!(access.next_rip, 0x1235);
        }
        _ => panic!("expected port access"),
    }
}

#[test]
fn decodes_in_word_from_dx_with_operand_override() {
    // 66 ED: in ax, dx
    let decoded = decode_with(&[0x66, 0xED], 0x1234).unwrap();
    match decoded {
        Decoded::Port(access) => {
            assert_eq!(access.size, 2);
            assert!(!access.write);
            assert_eq!(access.next_rip, 0x1236);
        }
        _ => panic!("expected port access"),
    }
}

#[test]
fn rejects_unsupported_register_only_form() {
    // 8B C0: mov eax, eax (mod = 11) is not a memory access.
    assert_eq!(decode_with(&[0x8B, 0xC0], 0), Err(DecodeError::Unsupported));
}

#[test]
fn rejects_truncated_instruction() {
    assert_eq!(decode_with(&[0x8B], 0), Err(DecodeError::Truncated));
    assert_eq!(
        decode_with(&[0x48, 0x8B, 0x43], 0),
        Err(DecodeError::Truncated)
    );
}

#[test]
fn rejects_truncated_prefixes() {
    assert_eq!(decode_with(&[0x66], 0), Err(DecodeError::Truncated));
    assert_eq!(decode_with(&[0x67], 0), Err(DecodeError::Truncated));
    assert_eq!(decode_with(&[0x64], 0), Err(DecodeError::Truncated));
    assert_eq!(decode_with(&[0x48], 0), Err(DecodeError::Truncated));
}

#[test]
fn rejects_truncated_modrm_sib_disp_and_immediate() {
    // Missing SIB byte.
    assert_eq!(decode_with(&[0x8B, 0x04], 0), Err(DecodeError::Truncated));
    // Missing disp8.
    assert_eq!(decode_with(&[0x8B, 0x43], 0), Err(DecodeError::Truncated));
    // Missing disp32.
    assert_eq!(
        decode_with(&[0x8B, 0x05, 0x00, 0x00], 0),
        Err(DecodeError::Truncated)
    );
    // Missing 32-bit moffs address.
    assert_eq!(
        decode_with(&[0xA0, 0x00, 0x00], 0),
        Err(DecodeError::Truncated)
    );
    // Missing 64-bit moffs address.
    assert_eq!(
        decode_with(&[0xA1, 0x00, 0x00, 0x00, 0x00], 0),
        Err(DecodeError::Truncated)
    );
    // Missing mov-immediate value.
    assert_eq!(
        decode_with(&[0xC7, 0x03, 0x01, 0x02], 0),
        Err(DecodeError::Truncated)
    );
    // Missing 32-bit-address displacement.
    assert_eq!(
        decode_with(&[0x67, 0x8B, 0x05, 0x00, 0x00], 0),
        Err(DecodeError::Truncated)
    );
    // Truncated two-byte opcode.
    assert_eq!(decode_with(&[0x0F], 0), Err(DecodeError::Truncated));
    assert_eq!(
        decode_with(&[0x49, 0xBA, 0x00], 0),
        Err(DecodeError::Truncated)
    );
}

#[test]
fn rejects_other_opcodes() {
    assert_eq!(decode_with(&[0x0F, 0x31], 0), Err(DecodeError::Unsupported));
    assert_eq!(decode_with(&[0x90], 0), Err(DecodeError::Unsupported));
}

#[test]
fn next_rip_tracks_instruction_length() {
    let decoded = decode_with(&[0xE6, 0xE9], 0xFFFF_FFFF_8000_0000).unwrap();
    assert_eq!(decoded.next_rip(), 0xFFFF_FFFF_8000_0002);
    assert_eq!(decoded.instruction_length(0xFFFF_FFFF_8000_0000), 2);
    assert!(!decoded.describe().is_empty());
}

#[test]
fn decodes_rdmsr() {
    let decoded = decode_with(&[0x0F, 0x32], 0x1000).unwrap();
    match decoded {
        Decoded::Msr(access) => {
            assert!(!access.write);
            assert_eq!(access.next_rip, 0x1002);
        }
        _ => panic!("expected msr access"),
    }
}

#[test]
fn decodes_wrmsr_with_a_rex_prefix() {
    // REX.W is accepted (and ignored) before wrmsr.
    let decoded = decode_with(&[0x48, 0x0F, 0x30], 0x2000).unwrap();
    match decoded {
        Decoded::Msr(access) => {
            assert!(access.write);
            assert_eq!(access.next_rip, 0x2003);
        }
        _ => panic!("expected msr access"),
    }
}

#[test]
fn rejects_other_two_byte_opcodes() {
    assert_eq!(
        decode_with(&[0x0F, 0x31], 0x1000),
        Err(DecodeError::Unsupported)
    );
}
