//! L2: minimal x86-64 instruction decoder used for exit emulation.

extern crate alloc;

#[path = "../../kernel/src/s9vm/decode.rs"]
mod decode;

use decode::{decode, Decoded, DecodeError};

fn regs() -> [u64; 16] {
    let mut values = [0u64; 16];
    values[0] = 0x1111;
    values[2] = 0x3F8;
    values[3] = 0x1000;
    values[6] = 0x5000;
    values[8] = 0x4000;
    values[12] = 0x6000;
    values
}

fn decode_with(bytes: &[u8], rip: u64) -> Result<Decoded, DecodeError> {
    let values = regs();
    decode(bytes, rip, |index| values[index as usize])
}

#[test]
fn decodes_mov_register_from_base_plus_disp8() {
    let decoded = decode_with(&[0x48, 0x8B, 0x43, 0x10], 0x3000).unwrap();
    match decoded {
        Decoded::Memory(access) => {
            assert_eq!(access.address, 0x1010);
            assert_eq!(access.size, 8);
            assert!(!access.write);
            assert_eq!(access.register, 0);
            assert_eq!(access.next_rip, 0x3004);
        }
        _ => panic!("expected memory access"),
    }
}

#[test]
fn decodes_mov_rip_relative_write() {
    let decoded = decode_with(&[0x89, 0x05, 0x20, 0x00, 0x00, 0x00], 0x3000).unwrap();
    match decoded {
        Decoded::Memory(access) => {
            assert_eq!(access.address, 0x3026);
            assert_eq!(access.size, 4);
            assert!(access.write);
            assert_eq!(access.register, 0);
            assert_eq!(access.next_rip, 0x3006);
        }
        _ => panic!("expected memory access"),
    }
}

#[test]
fn decodes_rex_extension_registers() {
    // 4D 8B 08: mov r9, [r8]
    let decoded = decode_with(&[0x4D, 0x8B, 0x08], 0x100).unwrap();
    match decoded {
        Decoded::Memory(access) => {
            assert_eq!(access.register, 9);
            assert_eq!(access.address, 0x4000);
            assert_eq!(access.size, 8);
        }
        _ => panic!("expected memory access"),
    }
}

#[test]
fn decodes_sixteen_bit_operand_override() {
    // 66 8B 06: mov ax, [rsi]
    let decoded = decode_with(&[0x66, 0x8B, 0x06], 0x100).unwrap();
    match decoded {
        Decoded::Memory(access) => {
            assert_eq!(access.size, 2);
            assert_eq!(access.address, 0x5000);
        }
        _ => panic!("expected memory access"),
    }
}

#[test]
fn decodes_sib_with_base_and_disp8() {
    // 49 8B 44 24 08: mov rax, [r12 + 8]
    let decoded = decode_with(&[0x49, 0x8B, 0x44, 0x24, 0x08], 0x100).unwrap();
    match decoded {
        Decoded::Memory(access) => {
            assert_eq!(access.address, 0x6008);
            assert_eq!(access.size, 8);
        }
        _ => panic!("expected memory access"),
    }
}

#[test]
fn decodes_absolute_sib_disp32() {
    // 8B 04 25 00 20 00 00: mov eax, [0x2000]
    let decoded = decode_with(&[0x8B, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00], 0x100).unwrap();
    match decoded {
        Decoded::Memory(access) => {
            assert_eq!(access.address, 0x2000);
            assert_eq!(access.size, 4);
        }
        _ => panic!("expected memory access"),
    }
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
fn decodes_out_word_immediate_port() {
    let decoded = decode_with(&[0xE7, 0x21], 0x0).unwrap();
    match decoded {
        Decoded::Port(access) => {
            assert_eq!(access.port, 0x21);
            assert_eq!(access.size, 2);
            assert!(access.write);
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
    assert_eq!(decode_with(&[0x48, 0x8B, 0x43], 0), Err(DecodeError::Truncated));
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
