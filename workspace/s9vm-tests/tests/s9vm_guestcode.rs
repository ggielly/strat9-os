//! Host tests for the s9vm guest payloads used by the smoke tests.
//!
//! The payloads are decoded by the **kernel's own decoder**, so a wrong
//! encoding is caught on the build machine instead of showing up as a triple
//! fault at boot (the guest would run into zero-filled memory and fault at the
//! page boundary, far from the real problem).

extern crate alloc;

#[path = "../../kernel/src/s9vm/decode.rs"]
mod decode;
#[path = "../../kernel/src/s9vm/guestcode.rs"]
mod guestcode;

use decode::{Decoded, RegisterAccess};
use guestcode::{DEBUG_PORT, HLT, LOADER_CODE, LOADER_MARKER};

fn decode_at(bytes: &[u8], rip: u64) -> Decoded {
    decode::decode(bytes, rip, |_index| 0).expect("payload instruction must decode")
}

#[test]
fn loader_payload_first_instruction_is_mov_al_marker() {
    let decoded = decode_at(LOADER_CODE, 0x10100);
    match decoded {
        Decoded::Register(RegisterAccess { .. }) => {
            assert_eq!(decoded.instruction_length(0x10100), 2);
            assert_eq!(LOADER_CODE[0], 0xB0);
            assert_eq!(LOADER_CODE[1], LOADER_MARKER);
        }
        other => panic!("expected a register move, got {other:?}"),
    }
}

#[test]
fn loader_payload_second_instruction_is_out_debug_port() {
    let rip = 0x10102;
    let decoded = decode_at(&LOADER_CODE[2..], rip);
    match decoded {
        Decoded::Port(access) => {
            assert_eq!(access.port, DEBUG_PORT);
            assert_eq!(decoded.instruction_length(rip), 2);
        }
        other => panic!("expected a port access, got {other:?}"),
    }
}

#[test]
fn loader_payload_ends_with_halt() {
    assert_eq!(*LOADER_CODE.last().expect("payload is not empty"), HLT);
    // Exactly two instructions then `hlt`: the guest must not fall through
    // into the zero-filled tail of its page.
    assert_eq!(LOADER_CODE.len(), 5);
}

#[test]
fn loader_payload_is_position_independent() {
    // Every instruction is a fixed-length, absolute-free encoding: decoding at
    // a different RIP yields the same lengths, which is what the relocated
    // entry point relies on.
    let base = 0x10_0000;
    let first = decode_at(LOADER_CODE, base);
    assert_eq!(first.instruction_length(base), 2);
    let second = decode_at(&LOADER_CODE[2..], base + 2);
    assert_eq!(second.instruction_length(base + 2), 2);
}
