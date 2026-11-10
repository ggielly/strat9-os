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
use guestcode::{
    ACPI_CODE, ACPI_FAIL_MARKER, ACPI_FAIL_TAIL, ACPI_MARKER, ACPI_SUCCESS_TAIL, DEBUG_PORT, HLT,
    LOADER_CODE, LOADER_MARKER, SMP_CODE_0, SMP_CODE_1, SMP_HLT_OFFSET, SMP_MARKERS,
    SMP_SHARED_GPA,
};

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

// ---------------------------------------------------------------------------
// ACPI-discovery payload
// ---------------------------------------------------------------------------

#[test]
fn acpi_payload_starts_with_the_scan_base() {
    // `mov ebx, 0x000E0000`: first address of the legacy BIOS scan window.
    let rip = 0x10_0000;
    let decoded = decode_at(ACPI_CODE, rip);
    match decoded {
        Decoded::Register(RegisterAccess {
            register,
            size,
            value,
            ..
        }) => {
            assert_eq!(register, 3, "destination must be EBX");
            assert_eq!(size, 4);
            assert_eq!(value, 0x000E_0000);
            assert_eq!(decoded.instruction_length(rip), 5);
        }
        other => panic!("expected the scan base load, got {other:?}"),
    }
}

#[test]
fn acpi_payload_fits_in_one_guest_page() {
    assert!(!ACPI_CODE.is_empty());
    assert!(ACPI_CODE.len() < 4096);
    assert!(ACPI_SUCCESS_TAIL < ACPI_CODE.len());
    assert!(ACPI_FAIL_TAIL < ACPI_CODE.len());
    assert!(ACPI_SUCCESS_TAIL < ACPI_FAIL_TAIL);
    assert_eq!(*ACPI_CODE.last().expect("payload is not empty"), HLT);
}

#[test]
fn acpi_success_tail_publishes_the_marker() {
    let rip = 0x10_0000 + ACPI_SUCCESS_TAIL as u64;
    let bytes = &ACPI_CODE[ACPI_SUCCESS_TAIL..];
    let decoded = decode_at(bytes, rip);
    match decoded {
        Decoded::Register(RegisterAccess {
            register,
            size,
            value,
            ..
        }) => {
            assert_eq!(register, 0, "marker is written to AL");
            assert_eq!(size, 1);
            assert_eq!(value, ACPI_MARKER as u64);
            assert_eq!(decoded.instruction_length(rip), 2);
        }
        other => panic!("expected `mov al, marker`, got {other:?}"),
    }
    assert_eq!(bytes[0], 0xB0);
    assert_eq!(bytes[1], ACPI_MARKER);
}

#[test]
fn acpi_success_tail_outputs_marker_and_count() {
    let bytes = &ACPI_CODE[ACPI_SUCCESS_TAIL..];
    let mut offset = 0usize;
    let rip = 0x10_0000 + ACPI_SUCCESS_TAIL as u64;

    // 1. `mov al, 'A'`
    let first = decode_at(bytes, rip);
    assert_eq!(first.instruction_length(rip), 2);
    offset += 2;

    // 2. `out 0xE9, al` (marker)
    let marker_out = decode_at(&bytes[offset..], rip + offset as u64);
    match marker_out {
        Decoded::Port(access) => {
            assert_eq!(access.port, DEBUG_PORT);
            assert!(access.write);
            assert_eq!(access.size, 1);
            assert_eq!(marker_out.instruction_length(rip + offset as u64), 2);
        }
        other => panic!("expected the marker `out`, got {other:?}"),
    }
    offset += 2;

    // 3. `mov al, dl` (the Local APIC count). The kernel decoder only accepts
    //    the memory forms of `mov`, so the register form is checked as raw
    //    bytes: `88 D0` = `mov al, dl`.
    assert_eq!(bytes[offset], 0x88);
    assert_eq!(bytes[offset + 1], 0xD0);
    offset += 2;

    // 4. `out 0xE9, al` (count)
    let count_out = decode_at(&bytes[offset..], rip + offset as u64);
    match count_out {
        Decoded::Port(access) => {
            assert_eq!(access.port, DEBUG_PORT);
            assert!(access.write);
            assert_eq!(access.size, 1);
            assert_eq!(count_out.instruction_length(rip + offset as u64), 2);
        }
        other => panic!("expected the count `out`, got {other:?}"),
    }
    offset += 2;

    // 5. `hlt`
    assert_eq!(bytes[offset], HLT);
    assert_eq!(offset + 1, ACPI_FAIL_TAIL - ACPI_SUCCESS_TAIL);
}

#[test]
fn acpi_failure_tail_publishes_the_failure_marker() {
    let bytes = &ACPI_CODE[ACPI_FAIL_TAIL..];
    let rip = 0x10_0000 + ACPI_FAIL_TAIL as u64;
    let decoded = decode_at(bytes, rip);
    match decoded {
        Decoded::Register(RegisterAccess {
            register, value, ..
        }) => {
            assert_eq!(register, 0);
            assert_eq!(value, ACPI_FAIL_MARKER as u64);
            assert_eq!(decoded.instruction_length(rip), 2);
        }
        other => panic!("expected `mov al, 'F'`, got {other:?}"),
    }
    assert_eq!(bytes[1], ACPI_FAIL_MARKER);

    let out = decode_at(&bytes[2..], rip + 2);
    match out {
        Decoded::Port(access) => {
            assert_eq!(access.port, DEBUG_PORT);
            assert!(access.write);
        }
        other => panic!("expected the failure `out`, got {other:?}"),
    }
    assert_eq!(bytes[4], HLT);
    assert_eq!(bytes.len(), 5);
}

// ---------------------------------------------------------------------------
// SMP (two-vCPU) payloads
// ---------------------------------------------------------------------------

#[test]
fn smp_payloads_are_fixed_length_and_distinct() {
    assert_eq!(SMP_CODE_0.len(), 14);
    assert_eq!(SMP_CODE_0.len(), SMP_CODE_1.len());
    assert_ne!(SMP_CODE_0, SMP_CODE_1);
    assert_ne!(SMP_MARKERS[0], SMP_MARKERS[1]);
    assert_eq!(*SMP_CODE_0.last().expect("payload is not empty"), HLT);
    assert_eq!(*SMP_CODE_1.last().expect("payload is not empty"), HLT);
    assert_eq!(SMP_HLT_OFFSET as usize, SMP_CODE_0.len() - 1);
    // The two payloads differ in their marker byte and in the shared-page
    // address, so a wrong per-vCPU constant cannot silently alias.
    assert_eq!(SMP_CODE_0[1], SMP_MARKERS[0]);
    assert_eq!(SMP_CODE_1[1], SMP_MARKERS[1]);
    assert_eq!(&SMP_CODE_0[3..11], &(SMP_SHARED_GPA).to_le_bytes());
    assert_eq!(&SMP_CODE_1[3..11], &(SMP_SHARED_GPA + 1).to_le_bytes());
}

fn decode_smp_payload(code: &[u8], marker: u8, shared_gpa: u64) {
    let base = 0x10_0000;

    // 1. `mov al, marker`
    let first = decode_at(code, base);
    match first {
        Decoded::Register(RegisterAccess {
            register,
            size,
            value,
            ..
        }) => {
            assert_eq!(register, 0);
            assert_eq!(size, 1);
            assert_eq!(value, u64::from(marker));
            assert_eq!(first.instruction_length(base), 2);
        }
        other => panic!("expected `mov al, marker`, got {other:?}"),
    }

    // 2. `mov [shared], al` (A2 = moffs64): decoded as a one-byte store to the
    //    shared guest page.
    let second = decode_at(&code[2..], base + 2);
    match second {
        Decoded::Memory(access) => {
            assert_eq!(access.address, shared_gpa);
            assert_eq!(access.size, 1);
            assert!(access.write);
            assert_eq!(access.register, 0);
            assert_eq!(second.instruction_length(base + 2), 9);
        }
        other => panic!("expected the shared-page store, got {other:?}"),
    }
    assert_eq!(code[2], 0xA2);

    // 3. `out 0xE9, al`
    let out = decode_at(&code[11..], base + 11);
    match out {
        Decoded::Port(access) => {
            assert_eq!(access.port, DEBUG_PORT);
            assert!(access.write);
            assert_eq!(access.size, 1);
            assert_eq!(out.instruction_length(base + 11), 2);
        }
        other => panic!("expected the marker `out`, got {other:?}"),
    }

    // 4. `hlt`
    assert_eq!(code[13], HLT);
}

#[test]
fn smp_payload_zero_is_decodable() {
    decode_smp_payload(SMP_CODE_0, SMP_MARKERS[0], SMP_SHARED_GPA);
}

#[test]
fn smp_payload_one_is_decodable() {
    decode_smp_payload(SMP_CODE_1, SMP_MARKERS[1], SMP_SHARED_GPA + 1);
}
