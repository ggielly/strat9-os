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

//! s9vm : machine-code payloads used by the host-side smoke tests.
//!
//! The payloads live in a pure module so they can be **decoded by the kernel's
//! own instruction decoder in a host test**, not only executed on a machine
//! that exposes hardware virtualization. A wrong payload encoding otherwise
//! only shows up as a triple fault at boot: the guest walks into zero-filled
//! memory and faults far away from the real problem, which is expensive to
//! diagnose on hardware.
//!
//! The `guestos` phase payload is deliberately **not** stored here: it is
//! assembled at run time by [`crate::s9vm::guestprog::guestos`], so every
//! instruction is a typed encoding that the host tests re-decode. The arrays
//! below remain hand-written for the phases that predate the assembler.
//!
//! # Loader payload
//!
//! [`LOADER_CODE`] is the guest program of the image-loader phase: publish the
//! marker on the debug port, then halt.
//!
//! | Bytes | Instruction |
//! |---|---|
//! | `B0 <marker>` | `mov al, marker` |
//! | `E6 E9` | `out 0xE9, al` |
//! | `F4` | `hlt` |
//!
//! The I/O instruction uses the **immediate-port** form on purpose: in 64-bit
//! mode `BA` is `MOV r32, imm32` (five bytes), not `MOV DX, imm16`; the
//! register-port form would need a `66` operand-size prefix. A first version of
//! this payload used `BA E9 00 EE F4`, which the processor decoded as
//! `mov edx, 0xF4EE00E9`: the guest then ran into the zero-filled tail of its
//! page and triple-faulted at the page boundary.

/// Byte published by the loader-phase guest on the debug port.
pub const LOADER_MARKER: u8 = b'L';
/// I/O port the loader-phase guest writes its marker to.
pub const DEBUG_PORT: u16 = 0xE9;
/// Guest program of the image-loader phase (see the module documentation).
pub const LOADER_CODE: &[u8] = &[0xB0, LOADER_MARKER, 0xE6, DEBUG_PORT as u8, 0xF4];
/// `hlt` opcode, the last instruction of every payload.
pub const HLT: u8 = 0xF4;

// ============================================================================
// ACPI-discovery payload
// ============================================================================

/// Byte published by the ACPI-discovery guest when every check passed.
///
/// The byte is followed by the number of MADT Local APIC entries the guest
/// counted, both written to [`DEBUG_PORT`].
pub const ACPI_MARKER: u8 = b'A';
/// Byte published by the ACPI-discovery guest when a check failed.
pub const ACPI_FAIL_MARKER: u8 = b'F';
/// Offset of the success tail (marker + count + `hlt`) inside [`ACPI_CODE`].
///
/// The tail is the only part of the payload that uses the instruction subset
/// understood by the kernel decoder, so the host test decodes it directly.
pub const ACPI_SUCCESS_TAIL: usize = 0x81;
/// Offset of the failure tail (failure marker + `hlt`) inside [`ACPI_CODE`].
pub const ACPI_FAIL_TAIL: usize = 0x8A;

/// Guest program of the ACPI-discovery phase.
///
/// The payload is position independent and runs in 64-bit long mode with the
/// legacy BIOS window `0x000E_0000..=0x000F_FFFF` identity-mapped by the
/// kernel. It performs, entirely guest-side:
///
/// 1. scan the window on 16-byte boundaries for the 8-byte `"RSD PTR "`
///    signature (one `cmp qword` per candidate);
/// 2. validate the ACPI 1.0 checksum of the RSDP: the sum of its first 20
///    bytes must be `0 mod 256`;
/// 3. read the XSDT pointer at RSDP offset 24 and check that XSDT entries
///    `[0]` and `[1]` start with the `FACP` (FADT) and `APIC` (MADT)
///    signatures;
/// 4. walk the MADT entries (header 44 bytes, then `type`/`length` records)
///    and count the Local APIC entries (`type == 0`);
/// 5. on success write [`ACPI_MARKER`] then the count (low byte) to the debug
///    port [`DEBUG_PORT`]; on any failure write [`ACPI_FAIL_MARKER`]; finally
///    `hlt`.
///
/// Register use: `rbx` = scan pointer, `r9` = XSDT, `r10` = MADT, `r11d` =
/// MADT length, `edx` = Local APIC count. No stack access, no absolute
/// addressing: the payload is relocatable.
pub const ACPI_CODE: &[u8] = &[
    0xBB,
    0x00,
    0x00,
    0x0E,
    0x00, // mov ebx, 0x000E0000
    0x48,
    0x81,
    0xFB,
    0x00,
    0x00,
    0x10,
    0x00, // cmp rbx, 0x00100000
    0x73,
    0x7C, // jae fail
    0x48,
    0xB8,
    0x52,
    0x53,
    0x44,
    0x20,
    0x50,
    0x54,
    0x52,
    0x20, // mov rax, "RSD PTR "
    0x48,
    0x39,
    0x03, // cmp qword [rbx], rax
    0x74,
    0x05, // je found
    0x83,
    0xC3,
    0x10, // add ebx, 16
    0xEB,
    0xE3, // jmp scan
    0xB9,
    0x14,
    0x00,
    0x00,
    0x00, // mov ecx, 20
    0x31,
    0xC0, // xor eax, eax
    0x48,
    0x89,
    0xDA, // mov rdx, rbx
    0x02,
    0x02, // add al, [rdx]
    0x48,
    0xFF,
    0xC2, // inc rdx
    0xFF,
    0xC9, // dec ecx
    0x75,
    0xF7, // jnz sum
    0x84,
    0xC0, // test al, al
    0x75,
    0x51, // jnz fail
    0x4C,
    0x8B,
    0x4B,
    0x18, // mov r9, [rbx+24]
    0x41,
    0x8B,
    0x41,
    0x24, // mov eax, [r9+36]
    0x3D,
    0x46,
    0x43,
    0x41,
    0x50, // cmp eax, "FACP"
    0x75,
    0x42, // jne fail
    0x41,
    0x8B,
    0x41,
    0x2C, // mov eax, [r9+44]
    0x3D,
    0x41,
    0x50,
    0x49,
    0x43, // cmp eax, "APIC"
    0x75,
    0x37, // jne fail
    0x4D,
    0x8B,
    0x51,
    0x2C, // mov r10, [r9+44]
    0x45,
    0x8B,
    0x5A,
    0x04, // mov r11d, [r10+4]
    0xB9,
    0x2C,
    0x00,
    0x00,
    0x00, // mov ecx, 44
    0x31,
    0xD2, // xor edx, edx
    0x44,
    0x39,
    0xD9, // cmp ecx, r11d
    0x73,
    0x1A, // jae pass
    0x41,
    0x0F,
    0xB6,
    0x04,
    0x0A, // movzx eax, byte [r10+rcx]
    0x85,
    0xC0, // test eax, eax
    0x75,
    0x02, // jnz next
    0xFF,
    0xC2, // inc edx
    0x41,
    0x0F,
    0xB6,
    0x44,
    0x0A,
    0x01, // movzx eax, byte [r10+rcx+1]
    0x83,
    0xF8,
    0x02, // cmp eax, 2
    0x72,
    0x0D, // jb fail
    0x01,
    0xC1, // add ecx, eax
    0xEB,
    0xE1, // jmp madt
    // pass: marker then Local APIC count
    0xB0,
    ACPI_MARKER, // mov al, 'A'
    0xE6,
    DEBUG_PORT as u8, // out 0xE9, al
    0x88,
    0xD0, // mov al, dl
    0xE6,
    DEBUG_PORT as u8, // out 0xE9, al
    0xF4,             // hlt
    // fail: marker only
    0xB0,
    ACPI_FAIL_MARKER, // mov al, 'F'
    0xE6,
    DEBUG_PORT as u8, // out 0xE9, al
    0xF4,             // hlt
];

/// The payload must fit in the single guest code page the phase maps.
const _: () = assert!(ACPI_CODE.len() < 4096);

// ============================================================================
// SMP (multi-vCPU) payloads
// ============================================================================

/// Guest-physical page shared by both vCPUs of the SMP phase.
///
/// Each payload stores its marker in this page before reporting it on the
/// debug port, so the kernel can prove that two independent vCPU contexts
/// produced two distinct results.
pub const SMP_SHARED_GPA: u64 = 0x0001_4000;
/// Per-vCPU markers published by the SMP payloads (`[vcpu0, vcpu1]`).
pub const SMP_MARKERS: [u8; 2] = [b'P', b'Q'];
/// Length of the `out` instruction in the SMP payloads (`out 0xE9, al`).
pub const SMP_OUT_INSTRUCTION_LEN: u64 = 2;
/// Offset of the final `hlt` inside [`SMP_CODE_0`] and [`SMP_CODE_1`].
pub const SMP_HLT_OFFSET: u64 = 13;

/// Guest program of the first vCPU of the SMP phase.
///
/// ```text
/// mov al, 'P'                 ; B0 50
/// mov [0x00014000], al        ; A2 00 40 01 00 00 00 00 00  (moffs64)
/// out 0xE9, al                ; E6 E9
/// hlt                         ; F4
/// ```
///
/// The absolute `moffs` write to the shared page is deliberate: it leaves a
/// kernel-visible trace of the marker that does not depend on the exit path,
/// so the phase can tell a missing exit from a lost register value. The
/// payload is 14 bytes and never falls through into the zero-filled tail of
/// its page.
pub const SMP_CODE_0: &[u8] = &[
    0xB0,
    SMP_MARKERS[0], // mov al, 'P'
    0xA2,           // mov moffs64, al
    0x00,
    0x40,
    0x01,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // address 0x0001_4000 (little endian)
    0xE6,
    DEBUG_PORT as u8, // out 0xE9, al
    0xF4,             // hlt
];

/// Guest program of the second vCPU of the SMP phase.
///
/// Identical to [`SMP_CODE_0`] except for the marker (`Q`) and the shared-page
/// byte it writes (`0x0001_4001`), so the two vCPUs produce distinguishable
/// results in the same page.
pub const SMP_CODE_1: &[u8] = &[
    0xB0,
    SMP_MARKERS[1], // mov al, 'Q'
    0xA2,           // mov moffs64, al
    0x01,
    0x40,
    0x01,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // address 0x0001_4001 (little endian)
    0xE6,
    DEBUG_PORT as u8, // out 0xE9, al
    0xF4,             // hlt
];

/// Both SMP payloads must fit in their single guest code page.
const _: () = assert!(SMP_CODE_0.len() < 4096);
const _: () = assert!(SMP_CODE_1.len() < 4096);
const _: () = assert!(SMP_CODE_0.len() == SMP_CODE_1.len());
const _: () = assert!(SMP_HLT_OFFSET as usize == SMP_CODE_0.len() - 1);
