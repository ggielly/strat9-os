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

//! s9vm : real-mode BIOS ROM stubs, low-memory layout and demo boot image.
//!
//! A DOS-class guest needs the classic 16-bit firmware surface: an interrupt
//! vector table, a BIOS data area, ROM interrupt stubs and a bootable disk
//! image. This module produces all of it as pure data:
//!
//! - [`stub_bytes`] hand-encodes one 16-bit real-mode interrupt stub: it saves
//!   the caller registers, reports the interrupt number on the debug port, and
//!   patches the caller's stacked `FLAGS` (`CF`/`ZF`) from a scratch byte;
//! - [`install`] writes the stubs, the IVT entries and the BDA/EBDA fields into
//!   a guest low-memory image through the [`RomMemory`] trait;
//! - [`demo_disk_image`] builds a deterministic 1.44 MiB floppy image whose
//!   boot sector prints a banner, loads the second stage through `INT 13h` and
//!   jumps to it; the second stage prints its own banner, reads a key through
//!   `INT 16h` (bounded retry), and reports success with the byte `0x4B` on
//!   debug port `0x00E9`.
//!
//! # Low-memory layout
//!
//! | Range | Content |
//! |---|---|
//! | `0x0000..0x0400` | interrupt vector table (256 far pointers) |
//! | `0x0400..0x0500` | BIOS data area |
//! | `0x0500` | scratch byte used by the BIOS stubs ([`SCRATCH_GPA`]) |
//! | `0x7C00..0x7E00` | boot sector ([`BOOT_SECTOR_GPA`]) |
//! | `0x7E00..0x8000` | demo second stage |
//! | `0xB8000..0xBFFFF` | text mode video memory ([`VIDEO_BASE`]) |
//! | `0xF0000..0xF8000` | BIOS ROM image (`F000:0000`, [`ROM_BASE`]) |
//!
//! The ROM image is 32 KiB at segment `F000`. The per-vector stubs live at
//! `F000:0100 + vector * 0x08` (six bytes each; all 256 stubs end at
//! `F000:0900`) and the shared tail every stub jumps to is at `F000:0900`,
//! followed by the rest of the free ROM area.
//!
//! # Per-vector stub disassembly (vector `0x10`, port `0xE010`)
//!
//! Each per-vector stub only sets `DX` to the debug port and jumps to the
//! shared tail; the `OUT` and the flag patch happen there, once.
//!
//! ```text
//! offset  bytes        instruction            meaning
//! 0x00    BA 10 E0     mov dx, 0xE010         port = 0xE000 + vector
//! 0x03    E9 xx xx     jmp 0x0900             shared tail (relative)
//! ```
//!
//! # Shared tail disassembly (`F000:0900`, 44 bytes)
//!
//! Entry state (the `INT` instruction already pushed the interrupt frame):
//! `[SP] = IP`, `[SP+2] = CS`, `[SP+4] = FLAGS`; `DX` holds the port chosen by
//! the per-vector stub. The tail echoes `AL` (the incoming argument, which
//! identifies the caller request on the reported port), then patches only the
//! stacked `FLAGS` word and returns with every register preserved. This is
//! essential: the kernel writes BIOS return values into the guest register file
//! at the `OUT` exit (AX for `INT 16h`, AH for `INT 13h`, CX/DX for `INT 10h`
//! AH=03, ...) and those values must reach the caller through the `IRET`.
//!
//! ```text
//! offset  bytes              instruction                     meaning
//! 0x00    EE                 out dx, al                      report vector, AL intact
//! 0x01    1E                 push ds                         save the caller DS
//! 0x02    6A 00              push 0                          DS = 0
//! 0x04    1F                 pop ds
//! 0x05    50                 push ax                         save the returned AX
//! 0x06    55                 push bp
//! 0x07    89 E5              mov bp, sp                      frame; FLAGS at [bp+0x0A]
//! 0x09    A0 00 05           mov al, [0x0500]                scratch byte
//! 0x0C    A8 01              test al, 1                      CF from bit 0
//! 0x0E    74 06              jz 0x16
//! 0x10    83 4E 0A 01        or word [bp+0x0A], 0x0001
//! 0x14    EB 04              jmp 0x1A
//! 0x16    83 66 0A FE        and word [bp+0x0A], 0xFFFE
//! 0x1A    A8 02              test al, 2                      ZF from bit 1
//! 0x1C    74 06              jz 0x24
//! 0x1E    83 4E 0A 40        or word [bp+0x0A], 0x0040
//! 0x22    EB 04              jmp 0x28
//! 0x24    83 66 0A BF        and word [bp+0x0A], 0xFFBF
//! 0x28    5D                 pop bp
//! 0x29    58                 pop ax                          restore the returned AX
//! 0x2A    1F                 pop ds                          restore the caller DS
//! 0x2B    CF                 iret
//! ```
//!
//! Scratch byte semantics: bit 0 = carry flag, bit 1 = zero flag; every other
//! bit is ignored. Only 8- and 16-bit instructions are used, so the upper halves
//! of the 32-bit registers are never touched. `SP`, `SS` and `ES` are not
//! modified at all; `AX`, `BP` and `DS` are saved and restored.
//!
//! # Demo boot sector disassembly (`0x7C00`, 0x65 code bytes)
//!
//! ```text
//! 0x00  EB 1C              jmp short main
//! 0x02  90                 nop
//! 0x03  53 39 56 4D 20 ... 'S9VM DOS-BOOT', 13, 10, 0
//! 0x13  44 49 53 4B 20 ... 'DISK ERR', 13, 10, 0
//! 0x1E  FA                 cli
//! 0x1F  31 C0              xor ax, ax
//! 0x21  8E D0              mov ss, ax
//! 0x23  BC 00 7C           mov sp, 0x7C00
//! 0x26  8E D8              mov ds, ax
//! 0x28  8E C0              mov es, ax
//! 0x2A  FB                 sti
//! 0x2B  BE 03 7C           mov si, 0x7C03            banner
//! 0x2E  E8 28 00           call print
//! 0x31  B4 02              mov ah, 0x02              INT 13h: read one sector
//! 0x33  B0 01              mov al, 0x01
//! 0x35  B5 00              mov ch, 0x00              cylinder 0
//! 0x37  B1 02              mov cl, 0x02              sector 2 (1-based)
//! 0x39  B6 00              mov dh, 0x00              head 0
//! 0x3B  B2 00              mov dl, 0x00              drive 0
//! 0x3D  BB 00 7E           mov bx, 0x7E00            ES:BX destination
//! 0x40  CD 13              int 0x13
//! 0x42  72 05              jc disk_error
//! 0x44  EA 00 7E 00 00     jmp far 0x0000:0x7E00    run the second stage
//! 0x49  BE 13 7C           mov si, 0x7C13            error message
//! 0x4C  E8 0A 00           call print
//! 0x4F  B0 46              mov al, 0x46              failure marker 'F'
//! 0x51  BA E9 00           mov dx, 0x00E9
//! 0x54  EE                 out dx, al
//! 0x55  FA                 cli
//! 0x56  F4                 hlt
//! 0x57  EB FC              jmp 0x55                  halt forever
//! 0x59  B4 0E              print: mov ah, 0x0E       INT 10h teletype
//! 0x5B  AC                 lodsb
//! 0x5C  84 C0              test al, al
//! 0x5E  74 04              jz done
//! 0x60  CD 10              int 0x10
//! 0x62  EB F7              jmp next
//! 0x64  C3                 ret
//! ```
//!
//! # Demo second stage disassembly (`0x7E00`, 0x48 code bytes)
//!
//! ```text
//! 0x00  FA                 cli
//! 0x01  31 C0              xor ax, ax
//! 0x03  8E D8              mov ds, ax
//! 0x05  8E C0              mov es, ax
//! 0x07  8E D0              mov ss, ax
//! 0x09  BC 00 7C           mov sp, 0x7C00
//! 0x0C  FB                 sti
//! 0x0D  BE 3C 7E           mov si, 0x7E3C            'STAGE2 OK' banner
//! 0x10  E8 1D 00           call print
//! 0x13  B9 10 00           mov cx, 0x0010            bounded retry count
//! 0x16  B4 00              retry: mov ah, 0x00       INT 16h: read a key
//! 0x18  CD 16              int 0x16
//! 0x1A  75 06              jnz key                   ZF=0: a key is available
//! 0x1C  E2 F8              loop retry
//! 0x1E  B0 3F              mov al, '?'               give up: print '?'
//! 0x20  EB 00              jmp show
//! 0x22  B4 0E              show: mov ah, 0x0E        print the character
//! 0x24  CD 10              int 0x10
//! 0x26  B0 4B              mov al, 0x4B              success marker 'K'
//! 0x28  BA E9 00           mov dx, 0x00E9
//! 0x2B  EE                 out dx, al
//! 0x2C  FA                 cli
//! 0x2D  F4                 hlt
//! 0x2E  EB FD              jmp 0x2D                  halt forever
//! 0x30  B4 0E              print: mov ah, 0x0E
//! 0x32  AC                 lodsb
//! 0x33  84 C0              test al, al
//! 0x35  74 04              jz done
//! 0x37  CD 10              int 0x10
//! 0x39  EB F7              jmp next
//! 0x3B  C3                 ret
//! 0x3C  53 54 41 47 ...    'STAGE2 OK', 13, 10, 0
//! ```
//!
//! The demo is deliberately hand-assembled data: there is no assembler in the
//! build, and the exact bytes are part of the contract the selftest checks.
//! The shared tail patches only `CF`/`ZF` and preserves the register file, so
//! when the kernel answers `INT 16h` by writing the key into `AX` at the `OUT`
//! exit, the demo's `INT 16h` returns that key and prints it; `'?'` is printed
//! only when the bounded retry loop gives up.

use alloc::{vec, vec::Vec};

/// Base of the interrupt vector table.
pub const IVT_BASE: u32 = 0x0000;
/// Base of the BIOS data area.
pub const BDA_BASE: u32 = 0x0400;
/// Scratch byte read by the interrupt stubs (`CF` = bit 0, `ZF` = bit 1).
pub const SCRATCH_GPA: u32 = 0x0500;
/// Guest-physical address where a boot sector is loaded.
pub const BOOT_SECTOR_GPA: u32 = 0x7C00;
/// Initial real-mode stack pointer (`SS:SP = 0x0000:0x7C00`).
pub const BOOT_STACK_TOP: u16 = 0x7C00;
/// Guest-physical base of the text-mode video memory.
pub const VIDEO_BASE: u32 = 0xB8000;
/// Real-mode segment of the BIOS ROM.
pub const ROM_SEGMENT: u16 = 0xF000;
/// Guest-physical base of the BIOS ROM.
pub const ROM_BASE: u32 = 0xF0000;
/// Size of the BIOS ROM image.
pub const ROM_LEN: u32 = 0x8000;
/// Offset inside the ROM segment of the first interrupt stub.
pub const ROM_STUB_BASE: u16 = 0x0100;
/// First I/O port used to report an interrupt: `port = base + vector`.
pub const BIOS_PORT_BASE: u16 = 0xE000;
/// Spacing between two per-vector stubs in the ROM.
pub const STUB_STRIDE: u16 = 0x10;
/// Length of one per-vector stub: `mov dx, port` (3) + `jmp tail` (3).
pub const MAX_STUB_LEN: u16 = 11;
/// ROM offset of the shared stub tail (after the 256 per-vector stubs).
pub const ROM_SHARED_TAIL: u16 = 0x1100;
/// Upper bound on the shared tail length, so the tail stays inside the ROM.
pub const MAX_SHARED_TAIL_LEN: u16 = 0x80;
/// Offset inside the stacked interrupt frame where the shared tail patches the
/// caller `FLAGS` word, relative to the tail's `BP` frame: `[BP + 0x0A]`.
pub const TAIL_FLAGS_OFFSET: u16 = 0x0A;

/// Vectors a stub is installed for.
///
/// The set is the classic BIOS/DOS surface: print screen (`0x05`), the timer
/// and IRQ vectors (`0x08..=0x0F`, including the printer line), the main BIOS
/// services (`0x10` video, `0x11` equipment, `0x12` memory size, `0x13` disk,
/// `0x14` serial, `0x15` system, `0x16` keyboard, `0x17` printer), the time
/// service (`0x1A`), the user timer-tick hook (`0x1C`) and the RTC alarm
/// (`0x4A`).
pub const VECTORS: [u8; 22] = [
    0x05, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x1A, 0x1C, 0x4A,
];

/// Debug port used by the demo boot image to report its progress.
pub const DEMO_DEBUG_PORT: u16 = 0x00E9;
/// Marker written on the debug port when the demo succeeds (`'K'`).
pub const DEMO_SUCCESS_MARKER: u8 = 0x4B;
/// Marker written on the debug port when the demo cannot load its stage 2.
pub const DEMO_FAILURE_MARKER: u8 = 0x46;
/// Demo boot-sector banner (without CR/LF).
pub const DEMO_BANNER: &[u8] = b"S9VM DOS-BOOT";
/// Demo stage-2 banner (without CR/LF).
pub const DEMO_STAGE2_BANNER: &[u8] = b"STAGE2 OK";
/// Demo disk-error message (without CR/LF).
pub const DEMO_ERROR: &[u8] = b"DISK ERR";

/// Floppy geometry: 80 cylinders.
pub const FLOPPY_CYLINDERS: u16 = 80;
/// Floppy geometry: 2 heads.
pub const FLOPPY_HEADS: u8 = 2;
/// Floppy geometry: 18 sectors per track.
pub const FLOPPY_SECTORS: u8 = 18;
/// Size of one disk sector.
pub const SECTOR_SIZE: usize = 512;
/// Total size of a 1.44 MiB floppy image.
pub const FLOPPY_BYTES: usize = 1_474_560;
/// Total number of sectors of the floppy image.
pub const FLOPPY_TOTAL_SECTORS: u64 = 2_880;

/// BDA field: installed equipment word.
pub const BDA_EQUIPMENT: u32 = 0x0410;
/// BDA field: conventional memory size in KiB (low 16 bits).
pub const BDA_MEMORY_SIZE: u32 = 0x0413;
/// BDA field: extended BIOS data area segment.
pub const BDA_EBDA_SEGMENT: u32 = 0x040E;
/// BDA field: current video mode.
pub const BDA_VIDEO_MODE: u32 = 0x0449;
/// BDA field: number of text columns.
pub const BDA_COLUMNS: u32 = 0x044A;
/// BDA field: cursor position of page 0 (row/column).
pub const BDA_CURSOR: u32 = 0x0450;
/// BDA field: CRTC I/O port base.
pub const BDA_CRTC_PORT: u32 = 0x0463;
/// BDA field: number of text rows minus one.
pub const BDA_ROWS: u32 = 0x0484;
/// BDA field: character height in scan lines.
pub const BDA_CHAR_HEIGHT: u32 = 0x0485;
/// BDA field: timer tick counter (32 bits).
pub const BDA_TICK_COUNT: u32 = 0x046C;

/// Equipment word value: one floppy drive, 80x25 colour, no coprocessor.
pub const EQUIPMENT_VALUE: u16 = 0x0021;
/// Conventional memory size value, in KiB.
pub const MEMORY_SIZE_VALUE: u16 = 640;
/// Extended BIOS data area segment value.
pub const EBDA_SEGMENT_VALUE: u16 = 0x9FC0;
/// Video mode value: 80x25 colour text.
pub const VIDEO_MODE_VALUE: u8 = 3;
/// Text column count value.
pub const COLUMNS_VALUE: u16 = 80;
/// Cursor position value (row 0, column 0).
pub const CURSOR_VALUE: u16 = 0;
/// CRTC I/O port base value.
pub const CRTC_PORT_VALUE: u16 = 0x03D4;
/// Text row count value (rows minus one).
pub const ROWS_VALUE: u8 = 24;
/// Character height value, in scan lines.
pub const CHAR_HEIGHT_VALUE: u8 = 16;
/// Initial timer tick value.
pub const TICK_COUNT_VALUE: u32 = 0;

/// Reasons why a ROM install operation is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RomError {
    /// A region is too small to hold the BIOS data it must receive.
    TooSmall,
    /// A requested vector is outside the supported set ([`VECTORS`]).
    UnsupportedVector(u8),
    /// The target memory refused a write (out of its mapped range).
    WriteFailed,
}

/// Minimal guest low-memory access used by the install helpers.
///
/// The real guest memory implementation lives in the kernel loader; tests use
/// a flat `Vec<u8>`. Addresses are guest-physical (linear) addresses.
pub trait RomMemory {
    /// Writes `bytes` at `linear`. Returns `false` when the range is not
    /// writable or not mapped.
    fn write(&mut self, linear: u32, bytes: &[u8]) -> bool;

    /// Reads `out.len()` bytes from `linear`. Returns `false` when the range is
    /// not readable or not mapped.
    fn read(&mut self, linear: u32, out: &mut [u8]) -> bool;

    /// Writes a little-endian `u16` at `linear`.
    fn write_u16(&mut self, linear: u32, value: u16) -> bool {
        self.write(linear, &value.to_le_bytes())
    }

    /// Writes a little-endian `u32` at `linear`.
    fn write_u32(&mut self, linear: u32, value: u32) -> bool {
        self.write(linear, &value.to_le_bytes())
    }
}

/// I/O port that reports `vector` to the host.
pub const fn bios_port(vector: u8) -> u16 {
    BIOS_PORT_BASE + vector as u16
}

/// ROM offset of the stub for `vector`.
pub const fn stub_offset(vector: u8) -> u16 {
    ROM_STUB_BASE + vector as u16 * STUB_STRIDE
}

/// Guest-physical address of the stub for `vector`.
pub const fn stub_gpa(vector: u8) -> u32 {
    ROM_BASE + stub_offset(vector) as u32
}

/// Guest-physical address of the shared stub tail.
pub const fn shared_tail_gpa() -> u32 {
    ROM_BASE + ROM_SHARED_TAIL as u32
}

/// Returns true when `vector` belongs to [`VECTORS`].
pub fn is_supported_vector(vector: u8) -> bool {
    VECTORS.contains(&vector)
}

/// Encodes the per-vector real-mode stub for `vector`.
///
/// The stub must not destroy the registers the BIOS service uses: it pushes the
/// caller `AX` and `DX` (the kernel reads them back from the guest stack at the
/// `OUT` exit), loads the debug port into `DX`, moves the command byte (`AH`)
/// into `AL` for the `OUT`, then jumps to the shared tail
/// ([`shared_tail_bytes`]) which drops the saved registers, restores the
/// kernel-written results and patches the caller's stacked `FLAGS`.
///
/// The encoding is at most [`MAX_STUB_LEN`] bytes.
pub fn stub_bytes(vector: u8) -> Vec<u8> {
    let port = bios_port(vector);
    let port_lo = (port & 0xFF) as u8;
    let port_hi = (port >> 8) as u8;
    // Address of the instruction after the jump, inside the ROM.
    let next = u32::from(stub_offset(vector)) + u32::from(MAX_STUB_LEN);
    // The tail always follows the 256 per-vector stubs, so the displacement is
    // positive and fits in the signed 16-bit jump offset.
    let displacement = (u32::from(ROM_SHARED_TAIL) as i32 - next as i32) as i16;
    let rel = displacement.to_le_bytes();
    vec![
        0x50, // push ax (the BIOS command is in AH)
        0x52, // push dx (drive/head for INT 13h, page for INT 10h)
        0x88, 0xE0, // mov al, ah (send the command as the OUT byte)
        0xBA, port_lo, port_hi, // mov dx, port
        0xEE, // out dx, al
        0xE9, rel[0], rel[1], // jmp shared_tail
    ]
}

/// Encodes the shared stub tail installed at [`ROM_SHARED_TAIL`].
///
/// The `OUT` already happened in the stub; on entry the caller `DX` and `AX`
/// are saved on the guest stack and the kernel has overwritten the guest `AX`
/// (and possibly `DX`) with the BIOS result. The tail drops the saved values,
/// patches only the caller's stacked `FLAGS` from the scratch byte at
/// [`SCRATCH_GPA`] (bit 0 -> `CF`, bit 1 -> `ZF`) and returns with `iret`, so
/// the BIOS return values written by the kernel reach the guest.
pub fn shared_tail_bytes() -> Vec<u8> {
    let flags = TAIL_FLAGS_OFFSET as u8;
    vec![
        0x83, 0xC4, 0x04, // add sp, 4 (drop the saved DX and AX)
        0x50, // push ax (kernel result)
        0x55, // push bp
        0x1E, // push ds
        0x6A, 0x00, // push 0
        0x1F, // pop ds
        0x89, 0xE5, // mov bp, sp
        0xA0, 0x00, 0x05, // mov al, [0x0500]
        0xA8, 0x01, // test al, 1
        0x74, 0x06, // jz clear_cf
        0x83, 0x4E, flags, 0x01, // or word [bp+flags], 0x0001
        0xEB, 0x04, // jmp zf
        0x83, 0x66, flags, 0xFE, // and word [bp+flags], 0xFFFE
        0xA8, 0x02, // test al, 2
        0x74, 0x06, // jz clear_zf
        0x83, 0x4E, flags, 0x40, // or word [bp+flags], 0x0040
        0xEB, 0x04, // jmp done
        0x83, 0x66, flags, 0xBF, // and word [bp+flags], 0xFFBF
        0x5D, // pop bp
        0x58, // pop ax
        0x1F, // pop ds
        0xCF, // iret
    ]
}

/// Writes one IVT entry per supported vector.
///
/// The entry is a real-mode far pointer `offset:segment` where `offset` is
/// [`stub_offset`] and `segment` is [`ROM_SEGMENT`].
pub fn write_ivt(mem: &mut impl RomMemory, vectors: &[u8]) -> Result<(), RomError> {
    for &vector in vectors {
        if !is_supported_vector(vector) {
            return Err(RomError::UnsupportedVector(vector));
        }
        let entry = IVT_BASE + u32::from(vector) * 4;
        let offset = stub_offset(vector);
        if !mem.write_u16(entry, offset) || !mem.write_u16(entry + 2, ROM_SEGMENT) {
            return Err(RomError::WriteFailed);
        }
    }
    Ok(())
}

/// Writes the BIOS data area fields a DOS boot needs.
pub fn write_bda(mem: &mut impl RomMemory) -> Result<(), RomError> {
    let writes: [(u32, u16); 6] = [
        (BDA_EQUIPMENT, EQUIPMENT_VALUE),
        (BDA_MEMORY_SIZE, MEMORY_SIZE_VALUE),
        (BDA_EBDA_SEGMENT, EBDA_SEGMENT_VALUE),
        (BDA_COLUMNS, COLUMNS_VALUE),
        (BDA_CURSOR, CURSOR_VALUE),
        (BDA_CRTC_PORT, CRTC_PORT_VALUE),
    ];
    for (address, value) in writes {
        if !mem.write_u16(address, value) {
            return Err(RomError::WriteFailed);
        }
    }
    if !mem.write(BDA_VIDEO_MODE, &[VIDEO_MODE_VALUE])
        || !mem.write(BDA_ROWS, &[ROWS_VALUE])
        || !mem.write(BDA_CHAR_HEIGHT, &[CHAR_HEIGHT_VALUE])
        || !mem.write_u32(BDA_TICK_COUNT, TICK_COUNT_VALUE)
    {
        return Err(RomError::WriteFailed);
    }
    Ok(())
}

/// Installs the per-vector stubs, the shared tail, the IVT entries and the BDA
/// fields.
///
/// The stubs are written at [`stub_gpa`], the shared tail at
/// [`shared_tail_gpa`], the IVT entries point at the per-vector stubs and the
/// BDA/EBDA fields are initialised for a 640 KiB machine. The scratch byte is
/// left untouched: the host sets it before each interrupt.
pub fn install(mem: &mut impl RomMemory, vectors: &[u8]) -> Result<(), RomError> {
    for &vector in vectors {
        if !is_supported_vector(vector) {
            return Err(RomError::UnsupportedVector(vector));
        }
        let stub = stub_bytes(vector);
        if !mem.write(stub_gpa(vector), &stub) {
            return Err(RomError::WriteFailed);
        }
    }
    let tail = shared_tail_bytes();
    if !mem.write(shared_tail_gpa(), &tail) {
        return Err(RomError::WriteFailed);
    }
    write_ivt(mem, vectors)?;
    write_bda(mem)
}

/// Builds a complete ROM image (zero-filled [`ROM_LEN`] bytes) with the stubs
/// and the shared tail installed at their ROM offsets.
///
/// Useful for a loader that copies one contiguous ROM blob instead of writing
/// the pieces individually.
pub fn rom_image(vectors: &[u8]) -> Result<Vec<u8>, RomError> {
    let stub_area_end = u32::from(ROM_STUB_BASE) + 256 * u32::from(STUB_STRIDE);
    let tail_end = u32::from(ROM_SHARED_TAIL) + u32::from(MAX_SHARED_TAIL_LEN);
    if stub_area_end > u32::from(ROM_SHARED_TAIL) || tail_end > ROM_LEN {
        return Err(RomError::TooSmall);
    }
    let mut rom = vec![0u8; ROM_LEN as usize];
    for &vector in vectors {
        if !is_supported_vector(vector) {
            return Err(RomError::UnsupportedVector(vector));
        }
        let stub = stub_bytes(vector);
        let offset = stub_offset(vector) as usize;
        rom[offset..offset + stub.len()].copy_from_slice(&stub);
    }
    let tail = shared_tail_bytes();
    let tail_offset = ROM_SHARED_TAIL as usize;
    rom[tail_offset..tail_offset + tail.len()].copy_from_slice(&tail);
    Ok(rom)
}

/// Converts a floppy CHS address (sector is 1-based) to a linear block address.
///
/// Returns `None` when the cylinder, head or sector is outside the 1.44 MiB
/// geometry ([`FLOPPY_CYLINDERS`] x [`FLOPPY_HEADS`] x [`FLOPPY_SECTORS`]).
pub const fn chs_to_lba(cyl: u16, head: u8, sector: u8) -> Option<u64> {
    if cyl >= FLOPPY_CYLINDERS || head >= FLOPPY_HEADS || sector == 0 || sector > FLOPPY_SECTORS {
        return None;
    }
    Some(
        (cyl as u64 * FLOPPY_HEADS as u64 + head as u64) * FLOPPY_SECTORS as u64
            + (sector as u64 - 1),
    )
}

/// Converts a linear block address back to a floppy CHS address (1-based
/// sector). Returns `None` for an LBA outside the image.
pub const fn lba_to_chs(lba: u64) -> Option<(u16, u8, u8)> {
    if lba >= FLOPPY_TOTAL_SECTORS {
        return None;
    }
    let per_cylinder = FLOPPY_HEADS as u64 * FLOPPY_SECTORS as u64;
    let cyl = lba / per_cylinder;
    let remainder = lba % per_cylinder;
    let head = remainder / FLOPPY_SECTORS as u64;
    let sector = remainder % FLOPPY_SECTORS as u64 + 1;
    Some((cyl as u16, head as u8, sector as u8))
}

/// Demo boot-sector code and strings (before the trailing signature).
///
/// Hand-assembled 16-bit real mode; see the module documentation for the
/// instruction-by-instruction disassembly.
const DEMO_BOOT_CODE: &[u8] = &[
    0xEB, 0x1C, 0x90, 0x53, 0x39, 0x56, 0x4D, 0x20, 0x44, 0x4F, 0x53, 0x2D, 0x42, 0x4F, 0x4F, 0x54,
    0x0D, 0x0A, 0x00, 0x44, 0x49, 0x53, 0x4B, 0x20, 0x45, 0x52, 0x52, 0x0D, 0x0A, 0x00, 0xFA, 0x31,
    0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C, 0x8E, 0xD8, 0x8E, 0xC0, 0xFB, 0xBE, 0x03, 0x7C, 0xE8, 0x28,
    0x00, 0xB4, 0x02, 0xB0, 0x01, 0xB5, 0x00, 0xB1, 0x02, 0xB6, 0x00, 0xB2, 0x00, 0xBB, 0x00, 0x7E,
    0xCD, 0x13, 0x72, 0x05, 0xEA, 0x00, 0x7E, 0x00, 0x00, 0xBE, 0x13, 0x7C, 0xE8, 0x0A, 0x00, 0xB0,
    0x46, 0xBA, 0xE9, 0x00, 0xEE, 0xFA, 0xF4, 0xEB, 0xFC, 0xB4, 0x0E, 0xAC, 0x84, 0xC0, 0x74, 0x04,
    0xCD, 0x10, 0xEB, 0xF7, 0xC3,
];

/// Demo second-stage code and strings (before the trailing signature).
///
/// Hand-assembled 16-bit real mode; see the module documentation for the
/// instruction-by-instruction disassembly.
const DEMO_STAGE2_CODE: &[u8] = &[
    0xFA, 0x31, 0xC0, 0x8E, 0xD8, 0x8E, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C, 0xFB, 0xBE, 0x3C, 0x7E,
    0xE8, 0x1D, 0x00, 0xB9, 0x10, 0x00, 0xB4, 0x00, 0xCD, 0x16, 0x75, 0x06, 0xE2, 0xF8, 0xB0, 0x3F,
    0xEB, 0x00, 0xB4, 0x0E, 0xCD, 0x10, 0xB0, 0x4B, 0xBA, 0xE9, 0x00, 0xEE, 0xFA, 0xF4, 0xEB, 0xFD,
    0xB4, 0x0E, 0xAC, 0x84, 0xC0, 0x74, 0x04, 0xCD, 0x10, 0xEB, 0xF7, 0xC3, 0x53, 0x54, 0x41, 0x47,
    0x45, 0x32, 0x20, 0x4F, 0x4B, 0x0D, 0x0A, 0x00,
];

/// Builds the demo boot sector: code, zero padding and the `0x55AA` signature.
pub fn demo_boot_sector() -> [u8; SECTOR_SIZE] {
    let mut sector = [0u8; SECTOR_SIZE];
    sector[..DEMO_BOOT_CODE.len()].copy_from_slice(DEMO_BOOT_CODE);
    sector[510] = 0x55;
    sector[511] = 0xAA;
    sector
}

/// Builds the demo second stage: code, zero padding and the `0x55AA` signature.
pub fn demo_stage2() -> [u8; SECTOR_SIZE] {
    let mut sector = [0u8; SECTOR_SIZE];
    sector[..DEMO_STAGE2_CODE.len()].copy_from_slice(DEMO_STAGE2_CODE);
    sector[510] = 0x55;
    sector[511] = 0xAA;
    sector
}

/// Builds the deterministic 1.44 MiB demo floppy image.
///
/// Sector 0 is [`demo_boot_sector`], sector 1 is [`demo_stage2`]; every other
/// sector is zero.
pub fn demo_disk_image() -> Vec<u8> {
    let mut image = vec![0u8; FLOPPY_BYTES];
    image[..SECTOR_SIZE].copy_from_slice(&demo_boot_sector());
    image[SECTOR_SIZE..2 * SECTOR_SIZE].copy_from_slice(&demo_stage2());
    image
}
