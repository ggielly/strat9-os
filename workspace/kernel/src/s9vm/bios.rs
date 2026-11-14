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

//! s9vm : pure PC BIOS service model for a real-mode DOS-class guest.
//!
//! This module implements the software half of the classic firmware surface:
//! it takes the guest register file captured at a BIOS interrupt, performs the
//! requested service on a guest memory image and a synthetic block device, and
//! returns the updated register values. It **touches no hardware**: the kernel
//! adapter ([`BiosMemory`] / [`BiosDisk`]) supplies guest memory and disk
//! sectors, and publishes the resulting `CF`/`ZF` through the scratch byte.
//!
//! # Scratch-byte protocol
//!
//! The real-mode ROM stubs installed by [`crate::s9vm::biosrom`] cannot return
//! values in registers by themselves: they `OUT` to a debug port, the host
//! services the call, and the stub patches the caller's stacked `FLAGS` from a
//! single byte at [`SCRATCH_GPA`]. At the end of **every** call, handled or
//! not, this model writes that byte:
//!
//! ```text
//! bit 0  CF value ([`SCRATCH_CF`])
//! bit 1  ZF value ([`SCRATCH_ZF`])
//! other  zero
//! ```
//!
//! [`BiosOutcome::Unknown`] writes `0x00` (`CF=0`, `ZF=0`) and leaves the BDA
//! alone: the guest is expected to have installed its own handler for that
//! vector. On handled calls the two flags are also mirrored into
//! [`BiosRegisters::flags`], for adapters that derive the scratch byte from the
//! returned register file; the scratch byte stays authoritative.
//!
//! # Services
//!
//! | Vector | Function | Behaviour |
//! |---|---|---|
//! | `05h` | print screen | accepted, no-op (`CF=0`) |
//! | `08h`, `1Ch` | timer / user tick | [`BiosOutcome::Unknown`] |
//! | `10h` | video | mode, cursor, scroll, characters, string |
//! | `11h` | equipment | `AX=0x0021` |
//! | `12h` | memory size | `AX=640` KiB |
//! | `13h` | disk | reset, status, CHS read, params, type, extensions, DAP read |
//! | `15h` | system | `88h` only; `C0h`/`E8h` rejected |
//! | `16h` | keyboard | polling queue, `AH=00/01/02` |
//! | `17h` | printer | accepted, status `30h` |
//! | `1Ah` | time | tick count and RTC time |
//!
//! Any other vector is [`BiosOutcome::Unknown`].
//!
//! # Failure statuses
//!
//! Every rejected request sets `CF=1` and a documented status:
//!
//! | Constant | Value | Used by |
//! |---|---|---|
//! | [`STATUS_INVALID_FUNCTION`] | `01h` | video/system/keyboard/disk subfunction |
//! | [`DISK_STATUS_WRITE_PROTECTED`] | `03h` | disk write requests (synthetic disk) |
//! | [`DISK_STATUS_SECTOR_NOT_FOUND`] | `04h` | bad CHS/LBA, backend error, unmapped buffer |
//! | [`DISK_STATUS_MEDIA_NOT_FOUND`] | `0Ch` | unsupported drive number |
//! | [`STATUS_NOT_SUPPORTED`] | `86h` | unsupported `INT 15h` subfunction |
//!
//! # BIOS data area
//!
//! [`initialise_bda`] fills the fields a DOS boot reads (equipment, memory
//! size, EBDA segment, keyboard head/tail, tick count, video mode, columns,
//! cursor, page, CRTC port, rows and character height). After every handled
//! call [`BiosState::handle`] republishes the fields it owns: video mode,
//! cursor, tick count and keyboard head/tail.
//!
//! The keyboard buffer is modelled as a compact [`alloc::collections::VecDeque`]
//! rather than a real ring. The BDA therefore publishes a synthetic ring
//! descriptor: head `0`, tail `2 * queued bytes` capped at the 32-byte buffer.
//! This keeps the "head equals tail when empty" invariant without storing ring
//! indices in the state.
//!
//! # Disk geometry
//!
//! [`FLOPPY_1440`] is the canonical 80 x 2 x 18 x 512 geometry (2880 sectors,
//! 1.44 MiB). [`DiskGeometry::from_sectors`] returns it for images of at most
//! 2880 sectors and a documented fixed-disk-ish 1024 x 16 x 63 x 512 geometry
//! above that (1,032,192 sectors, about 504 MiB). The geometry only describes
//! CHS decoding; the authoritative sector count is
//! [`BiosDisk::sectors`], and reads past it fail with status `04h`.
//!
//! `CHS` sectors are one-based, as on the PC. Cylinder bits 9:8 travel in
//! `CL` bits 7:6 and are reassembled by the model.
//!
//! # Documented deviations
//!
//! - `INT 10h AH=03` returns the cursor shape in `CX=0x0607`; the prompt also
//!   said `CH=0`, but the two cannot both hold, and `0x0607` wins because the
//!   shape is the documented return value. `CH` is `0x06` (shape start line).
//! - `INT 11h` returns `AX=0x0021`. In that word bit 0 announces the floppy
//!   drive and bits 7:6 are `00b`, **not** `01b`: the two fields would make
//!   `0x0061`, so the authoritative literal `0x0021` is used.
//! - `INT 13h AH=08` returns `DL=2` for drive `00h` and `DL=3` for drive
//!   `80h`. Only those two drive numbers are accepted (a stricter reading of
//!   the classic "below `0x80` means floppy" shorthand); anything else fails
//!   with status `0Ch`.
//! - Text services write the default attribute `07h` where the caller does not
//!   supply one (`AH=0Eh`, scrolling blank lines use `BH`).
//! - Guest buffer writes are attempted byte by byte through [`BiosMemory`].
//!   A byte the adapter refuses aborts the call with status `04h`; bytes
//!   already written stay written (the adapter is free to reject a range that
//!   crosses the end of mapped memory).
//! - `INT 17h` accepts output but has no parallel port to deliver it to; the
//!   bytes are discarded and only the ready status is reported.

use alloc::{collections::VecDeque, string::String, vec::Vec};

/// Guest-physical address of the byte the ROM stubs read back.
pub const SCRATCH_GPA: u32 = 0x0500;
/// Scratch bit 0: carry flag.
pub const SCRATCH_CF: u8 = 1;
/// Scratch bit 1: zero flag.
pub const SCRATCH_ZF: u8 = 2;

/// Base of the BIOS data area.
pub const BDA_BASE: u32 = 0x0400;
/// BDA field: extended BIOS data area segment.
pub const BDA_EBDA_SEGMENT: u32 = 0x040E;
/// BDA field: installed equipment word.
pub const BDA_EQUIPMENT: u32 = 0x0410;
/// BDA field: conventional memory size, in KiB.
pub const BDA_MEMORY_SIZE: u32 = 0x0413;
/// BDA field: keyboard buffer head offset.
pub const BDA_KEYBOARD_HEAD: u32 = 0x041A;
/// BDA field: keyboard buffer tail offset.
pub const BDA_KEYBOARD_TAIL: u32 = 0x041C;
/// BDA field: current video mode.
pub const BDA_VIDEO_MODE: u32 = 0x0449;
/// BDA field: number of text columns.
pub const BDA_COLUMNS: u32 = 0x044A;
/// BDA field: cursor position of page 0 (`row << 8 | column`).
pub const BDA_CURSOR: u32 = 0x0450;
/// BDA field: active display page.
pub const BDA_PAGE: u32 = 0x0462;
/// BDA field: CRTC I/O port base.
pub const BDA_CRTC_PORT: u32 = 0x0463;
/// BDA field: timer tick counter, 32 bits.
pub const BDA_TICK_COUNT: u32 = 0x046C;
/// BDA field: text rows minus one.
pub const BDA_ROWS: u32 = 0x0484;
/// BDA field: character height, in scan lines.
pub const BDA_CHAR_HEIGHT: u32 = 0x0485;

/// BDA equipment word: one floppy drive, 80x25 colour (bit 0 and bits 5:4).
///
/// The floppy-count field in bits 7:6 stays `00b`; drive presence is carried by
/// bit 0. This is the value the guest sees through `INT 11h`.
pub const EQUIPMENT_WORD: u16 = 0x0021;
/// Conventional memory size reported by [`initialise_bda`] and `INT 12h`.
pub const MEMORY_SIZE_KIB: u16 = 640;
/// Extended BIOS data area segment written by [`initialise_bda`].
pub const EBDA_SEGMENT: u16 = 0x9FC0;
/// Video mode installed by [`initialise_bda`] (80x25 colour text).
pub const DEFAULT_VIDEO_MODE: u8 = 3;
/// Text columns installed in the BDA.
pub const DEFAULT_COLUMNS: u16 = 80;
/// CRTC I/O port base installed in the BDA.
pub const DEFAULT_CRTC_PORT: u16 = 0x03D4;
/// Text rows minus one installed in the BDA.
pub const DEFAULT_ROWS_MINUS_ONE: u8 = 24;
/// Character height, in scan lines, installed in the BDA.
pub const DEFAULT_CHAR_HEIGHT: u8 = 16;
/// Active display page installed in the BDA.
pub const DEFAULT_PAGE: u8 = 0;
/// Attribute used by text services that do not take one from the caller.
pub const DEFAULT_ATTRIBUTE: u8 = 0x07;
/// Character written to blank cells.
pub const SPACE: u8 = 0x20;
/// Maximum number of keys the model queues.
pub const KEY_BUFFER_CAPACITY: usize = 16;
/// Size of the BDA-visible keyboard ring, in bytes.
pub const KEY_BUFFER_BYTES: u16 = 32;
/// First slot offset of the BDA keyboard ring.
///
/// The BDA head/tail words (`0x41A`/`0x41C`) hold offsets relative to the BDA
/// base, so the first entry of the ring sits at `0x41E` and the values wrap
/// inside `0x1E..=0x3E`, exactly as a PC firmware leaves them.
pub const KEY_BUFFER_FIRST_OFFSET: u16 = 0x1E;
/// Guest-physical base of the BDA keyboard ring entries.
pub const BDA_KEY_BUFFER: u32 = 0x041E;

/// Guest-physical base of text-mode video memory.
pub const VIDEO_BASE: u32 = 0xB8000;
/// Size of the video window cleared when a mode is set.
pub const VIDEO_LEN: u32 = 0x8000;
/// Text columns of the modelled screen.
pub const TEXT_COLUMNS: u8 = 80;
/// Text rows of the modelled screen.
pub const TEXT_ROWS: u8 = 25;

/// `FLAGS` bit 0: carry.
pub const FLAG_CARRY: u16 = 1 << 0;
/// `FLAGS` bit 6: zero.
pub const FLAG_ZERO: u16 = 1 << 6;

/// Success status (`CF=0`).
pub const STATUS_OK: u8 = 0x00;
/// Invalid function or invalid parameter status.
pub const STATUS_INVALID_FUNCTION: u8 = 0x01;
/// Unsupported system function status (`INT 15h`).
pub const STATUS_NOT_SUPPORTED: u8 = 0x86;

/// Disk status: success.
pub const DISK_STATUS_OK: u8 = 0x00;
/// Disk status: invalid function or invalid address packet.
pub const DISK_STATUS_INVALID_FUNCTION: u8 = 0x01;
/// Disk status: the synthetic disk is read-only.
pub const DISK_STATUS_WRITE_PROTECTED: u8 = 0x03;
/// Disk status: bad CHS/LBA, backend error, or unmapped guest buffer.
pub const DISK_STATUS_SECTOR_NOT_FOUND: u8 = 0x04;
/// Disk status: unsupported drive number.
pub const DISK_STATUS_MEDIA_NOT_FOUND: u8 = 0x0C;
/// Floppy drive number.
pub const FLOPPY_DRIVE: u8 = 0x00;
/// Fixed-disk drive number.
pub const HARD_DISK_DRIVE: u8 = 0x80;
/// Signature returned by the disk extensions presence check.
pub const EXTENSIONS_SIGNATURE: u16 = 0xAA55;
/// Required size of an extended disk address packet.
pub const DAP_SIZE: u8 = 16;
/// Status reported by the printer service: selected and ready.
pub const PRINTER_STATUS: u8 = 0x30;

/// Total number of sectors of a 1.44 MiB floppy.
pub const FLOPPY_TOTAL_SECTORS: u64 = 2880;
/// Size of one disk sector, in bytes.
pub const SECTOR_SIZE: usize = 512;
/// Floppy geometry installed by [`BiosState::new`]: 80 x 2 x 18 x 512.
pub const FLOPPY_1440: DiskGeometry = DiskGeometry {
    cylinders: 80,
    heads: 2,
    sectors_per_track: 18,
    sector_size: 512,
};
/// Fixed-disk-ish geometry for images larger than a floppy: 1024 x 16 x 63 x
/// 512 (about 504 MiB, 1,032,192 sectors).
pub const HARD_DISK_GEOMETRY: DiskGeometry = DiskGeometry {
    cylinders: 1024,
    heads: 16,
    sectors_per_track: 63,
    sector_size: 512,
};

/// Guest register file visible to one BIOS call.
///
/// The fields mirror the 16-bit real-mode register set. [`gpr`] and
/// [`set_gpr`] use the x86 encoding order so the kernel adapter can move the
/// eight general-purpose registers without a lookup table of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BiosRegisters {
    /// Accumulator.
    pub ax: u16,
    /// Base.
    pub bx: u16,
    /// Counter.
    pub cx: u16,
    /// Data.
    pub dx: u16,
    /// Source index.
    pub si: u16,
    /// Destination index.
    pub di: u16,
    /// Base pointer.
    pub bp: u16,
    /// Stack pointer.
    pub sp: u16,
    /// Data segment.
    pub ds: u16,
    /// Extra segment.
    pub es: u16,
    /// Stack segment.
    pub ss: u16,
    /// Code segment.
    pub cs: u16,
    /// Instruction pointer.
    pub ip: u16,
    /// Flags word; only `CF` and `ZF` are interpreted by this module.
    pub flags: u16,
}

impl BiosRegisters {
    /// Creates a zeroed register file.
    pub const fn new() -> Self {
        Self {
            ax: 0,
            bx: 0,
            cx: 0,
            dx: 0,
            si: 0,
            di: 0,
            bp: 0,
            sp: 0,
            ds: 0,
            es: 0,
            ss: 0,
            cs: 0,
            ip: 0,
            flags: 0,
        }
    }

    /// Returns a general-purpose register in x86 encoding order.
    ///
    /// `0=ax`, `1=cx`, `2=dx`, `3=bx`, `4=sp`, `5=bp`, `6=si`, `7=di`.
    /// Encodings 8..=15 (and anything above) read as zero.
    pub fn gpr(&self, register: u8) -> u16 {
        match register {
            0 => self.ax,
            1 => self.cx,
            2 => self.dx,
            3 => self.bx,
            4 => self.sp,
            5 => self.bp,
            6 => self.si,
            7 => self.di,
            _ => 0,
        }
    }

    /// Writes a general-purpose register in x86 encoding order.
    ///
    /// Encodings 8..=15 (and anything above) are ignored.
    pub fn set_gpr(&mut self, register: u8, value: u16) {
        match register {
            0 => self.ax = value,
            1 => self.cx = value,
            2 => self.dx = value,
            3 => self.bx = value,
            4 => self.sp = value,
            5 => self.bp = value,
            6 => self.si = value,
            7 => self.di = value,
            _ => {}
        }
    }

    /// True when the carry flag is set in [`BiosRegisters::flags`].
    pub const fn carry(&self) -> bool {
        self.flags & FLAG_CARRY != 0
    }

    /// Sets or clears the carry flag in [`BiosRegisters::flags`].
    pub fn set_carry(&mut self, value: bool) {
        if value {
            self.flags |= FLAG_CARRY;
        } else {
            self.flags &= !FLAG_CARRY;
        }
    }

    /// True when the zero flag is set in [`BiosRegisters::flags`].
    pub const fn zero(&self) -> bool {
        self.flags & FLAG_ZERO != 0
    }

    /// Sets or clears the zero flag in [`BiosRegisters::flags`].
    pub fn set_zero(&mut self, value: bool) {
        if value {
            self.flags |= FLAG_ZERO;
        } else {
            self.flags &= !FLAG_ZERO;
        }
    }
}

impl Default for BiosRegisters {
    fn default() -> Self {
        Self::new()
    }
}

/// Guest memory access used by the service model.
///
/// Addresses are guest-physical (linear) addresses. Every method is
/// bounds-checked by the adapter: an unmapped or out-of-range access returns
/// `None`/`false` and never panics.
pub trait BiosMemory {
    /// Reads one byte. Returns `None` when the address is not readable.
    fn read_u8(&mut self, linear: u32) -> Option<u8>;

    /// Writes one byte. Returns `false` when the address is not writable.
    fn write_u8(&mut self, linear: u32, value: u8) -> bool;

    /// Reads `out.len()` bytes. Returns `false` when the range is not readable.
    fn read(&mut self, linear: u32, out: &mut [u8]) -> bool;

    /// Writes `bytes`. Returns `false` when the range is not writable.
    fn write(&mut self, linear: u32, bytes: &[u8]) -> bool;
}

/// Synthetic block-device access used by `INT 13h`.
///
/// Sector numbers are linear block addresses. A read-only medium (the default)
/// keeps `INT 13h AH=03`/`AH=43h` reporting write-protected; a backend that can
/// persist writes overrides [`BiosDisk::write_sector`].
pub trait BiosDisk {
    /// Number of 512-byte sectors available.
    fn sectors(&self) -> u64;

    /// Reads one sector into `out`. Returns `false` on a backend error.
    fn read_sector(&mut self, sector: u64, out: &mut [u8; 512]) -> bool;

    /// Writes one sector from `data`.
    ///
    /// The default implementation reports a read-only medium.
    fn write_sector(&mut self, sector: u64, data: &[u8; 512]) -> bool {
        let _ = (sector, data);
        false
    }
}

/// CHS geometry used to decode and report disk addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskGeometry {
    /// Number of cylinders.
    pub cylinders: u16,
    /// Number of heads.
    pub heads: u8,
    /// Sectors per track (one-based sectors).
    pub sectors_per_track: u8,
    /// Bytes per sector.
    pub sector_size: u16,
}

impl DiskGeometry {
    /// Converts a one-based CHS address to a linear block address.
    ///
    /// Returns `None` when the cylinder, head or sector is outside the
    /// geometry. A sector of zero is invalid.
    pub fn lba(&self, cyl: u16, head: u8, sector: u8) -> Option<u64> {
        if cyl >= self.cylinders
            || head >= self.heads
            || sector == 0
            || sector > self.sectors_per_track
        {
            return None;
        }
        Some(
            (cyl as u64 * self.heads as u64 + head as u64) * self.sectors_per_track as u64
                + sector as u64
                - 1,
        )
    }

    /// Selects a geometry from an image sector count.
    ///
    /// Images of at most [`FLOPPY_TOTAL_SECTORS`] sectors get [`FLOPPY_1440`];
    /// larger images get [`HARD_DISK_GEOMETRY`] (1024 x 16 x 63 x 512).
    pub const fn from_sectors(sectors: u64) -> Self {
        if sectors <= FLOPPY_TOTAL_SECTORS {
            FLOPPY_1440
        } else {
            HARD_DISK_GEOMETRY
        }
    }
}

/// Result of dispatching one interrupt vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BiosOutcome {
    /// The model serviced the call; the scratch byte carries `CF`/`ZF`.
    Handled,
    /// No service is installed: the guest owns this vector. The scratch byte
    /// is still written, with `CF=0` and `ZF=0`.
    Unknown,
}

/// Architectural state of the BIOS service model.
///
/// The state is deliberately small: cursor, mode, tick counter, keyboard queue,
/// disk geometry and a frozen RTC time. The kernel adapter owns the guest
/// memory image and the backing disk; [`BiosState::handle`] only mutates the
/// state and the memory/disk it is given.
#[derive(Debug)]
pub struct BiosState {
    /// Cursor row, 0..=24.
    pub cursor_row: u8,
    /// Cursor column, 0..=79.
    pub cursor_col: u8,
    /// Current video mode (3 or 7).
    pub video_mode: u8,
    /// Timer tick counter (nominally 18.2 Hz).
    pub ticks: u32,
    /// Keys waiting for `INT 16h`, oldest first.
    /// Queued (scan code, ASCII) pairs, the layout INT 16h returns.
    ///
    /// A printable key carries its ASCII byte with a zero scan code until a
    /// guest handler fills the BDA ring; an extended key (arrows, Home/End)
    /// carries the scan code with a zero ASCII byte, which is exactly what a
    /// PC keyboard buffer holds.
    pub keyboard: VecDeque<(u8, u8)>,
    /// CHS geometry reported to the guest.
    pub disk: DiskGeometry,
    /// RTC hour, binary, 0..=23 by convention.
    pub rtc_hour: u8,
    /// RTC minute, binary, 0..=59 by convention.
    pub rtc_minute: u8,
    /// RTC second, binary, 0..=59 by convention.
    pub rtc_second: u8,
}

impl BiosState {
    /// Creates the reset state: mode 3, cursor at home, floppy geometry, empty
    /// keyboard queue and a midnight RTC.
    pub fn new() -> Self {
        Self {
            cursor_row: 0,
            cursor_col: 0,
            video_mode: DEFAULT_VIDEO_MODE,
            ticks: 0,
            keyboard: VecDeque::new(),
            disk: FLOPPY_1440,
            rtc_hour: 0,
            rtc_minute: 0,
            rtc_second: 0,
        }
    }

    /// Queues one ASCII key for `INT 16h`.
    ///
    /// The queue is bounded by [`KEY_BUFFER_CAPACITY`]; keys arriving when it
    /// is full are dropped, like a real keyboard controller overrun.
    pub fn push_key(&mut self, ascii: u8) {
        self.push_scan_key(0, ascii);
    }

    /// Queues the `(scan code, ASCII)` pair `INT 16h` returns.
    ///
    /// A guest `INT 9` handler stores this pair in the BDA ring, so the runner
    /// feeds extended keys (arrows, Home/End) through the same bounded queue:
    /// they carry the scan code and a zero ASCII byte.
    pub fn push_scan_key(&mut self, scan: u8, ascii: u8) {
        if self.keyboard.len() < KEY_BUFFER_CAPACITY {
            self.keyboard.push_back((scan, ascii));
        }
    }

    /// Advances the 18.2 Hz tick counter (wrapping).
    pub fn advance_ticks(&mut self, ticks: u32) {
        self.ticks = self.ticks.wrapping_add(ticks);
    }

    /// Services one BIOS interrupt.
    ///
    /// `vector` is the interrupt number, `regs` the guest register file (read
    /// for arguments and updated with results), `mem` the guest memory image
    /// and `disk` the synthetic block device. The scratch byte is written on
    /// every path; the BDA is refreshed on every handled path.
    pub fn handle(
        &mut self,
        vector: u8,
        regs: &mut BiosRegisters,
        mem: &mut impl BiosMemory,
        disk: &mut dyn BiosDisk,
    ) -> BiosOutcome {
        let completion = match vector {
            0x05 => Some(Completion::OK),
            0x08 | 0x1C => None,
            0x10 => Some(self.video_service(regs, mem)),
            0x11 => {
                regs.ax = EQUIPMENT_WORD;
                Some(Completion::OK)
            }
            0x12 => {
                regs.ax = MEMORY_SIZE_KIB;
                Some(Completion::OK)
            }
            0x13 => Some(self.disk_service(regs, mem, disk)),
            0x15 => Some(self.system_service(regs)),
            0x16 => Some(self.keyboard_service(regs, mem)),
            0x17 => Some(self.printer_service(regs)),
            0x1A => Some(self.time_service(regs)),
            _ => None,
        };
        match completion {
            Some(completion) => {
                self.sync_bda(mem);
                // The scratch byte is the authoritative return path, but the
                // flags are mirrored into the register file too so adapters
                // that publish the scratch byte from the returned registers
                // observe the same values.
                regs.set_carry(completion.carry);
                regs.set_zero(completion.zero);
                let mut scratch = 0u8;
                if completion.carry {
                    scratch |= SCRATCH_CF;
                }
                if completion.zero {
                    scratch |= SCRATCH_ZF;
                }
                let _ = mem.write_u8(SCRATCH_GPA, scratch);
                BiosOutcome::Handled
            }
            None => {
                let _ = mem.write_u8(SCRATCH_GPA, 0);
                BiosOutcome::Unknown
            }
        }
    }

    /// Republishes the BDA fields owned by the model.
    fn sync_bda(&self, mem: &mut impl BiosMemory) {
        let _ = mem.write_u8(BDA_VIDEO_MODE, self.video_mode);
        let _ = write_u16(
            mem,
            BDA_CURSOR,
            (self.cursor_row as u16) << 8 | self.cursor_col as u16,
        );
        let _ = write_u32(mem, BDA_TICK_COUNT, self.ticks);
        // The keyboard ring (head/tail at 0x41A/0x41C, entries at 0x41E) is
        // maintained by whoever owns the keyboard: once the guest installs its
        // own `INT 9` handler, DOS fills it and the firmware `INT 16h` service
        // consumes it. Republishing it from the model queue here would reset
        // the ring on every unrelated BIOS call (every INT 10h/INT 13h).
    }

    /// Clamps and stores the text cursor.
    fn set_cursor(&mut self, row: u8, col: u8) {
        self.cursor_row = row.min(TEXT_ROWS - 1);
        self.cursor_col = col.min(TEXT_COLUMNS - 1);
    }

    /// Sets up one text mode and clears the video window.
    fn set_video_mode(&mut self, mode: u8, mem: &mut impl BiosMemory) {
        self.video_mode = mode;
        self.cursor_row = 0;
        self.cursor_col = 0;
        let mut address = VIDEO_BASE;
        let end = VIDEO_BASE + VIDEO_LEN;
        while address < end {
            let _ = mem.write_u8(address, SPACE);
            let _ = mem.write_u8(address + 1, DEFAULT_ATTRIBUTE);
            address += 2;
        }
        let _ = write_u16(mem, BDA_COLUMNS, DEFAULT_COLUMNS);
        let _ = mem.write_u8(BDA_ROWS, DEFAULT_ROWS_MINUS_ONE);
        let _ = mem.write_u8(BDA_CHAR_HEIGHT, DEFAULT_CHAR_HEIGHT);
    }

    /// `INT 10h`: video services.
    fn video_service(&mut self, regs: &mut BiosRegisters, mem: &mut impl BiosMemory) -> Completion {
        match (regs.ax >> 8) as u8 {
            0x00 => {
                let mode = regs.ax as u8;
                if mode == 3 || mode == 7 {
                    self.set_video_mode(mode, mem);
                    set_ah(regs, STATUS_OK);
                    Completion::OK
                } else {
                    fail_ah(regs, STATUS_INVALID_FUNCTION)
                }
            }
            0x01 => {
                // Cursor shape is accepted but not stored: the model reports a
                // fixed 0x0607 shape through AH=03.
                Completion::OK
            }
            0x02 => {
                self.set_cursor((regs.dx >> 8) as u8, regs.dx as u8);
                Completion::OK
            }
            0x03 => {
                let row = self.cursor_row;
                let col = self.cursor_col;
                regs.cx = 0x0607;
                regs.dx = (row as u16) << 8 | col as u16;
                Completion::OK
            }
            0x05 => {
                if regs.ax as u8 == DEFAULT_PAGE {
                    let _ = mem.write_u8(BDA_PAGE, DEFAULT_PAGE);
                    Completion::OK
                } else {
                    fail_ah(regs, STATUS_INVALID_FUNCTION)
                }
            }
            0x06 | 0x07 => {
                let up = (regs.ax >> 8) as u8 == 0x06;
                let lines = regs.ax as u8;
                let attr = (regs.bx >> 8) as u8;
                let top = ((regs.cx >> 8) as u8).min(TEXT_ROWS - 1);
                let left = (regs.cx as u8).min(TEXT_COLUMNS - 1);
                let bottom = ((regs.dx >> 8) as u8).min(TEXT_ROWS - 1);
                let right = (regs.dx as u8).min(TEXT_COLUMNS - 1);
                if top <= bottom && left <= right {
                    let _ = scroll_region(mem, up, lines, attr, top, left, bottom, right);
                }
                Completion::OK
            }
            0x08 => {
                let (ch, attr) = read_cell(mem, self.cursor_row, self.cursor_col);
                regs.ax = (attr as u16) << 8 | ch as u16;
                Completion::OK
            }
            0x09 => {
                self.write_repeated(regs.ax as u8, regs.cx, Some(regs.bx as u8), mem);
                Completion::OK
            }
            0x0A => {
                self.write_repeated(regs.ax as u8, regs.cx, None, mem);
                Completion::OK
            }
            0x0E => {
                self.teletype(regs.ax as u8, mem);
                Completion::OK
            }
            0x0F => {
                regs.ax = (DEFAULT_COLUMNS << 8) | self.video_mode as u16;
                Completion::OK
            }
            0x13 => self.write_string(regs, mem),
            _ => fail_ah(regs, STATUS_INVALID_FUNCTION),
        }
    }

    /// Writes `count` copies of `ch` at the cursor, optionally keeping the
    /// existing attribute (`attr` is `None`). The cursor does not move; cells
    /// are filled across rows up to the end of the screen.
    fn write_repeated(&self, ch: u8, count: u16, attr: Option<u8>, mem: &mut impl BiosMemory) {
        let total = TEXT_COLUMNS as u32 * TEXT_ROWS as u32;
        let mut index = self.cursor_row as u32 * TEXT_COLUMNS as u32 + self.cursor_col as u32;
        for _ in 0..count {
            if index >= total {
                break;
            }
            let row = (index / TEXT_COLUMNS as u32) as u8;
            let col = (index % TEXT_COLUMNS as u32) as u8;
            let attribute = match attr {
                Some(value) => value,
                None => read_cell(mem, row, col).1,
            };
            let _ = write_cell(mem, row, col, ch, attribute);
            index += 1;
        }
    }

    /// `INT 10h AH=0Eh`: teletype output.
    fn teletype(&mut self, ch: u8, mem: &mut impl BiosMemory) {
        match ch {
            0x07 => {}
            0x08 => {
                if self.cursor_col > 0 {
                    self.cursor_col -= 1;
                } else if self.cursor_row > 0 {
                    self.cursor_row -= 1;
                    self.cursor_col = TEXT_COLUMNS - 1;
                }
            }
            0x09 => {
                let next = (self.cursor_col / 8 + 1) * 8;
                if next < TEXT_COLUMNS {
                    self.cursor_col = next;
                } else {
                    self.cursor_col = 0;
                    self.newline(mem);
                }
            }
            0x0A => self.newline(mem),
            0x0D => self.cursor_col = 0,
            _ => {
                let _ = write_cell(mem, self.cursor_row, self.cursor_col, ch, DEFAULT_ATTRIBUTE);
                self.cursor_col += 1;
                if self.cursor_col >= TEXT_COLUMNS {
                    self.cursor_col = 0;
                    self.newline(mem);
                }
            }
        }
    }

    /// Moves to the next teletype line, scrolling when already on the last one.
    fn newline(&mut self, mem: &mut impl BiosMemory) {
        if self.cursor_row + 1 < TEXT_ROWS {
            self.cursor_row += 1;
        } else {
            let _ = scroll_region(
                mem,
                true,
                1,
                DEFAULT_ATTRIBUTE,
                0,
                0,
                TEXT_ROWS - 1,
                TEXT_COLUMNS - 1,
            );
        }
    }

    /// `INT 10h AH=13h`: writes a counted string with optional attribute pairs.
    fn write_string(&mut self, regs: &mut BiosRegisters, mem: &mut impl BiosMemory) -> Completion {
        let length = regs.cx as usize;
        let mode = regs.ax as u8;
        let default_attr = regs.bx as u8;
        let base = linear_address(regs.es, regs.bp);
        let with_attributes = mode & 0x02 != 0;
        let update_cursor = mode & 0x01 != 0;
        let stride = if with_attributes { 2 } else { 1 };
        let mut row = ((regs.dx >> 8) as u8).min(TEXT_ROWS - 1);
        let mut col = (regs.dx as u8).min(TEXT_COLUMNS - 1);
        for index in 0..length {
            let address = base.saturating_add((index * stride) as u32);
            let Some(ch) = mem.read_u8(address) else {
                break;
            };
            let attribute = if with_attributes {
                mem.read_u8(address + 1).unwrap_or(default_attr)
            } else {
                default_attr
            };
            if !write_cell(mem, row, col, ch, attribute) {
                break;
            }
            col += 1;
            if col >= TEXT_COLUMNS {
                col = 0;
                if row + 1 >= TEXT_ROWS {
                    row = TEXT_ROWS - 1;
                    col = TEXT_COLUMNS - 1;
                    break;
                }
                row += 1;
            }
        }
        if update_cursor {
            self.set_cursor(row, col);
        }
        Completion::OK
    }

    /// `INT 13h`: disk services.
    fn disk_service(
        &mut self,
        regs: &mut BiosRegisters,
        mem: &mut impl BiosMemory,
        disk: &mut dyn BiosDisk,
    ) -> Completion {
        match (regs.ax >> 8) as u8 {
            0x00 => {
                set_ah(regs, DISK_STATUS_OK);
                Completion::OK
            }
            0x01 => {
                set_ah(regs, DISK_STATUS_OK);
                Completion::OK
            }
            0x02 => {
                let Some(_hard) = drive_kind(regs.dx as u8) else {
                    return fail_ah(regs, DISK_STATUS_MEDIA_NOT_FOUND);
                };
                let count = (regs.ax & 0xFF) as u64;
                let sector = (regs.cx & 0x3F) as u8;
                let cyl = ((regs.cx >> 8) & 0xFF) | (((regs.cx >> 6) & 0x03) << 8);
                let head = (regs.dx >> 8) as u8;
                let Some(lba) = self.disk.lba(cyl, head, sector) else {
                    return fail_ah(regs, DISK_STATUS_SECTOR_NOT_FOUND);
                };
                let buffer = linear_address(regs.es, regs.bx);
                match read_sectors(mem, disk, lba, count, buffer) {
                    Ok(()) => {
                        set_ah(regs, DISK_STATUS_OK);
                        Completion::OK
                    }
                    Err(status) => fail_ah(regs, status),
                }
            }
            0x03 => {
                let Some(_hard) = drive_kind(regs.dx as u8) else {
                    return fail_ah(regs, DISK_STATUS_MEDIA_NOT_FOUND);
                };
                let count = (regs.ax & 0xFF) as u64;
                let sector = (regs.cx & 0x3F) as u8;
                let cyl = ((regs.cx >> 8) & 0xFF) | (((regs.cx >> 6) & 0x03) << 8);
                let head = (regs.dx >> 8) as u8;
                let Some(lba) = self.disk.lba(cyl, head, sector) else {
                    return fail_ah(regs, DISK_STATUS_SECTOR_NOT_FOUND);
                };
                let buffer = linear_address(regs.es, regs.bx);
                match write_sectors(mem, disk, lba, count, buffer) {
                    Ok(()) => {
                        set_ah(regs, DISK_STATUS_OK);
                        Completion::OK
                    }
                    Err(status) => fail_ah(regs, status),
                }
            }
            0x04 => {
                // Verify sectors: the track and sector addresses must exist on
                // the medium, but there is no data transfer. DOS issues this
                // after every write when verification is on, and formatters use
                // it to validate the volume they just created.
                let Some(_hard) = drive_kind(regs.dx as u8) else {
                    return fail_ah(regs, DISK_STATUS_MEDIA_NOT_FOUND);
                };
                let count = (regs.ax & 0xFF) as u64;
                let sector = (regs.cx & 0x3F) as u8;
                let cyl = ((regs.cx >> 8) & 0xFF) | (((regs.cx >> 6) & 0x03) << 8);
                let head = (regs.dx >> 8) as u8;
                let Some(lba) = self.disk.lba(cyl, head, sector) else {
                    return fail_ah(regs, DISK_STATUS_SECTOR_NOT_FOUND);
                };
                match verify_sectors(disk, lba, count) {
                    Ok(()) => {
                        set_ah(regs, DISK_STATUS_OK);
                        Completion::OK
                    }
                    Err(status) => fail_ah(regs, status),
                }
            }
            0x05 => {
                let Some(_hard) = drive_kind(regs.dx as u8) else {
                    return fail_ah(regs, DISK_STATUS_MEDIA_NOT_FOUND);
                };
                let count = u64::from(regs.ax & 0xFF);
                let table = linear_address(regs.es, regs.bx);
                match self.format_track(mem, disk, count, table) {
                    Ok(()) => {
                        set_ah(regs, DISK_STATUS_OK);
                        Completion::OK
                    }
                    Err(status) => fail_ah(regs, status),
                }
            }
            0x09 | 0x0C | 0x0D | 0x0E | 0x0F => {
                // Initialise, seek, reset and sector-buffer services: the
                // synthetic controller is always ready and has no seek latency.
                set_ah(regs, DISK_STATUS_OK);
                Completion::OK
            }
            0x08 => {
                let Some(hard) = drive_kind(regs.dx as u8) else {
                    return fail_ah(regs, DISK_STATUS_MEDIA_NOT_FOUND);
                };
                let cylinders = self.disk.cylinders.saturating_sub(1);
                let heads = self.disk.heads.saturating_sub(1);
                regs.cx = ((cylinders & 0xFF) << 8)
                    | (self.disk.sectors_per_track as u16 & 0x3F)
                    | (((cylinders >> 8) & 0x03) << 6);
                // DL is the number of drives of the requested class, not the
                // AH=15h type code: one modelled drive per class. A larger
                // count makes DOS probe absent drives (0x81, 0x82, ...).
                regs.dx = (heads as u16) << 8 | 1;
                // BL: CMOS drive type for floppies (4 = 1.44 MB), 0 for disks.
                regs.bx = (regs.bx & 0xFF00) | if hard { 0 } else { 4 };
                regs.es = 0;
                regs.di = 0;
                set_ah(regs, DISK_STATUS_OK);
                Completion::OK
            }
            0x15 => {
                let Some(hard) = drive_kind(regs.dx as u8) else {
                    return fail_ah(regs, DISK_STATUS_MEDIA_NOT_FOUND);
                };
                set_ah(regs, if hard { 3 } else { 2 });
                Completion::OK
            }
            0x16 => {
                // Detect disk change. The modelled medium never changes
                // underneath the guest, so a known drive reports "no change"
                // instead of the "general failure" DOS shows for an
                // unsupported service on removable media.
                let Some(_hard) = drive_kind(regs.dx as u8) else {
                    return fail_ah(regs, DISK_STATUS_MEDIA_NOT_FOUND);
                };
                regs.ax &= 0xFF00;
                set_ah(regs, DISK_STATUS_OK);
                Completion::OK
            }
            0x17 => {
                // Set DASD type. The medium type is fixed by the modelled drive
                // (1.44 MB floppy), so the request is accepted as a no-op; DOS
                // uses it before formatting a fixed disk.
                let Some(_hard) = drive_kind(regs.dx as u8) else {
                    return fail_ah(regs, DISK_STATUS_MEDIA_NOT_FOUND);
                };
                set_ah(regs, DISK_STATUS_OK);
                Completion::OK
            }
            0x41 => {
                regs.bx = EXTENSIONS_SIGNATURE;
                set_ah(regs, DISK_STATUS_OK);
                Completion::OK
            }
            0x42 => {
                let dap = linear_address(regs.ds, regs.si);
                let Some(size) = mem.read_u8(dap) else {
                    return fail_ah(regs, DISK_STATUS_INVALID_FUNCTION);
                };
                if size != DAP_SIZE {
                    return fail_ah(regs, DISK_STATUS_INVALID_FUNCTION);
                }
                let Some(count) = read_u16(mem, dap + 2) else {
                    return fail_ah(regs, DISK_STATUS_INVALID_FUNCTION);
                };
                let Some(offset) = read_u16(mem, dap + 4) else {
                    return fail_ah(regs, DISK_STATUS_INVALID_FUNCTION);
                };
                let Some(segment) = read_u16(mem, dap + 6) else {
                    return fail_ah(regs, DISK_STATUS_INVALID_FUNCTION);
                };
                let Some(lba) = read_u64(mem, dap + 8) else {
                    return fail_ah(regs, DISK_STATUS_INVALID_FUNCTION);
                };
                let buffer = linear_address(segment, offset);
                match read_sectors(mem, disk, lba, u64::from(count), buffer) {
                    Ok(()) => {
                        set_ah(regs, DISK_STATUS_OK);
                        Completion::OK
                    }
                    Err(status) => fail_ah(regs, status),
                }
            }
            0x43 => {
                let dap = linear_address(regs.ds, regs.si);
                let Some(size) = mem.read_u8(dap) else {
                    return fail_ah(regs, DISK_STATUS_INVALID_FUNCTION);
                };
                if size != DAP_SIZE {
                    return fail_ah(regs, DISK_STATUS_INVALID_FUNCTION);
                }
                let Some(count) = read_u16(mem, dap + 2) else {
                    return fail_ah(regs, DISK_STATUS_INVALID_FUNCTION);
                };
                let Some(offset) = read_u16(mem, dap + 4) else {
                    return fail_ah(regs, DISK_STATUS_INVALID_FUNCTION);
                };
                let Some(segment) = read_u16(mem, dap + 6) else {
                    return fail_ah(regs, DISK_STATUS_INVALID_FUNCTION);
                };
                let Some(lba) = read_u64(mem, dap + 8) else {
                    return fail_ah(regs, DISK_STATUS_INVALID_FUNCTION);
                };
                let buffer = linear_address(segment, offset);
                match write_sectors(mem, disk, lba, u64::from(count), buffer) {
                    Ok(()) => {
                        set_ah(regs, DISK_STATUS_OK);
                        Completion::OK
                    }
                    Err(status) => fail_ah(regs, status),
                }
            }
            _ => fail_ah(regs, DISK_STATUS_INVALID_FUNCTION),
        }
    }

    /// `INT 13h AH=05h`: formats a track.
    ///
    /// `table` points at the classic four-byte record per sector (cylinder,
    /// head, sector, size code). Every described sector is zero-filled through
    /// the block backend, which is the state a freshly formatted FAT volume
    /// expects. A read-only backend fails with the write-protected status.
    fn format_track(
        &self,
        mem: &mut impl BiosMemory,
        disk: &mut dyn BiosDisk,
        count: u64,
        table: u32,
    ) -> Result<(), u8> {
        let zero = [0u8; SECTOR_SIZE];
        for index in 0..count {
            let entry = table + (index as u32) * 4;
            let cyl = u16::from(mem.read_u8(entry).ok_or(DISK_STATUS_SECTOR_NOT_FOUND)?);
            let head = mem.read_u8(entry + 1).ok_or(DISK_STATUS_SECTOR_NOT_FOUND)?;
            let sector = mem.read_u8(entry + 2).ok_or(DISK_STATUS_SECTOR_NOT_FOUND)?;
            let Some(lba) = self.disk.lba(cyl, head, sector) else {
                return Err(DISK_STATUS_SECTOR_NOT_FOUND);
            };
            if lba >= disk.sectors() {
                return Err(DISK_STATUS_SECTOR_NOT_FOUND);
            }
            if !disk.write_sector(lba, &zero) {
                return Err(DISK_STATUS_WRITE_PROTECTED);
            }
        }
        Ok(())
    }

    /// `INT 15h`: system services.
    fn system_service(&mut self, regs: &mut BiosRegisters) -> Completion {
        match (regs.ax >> 8) as u8 {
            0x88 => {
                // No extended memory above 1 MiB in this model.
                regs.ax = 0;
                Completion::OK
            }
            _ => fail_ah(regs, STATUS_NOT_SUPPORTED),
        }
    }

    /// `INT 16h`: keyboard services.
    ///
    /// The ring at `0x41E` is the interface DOS uses: its own `INT 9` handler
    /// translates each scancode and stores it there (head/tail at
    /// `0x41A`/`0x41C`), and the firmware service is expected to consume it.
    /// The model queue is only a fallback for a guest that never installed its
    /// own handler (there the firmware is the only producer).
    fn keyboard_service(
        &mut self,
        regs: &mut BiosRegisters,
        mem: &mut impl BiosMemory,
    ) -> Completion {
        match (regs.ax >> 8) as u8 {
            0x00 => match self.take_key(mem, true) {
                Some((scan, ascii)) => {
                    regs.ax = (u16::from(scan) << 8) | u16::from(ascii);
                    Completion::with_zero(false)
                }
                None => {
                    regs.ax = 0;
                    Completion::with_zero(true)
                }
            },
            0x01 => match self.take_key(mem, false) {
                Some((scan, ascii)) => {
                    regs.ax = (u16::from(scan) << 8) | u16::from(ascii);
                    Completion::with_zero(false)
                }
                None => {
                    regs.ax = 0;
                    Completion::with_zero(true)
                }
            },
            0x02 => {
                // Shift status lives in the BDA (`0x417`); the model keeps no
                // shift state, so report "no shift held".
                regs.ax &= 0xFF00;
                Completion::OK
            }
            _ => fail_ah(regs, STATUS_INVALID_FUNCTION),
        }
    }

    /// Returns the next key from the guest ring, then from the model queue.
    ///
    /// `consume` advances the ring tail by one entry (two bytes) or pops the
    /// model queue; a peek reads without changing either.
    fn take_key(&mut self, mem: &mut impl BiosMemory, consume: bool) -> Option<(u8, u8)> {
        if let Some((head, tail)) = self.keyboard_ring(mem) {
            if head != tail {
                let offset = ring_offset(tail)?;
                let scan = mem.read_u8(BDA_KEY_BUFFER + u32::from(offset))?;
                let ascii = mem.read_u8(BDA_KEY_BUFFER + u32::from(offset) + 1)?;
                if consume {
                    let next = KEY_BUFFER_FIRST_OFFSET + ((offset + 2) & (KEY_BUFFER_BYTES - 1));
                    let _ = write_u16(mem, BDA_KEYBOARD_TAIL, next);
                }
                return Some((scan, ascii));
            }
        }
        if consume {
            self.keyboard.pop_front()
        } else {
            self.keyboard.front().copied()
        }
    }

    /// Reads the guest keyboard ring head/tail words.
    fn keyboard_ring(&self, mem: &mut impl BiosMemory) -> Option<(u16, u16)> {
        let head = read_u16(mem, BDA_KEYBOARD_HEAD)?;
        let tail = read_u16(mem, BDA_KEYBOARD_TAIL)?;
        Some((head, tail))
    }

    /// `INT 17h`: printer services (accepted, output discarded).
    fn printer_service(&mut self, regs: &mut BiosRegisters) -> Completion {
        match (regs.ax >> 8) as u8 {
            0x00 | 0x01 | 0x02 => {
                set_ah(regs, PRINTER_STATUS);
                Completion::OK
            }
            _ => fail_ah(regs, STATUS_INVALID_FUNCTION),
        }
    }

    /// `INT 1Ah`: time services.
    fn time_service(&mut self, regs: &mut BiosRegisters) -> Completion {
        match (regs.ax >> 8) as u8 {
            0x00 => {
                regs.cx = (self.ticks >> 16) as u16;
                regs.dx = self.ticks as u16;
                regs.ax &= 0xFF00;
                Completion::OK
            }
            0x02 => {
                regs.cx = (bcd(self.rtc_hour) as u16) << 8 | bcd(self.rtc_minute) as u16;
                regs.dx = (bcd(self.rtc_second) as u16) << 8;
                Completion::OK
            }
            _ => fail_ah(regs, STATUS_INVALID_FUNCTION),
        }
    }
}

impl Default for BiosState {
    fn default() -> Self {
        Self::new()
    }
}

/// Outcome of one service handler: the pair of flags the scratch byte carries.
#[derive(Debug, Clone, Copy)]
struct Completion {
    carry: bool,
    zero: bool,
}

impl Completion {
    /// `CF=0`, `ZF=0`.
    const OK: Self = Self {
        carry: false,
        zero: false,
    };

    /// `CF=0`, `ZF=value`.
    const fn with_zero(value: bool) -> Self {
        Self {
            carry: false,
            zero: value,
        }
    }
}

/// Writes `status` into `AH` and reports a failure.
fn fail_ah(regs: &mut BiosRegisters, status: u8) -> Completion {
    set_ah(regs, status);
    Completion {
        carry: true,
        zero: false,
    }
}

/// Replaces `AH` without touching `AL`.
fn set_ah(regs: &mut BiosRegisters, value: u8) {
    regs.ax = (regs.ax & 0x00FF) | (u16::from(value) << 8);
}

/// Accepts only the two documented drive numbers.
///
/// Returns `Some(true)` for the fixed disk, `Some(false)` for the floppy and
/// `None` for anything else.
fn drive_kind(drive: u8) -> Option<bool> {
    match drive {
        FLOPPY_DRIVE => Some(false),
        HARD_DISK_DRIVE => Some(true),
        _ => None,
    }
}

/// Computes a real-mode linear address from a segment and an offset.
pub const fn linear_address(segment: u16, offset: u16) -> u32 {
    (segment as u32) * 16 + offset as u32
}

/// Checks that `count` sectors starting at `lba` exist on the medium.
///
/// `INT 13h AH=04h` verifies addresses without transferring data: the synthetic
/// controller has no latent media errors, so an in-range request succeeds. DOS
/// issues it after each write when verification is enabled, and formatters use
/// it to check the volume they just created.
fn verify_sectors(disk: &mut dyn BiosDisk, lba: u64, count: u64) -> Result<(), u8> {
    let total = disk.sectors();
    for index in 0..count {
        let current = lba.checked_add(index).ok_or(DISK_STATUS_SECTOR_NOT_FOUND)?;
        if current >= total {
            return Err(DISK_STATUS_SECTOR_NOT_FOUND);
        }
    }
    Ok(())
}

/// Reads one sector after another into a guest buffer.
///
/// Each byte is written through [`BiosMemory`], so a buffer that leaves mapped
/// memory aborts the transfer with [`DISK_STATUS_SECTOR_NOT_FOUND`] instead of
/// panicking. Bytes already written are not rolled back.
fn read_sectors(
    mem: &mut impl BiosMemory,
    disk: &mut dyn BiosDisk,
    lba: u64,
    count: u64,
    buffer: u32,
) -> Result<(), u8> {
    let mut sector = [0u8; SECTOR_SIZE];
    let total = disk.sectors();
    for index in 0..count {
        let current = lba.checked_add(index).ok_or(DISK_STATUS_SECTOR_NOT_FOUND)?;
        if current >= total || !disk.read_sector(current, &mut sector) {
            return Err(DISK_STATUS_SECTOR_NOT_FOUND);
        }
        let base = u64::from(buffer) + index * SECTOR_SIZE as u64;
        for (offset, byte) in sector.iter().enumerate() {
            let address = base + offset as u64;
            if address > u64::from(u32::MAX) {
                return Err(DISK_STATUS_SECTOR_NOT_FOUND);
            }
            if !mem.write_u8(address as u32, *byte) {
                return Err(DISK_STATUS_SECTOR_NOT_FOUND);
            }
        }
    }
    Ok(())
}

/// Writes `count` sectors from a guest buffer, one sector at a time.
///
/// Mirrors [`read_sectors`]: the guest buffer is read byte by byte so an
/// unmapped page fails the call instead of touching host memory.
fn write_sectors(
    mem: &mut impl BiosMemory,
    disk: &mut dyn BiosDisk,
    lba: u64,
    count: u64,
    buffer: u32,
) -> Result<(), u8> {
    let mut sector = [0u8; SECTOR_SIZE];
    let total = disk.sectors();
    for index in 0..count {
        let current = lba.checked_add(index).ok_or(DISK_STATUS_SECTOR_NOT_FOUND)?;
        if current >= total {
            return Err(DISK_STATUS_SECTOR_NOT_FOUND);
        }
        let base = u64::from(buffer) + index * SECTOR_SIZE as u64;
        for (offset, slot) in sector.iter_mut().enumerate() {
            let address = base + offset as u64;
            if address > u64::from(u32::MAX) {
                return Err(DISK_STATUS_SECTOR_NOT_FOUND);
            }
            *slot = mem
                .read_u8(address as u32)
                .ok_or(DISK_STATUS_SECTOR_NOT_FOUND)?;
        }
        if !disk.write_sector(current, &sector) {
            return Err(DISK_STATUS_WRITE_PROTECTED);
        }
    }
    Ok(())
}

/// Decodes a BDA keyboard ring offset.
///
/// A PC firmware keeps the head/tail words as offsets inside the BDA
/// (`0x1E..=0x3E`); a guest that kept the older `0..0x20` convention is also
/// accepted, which keeps the model usable from either producer.
fn ring_offset(value: u16) -> Option<u16> {
    if value >= KEY_BUFFER_FIRST_OFFSET && value < KEY_BUFFER_FIRST_OFFSET + KEY_BUFFER_BYTES {
        Some(value - KEY_BUFFER_FIRST_OFFSET)
    } else if value < KEY_BUFFER_BYTES {
        Some(value)
    } else {
        None
    }
}
/// Reads a little-endian `u16` from guest memory.
fn read_u16(mem: &mut impl BiosMemory, address: u32) -> Option<u16> {
    let mut bytes = [0u8; 2];
    if mem.read(address, &mut bytes) {
        Some(u16::from_le_bytes(bytes))
    } else {
        None
    }
}

/// Reads a little-endian `u64` from guest memory.
fn read_u64(mem: &mut impl BiosMemory, address: u32) -> Option<u64> {
    let mut bytes = [0u8; 8];
    if mem.read(address, &mut bytes) {
        Some(u64::from_le_bytes(bytes))
    } else {
        None
    }
}

/// Writes a little-endian `u16` to guest memory.
fn write_u16(mem: &mut impl BiosMemory, address: u32, value: u16) -> bool {
    mem.write(address, &value.to_le_bytes())
}

/// Writes a little-endian `u32` to guest memory.
fn write_u32(mem: &mut impl BiosMemory, address: u32, value: u32) -> bool {
    mem.write(address, &value.to_le_bytes())
}

/// Guest-physical address of one text cell.
const fn video_cell(row: u8, col: u8) -> u32 {
    VIDEO_BASE + (row as u32 * TEXT_COLUMNS as u32 + col as u32) * 2
}

/// Reads one character/attribute cell, falling back to a blank cell.
fn read_cell(mem: &mut impl BiosMemory, row: u8, col: u8) -> (u8, u8) {
    let address = video_cell(row, col);
    let ch = mem.read_u8(address).unwrap_or(SPACE);
    let attr = mem.read_u8(address + 1).unwrap_or(DEFAULT_ATTRIBUTE);
    (ch, attr)
}

/// Writes one character/attribute cell when it is inside the text screen.
fn write_cell(mem: &mut impl BiosMemory, row: u8, col: u8, ch: u8, attr: u8) -> bool {
    if row >= TEXT_ROWS || col >= TEXT_COLUMNS {
        return false;
    }
    let address = video_cell(row, col);
    let character = mem.write_u8(address, ch);
    let attribute = mem.write_u8(address + 1, attr);
    character && attribute
}

/// Scrolls a rectangular text window up or down.
///
/// `lines == 0` blanks the whole window. Vacated cells receive `attr`. The
/// caller has already clamped the window to the screen and checked that
/// `top <= bottom` and `left <= right`.
fn scroll_region(
    mem: &mut impl BiosMemory,
    up: bool,
    lines: u8,
    attr: u8,
    top: u8,
    left: u8,
    bottom: u8,
    right: u8,
) -> bool {
    let height = bottom - top + 1;
    let count = if lines == 0 {
        height
    } else {
        lines.min(height)
    };
    if up {
        for row in top..=bottom {
            for col in left..=right {
                let (ch, attribute) = if row + count <= bottom {
                    read_cell(mem, row + count, col)
                } else {
                    (SPACE, attr)
                };
                let _ = write_cell(mem, row, col, ch, attribute);
            }
        }
    } else {
        for row in (top..=bottom).rev() {
            for col in left..=right {
                let (ch, attribute) = if row >= top + count {
                    read_cell(mem, row - count, col)
                } else {
                    (SPACE, attr)
                };
                let _ = write_cell(mem, row, col, ch, attribute);
            }
        }
    }
    true
}

/// Encodes a binary byte as two packed BCD digits.
///
/// Values above 99 are clamped so the result always consists of valid digits;
/// callers are expected to keep the RTC fields in range.
fn bcd(value: u8) -> u8 {
    let clamped = value.min(99);
    (clamped / 10 << 4) | (clamped % 10)
}

/// Installs the BIOS data area fields a DOS boot reads.
///
/// The image receives a 640 KiB machine with one 1.44 MiB floppy, an EBDA
/// segment, a home cursor on page 0, an 80x25 colour text mode, a `0x03D4`
/// CRTC port and a zero tick counter. Writes that the adapter refuses are
/// ignored: the helper never panics.
pub fn initialise_bda(mem: &mut impl BiosMemory) {
    let _ = write_u16(mem, BDA_EBDA_SEGMENT, EBDA_SEGMENT);
    let _ = write_u16(mem, BDA_EQUIPMENT, EQUIPMENT_WORD);
    let _ = write_u16(mem, BDA_MEMORY_SIZE, MEMORY_SIZE_KIB);
    // A PC firmware leaves the keyboard ring empty: head == tail == the first
    // slot offset (0x1E), the convention DOS continues from.
    let _ = write_u16(mem, BDA_KEYBOARD_HEAD, KEY_BUFFER_FIRST_OFFSET);
    let _ = write_u16(mem, BDA_KEYBOARD_TAIL, KEY_BUFFER_FIRST_OFFSET);
    let _ = mem.write_u8(BDA_VIDEO_MODE, DEFAULT_VIDEO_MODE);
    let _ = write_u16(mem, BDA_COLUMNS, DEFAULT_COLUMNS);
    let _ = write_u16(mem, BDA_CURSOR, 0);
    let _ = mem.write_u8(BDA_PAGE, DEFAULT_PAGE);
    let _ = write_u16(mem, BDA_CRTC_PORT, DEFAULT_CRTC_PORT);
    let _ = mem.write_u8(BDA_ROWS, DEFAULT_ROWS_MINUS_ONE);
    let _ = mem.write_u8(BDA_CHAR_HEIGHT, DEFAULT_CHAR_HEIGHT);
    let _ = write_u32(mem, BDA_TICK_COUNT, 0);
}

/// Renders the 80x25 text screen as trimmed lines.
///
/// Each row is read from [`VIDEO_BASE`] (character bytes at even addresses),
/// trailing spaces are removed, trailing empty rows are dropped and rows are
/// joined with `'\n'`. Bytes outside the printable ASCII range become spaces.
pub fn read_text(mem: &mut impl BiosMemory) -> String {
    let mut rows: Vec<String> = Vec::with_capacity(TEXT_ROWS as usize);
    for row in 0..TEXT_ROWS {
        let mut line = String::new();
        for col in 0..TEXT_COLUMNS {
            let (ch, _) = read_cell(mem, row, col);
            line.push(if (0x20..=0x7E).contains(&ch) {
                ch as char
            } else {
                ' '
            });
        }
        while line.ends_with(' ') {
            line.pop();
        }
        rows.push(line);
    }
    while rows.last().map_or(false, |line| line.is_empty()) {
        rows.pop();
    }
    let mut text = String::new();
    for (index, line) in rows.iter().enumerate() {
        if index != 0 {
            text.push('\n');
        }
        text.push_str(line);
    }
    text
}
