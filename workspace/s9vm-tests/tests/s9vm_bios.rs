//! L2: s9vm pure PC BIOS service model (real kernel code).
//!
//! The fixture supplies a flat 1 MiB guest memory image and a deterministic
//! 1.44 MiB synthetic disk (sector `i` filled with `i as u8`). Every test
//! drives [`bios::BiosState::handle`] exactly as the kernel adapter does and
//! checks the returned registers, the scratch byte and the guest buffers.

extern crate alloc;

#[path = "../../kernel/src/s9vm/bios.rs"]
mod bios;

use bios::{
    initialise_bda, linear_address, read_text, BiosDisk, BiosMemory, BiosOutcome, BiosRegisters,
    BiosState, DiskGeometry, BDA_BASE, BDA_CHAR_HEIGHT, BDA_COLUMNS, BDA_CRTC_PORT, BDA_CURSOR,
    BDA_EBDA_SEGMENT, BDA_EQUIPMENT, BDA_KEYBOARD_HEAD, BDA_KEYBOARD_TAIL, BDA_MEMORY_SIZE,
    BDA_PAGE, BDA_ROWS, BDA_TICK_COUNT, BDA_VIDEO_MODE, DISK_STATUS_INVALID_FUNCTION,
    DISK_STATUS_MEDIA_NOT_FOUND, DISK_STATUS_SECTOR_NOT_FOUND, DISK_STATUS_WRITE_PROTECTED,
    EQUIPMENT_WORD, EXTENSIONS_SIGNATURE, FLOPPY_1440, FLOPPY_TOTAL_SECTORS, HARD_DISK_GEOMETRY,
    KEY_BUFFER_BYTES, KEY_BUFFER_CAPACITY, MEMORY_SIZE_KIB, PRINTER_STATUS, SCRATCH_CF,
    SCRATCH_GPA, SCRATCH_ZF, STATUS_INVALID_FUNCTION, STATUS_NOT_SUPPORTED, TEXT_COLUMNS,
    TEXT_ROWS, VIDEO_BASE, VIDEO_LEN,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Flat guest memory of 1 MiB, addressed with linear addresses.
struct TestMemory {
    data: Vec<u8>,
}

impl TestMemory {
    fn new() -> Self {
        Self {
            data: vec![0u8; 0x10_0000],
        }
    }

    fn u8_at(&self, address: u32) -> u8 {
        self.data[address as usize]
    }

    fn u16_at(&self, address: u32) -> u16 {
        let index = address as usize;
        u16::from_le_bytes([self.data[index], self.data[index + 1]])
    }

    fn u32_at(&self, address: u32) -> u32 {
        let index = address as usize;
        u32::from_le_bytes([
            self.data[index],
            self.data[index + 1],
            self.data[index + 2],
            self.data[index + 3],
        ])
    }

    fn set_bytes(&mut self, address: u32, bytes: &[u8]) {
        let start = address as usize;
        self.data[start..start + bytes.len()].copy_from_slice(bytes);
    }

    fn fill(&mut self, address: u32, len: usize, value: u8) {
        let start = address as usize;
        self.data[start..start + len].fill(value);
    }
}

impl BiosMemory for TestMemory {
    fn read_u8(&mut self, linear: u32) -> Option<u8> {
        self.data.get(linear as usize).copied()
    }

    fn write_u8(&mut self, linear: u32, value: u8) -> bool {
        match self.data.get_mut(linear as usize) {
            Some(slot) => {
                *slot = value;
                true
            }
            None => false,
        }
    }

    fn read(&mut self, linear: u32, out: &mut [u8]) -> bool {
        let start = linear as usize;
        let Some(end) = start.checked_add(out.len()) else {
            return false;
        };
        match self.data.get(start..end) {
            Some(bytes) => {
                out.copy_from_slice(bytes);
                true
            }
            None => false,
        }
    }

    fn write(&mut self, linear: u32, bytes: &[u8]) -> bool {
        let start = linear as usize;
        let Some(end) = start.checked_add(bytes.len()) else {
            return false;
        };
        match self.data.get_mut(start..end) {
            Some(slot) => {
                slot.copy_from_slice(bytes);
                true
            }
            None => false,
        }
    }
}

/// Synthetic 1.44 MiB disk: sector `i` is filled with `(i & 0xFF)`.
struct TestDisk {
    sectors: u64,
    fail_from: Option<u64>,
}

impl TestDisk {
    fn new() -> Self {
        Self {
            sectors: FLOPPY_TOTAL_SECTORS,
            fail_from: None,
        }
    }

    fn with_sectors(sectors: u64) -> Self {
        Self {
            sectors,
            fail_from: None,
        }
    }
}

impl BiosDisk for TestDisk {
    fn sectors(&self) -> u64 {
        self.sectors
    }

    fn read_sector(&mut self, sector: u64, out: &mut [u8; 512]) -> bool {
        if sector >= self.sectors || self.fail_from == Some(sector) {
            return false;
        }
        out.fill((sector & 0xFF) as u8);
        true
    }
}

struct Fixture {
    state: BiosState,
    mem: TestMemory,
    disk: TestDisk,
}

impl Fixture {
    fn new() -> Self {
        let mut mem = TestMemory::new();
        initialise_bda(&mut mem);
        Self {
            state: BiosState::new(),
            mem,
            disk: TestDisk::new(),
        }
    }

    fn call(&mut self, vector: u8, regs: &mut BiosRegisters) -> BiosOutcome {
        self.state
            .handle(vector, regs, &mut self.mem, &mut self.disk)
    }

    fn scratch(&self) -> u8 {
        self.mem.u8_at(SCRATCH_GPA)
    }

    fn carry(&self) -> bool {
        self.scratch() & SCRATCH_CF != 0
    }

    fn zero(&self) -> bool {
        self.scratch() & SCRATCH_ZF != 0
    }

    fn cell(&self, row: u8, col: u8) -> (u8, u8) {
        cell(&self.mem, row, col)
    }

    fn set_cell(&mut self, row: u8, col: u8, ch: u8, attr: u8) {
        set_cell(&mut self.mem, row, col, ch, attr);
    }
}

fn cell(mem: &TestMemory, row: u8, col: u8) -> (u8, u8) {
    let address = VIDEO_BASE + (row as u32 * TEXT_COLUMNS as u32 + col as u32) * 2;
    (mem.u8_at(address), mem.u8_at(address + 1))
}

fn set_cell(mem: &mut TestMemory, row: u8, col: u8, ch: u8, attr: u8) {
    let address = VIDEO_BASE + (row as u32 * TEXT_COLUMNS as u32 + col as u32) * 2;
    mem.set_bytes(address, &[ch, attr]);
}

fn ah(regs: &BiosRegisters) -> u8 {
    (regs.ax >> 8) as u8
}

fn al(regs: &BiosRegisters) -> u8 {
    regs.ax as u8
}

fn write_dap(
    mem: &mut TestMemory,
    address: u32,
    size: u8,
    count: u16,
    offset: u16,
    segment: u16,
    lba: u64,
) {
    let mut bytes = [0u8; 16];
    bytes[0] = size;
    bytes[2..4].copy_from_slice(&count.to_le_bytes());
    bytes[4..6].copy_from_slice(&offset.to_le_bytes());
    bytes[6..8].copy_from_slice(&segment.to_le_bytes());
    bytes[8..16].copy_from_slice(&lba.to_le_bytes());
    mem.set_bytes(address, &bytes);
}

// ---------------------------------------------------------------------------
// Register file, traits and geometry
// ---------------------------------------------------------------------------

#[test]
fn registers_new_is_zeroed_and_matches_default() {
    let regs = BiosRegisters::new();
    assert_eq!(regs.ax, 0);
    assert_eq!(regs.bx, 0);
    assert_eq!(regs.cx, 0);
    assert_eq!(regs.dx, 0);
    assert_eq!(regs.si, 0);
    assert_eq!(regs.di, 0);
    assert_eq!(regs.bp, 0);
    assert_eq!(regs.sp, 0);
    assert_eq!(regs.ds, 0);
    assert_eq!(regs.es, 0);
    assert_eq!(regs.ss, 0);
    assert_eq!(regs.cs, 0);
    assert_eq!(regs.ip, 0);
    assert_eq!(regs.flags, 0);
    assert!(!regs.carry());
    assert!(!regs.zero());
    assert_eq!(BiosRegisters::default(), regs);
}

#[test]
fn gpr_uses_x86_encoding_order() {
    let mut regs = BiosRegisters::new();
    let values = [
        0x1111u16, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888,
    ];
    for (index, value) in values.iter().enumerate() {
        regs.set_gpr(index as u8, *value);
    }
    assert_eq!(regs.ax, 0x1111);
    assert_eq!(regs.cx, 0x2222);
    assert_eq!(regs.dx, 0x3333);
    assert_eq!(regs.bx, 0x4444);
    assert_eq!(regs.sp, 0x5555);
    assert_eq!(regs.bp, 0x6666);
    assert_eq!(regs.si, 0x7777);
    assert_eq!(regs.di, 0x8888);
    for index in 0..8u8 {
        assert_eq!(regs.gpr(index), values[index as usize]);
    }
}

#[test]
fn gpr_rejects_extended_and_out_of_range_encodings() {
    let mut regs = BiosRegisters::new();
    regs.ax = 0x1234;
    for register in 8..=15u8 {
        assert_eq!(regs.gpr(register), 0);
        regs.set_gpr(register, 0xFFFF);
    }
    for register in 16..=255u8 {
        assert_eq!(regs.gpr(register), 0);
        regs.set_gpr(register, 0xFFFF);
    }
    assert_eq!(regs.ax, 0x1234);
    assert_eq!(regs.di, 0);
}

#[test]
fn carry_and_zero_helpers_toggle_only_their_bit() {
    let mut regs = BiosRegisters::new();
    regs.set_carry(true);
    assert!(regs.carry());
    assert_eq!(regs.flags, 0x0001);
    regs.set_zero(true);
    assert!(regs.zero());
    assert_eq!(regs.flags, 0x0041);
    regs.set_carry(false);
    assert!(!regs.carry());
    assert!(regs.zero());
    assert_eq!(regs.flags, 0x0040);
    regs.set_zero(false);
    assert_eq!(regs.flags, 0);
}

#[test]
fn floppy_geometry_is_one_point_four_four() {
    assert_eq!(FLOPPY_1440.cylinders, 80);
    assert_eq!(FLOPPY_1440.heads, 2);
    assert_eq!(FLOPPY_1440.sectors_per_track, 18);
    assert_eq!(FLOPPY_1440.sector_size, 512);
    assert_eq!(FLOPPY_TOTAL_SECTORS, 2880);
}

#[test]
fn geometry_lba_maps_one_based_sectors() {
    let geometry = FLOPPY_1440;
    assert_eq!(geometry.lba(0, 0, 1), Some(0));
    assert_eq!(geometry.lba(0, 0, 18), Some(17));
    assert_eq!(geometry.lba(0, 1, 1), Some(18));
    assert_eq!(geometry.lba(1, 0, 1), Some(36));
    assert_eq!(geometry.lba(79, 1, 18), Some(2879));
    assert_eq!(geometry.lba(80, 0, 1), None);
    assert_eq!(geometry.lba(0, 2, 1), None);
    assert_eq!(geometry.lba(0, 0, 0), None);
    assert_eq!(geometry.lba(0, 0, 19), None);
}

#[test]
fn geometry_from_sectors_selects_floppy_or_fixed_disk() {
    assert_eq!(DiskGeometry::from_sectors(0), FLOPPY_1440);
    assert_eq!(DiskGeometry::from_sectors(2880), FLOPPY_1440);
    assert_eq!(DiskGeometry::from_sectors(2881), HARD_DISK_GEOMETRY);
    assert_eq!(HARD_DISK_GEOMETRY.cylinders, 1024);
    assert_eq!(HARD_DISK_GEOMETRY.heads, 16);
    assert_eq!(HARD_DISK_GEOMETRY.sectors_per_track, 63);
    assert_eq!(HARD_DISK_GEOMETRY.sector_size, 512);
    assert_eq!(DiskGeometry::from_sectors(u64::MAX), HARD_DISK_GEOMETRY);
}

#[test]
fn linear_address_combines_segment_and_offset() {
    assert_eq!(linear_address(0, 0), 0);
    assert_eq!(linear_address(0x1234, 0x5678), 0x179B8);
    assert_eq!(linear_address(0xFFFF, 0xFFFF), 0x10FFEF);
}

// ---------------------------------------------------------------------------
// BIOS data area and scratch protocol
// ---------------------------------------------------------------------------

#[test]
fn initialise_bda_writes_dos_fields() {
    let mut mem = TestMemory::new();
    initialise_bda(&mut mem);
    assert_eq!(BDA_BASE, 0x0400);
    assert_eq!(BDA_EQUIPMENT, BDA_BASE + 0x10);
    assert_eq!(mem.u16_at(BDA_EBDA_SEGMENT), 0x9FC0);
    assert_eq!(mem.u16_at(BDA_EQUIPMENT), EQUIPMENT_WORD);
    assert_eq!(mem.u16_at(BDA_MEMORY_SIZE), MEMORY_SIZE_KIB);
    assert_eq!(mem.u16_at(BDA_KEYBOARD_HEAD), 0);
    assert_eq!(mem.u16_at(BDA_KEYBOARD_TAIL), 0);
    assert_eq!(mem.u32_at(BDA_TICK_COUNT), 0);
    assert_eq!(mem.u8_at(BDA_VIDEO_MODE), 3);
    assert_eq!(mem.u16_at(BDA_COLUMNS), 80);
    assert_eq!(mem.u16_at(BDA_CURSOR), 0);
    assert_eq!(mem.u8_at(BDA_PAGE), 0);
    assert_eq!(mem.u16_at(BDA_CRTC_PORT), 0x03D4);
    assert_eq!(mem.u8_at(BDA_ROWS), 24);
    assert_eq!(mem.u8_at(BDA_CHAR_HEIGHT), 16);
}

#[test]
fn unknown_vectors_write_a_clear_scratch_byte() {
    let mut fixture = Fixture::new();
    for vector in [0x08u8, 0x1C, 0x20, 0x4A, 0xFF] {
        fixture.mem.fill(SCRATCH_GPA, 1, 0xFF);
        let mut regs = BiosRegisters::new();
        assert_eq!(fixture.call(vector, &mut regs), BiosOutcome::Unknown);
        assert_eq!(fixture.scratch(), 0);
        assert!(!fixture.carry());
        assert!(!fixture.zero());
    }
}

#[test]
fn successful_call_clears_both_scratch_bits() {
    let mut fixture = Fixture::new();
    fixture.mem.fill(SCRATCH_GPA, 1, 0xFF);
    let mut regs = BiosRegisters::new();
    assert_eq!(fixture.call(0x12, &mut regs), BiosOutcome::Handled);
    assert_eq!(fixture.scratch(), 0);
}

#[test]
fn failed_call_sets_only_the_carry_bit() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0301;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert_eq!(fixture.scratch(), SCRATCH_CF);
    assert!(fixture.carry());
    assert!(!fixture.zero());
}

#[test]
fn empty_keyboard_sets_only_the_zero_bit() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    assert_eq!(fixture.call(0x16, &mut regs), BiosOutcome::Handled);
    assert_eq!(fixture.scratch(), SCRATCH_ZF);
    assert!(!fixture.carry());
    assert!(fixture.zero());
}

#[test]
fn handle_mirrors_cf_and_zf_into_the_register_file() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.flags = 0x8000;
    regs.ax = 0x0301;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert!(regs.carry());
    assert!(!regs.zero());
    assert_eq!(regs.flags & 0x8000, 0x8000);
    assert_eq!(fixture.scratch(), SCRATCH_CF);

    let mut regs = BiosRegisters::new();
    assert_eq!(fixture.call(0x16, &mut regs), BiosOutcome::Handled);
    assert!(!regs.carry());
    assert!(regs.zero());
    assert_eq!(fixture.scratch(), SCRATCH_ZF);
}

#[test]
fn every_vector_writes_a_valid_scratch_byte() {
    let mut fixture = Fixture::new();
    for vector in 0..=255u8 {
        fixture.mem.fill(SCRATCH_GPA, 1, 0xFF);
        let mut regs = BiosRegisters::new();
        let _ = fixture.call(vector, &mut regs);
        assert!(fixture.scratch() <= SCRATCH_CF | SCRATCH_ZF);
    }
}

// ---------------------------------------------------------------------------
// INT 10h: modes, cursor, pages
// ---------------------------------------------------------------------------

#[test]
fn set_mode_3_clears_the_video_window() {
    let mut fixture = Fixture::new();
    fixture.mem.fill(VIDEO_BASE, VIDEO_LEN as usize, 0xAA);
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0003;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!(fixture.scratch(), 0);
    assert_eq!(ah(&regs), 0);
    assert_eq!(fixture.state.video_mode, 3);
    assert_eq!(fixture.mem.u8_at(BDA_VIDEO_MODE), 3);
    assert_eq!(fixture.cell(0, 0), (0x20, 0x07));
    let end = VIDEO_BASE + VIDEO_LEN - 2;
    assert_eq!(fixture.mem.u8_at(end), 0x20);
    assert_eq!(fixture.mem.u8_at(end + 1), 0x07);
    assert_eq!((fixture.state.cursor_row, fixture.state.cursor_col), (0, 0));
    assert_eq!(fixture.mem.u16_at(BDA_CURSOR), 0);
}

#[test]
fn set_mode_7_is_accepted_and_recorded() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0007;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!(fixture.state.video_mode, 7);
    assert_eq!(fixture.mem.u8_at(BDA_VIDEO_MODE), 7);
    assert!(!fixture.carry());
}

#[test]
fn set_mode_rejects_other_modes_without_touching_the_screen() {
    let mut fixture = Fixture::new();
    fixture.set_cell(0, 0, b'M', 0x0F);
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0013;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert!(fixture.carry());
    assert_eq!(ah(&regs), STATUS_INVALID_FUNCTION);
    assert_eq!(fixture.state.video_mode, 3);
    assert_eq!(fixture.cell(0, 0), (b'M', 0x0F));
}

#[test]
fn cursor_shape_is_accepted_as_a_no_op() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0100;
    regs.cx = 0x0B0C;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert!(!fixture.carry());
    assert_eq!(fixture.scratch(), 0);
}

#[test]
fn set_cursor_clamps_and_updates_the_bda() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0200;
    regs.dx = 30 << 8 | 100;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!(
        (fixture.state.cursor_row, fixture.state.cursor_col),
        (24, 79)
    );
    assert_eq!(fixture.mem.u16_at(BDA_CURSOR), 24 << 8 | 79);

    regs.dx = 5 << 8 | 7;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!((fixture.state.cursor_row, fixture.state.cursor_col), (5, 7));
    assert_eq!(fixture.mem.u16_at(BDA_CURSOR), 5 << 8 | 7);
}

#[test]
fn get_cursor_returns_position_and_shape() {
    let mut fixture = Fixture::new();
    fixture.state.cursor_row = 12;
    fixture.state.cursor_col = 34;
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0300;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!(regs.cx, 0x0607);
    assert_eq!(regs.dx, 12 << 8 | 34);
    assert!(!fixture.carry());
}

#[test]
fn set_page_zero_succeeds_and_other_pages_fail() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0500;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert!(!fixture.carry());
    assert_eq!(fixture.mem.u8_at(BDA_PAGE), 0);

    regs.ax = 0x0501;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert!(fixture.carry());
    assert_eq!(ah(&regs), STATUS_INVALID_FUNCTION);
}

// ---------------------------------------------------------------------------
// INT 10h: characters and teletype
// ---------------------------------------------------------------------------

#[test]
fn read_char_and_attribute_at_cursor() {
    let mut fixture = Fixture::new();
    fixture.state.cursor_row = 3;
    fixture.state.cursor_col = 4;
    fixture.set_cell(3, 4, b'Q', 0x2E);
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0800;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!(al(&regs), b'Q');
    assert_eq!(ah(&regs), 0x2E);
}

#[test]
fn write_char_and_attribute_repeats_without_moving_the_cursor() {
    let mut fixture = Fixture::new();
    fixture.state.cursor_row = 1;
    fixture.state.cursor_col = 2;
    let mut regs = BiosRegisters::new();
    regs.ax = 0x092A;
    regs.bx = 0x004E;
    regs.cx = 3;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    for col in 2..=4 {
        assert_eq!(fixture.cell(1, col), (b'*', 0x4E));
    }
    assert_eq!((fixture.state.cursor_row, fixture.state.cursor_col), (1, 2));
    assert_eq!(fixture.mem.u16_at(BDA_CURSOR), 1 << 8 | 2);
}

#[test]
fn write_char_only_preserves_the_existing_attribute() {
    let mut fixture = Fixture::new();
    fixture.state.cursor_row = 2;
    fixture.state.cursor_col = 0;
    fixture.set_cell(2, 0, b'o', 0x1F);
    fixture.set_cell(2, 1, b'o', 0x1F);
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0A58;
    regs.cx = 2;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!(fixture.cell(2, 0), (b'X', 0x1F));
    assert_eq!(fixture.cell(2, 1), (b'X', 0x1F));
}

#[test]
fn teletype_prints_and_advances_the_cursor() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0E41;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!(fixture.cell(0, 0), (b'A', 0x07));
    assert_eq!((fixture.state.cursor_row, fixture.state.cursor_col), (0, 1));
    assert_eq!(fixture.mem.u16_at(BDA_CURSOR), 1);
}

#[test]
fn teletype_backspace_moves_one_cell_back() {
    let mut fixture = Fixture::new();
    fixture.state.cursor_row = 0;
    fixture.state.cursor_col = 2;
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0E08;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!(fixture.state.cursor_col, 1);

    fixture.state.cursor_row = 0;
    fixture.state.cursor_col = 0;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!((fixture.state.cursor_row, fixture.state.cursor_col), (0, 0));

    fixture.state.cursor_row = 1;
    fixture.state.cursor_col = 0;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!(
        (fixture.state.cursor_row, fixture.state.cursor_col),
        (0, 79)
    );
}

#[test]
fn teletype_handles_cr_lf_and_bell() {
    let mut fixture = Fixture::new();
    fixture.state.cursor_row = 3;
    fixture.state.cursor_col = 5;
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0E0D;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!((fixture.state.cursor_row, fixture.state.cursor_col), (3, 0));

    regs.ax = 0x0E0A;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!((fixture.state.cursor_row, fixture.state.cursor_col), (4, 0));

    regs.ax = 0x0E07;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!((fixture.state.cursor_row, fixture.state.cursor_col), (4, 0));
    assert_eq!(fixture.cell(4, 0), (0, 0));
}

#[test]
fn teletype_tab_advances_to_the_next_eight_column_stop() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0E09;
    fixture.state.cursor_col = 1;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!(fixture.state.cursor_col, 8);
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!(fixture.state.cursor_col, 16);
    fixture.state.cursor_col = 72;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!((fixture.state.cursor_row, fixture.state.cursor_col), (1, 0));
}

#[test]
fn teletype_wraps_at_eighty_columns() {
    let mut fixture = Fixture::new();
    fixture.state.cursor_row = 0;
    fixture.state.cursor_col = 79;
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0E58;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!(fixture.cell(0, 79), (b'X', 0x07));
    assert_eq!((fixture.state.cursor_row, fixture.state.cursor_col), (1, 0));
    assert_eq!(fixture.mem.u16_at(BDA_CURSOR), 1 << 8);
}

#[test]
fn teletype_scrolls_when_writing_past_the_last_row() {
    let mut fixture = Fixture::new();
    fixture.set_cell(0, 0, b'A', 0x07);
    fixture.set_cell(1, 0, b'B', 0x07);
    fixture.state.cursor_row = TEXT_ROWS - 1;
    fixture.state.cursor_col = TEXT_COLUMNS - 1;
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0E5A;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!(fixture.cell(0, 0), (b'B', 0x07));
    assert_eq!(fixture.cell(23, 79), (b'Z', 0x07));
    assert_eq!(fixture.cell(24, 0), (0x20, 0x07));
    assert_eq!(
        (fixture.state.cursor_row, fixture.state.cursor_col),
        (24, 0)
    );
}

// ---------------------------------------------------------------------------
// INT 10h: scrolling
// ---------------------------------------------------------------------------

#[test]
fn scroll_up_moves_rows_and_blanks_with_bh() {
    let mut fixture = Fixture::new();
    for (row, ch) in [(0u8, b'A'), (1, b'B'), (2, b'C'), (3, b'D'), (4, b'E')] {
        fixture.set_cell(row, 0, ch, 0x07);
    }
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0602;
    regs.bx = 0x1700;
    regs.cx = 0x0000;
    regs.dx = 0x044F;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!(fixture.cell(0, 0), (b'C', 0x07));
    assert_eq!(fixture.cell(1, 0), (b'D', 0x07));
    assert_eq!(fixture.cell(2, 0), (b'E', 0x07));
    assert_eq!(fixture.cell(3, 0), (0x20, 0x17));
    assert_eq!(fixture.cell(4, 0), (0x20, 0x17));
    assert!(!fixture.carry());
}

#[test]
fn scroll_up_with_zero_lines_clears_the_window() {
    let mut fixture = Fixture::new();
    fixture.set_cell(2, 3, b'X', 0x0F);
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0600;
    regs.bx = 0x1E00;
    regs.cx = 0x0000;
    regs.dx = 0x044F;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    for row in 0..5 {
        assert_eq!(fixture.cell(row, 3), (0x20, 0x1E));
    }
}

#[test]
fn scroll_down_moves_rows_and_blanks_the_top() {
    let mut fixture = Fixture::new();
    for (row, ch) in [(0u8, b'A'), (1, b'B'), (2, b'C'), (3, b'D'), (4, b'E')] {
        fixture.set_cell(row, 0, ch, 0x07);
    }
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0701;
    regs.bx = 0x1E00;
    regs.cx = 0x0000;
    regs.dx = 0x044F;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!(fixture.cell(0, 0), (0x20, 0x1E));
    assert_eq!(fixture.cell(1, 0), (b'A', 0x07));
    assert_eq!(fixture.cell(4, 0), (b'D', 0x07));
}

#[test]
fn scroll_with_an_inverted_window_is_a_successful_no_op() {
    let mut fixture = Fixture::new();
    fixture.set_cell(0, 0, b'A', 0x07);
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0601;
    regs.bx = 0x0700;
    regs.cx = 0x0500;
    regs.dx = 0x044F;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert!(!fixture.carry());
    assert_eq!(fixture.cell(0, 0), (b'A', 0x07));
}

// ---------------------------------------------------------------------------
// INT 10h: write string
// ---------------------------------------------------------------------------

#[test]
fn write_string_writes_plain_characters_with_bl_attribute() {
    let mut fixture = Fixture::new();
    fixture.mem.set_bytes(0x6000, b"Hi!");
    let mut regs = BiosRegisters::new();
    regs.ax = 0x1300;
    regs.bx = 0x001E;
    regs.cx = 3;
    regs.dx = 2 << 8 | 5;
    regs.es = 0;
    regs.bp = 0x6000;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!(fixture.cell(2, 5), (b'H', 0x1E));
    assert_eq!(fixture.cell(2, 6), (b'i', 0x1E));
    assert_eq!(fixture.cell(2, 7), (b'!', 0x1E));
    assert_eq!((fixture.state.cursor_row, fixture.state.cursor_col), (0, 0));
}

#[test]
fn write_string_attribute_bitmap_reads_pairs() {
    let mut fixture = Fixture::new();
    fixture.mem.set_bytes(0x6000, &[b'A', 0x0F, b'B', 0x1C]);
    let mut regs = BiosRegisters::new();
    regs.ax = 0x1302;
    regs.cx = 2;
    regs.dx = 0;
    regs.es = 0;
    regs.bp = 0x6000;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!(fixture.cell(0, 0), (b'A', 0x0F));
    assert_eq!(fixture.cell(0, 1), (b'B', 0x1C));
}

#[test]
fn write_string_updates_the_cursor_only_when_bit_zero_is_set() {
    let mut fixture = Fixture::new();
    fixture.mem.set_bytes(0x6000, b"AB");
    let mut regs = BiosRegisters::new();
    regs.ax = 0x1300;
    regs.cx = 2;
    regs.dx = 1 << 8;
    regs.es = 0;
    regs.bp = 0x6000;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!((fixture.state.cursor_row, fixture.state.cursor_col), (0, 0));

    regs.ax = 0x1301;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!((fixture.state.cursor_row, fixture.state.cursor_col), (1, 2));
    assert_eq!(fixture.mem.u16_at(BDA_CURSOR), 1 << 8 | 2);
}

#[test]
fn write_string_clips_at_the_bottom_right_cell() {
    let mut fixture = Fixture::new();
    fixture.mem.set_bytes(0x6000, b"0123456789");
    let mut regs = BiosRegisters::new();
    regs.ax = 0x1301;
    regs.bx = 0x0007;
    regs.cx = 10;
    regs.dx = 24 << 8 | 78;
    regs.es = 0;
    regs.bp = 0x6000;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert_eq!(fixture.cell(24, 78), (b'0', 0x07));
    assert_eq!(fixture.cell(24, 79), (b'1', 0x07));
    assert!(!fixture.carry());
    assert_eq!(
        (fixture.state.cursor_row, fixture.state.cursor_col),
        (24, 79)
    );
}

#[test]
fn write_string_stops_when_the_source_is_unmapped() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x1301;
    regs.cx = 4;
    regs.dx = 0;
    regs.es = 0xFFFF;
    regs.bp = 0xFFF0;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert!(!fixture.carry());
    assert_eq!(fixture.cell(0, 0), (0, 0));
    assert_eq!((fixture.state.cursor_row, fixture.state.cursor_col), (0, 0));
}

#[test]
fn unknown_video_function_fails_with_invalid_function() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0B00;
    assert_eq!(fixture.call(0x10, &mut regs), BiosOutcome::Handled);
    assert!(fixture.carry());
    assert_eq!(ah(&regs), STATUS_INVALID_FUNCTION);
}

// ---------------------------------------------------------------------------
// read_text
// ---------------------------------------------------------------------------

#[test]
fn read_text_trims_rows_and_drops_trailing_empty_rows() {
    let mut fixture = Fixture::new();
    fixture.mem.set_bytes(
        VIDEO_BASE + (0 * TEXT_COLUMNS as u32) * 2,
        &[b'A', 0x07, b'B', 0x07, b'C', 0x07],
    );
    fixture.mem.set_bytes(
        VIDEO_BASE + (2 * TEXT_COLUMNS as u32) * 2,
        &[b'D', 0x07, b'E', 0x07],
    );
    assert_eq!(read_text(&mut fixture.mem), "ABC\n\nDE");
}

#[test]
fn read_text_replaces_non_printable_bytes_with_spaces() {
    let mut fixture = Fixture::new();
    let row = VIDEO_BASE;
    fixture.mem.set_bytes(
        row,
        &[b'A', 0x07, 0x01, 0x07, b'B', 0x07, 0x00, 0x07, b'C', 0x07],
    );
    assert_eq!(read_text(&mut fixture.mem), "A B C");
}

// ---------------------------------------------------------------------------
// INT 11h / INT 12h
// ---------------------------------------------------------------------------

#[test]
fn int11_reports_the_equipment_word() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0xDEAD;
    assert_eq!(fixture.call(0x11, &mut regs), BiosOutcome::Handled);
    assert_eq!(regs.ax, 0x0021);
    assert_eq!(regs.ax & 1, 1);
    assert_eq!((regs.ax >> 4) & 0x03, 0b10);
    assert!(!fixture.carry());
    assert_eq!(fixture.scratch(), 0);
}

#[test]
fn int12_reports_640_kib() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    assert_eq!(fixture.call(0x12, &mut regs), BiosOutcome::Handled);
    assert_eq!(regs.ax, 640);
    assert!(!fixture.carry());
}

// ---------------------------------------------------------------------------
// INT 13h: reset, status, CHS reads
// ---------------------------------------------------------------------------

#[test]
fn disk_reset_and_status_complete_with_ah_zero() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x00FF;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert_eq!(ah(&regs), 0);
    assert!(!fixture.carry());

    regs.ax = 0x01FF;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert_eq!(ah(&regs), 0);
    assert!(!fixture.carry());
}

#[test]
fn disk_reads_sector_zero_into_the_guest_buffer() {
    let mut fixture = Fixture::new();
    fixture.mem.fill(0x8000, 513, 0xAA);
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0201;
    regs.cx = 0x0001;
    regs.dx = 0x0000;
    regs.es = 0;
    regs.bx = 0x8000;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert_eq!(ah(&regs), 0);
    assert!(!fixture.carry());
    for offset in 0..512 {
        assert_eq!(fixture.mem.u8_at(0x8000 + offset), 0);
    }
    assert_eq!(fixture.mem.u8_at(0x8200), 0xAA);
}

#[test]
fn disk_reads_sector_one_with_its_pattern() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0201;
    regs.cx = 0x0002;
    regs.es = 0;
    regs.bx = 0x8000;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert!(!fixture.carry());
    for offset in 0..512 {
        assert_eq!(fixture.mem.u8_at(0x8000 + offset), 1);
    }
}

#[test]
fn disk_reads_the_last_sector_with_cylinder_high_bits() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0201;
    regs.cx = 0x4F12; // cylinder 79 (0x4F), sector 18
    regs.dx = 0x0100; // head 1, drive 0
    regs.es = 0;
    regs.bx = 0x8000;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert!(!fixture.carry());
    let pattern = (2879 & 0xFF) as u8;
    for offset in 0..512 {
        assert_eq!(fixture.mem.u8_at(0x8000 + offset), pattern);
    }
}

#[test]
fn disk_reads_multiple_sectors_back_to_back() {
    let mut fixture = Fixture::new();
    fixture.mem.fill(0x8000, 3 * 512, 0xAA);
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0202;
    regs.cx = 0x0002;
    regs.es = 0;
    regs.bx = 0x8000;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert!(!fixture.carry());
    for offset in 0..512 {
        assert_eq!(fixture.mem.u8_at(0x8000 + offset), 1);
        assert_eq!(fixture.mem.u8_at(0x8200 + offset), 2);
    }
    assert_eq!(fixture.mem.u8_at(0x8400), 0xAA);
}

#[test]
fn disk_decodes_cylinder_high_bits_on_a_fixed_disk() {
    let mut fixture = Fixture::new();
    fixture.state.disk = HARD_DISK_GEOMETRY;
    fixture.disk = TestDisk::with_sectors(400_000);
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0201;
    regs.cx = 0x2C41; // cylinder 300: low byte 0x2C, high bits 01b, sector 1
    regs.dx = 0x0000;
    regs.es = 0;
    regs.bx = 0x8000;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert!(!fixture.carry());
    let lba = 300u64 * 16 * 63;
    let pattern = (lba & 0xFF) as u8;
    for offset in 0..512 {
        assert_eq!(fixture.mem.u8_at(0x8000 + offset), pattern);
    }
}

#[test]
fn disk_read_past_the_geometry_reports_sector_not_found() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0201;
    regs.cx = 0x5001; // cylinder 80: outside the floppy geometry
    regs.es = 0;
    regs.bx = 0x8000;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert!(fixture.carry());
    assert_eq!(ah(&regs), DISK_STATUS_SECTOR_NOT_FOUND);
}

#[test]
fn disk_read_with_an_unmapped_buffer_fails_without_panicking() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0201;
    regs.cx = 0x0001;
    regs.es = 0xFFFF;
    regs.bx = 0xFFF0; // linear 0x10FFE0, past the 1 MiB image
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert!(fixture.carry());
    assert_eq!(ah(&regs), DISK_STATUS_SECTOR_NOT_FOUND);
}

#[test]
fn disk_writes_are_rejected_as_write_protected() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0301;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert!(fixture.carry());
    assert_eq!(ah(&regs), DISK_STATUS_WRITE_PROTECTED);
    assert_eq!(fixture.scratch(), SCRATCH_CF);
}

#[test]
fn disk_unknown_function_reports_invalid_function() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0400;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert!(fixture.carry());
    assert_eq!(ah(&regs), DISK_STATUS_INVALID_FUNCTION);
}

#[test]
fn disk_backend_failure_is_reported_as_sector_not_found() {
    let mut fixture = Fixture::new();
    fixture.disk.fail_from = Some(1);
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0201;
    regs.cx = 0x0002;
    regs.es = 0;
    regs.bx = 0x8000;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert!(fixture.carry());
    assert_eq!(ah(&regs), DISK_STATUS_SECTOR_NOT_FOUND);
}

#[test]
fn disk_read_has_no_bda_or_timer_side_effects() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0201;
    regs.cx = 0x0001;
    regs.es = 0;
    regs.bx = 0x8000;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert_eq!(fixture.state.ticks, 0);
    assert_eq!(fixture.mem.u32_at(BDA_TICK_COUNT), 0);
    assert_eq!(fixture.mem.u16_at(BDA_CURSOR), 0);
    assert_eq!(fixture.scratch(), 0);
}

// ---------------------------------------------------------------------------
// INT 13h: parameters, type, extensions and DAP
// ---------------------------------------------------------------------------

#[test]
fn disk_parameters_for_the_floppy_geometry() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0800;
    regs.dx = 0x0000;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert!(!fixture.carry());
    assert_eq!(ah(&regs), 0);
    assert_eq!(regs.cx >> 8, 79);
    assert_eq!(regs.cx & 0x3F, 18);
    assert_eq!((regs.cx >> 6) & 0x03, 0);
    assert_eq!((regs.dx >> 8) as u8, 1);
    assert_eq!(regs.dx as u8, 2);
    assert_eq!(regs.es, 0);
    assert_eq!(regs.di, 0);
}

#[test]
fn disk_parameters_for_a_fixed_disk() {
    let mut fixture = Fixture::new();
    fixture.state.disk = DiskGeometry::from_sectors(100_000);
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0800;
    regs.dx = 0x0080;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert!(!fixture.carry());
    assert_eq!(regs.cx >> 8, 0xFF);
    assert_eq!(regs.cx & 0x3F, 63);
    assert_eq!((regs.cx >> 6) & 0x03, 3);
    assert_eq!((regs.dx >> 8) as u8, 15);
    assert_eq!(regs.dx as u8, 3);
}

#[test]
fn disk_type_reports_floppy_and_fixed_disk() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x1500;
    regs.dx = 0x0000;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert_eq!(ah(&regs), 2);
    assert!(!fixture.carry());

    regs.ax = 0x1500;
    regs.dx = 0x0080;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert_eq!(ah(&regs), 3);
    assert!(!fixture.carry());
}

#[test]
fn disk_type_rejects_an_unknown_drive() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x1500;
    regs.dx = 0x0001;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert!(fixture.carry());
    assert_eq!(ah(&regs), DISK_STATUS_MEDIA_NOT_FOUND);
}

#[test]
fn disk_read_rejects_an_unknown_drive() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0201;
    regs.cx = 0x0001;
    regs.dx = 0x0001;
    regs.es = 0;
    regs.bx = 0x8000;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert!(fixture.carry());
    assert_eq!(ah(&regs), DISK_STATUS_MEDIA_NOT_FOUND);
}

#[test]
fn disk_extensions_report_the_signature() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x4100;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert_eq!(ah(&regs), 0);
    assert_eq!(regs.bx, EXTENSIONS_SIGNATURE);
    assert_eq!(regs.bx, 0xAA55);
    assert!(!fixture.carry());
}

#[test]
fn extended_read_uses_the_address_packet() {
    let mut fixture = Fixture::new();
    write_dap(&mut fixture.mem, 0x6000, 16, 2, 0x9000, 0, 5);
    let mut regs = BiosRegisters::new();
    regs.ax = 0x4200;
    regs.ds = 0;
    regs.si = 0x6000;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert!(!fixture.carry());
    assert_eq!(ah(&regs), 0);
    for offset in 0..512 {
        assert_eq!(fixture.mem.u8_at(0x9000 + offset), 5);
        assert_eq!(fixture.mem.u8_at(0x9200 + offset), 6);
    }
}

#[test]
fn extended_read_rejects_a_wrong_packet_size() {
    let mut fixture = Fixture::new();
    write_dap(&mut fixture.mem, 0x6000, 15, 1, 0x8000, 0, 0);
    let mut regs = BiosRegisters::new();
    regs.ax = 0x4200;
    regs.si = 0x6000;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert!(fixture.carry());
    assert_eq!(ah(&regs), DISK_STATUS_INVALID_FUNCTION);
}

#[test]
fn extended_read_out_of_range_reports_sector_not_found() {
    let mut fixture = Fixture::new();
    write_dap(&mut fixture.mem, 0x6000, 16, 1, 0x8000, 0, 2880);
    let mut regs = BiosRegisters::new();
    regs.ax = 0x4200;
    regs.si = 0x6000;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert!(fixture.carry());
    assert_eq!(ah(&regs), DISK_STATUS_SECTOR_NOT_FOUND);
}

#[test]
fn extended_read_from_an_unmapped_packet_fails() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x4200;
    regs.ds = 0xFFFF;
    regs.si = 0xFFF0;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert!(fixture.carry());
    assert_eq!(ah(&regs), DISK_STATUS_INVALID_FUNCTION);
}

#[test]
fn extended_write_is_rejected_as_write_protected() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x4300;
    assert_eq!(fixture.call(0x13, &mut regs), BiosOutcome::Handled);
    assert!(fixture.carry());
    assert_eq!(ah(&regs), DISK_STATUS_WRITE_PROTECTED);
}

// ---------------------------------------------------------------------------
// INT 15h
// ---------------------------------------------------------------------------

#[test]
fn int15_eighty_eight_reports_no_extended_memory() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x88FF;
    assert_eq!(fixture.call(0x15, &mut regs), BiosOutcome::Handled);
    assert_eq!(regs.ax, 0);
    assert!(!fixture.carry());
    assert_eq!(fixture.scratch(), 0);
}

#[test]
fn int15_rejects_c0_e8_and_unknown_functions() {
    let mut fixture = Fixture::new();
    for function in [0xC0u8, 0xE8, 0x99] {
        let mut regs = BiosRegisters::new();
        regs.ax = (function as u16) << 8;
        assert_eq!(fixture.call(0x15, &mut regs), BiosOutcome::Handled);
        assert!(fixture.carry());
        assert_eq!(ah(&regs), STATUS_NOT_SUPPORTED);
    }
}

// ---------------------------------------------------------------------------
// INT 16h
// ---------------------------------------------------------------------------

#[test]
fn keyboard_read_pops_one_key_and_clears_zero() {
    let mut fixture = Fixture::new();
    fixture.state.push_key(b'a');
    fixture.state.push_key(b'b');
    let mut regs = BiosRegisters::new();
    assert_eq!(fixture.call(0x16, &mut regs), BiosOutcome::Handled);
    assert_eq!(al(&regs), b'a');
    assert!(!fixture.zero());
    assert!(!fixture.carry());
    assert_eq!(fixture.state.keyboard.len(), 1);
    assert_eq!(fixture.call(0x16, &mut regs), BiosOutcome::Handled);
    assert_eq!(al(&regs), b'b');
}

#[test]
fn keyboard_read_on_empty_queue_reports_zero_flag() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x00FF;
    assert_eq!(fixture.call(0x16, &mut regs), BiosOutcome::Handled);
    assert_eq!(regs.ax, 0);
    assert!(fixture.zero());
    assert!(!fixture.carry());
    assert_eq!(fixture.scratch(), SCRATCH_ZF);
}

#[test]
fn keyboard_peek_returns_the_front_key_without_popping() {
    let mut fixture = Fixture::new();
    fixture.state.push_key(b'x');
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0100;
    assert_eq!(fixture.call(0x16, &mut regs), BiosOutcome::Handled);
    assert_eq!(al(&regs), b'x');
    assert!(!fixture.zero());
    assert_eq!(fixture.state.keyboard.len(), 1);

    let mut regs = BiosRegisters::new();
    regs.ax = 0x0100;
    fixture.state.keyboard.clear();
    assert_eq!(fixture.call(0x16, &mut regs), BiosOutcome::Handled);
    assert_eq!(regs.ax, 0);
    assert!(fixture.zero());
}

#[test]
fn keyboard_shift_status_reports_zero_in_al() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x02FF;
    assert_eq!(fixture.call(0x16, &mut regs), BiosOutcome::Handled);
    assert_eq!(ah(&regs), 2);
    assert_eq!(al(&regs), 0);
    assert!(!fixture.carry());
    assert!(!fixture.zero());
}

#[test]
fn keyboard_unknown_function_fails() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0300;
    assert_eq!(fixture.call(0x16, &mut regs), BiosOutcome::Handled);
    assert!(fixture.carry());
    assert_eq!(ah(&regs), STATUS_INVALID_FUNCTION);
}

#[test]
fn keyboard_queue_publishes_head_and_tail_in_the_bda() {
    let mut fixture = Fixture::new();
    fixture.state.push_key(b'1');
    fixture.state.push_key(b'2');
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0100;
    assert_eq!(fixture.call(0x16, &mut regs), BiosOutcome::Handled);
    assert_eq!(fixture.mem.u16_at(BDA_KEYBOARD_HEAD), 0);
    assert_eq!(fixture.mem.u16_at(BDA_KEYBOARD_TAIL), 4);

    let mut regs = BiosRegisters::new();
    assert_eq!(fixture.call(0x16, &mut regs), BiosOutcome::Handled);
    assert_eq!(fixture.call(0x16, &mut regs), BiosOutcome::Handled);
    assert_eq!(fixture.mem.u16_at(BDA_KEYBOARD_TAIL), 0);
}

#[test]
fn keyboard_queue_is_bounded_and_drops_the_overflow() {
    let mut fixture = Fixture::new();
    for key in 0..(KEY_BUFFER_CAPACITY as u8 + 4) {
        fixture.state.push_key(key);
    }
    assert_eq!(fixture.state.keyboard.len(), KEY_BUFFER_CAPACITY);
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0100;
    assert_eq!(fixture.call(0x16, &mut regs), BiosOutcome::Handled);
    assert_eq!(fixture.mem.u16_at(BDA_KEYBOARD_TAIL), KEY_BUFFER_BYTES);
    assert_eq!(fixture.mem.u16_at(BDA_KEYBOARD_TAIL), 32);
}

// ---------------------------------------------------------------------------
// INT 17h
// ---------------------------------------------------------------------------

#[test]
fn printer_character_reports_selected_and_ready() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0041;
    assert_eq!(fixture.call(0x17, &mut regs), BiosOutcome::Handled);
    assert_eq!(ah(&regs), PRINTER_STATUS);
    assert_eq!(ah(&regs), 0x30);
    assert_eq!(al(&regs), b'A');
    assert!(!fixture.carry());
}

#[test]
fn printer_initialise_reports_ready() {
    let mut fixture = Fixture::new();
    for function in [0x01u8, 0x02] {
        let mut regs = BiosRegisters::new();
        regs.ax = (function as u16) << 8;
        assert_eq!(fixture.call(0x17, &mut regs), BiosOutcome::Handled);
        assert_eq!(ah(&regs), PRINTER_STATUS);
        assert!(!fixture.carry());
    }
}

#[test]
fn printer_unknown_function_fails() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0300;
    assert_eq!(fixture.call(0x17, &mut regs), BiosOutcome::Handled);
    assert!(fixture.carry());
    assert_eq!(ah(&regs), STATUS_INVALID_FUNCTION);
}

// ---------------------------------------------------------------------------
// INT 1Ah
// ---------------------------------------------------------------------------

#[test]
fn ticks_are_reported_in_cx_dx_and_in_the_bda() {
    let mut fixture = Fixture::new();
    fixture.state.ticks = 0x1234_5678;
    let mut regs = BiosRegisters::new();
    regs.ax = 0x00FF;
    assert_eq!(fixture.call(0x1A, &mut regs), BiosOutcome::Handled);
    assert_eq!(regs.cx, 0x1234);
    assert_eq!(regs.dx, 0x5678);
    assert_eq!(al(&regs), 0);
    assert!(!fixture.carry());
    assert_eq!(fixture.mem.u32_at(BDA_TICK_COUNT), 0x1234_5678);

    fixture.state.advance_ticks(2);
    let mut regs = BiosRegisters::new();
    assert_eq!(fixture.call(0x1A, &mut regs), BiosOutcome::Handled);
    assert_eq!(regs.cx, 0x1234);
    assert_eq!(regs.dx, 0x567A);
}

#[test]
fn rtc_time_is_returned_in_bcd() {
    let mut fixture = Fixture::new();
    fixture.state.rtc_hour = 23;
    fixture.state.rtc_minute = 59;
    fixture.state.rtc_second = 45;
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0200;
    assert_eq!(fixture.call(0x1A, &mut regs), BiosOutcome::Handled);
    assert_eq!(regs.cx, 0x2359);
    assert_eq!(regs.dx, 0x4500);
    assert!(!fixture.carry());
}

#[test]
fn unknown_time_function_fails() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    regs.ax = 0x0300;
    assert_eq!(fixture.call(0x1A, &mut regs), BiosOutcome::Handled);
    assert!(fixture.carry());
    assert_eq!(ah(&regs), STATUS_INVALID_FUNCTION);
}

// ---------------------------------------------------------------------------
// INT 05h and adversarial inputs
// ---------------------------------------------------------------------------

#[test]
fn print_screen_is_accepted_as_a_no_op() {
    let mut fixture = Fixture::new();
    let mut regs = BiosRegisters::new();
    assert_eq!(fixture.call(0x05, &mut regs), BiosOutcome::Handled);
    assert_eq!(fixture.scratch(), 0);
    assert_eq!(regs, BiosRegisters::new());
}

#[test]
fn adversarial_register_patterns_never_panic() {
    let mut fixture = Fixture::new();
    let mut seed = 0x1234_5678u32;
    let vectors = [
        0x05u8, 0x08, 0x10, 0x11, 0x12, 0x13, 0x15, 0x16, 0x17, 0x1A, 0x1C, 0x42, 0x4A, 0xFF,
    ];
    for _ in 0..200 {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let mut regs = BiosRegisters::new();
        regs.ax = seed as u16;
        regs.bx = (seed >> 3) as u16;
        regs.cx = (seed >> 7) as u16;
        regs.dx = (seed >> 11) as u16;
        regs.si = (seed >> 15) as u16;
        regs.di = (seed >> 19) as u16;
        regs.bp = (seed >> 23) as u16;
        regs.sp = seed as u16;
        regs.ds = (seed >> 5) as u16;
        regs.es = (seed >> 9) as u16;
        regs.ss = (seed >> 13) as u16;
        regs.cs = (seed >> 17) as u16;
        regs.ip = (seed >> 21) as u16;
        regs.flags = 0xFFFF;
        for vector in vectors {
            fixture.mem.fill(SCRATCH_GPA, 1, 0xFF);
            let _ = fixture.call(vector, &mut regs);
            assert!(fixture.scratch() <= SCRATCH_CF | SCRATCH_ZF);
        }
    }
}

#[test]
fn extreme_register_values_never_panic() {
    let mut fixture = Fixture::new();
    let patterns = [0x0000u16, 0xFFFF, 0xAAAA, 0x5555, 0x8000, 0x7FFF];
    for vector in 0..=255u8 {
        for pattern in patterns {
            let mut regs = BiosRegisters::new();
            regs.ax = pattern;
            regs.bx = pattern;
            regs.cx = pattern;
            regs.dx = pattern;
            regs.si = pattern;
            regs.di = pattern;
            regs.bp = pattern;
            regs.sp = pattern;
            regs.ds = pattern;
            regs.es = pattern;
            regs.ss = pattern;
            regs.cs = pattern;
            regs.ip = pattern;
            regs.flags = pattern;
            let _ = fixture.call(vector, &mut regs);
            assert!(fixture.scratch() <= SCRATCH_CF | SCRATCH_ZF);
        }
    }
}
