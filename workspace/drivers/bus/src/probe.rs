use crate::mmio::{MmioRegion, memory_barrier};
use alloc::vec;

const REGION_SIZE: usize = 4096;
const REGION_WORDS: usize = REGION_SIZE / core::mem::size_of::<u64>();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeMode {
    Quick,
    Full,
}

pub struct ProbeResult {
    pub passed: u32,
    pub failed: u32,
}

impl ProbeResult {
    /// Creates a new instance.
    fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
        }
    }

    /// Performs the check operation.
    fn check(&mut self, ok: bool) {
        if ok {
            self.passed += 1;
        } else {
            self.failed += 1;
        }
    }

    /// Performs the all passed operation.
    pub fn all_passed(&self) -> bool {
        self.failed == 0 && self.passed > 0
    }
}

/// Performs the zero buf operation.
fn zero_buf(buf: &mut [u64]) {
    buf.fill(0);
}

/// Performs the run mmio probe operation.
pub fn run_mmio_probe() -> ProbeResult {
    run_mmio_probe_with_mode(ProbeMode::Full)
}

/// Performs the run mmio probe with mode operation.
pub fn run_mmio_probe_with_mode(mode: ProbeMode) -> ProbeResult {
    let mut r = ProbeResult::new();
    let mut buf = vec![0u64; REGION_WORDS];
    let base = buf.as_mut_ptr() as usize;

    match mode {
        ProbeMode::Quick => {
            probe_lifecycle(&mut r, base);
            zero_buf(&mut buf);
            probe_read_write_32(&mut r, base);
            zero_buf(&mut buf);
            probe_boundary_offsets(&mut r, base);
            zero_buf(&mut buf);
            probe_memory_barrier(&mut r, base);
        }
        ProbeMode::Full => {
            probe_lifecycle(&mut r, base);
            zero_buf(&mut buf);
            probe_read_write_8(&mut r, base);
            zero_buf(&mut buf);
            probe_read_write_16(&mut r, base);
            zero_buf(&mut buf);
            probe_read_write_32(&mut r, base);
            zero_buf(&mut buf);
            probe_read_write_64(&mut r, base);
            zero_buf(&mut buf);
            probe_set_bits(&mut r, base);
            zero_buf(&mut buf);
            probe_clear_bits(&mut r, base);
            zero_buf(&mut buf);
            probe_modify32(&mut r, base);
            zero_buf(&mut buf);
            probe_read_field32(&mut r, base);
            zero_buf(&mut buf);
            probe_write_field32(&mut r, base);
            zero_buf(&mut buf);
            probe_boundary_offsets(&mut r, base);
            zero_buf(&mut buf);
            probe_multi_width_overlap(&mut r, base);
            zero_buf(&mut buf);
            probe_walking_ones_32(&mut r, base);
            zero_buf(&mut buf);
            probe_walking_ones_64(&mut r, base);
            zero_buf(&mut buf);
            probe_memory_barrier(&mut r, base);
            zero_buf(&mut buf);
            probe_reinit(&mut r, base);
        }
    }

    r
}

/// Performs the make region operation.
fn make_region(base: usize) -> MmioRegion {
    let mut reg = MmioRegion::new();
    reg.init(base, REGION_SIZE);
    reg
}

/// Performs the probe lifecycle operation.
fn probe_lifecycle(r: &mut ProbeResult, base: usize) {
    let uninit = MmioRegion::new();
    r.check(!uninit.is_valid());
    r.check(uninit.base() == 0);

    let reg = make_region(base);
    r.check(reg.is_valid());
    r.check(reg.base() == base);
}

/// Performs the probe read write 8 operation.
fn probe_read_write_8(r: &mut ProbeResult, base: usize) {
    let reg = make_region(base);

    reg.write8(0, 0xAB);
    r.check(reg.read8(0) == 0xAB);

    reg.write8(1, 0x00);
    r.check(reg.read8(1) == 0x00);

    reg.write8(2, 0xFF);
    r.check(reg.read8(2) == 0xFF);

    reg.write8(0, 0x12);
    r.check(reg.read8(0) == 0x12);
    r.check(reg.read8(2) == 0xFF);

    for i in 0..16u8 {
        reg.write8(i as usize, i.wrapping_mul(17));
    }
    for i in 0..16u8 {
        r.check(reg.read8(i as usize) == i.wrapping_mul(17));
    }
}

/// Performs the probe read write 16 operation.
fn probe_read_write_16(r: &mut ProbeResult, base: usize) {
    let reg = make_region(base);

    reg.write16(0, 0xBEEF);
    r.check(reg.read16(0) == 0xBEEF);

    reg.write16(2, 0x0000);
    r.check(reg.read16(2) == 0x0000);

    reg.write16(4, 0xFFFF);
    r.check(reg.read16(4) == 0xFFFF);

    r.check(reg.read16(0) == 0xBEEF);

    reg.write16(0, 0x1234);
    reg.write16(2, 0x5678);
    let combined = reg.read32(0);
    let expected = 0x1234u32 | (0x5678u32 << 16);
    r.check(combined == expected);
}

/// Performs the probe read write 32 operation.
fn probe_read_write_32(r: &mut ProbeResult, base: usize) {
    let reg = make_region(base);

    reg.write32(0, 0xDEADBEEF);
    r.check(reg.read32(0) == 0xDEADBEEF);

    reg.write32(4, 0x00000000);
    r.check(reg.read32(4) == 0x00000000);

    reg.write32(8, 0xFFFFFFFF);
    r.check(reg.read32(8) == 0xFFFFFFFF);

    r.check(reg.read32(0) == 0xDEADBEEF);

    reg.write32(0, 0x01020304);
    r.check(reg.read8(0) == 0x04);
    r.check(reg.read8(1) == 0x03);
    r.check(reg.read8(2) == 0x02);
    r.check(reg.read8(3) == 0x01);

    for i in 0..32u32 {
        let off = (i as usize) * 4;
        if off + 4 > REGION_SIZE {
            break;
        }
        reg.write32(off, i.wrapping_mul(0x11111111));
    }
    for i in 0..32u32 {
        let off = (i as usize) * 4;
        if off + 4 > REGION_SIZE {
            break;
        }
        r.check(reg.read32(off) == i.wrapping_mul(0x11111111));
    }
}

/// Performs the probe read write 64 operation.
fn probe_read_write_64(r: &mut ProbeResult, base: usize) {
    let reg = make_region(base);

    reg.write64(0, 0xCAFEBABE_DEADBEEF);
    r.check(reg.read64(0) == 0xCAFEBABE_DEADBEEF);

    reg.write64(8, 0x0000000000000000);
    r.check(reg.read64(8) == 0x0000000000000000);

    reg.write64(16, 0xFFFFFFFFFFFFFFFF);
    r.check(reg.read64(16) == 0xFFFFFFFFFFFFFFFF);

    r.check(reg.read64(0) == 0xCAFEBABE_DEADBEEF);

    r.check(reg.read32(0) == 0xDEADBEEF);
    r.check(reg.read32(4) == 0xCAFEBABE);
}

/// Performs the probe set bits operation.
fn probe_set_bits(r: &mut ProbeResult, base: usize) {
    let reg = make_region(base);

    reg.write32(0, 0x00000000);
    reg.set_bits32(0, 0x0000000F);
    r.check(reg.read32(0) == 0x0000000F);

    reg.set_bits32(0, 0x000000F0);
    r.check(reg.read32(0) == 0x000000FF);

    reg.set_bits32(0, 0x000000FF);
    r.check(reg.read32(0) == 0x000000FF);

    reg.write32(0, 0x80000000);
    reg.set_bits32(0, 0x00000001);
    r.check(reg.read32(0) == 0x80000001);
}

/// Performs the probe clear bits operation.
fn probe_clear_bits(r: &mut ProbeResult, base: usize) {
    let reg = make_region(base);

    reg.write32(0, 0xFFFFFFFF);
    reg.clear_bits32(0, 0x0000000F);
    r.check(reg.read32(0) == 0xFFFFFFF0);

    reg.clear_bits32(0, 0x000000F0);
    r.check(reg.read32(0) == 0xFFFFFF00);

    reg.clear_bits32(0, 0x00000000);
    r.check(reg.read32(0) == 0xFFFFFF00);

    reg.write32(0, 0x80000001);
    reg.clear_bits32(0, 0x80000000);
    r.check(reg.read32(0) == 0x00000001);
}

/// Performs the probe modify32 operation.
fn probe_modify32(r: &mut ProbeResult, base: usize) {
    let reg = make_region(base);

    reg.write32(0, 0xAABBCCDD);
    reg.modify32(0, 0x0000FF00, 0x00001200);
    r.check(reg.read32(0) == 0xAABB12DD);

    reg.write32(0, 0xFFFFFFFF);
    reg.modify32(0, 0xFFFFFFFF, 0x12345678);
    r.check(reg.read32(0) == 0x12345678);

    reg.write32(0, 0x00000000);
    reg.modify32(0, 0x00000000, 0x00000000);
    r.check(reg.read32(0) == 0x00000000);

    reg.write32(0, 0x00FF00FF);
    reg.modify32(0, 0x00FF0000, 0x00AB0000);
    r.check(reg.read32(0) == 0x00AB00FF);
}

/// Performs the probe read field32 operation.
fn probe_read_field32(r: &mut ProbeResult, base: usize) {
    let reg = make_region(base);

    reg.write32(0, 0x12345678);

    r.check(reg.read_field32(0, 0x000000FF, 0) == 0x78);
    r.check(reg.read_field32(0, 0x0000FF00, 8) == 0x56);
    r.check(reg.read_field32(0, 0x00FF0000, 16) == 0x34);
    r.check(reg.read_field32(0, 0xFF000000, 24) == 0x12);

    r.check(reg.read_field32(0, 0x0000000F, 0) == 0x08);
    r.check(reg.read_field32(0, 0x000F0000, 16) == 0x04);

    reg.write32(0, 0x00000000);
    r.check(reg.read_field32(0, 0xFFFFFFFF, 0) == 0x00000000);

    reg.write32(0, 0xFFFFFFFF);
    r.check(reg.read_field32(0, 0xFFFFFFFF, 0) == 0xFFFFFFFF);
}

/// Performs the probe write field32 operation.
fn probe_write_field32(r: &mut ProbeResult, base: usize) {
    let reg = make_region(base);

    reg.write32(0, 0x00000000);
    reg.write_field32(0, 0x000000FF, 0, 0xAB);
    r.check(reg.read32(0) == 0x000000AB);

    reg.write32(0, 0xFFFFFFFF);
    reg.write_field32(0, 0x0000FF00, 8, 0x42);
    r.check(reg.read32(0) == 0xFFFF42FF);

    reg.write32(0, 0x12345678);
    reg.write_field32(0, 0xFF000000, 24, 0x99);
    r.check(reg.read32(0) == 0x99345678);

    reg.write32(0, 0xAAAAAAAA);
    reg.write_field32(0, 0x000F0000, 16, 0x05);
    let val = reg.read32(0);
    r.check((val & 0x000F0000) >> 16 == 0x05);
    r.check((val & 0xFFF0FFFF) == 0xAAA0AAAA);
}

/// Performs the probe boundary offsets operation.
fn probe_boundary_offsets(r: &mut ProbeResult, base: usize) {
    let reg = make_region(base);

    reg.write8(0, 0x01);
    r.check(reg.read8(0) == 0x01);

    reg.write8(REGION_SIZE - 1, 0xFE);
    r.check(reg.read8(REGION_SIZE - 1) == 0xFE);

    reg.write16(REGION_SIZE - 2, 0xABCD);
    r.check(reg.read16(REGION_SIZE - 2) == 0xABCD);

    reg.write32(REGION_SIZE - 4, 0xDEADC0DE);
    r.check(reg.read32(REGION_SIZE - 4) == 0xDEADC0DE);

    reg.write64(REGION_SIZE - 8, 0x0102030405060708);
    r.check(reg.read64(REGION_SIZE - 8) == 0x0102030405060708);
}

/// Performs the probe multi width overlap operation.
fn probe_multi_width_overlap(r: &mut ProbeResult, base: usize) {
    let reg = make_region(base);

    reg.write64(0, 0);
    reg.write8(0, 0x11);
    reg.write8(1, 0x22);
    reg.write8(2, 0x33);
    reg.write8(3, 0x44);
    reg.write8(4, 0x55);
    reg.write8(5, 0x66);
    reg.write8(6, 0x77);
    reg.write8(7, 0x88);
    r.check(reg.read16(0) == 0x2211);
    r.check(reg.read16(2) == 0x4433);
    r.check(reg.read32(0) == 0x44332211);
    r.check(reg.read32(4) == 0x88776655);
    r.check(reg.read64(0) == 0x8877665544332211);

    reg.write32(0, 0xAABBCCDD);
    r.check(reg.read8(0) == 0xDD);
    r.check(reg.read8(1) == 0xCC);
    r.check(reg.read8(2) == 0xBB);
    r.check(reg.read8(3) == 0xAA);
    r.check(reg.read16(0) == 0xCCDD);
    r.check(reg.read16(2) == 0xAABB);
}

/// Performs the probe walking ones 32 operation.
fn probe_walking_ones_32(r: &mut ProbeResult, base: usize) {
    let reg = make_region(base);

    for bit in 0..32u32 {
        let val = 1u32 << bit;
        reg.write32(0, val);
        r.check(reg.read32(0) == val);
    }

    reg.write32(0, 0);
    for bit in 0..32u32 {
        reg.set_bits32(0, 1u32 << bit);
    }
    r.check(reg.read32(0) == 0xFFFFFFFF);

    for bit in 0..32u32 {
        reg.clear_bits32(0, 1u32 << bit);
    }
    r.check(reg.read32(0) == 0x00000000);
}

/// Performs the probe walking ones 64 operation.
fn probe_walking_ones_64(r: &mut ProbeResult, base: usize) {
    let reg = make_region(base);

    for bit in 0..64u32 {
        let val = 1u64 << bit;
        reg.write64(0, val);
        r.check(reg.read64(0) == val);
    }

    reg.write64(0, 0xAAAAAAAAAAAAAAAA);
    r.check(reg.read64(0) == 0xAAAAAAAAAAAAAAAA);

    reg.write64(0, 0x5555555555555555);
    r.check(reg.read64(0) == 0x5555555555555555);
}

/// Performs the probe memory barrier operation.
fn probe_memory_barrier(r: &mut ProbeResult, base: usize) {
    let reg = make_region(base);

    reg.write32(0, 0x11111111);
    memory_barrier();
    r.check(reg.read32(0) == 0x11111111);

    reg.write32(0, 0x22222222);
    memory_barrier();
    reg.write32(4, 0x33333333);
    memory_barrier();
    r.check(reg.read32(0) == 0x22222222);
    r.check(reg.read32(4) == 0x33333333);

    for i in 0..16u32 {
        reg.write32((i as usize) * 4, i);
        memory_barrier();
    }
    for i in 0..16u32 {
        r.check(reg.read32((i as usize) * 4) == i);
    }
}

/// Performs the probe reinit operation.
fn probe_reinit(r: &mut ProbeResult, base: usize) {
    let mut reg = MmioRegion::new();
    r.check(!reg.is_valid());

    reg.init(base, REGION_SIZE);
    r.check(reg.is_valid());
    r.check(reg.base() == base);
    reg.write32(0, 0xABCD1234);
    r.check(reg.read32(0) == 0xABCD1234);

    let mut buf2 = vec![0u64; REGION_WORDS];
    let base2 = buf2.as_mut_ptr() as usize;
    reg.init(base2, REGION_SIZE);
    r.check(reg.is_valid());
    r.check(reg.base() == base2);
    r.check(reg.base() != base);
    r.check(reg.read32(0) == 0x00000000);

    reg.write32(0, 0x99887766);
    r.check(reg.read32(0) == 0x99887766);
}
