use alloc::{string::String, vec::Vec};
use crate::{BusChild, BusDriver, BusError, PowerState};
use crate::mmio::MmioRegion;

const WIN_CTRL_OFF: usize = 0x00;
const WIN_BASE_OFF: usize = 0x04;
const WIN_REMAP_LO_OFF: usize = 0x08;
const WIN_REMAP_HI_OFF: usize = 0x0C;

const WIN_CTRL_ENABLE: u32 = 1 << 0;
const WIN_CTRL_SYNCBARRIER: u32 = 1 << 1;
const WIN_CTRL_TGT_MASK: u32 = 0xF0;
const WIN_CTRL_TGT_SHIFT: u32 = 4;
const WIN_CTRL_ATTR_MASK: u32 = 0xFF00;
const WIN_CTRL_ATTR_SHIFT: u32 = 8;
const WIN_CTRL_SIZE_MASK: u32 = 0xFFFF_0000;
const WIN_CTRL_SIZE_SHIFT: u32 = 16;

const DDR_BASE_CS_OFF: fn(usize) -> usize = |n| n * 8;
const DDR_SIZE_CS_OFF: fn(usize) -> usize = |n| n * 8 + 4;

const DDR_SIZE_ENABLED: u32 = 1 << 0;
const DDR_SIZE_CS_MASK: u32 = 0x1C;
const DDR_SIZE_CS_SHIFT: u32 = 2;
const DDR_SIZE_MASK: u32 = 0xFFFF_FF00;

const UNIT_SYNC_BARRIER_OFF: usize = 0x84;
const UNIT_SYNC_BARRIER_ALL: u32 = 0xFFFF;

const MBUS_BRIDGE_CTRL_OFF: usize = 0x00;
const MBUS_BRIDGE_BASE_OFF: usize = 0x04;

const MAX_WINS: usize = 20;

const COMPATIBLE: &[&str] = &[
    "marvell,armada370-mbus",
    "marvell,armada380-mbus",
    "marvell,armadaxp-mbus",
    "marvell,dove-mbus",
    "marvell,kirkwood-mbus",
    "marvell,orion5x-88f5281-mbus",
    "marvell,orion5x-88f5182-mbus",
    "marvell,orion5x-88f5181-mbus",
    "marvell,orion5x-88f6183-mbus",
    "marvell,mv78xx0-mbus",
];

#[derive(Clone, Copy)]
pub struct MbusWindowData {
    pub ctrl: u32,
    pub base: u32,
    pub remap_lo: u32,
    pub remap_hi: u32,
}

pub struct MvebuMbus {
    mbus_regs: MmioRegion,
    sdram_regs: MmioRegion,
    bridge_regs: MmioRegion,
    num_wins: usize,
    has_bridge: bool,
    hw_io_coherency: bool,
    saved_wins: [MbusWindowData; MAX_WINS],
    power_state: PowerState,
}

impl MvebuMbus {
    pub fn new(num_wins: usize, has_bridge: bool) -> Self {
        Self {
            mbus_regs: MmioRegion::new(),
            sdram_regs: MmioRegion::new(),
            bridge_regs: MmioRegion::new(),
            num_wins,
            has_bridge,
            hw_io_coherency: false,
            saved_wins: [MbusWindowData { ctrl: 0, base: 0, remap_lo: 0, remap_hi: 0 }; MAX_WINS],
            power_state: PowerState::Off,
        }
    }

    pub fn init_sdram_regs(&mut self, base: usize, size: usize) {
        self.sdram_regs.init(base, size);
    }

    pub fn init_bridge_regs(&mut self, base: usize, size: usize) {
        self.bridge_regs.init(base, size);
        self.has_bridge = true;
    }

    pub fn set_hw_io_coherency(&mut self, enable: bool) {
        self.hw_io_coherency = enable;
    }

    fn win_offset(&self, win: usize) -> usize {
        if win < 8 {
            win * 0x10
        } else {
            0x90 + (win - 8) * 0x08
        }
    }

    fn has_remap(&self, win: usize) -> bool {
        win < 8
    }

    pub fn read_window(&self, win: usize) -> MbusWindowData {
        let off = self.win_offset(win);
        MbusWindowData {
            ctrl: self.mbus_regs.read32(off + WIN_CTRL_OFF),
            base: self.mbus_regs.read32(off + WIN_BASE_OFF),
            remap_lo: if self.has_remap(win) { self.mbus_regs.read32(off + WIN_REMAP_LO_OFF) } else { 0 },
            remap_hi: if self.has_remap(win) { self.mbus_regs.read32(off + WIN_REMAP_HI_OFF) } else { 0 },
        }
    }

    pub fn setup_window(&self, win: usize, base: u32, size: u32, target: u8, attr: u8, remap: Option<u64>) {
        let off = self.win_offset(win);

        self.mbus_regs.write32(off + WIN_CTRL_OFF, 0);

        self.mbus_regs.write32(off + WIN_BASE_OFF, base & 0xFFFF_0000);

        if self.has_remap(win) {
            if let Some(r) = remap {
                self.mbus_regs.write32(off + WIN_REMAP_LO_OFF, r as u32);
                self.mbus_regs.write32(off + WIN_REMAP_HI_OFF, (r >> 32) as u32);
            } else {
                self.mbus_regs.write32(off + WIN_REMAP_LO_OFF, 0);
                self.mbus_regs.write32(off + WIN_REMAP_HI_OFF, 0);
            }
        }

        let size_field = ((size / 0x10000) - 1) as u32;
        let ctrl = WIN_CTRL_ENABLE
            | ((target as u32) << WIN_CTRL_TGT_SHIFT) & WIN_CTRL_TGT_MASK
            | ((attr as u32) << WIN_CTRL_ATTR_SHIFT) & WIN_CTRL_ATTR_MASK
            | (size_field << WIN_CTRL_SIZE_SHIFT) & WIN_CTRL_SIZE_MASK;

        self.mbus_regs.write32(off + WIN_CTRL_OFF, ctrl);
    }

    pub fn disable_window(&self, win: usize) {
        let off = self.win_offset(win);
        self.mbus_regs.write32(off + WIN_CTRL_OFF, 0);
        self.mbus_regs.write32(off + WIN_BASE_OFF, 0);
        if self.has_remap(win) {
            self.mbus_regs.write32(off + WIN_REMAP_LO_OFF, 0);
            self.mbus_regs.write32(off + WIN_REMAP_HI_OFF, 0);
        }
    }

    pub fn save_windows(&mut self) {
        for i in 0..self.num_wins {
            self.saved_wins[i] = self.read_window(i);
        }
    }

    pub fn restore_windows(&self) {
        for i in 0..self.num_wins {
            let off = self.win_offset(i);
            let win = &self.saved_wins[i];
            self.mbus_regs.write32(off + WIN_CTRL_OFF, 0);
            self.mbus_regs.write32(off + WIN_BASE_OFF, win.base);
            if self.has_remap(i) {
                self.mbus_regs.write32(off + WIN_REMAP_LO_OFF, win.remap_lo);
                self.mbus_regs.write32(off + WIN_REMAP_HI_OFF, win.remap_hi);
            }
            self.mbus_regs.write32(off + WIN_CTRL_OFF, win.ctrl);
        }
    }
}

impl BusDriver for MvebuMbus {
    fn name(&self) -> &str { "mvebu-mbus" }

    fn compatible(&self) -> &[&str] { COMPATIBLE }

    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.mbus_regs.init(base, 0x200);
        self.power_state = PowerState::On;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), BusError> {
        self.power_state = PowerState::Off;
        Ok(())
    }

    fn suspend(&mut self) -> Result<(), BusError> {
        self.save_windows();
        self.power_state = PowerState::Suspended;
        Ok(())
    }

    fn resume(&mut self) -> Result<(), BusError> {
        self.restore_windows();
        self.power_state = PowerState::On;
        Ok(())
    }

    fn read_reg(&self, offset: usize) -> Result<u32, BusError> {
        if !self.mbus_regs.is_valid() { return Err(BusError::InitFailed); }
        Ok(self.mbus_regs.read32(offset))
    }

    fn write_reg(&mut self, offset: usize, value: u32) -> Result<(), BusError> {
        if !self.mbus_regs.is_valid() { return Err(BusError::InitFailed); }
        self.mbus_regs.write32(offset, value);
        Ok(())
    }
}
