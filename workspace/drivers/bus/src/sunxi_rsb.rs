use alloc::{string::String, vec::Vec};
use crate::{BusChild, BusDriver, BusError, PowerState};
use crate::mmio::MmioRegion;

const RSB_CTRL: usize = 0x00;
const RSB_CCR: usize = 0x04;
const RSB_INTE: usize = 0x08;
const RSB_INTS: usize = 0x0C;
const RSB_ADDR: usize = 0x10;
const RSB_DATA: usize = 0x1C;
const RSB_LCR: usize = 0x24;
const RSB_DMCR: usize = 0x28;
const RSB_CMD: usize = 0x2C;
const RSB_DAR: usize = 0x30;

const RSB_CTRL_START_TRANS: u32 = 1 << 7;
const RSB_CTRL_ABORT_TRANS: u32 = 1 << 6;
const RSB_CTRL_GLOBAL_INT_ENB: u32 = 1 << 1;
const RSB_CTRL_SOFT_RST: u32 = 1 << 0;

const RSB_INTS_TRANS_ERR_ACK: u32 = 1 << 16;
const RSB_INTS_TRANS_ERR_DATA_MASK: u32 = 0xF << 8;
const RSB_INTS_LOAD_BSY: u32 = 1 << 2;
const RSB_INTS_TRANS_ERR: u32 = 1 << 1;
const RSB_INTS_TRANS_OVER: u32 = 1 << 0;

const RSB_DMCR_DEVICE_START: u32 = 1 << 31;
const RSB_DMCR_MODE_DATA: u32 = 0x7C << 16;
const RSB_DMCR_MODE_REG: u32 = 0x3E << 8;

const RSB_CMD_RD8: u32 = 0x8B;
const RSB_CMD_RD16: u32 = 0x9C;
const RSB_CMD_RD32: u32 = 0xA6;
const RSB_CMD_WR8: u32 = 0x4E;
const RSB_CMD_WR16: u32 = 0x59;
const RSB_CMD_WR32: u32 = 0x63;
const RSB_CMD_STRA: u32 = 0xE8;

const MAX_POLL: u32 = 10000;

const COMPATIBLE: &[&str] = &["allwinner,sun8i-a23-rsb"];

fn ccr_sda_out_delay(v: u32) -> u32 { (v & 0x7) << 8 }
fn ccr_clk_div(v: u32) -> u32 { v & 0xFF }
fn dar_rta(v: u32) -> u32 { (v & 0xFF) << 16 }
fn dar_da(v: u32) -> u32 { v & 0xFFFF }

pub struct RsbAddrMap {
    pub hwaddr: u16,
    pub rtaddr: u8,
}

pub const DEFAULT_ADDR_MAP: &[RsbAddrMap] = &[
    RsbAddrMap { hwaddr: 0x3A3, rtaddr: 0x2D },
    RsbAddrMap { hwaddr: 0x745, rtaddr: 0x3A },
    RsbAddrMap { hwaddr: 0xE89, rtaddr: 0x4E },
];

pub struct SunxiRsb {
    regs: MmioRegion,
    clock_freq: u32,
    power_state: PowerState,
    children: Vec<BusChild>,
}

impl SunxiRsb {
    pub fn new() -> Self {
        Self {
            regs: MmioRegion::new(),
            clock_freq: 3_000_000,
            power_state: PowerState::Off,
            children: Vec::new(),
        }
    }

    pub fn set_clock_freq(&mut self, freq: u32) {
        self.clock_freq = freq;
    }

    fn soft_reset(&self) {
        self.regs.write32(RSB_CTRL, RSB_CTRL_SOFT_RST);
        for _ in 0..MAX_POLL {
            if self.regs.read32(RSB_CTRL) & RSB_CTRL_SOFT_RST == 0 {
                return;
            }
        }
    }

    fn wait_transfer_complete(&self) -> Result<u32, BusError> {
        for _ in 0..MAX_POLL {
            let status = self.regs.read32(RSB_INTS);
            if status & RSB_INTS_LOAD_BSY != 0 {
                self.regs.write32(RSB_INTS, status);
                return Err(BusError::Timeout);
            }
            if status & RSB_INTS_TRANS_ERR != 0 {
                self.regs.write32(RSB_INTS, status);
                return Err(BusError::ProtocolError);
            }
            if status & RSB_INTS_TRANS_OVER != 0 {
                self.regs.write32(RSB_INTS, status);
                return Ok(status);
            }
        }
        Err(BusError::Timeout)
    }

    fn start_transfer(&self) {
        self.regs.write32(RSB_CTRL, RSB_CTRL_START_TRANS | RSB_CTRL_GLOBAL_INT_ENB);
    }

    pub fn set_runtime_address(&self, hwaddr: u16, rtaddr: u8) -> Result<(), BusError> {
        self.regs.write32(RSB_CMD, RSB_CMD_STRA);
        self.regs.write32(RSB_DAR, dar_rta(rtaddr as u32) | dar_da(hwaddr as u32));
        self.start_transfer();
        self.wait_transfer_complete()?;
        Ok(())
    }

    pub fn init_device_mode(&self) -> Result<(), BusError> {
        self.regs.write32(RSB_DMCR, RSB_DMCR_DEVICE_START | RSB_DMCR_MODE_DATA | RSB_DMCR_MODE_REG);
        for _ in 0..MAX_POLL {
            if self.regs.read32(RSB_DMCR) & RSB_DMCR_DEVICE_START == 0 {
                return Ok(());
            }
        }
        Err(BusError::Timeout)
    }

    pub fn read8(&self, rtaddr: u8, reg: u8) -> Result<u8, BusError> {
        self.regs.write32(RSB_CMD, RSB_CMD_RD8);
        self.regs.write32(RSB_DAR, dar_rta(rtaddr as u32));
        self.regs.write32(RSB_ADDR, reg as u32);
        self.start_transfer();
        self.wait_transfer_complete()?;
        Ok(self.regs.read32(RSB_DATA) as u8)
    }

    pub fn write8(&self, rtaddr: u8, reg: u8, val: u8) -> Result<(), BusError> {
        self.regs.write32(RSB_CMD, RSB_CMD_WR8);
        self.regs.write32(RSB_DAR, dar_rta(rtaddr as u32));
        self.regs.write32(RSB_ADDR, reg as u32);
        self.regs.write32(RSB_DATA, val as u32);
        self.start_transfer();
        self.wait_transfer_complete()?;
        Ok(())
    }

    pub fn read16(&self, rtaddr: u8, reg: u8) -> Result<u16, BusError> {
        self.regs.write32(RSB_CMD, RSB_CMD_RD16);
        self.regs.write32(RSB_DAR, dar_rta(rtaddr as u32));
        self.regs.write32(RSB_ADDR, reg as u32);
        self.start_transfer();
        self.wait_transfer_complete()?;
        Ok(self.regs.read32(RSB_DATA) as u16)
    }

    pub fn write16(&self, rtaddr: u8, reg: u8, val: u16) -> Result<(), BusError> {
        self.regs.write32(RSB_CMD, RSB_CMD_WR16);
        self.regs.write32(RSB_DAR, dar_rta(rtaddr as u32));
        self.regs.write32(RSB_ADDR, reg as u32);
        self.regs.write32(RSB_DATA, val as u32);
        self.start_transfer();
        self.wait_transfer_complete()?;
        Ok(())
    }

    pub fn add_child(&mut self, child: BusChild) {
        self.children.push(child);
    }
}

impl BusDriver for SunxiRsb {
    fn name(&self) -> &str { "sunxi-rsb" }

    fn compatible(&self) -> &[&str] { COMPATIBLE }

    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x40);
        self.soft_reset();
        self.regs.write32(RSB_CCR, ccr_sda_out_delay(1) | ccr_clk_div(3));
        self.init_device_mode()?;
        self.power_state = PowerState::On;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), BusError> {
        self.soft_reset();
        self.power_state = PowerState::Off;
        Ok(())
    }

    fn read_reg(&self, offset: usize) -> Result<u32, BusError> {
        if !self.regs.is_valid() { return Err(BusError::InitFailed); }
        Ok(self.regs.read32(offset))
    }

    fn write_reg(&mut self, offset: usize, value: u32) -> Result<(), BusError> {
        if !self.regs.is_valid() { return Err(BusError::InitFailed); }
        self.regs.write32(offset, value);
        Ok(())
    }

    fn children(&self) -> Vec<BusChild> {
        self.children.clone()
    }
}
