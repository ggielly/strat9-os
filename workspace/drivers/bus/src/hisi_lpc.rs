use crate::{BusChild, BusDriver, BusError, PowerState, mmio::MmioRegion};
use alloc::{string::String, vec::Vec};

const LPC_REG_STARTUP_SIGNAL: usize = 0x00;
const LPC_REG_OP_STATUS: usize = 0x04;
const LPC_REG_OP_LEN: usize = 0x10;
const LPC_REG_CMD: usize = 0x14;
const LPC_REG_ADDR: usize = 0x20;
const LPC_REG_WDATA: usize = 0x24;
const LPC_REG_RDATA: usize = 0x28;

const STARTUP_SIGNAL_START: u32 = 1 << 0;
const OP_STATUS_IDLE: u32 = 1 << 0;
const OP_STATUS_FINISHED: u32 = 1 << 1;
const CMD_OP_READ: u32 = 0;
const CMD_OP_WRITE: u32 = 1 << 0;
const CMD_SAMEADDR: u32 = 1 << 3;

const LPC_MAX_DWIDTH: u32 = 4;
const LPC_PEROP_WAITCNT: u32 = 100;
const LPC_MAX_WAITCNT: u32 = 1300;

const COMPATIBLE: &[&str] = &["hisilicon,hip06-lpc", "hisilicon,hip07-lpc"];

pub struct HisiLpc {
    regs: MmioRegion,
    power_state: PowerState,
    children: Vec<BusChild>,
}

impl HisiLpc {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            regs: MmioRegion::new(),
            power_state: PowerState::Off,
            children: Vec::new(),
        }
    }

    /// Performs the wait idle operation.
    fn wait_idle(&self) -> Result<(), BusError> {
        for _ in 0..LPC_MAX_WAITCNT {
            let status = self.regs.read32(LPC_REG_OP_STATUS);
            if status & OP_STATUS_IDLE != 0 {
                return Ok(());
            }
        }
        Err(BusError::Timeout)
    }

    /// Performs the wait finish operation.
    fn wait_finish(&self) -> Result<(), BusError> {
        for _ in 0..LPC_MAX_WAITCNT {
            let status = self.regs.read32(LPC_REG_OP_STATUS);
            if status & OP_STATUS_FINISHED != 0 {
                return Ok(());
            }
        }
        Err(BusError::Timeout)
    }

    /// Performs the lpc read operation.
    pub fn lpc_read(&self, addr: u32, width: u32) -> Result<u32, BusError> {
        if width == 0 || width > LPC_MAX_DWIDTH {
            return Err(BusError::InvalidArgument);
        }

        self.wait_idle()?;

        self.regs.write32(LPC_REG_ADDR, addr);
        self.regs.write32(LPC_REG_CMD, CMD_OP_READ);
        self.regs.write32(LPC_REG_OP_LEN, width);
        self.regs
            .write32(LPC_REG_STARTUP_SIGNAL, STARTUP_SIGNAL_START);

        self.wait_finish()?;

        let mut result = 0u32;
        for i in 0..width {
            let byte = self.regs.read32(LPC_REG_RDATA) & 0xFF;
            result |= byte << (i * 8);
        }

        Ok(result)
    }

    /// Performs the lpc write operation.
    pub fn lpc_write(&self, addr: u32, width: u32, data: u32) -> Result<(), BusError> {
        if width == 0 || width > LPC_MAX_DWIDTH {
            return Err(BusError::InvalidArgument);
        }

        self.wait_idle()?;

        self.regs.write32(LPC_REG_ADDR, addr);
        self.regs.write32(LPC_REG_CMD, CMD_OP_WRITE);
        self.regs.write32(LPC_REG_OP_LEN, width);

        for i in 0..width {
            self.regs.write32(LPC_REG_WDATA, (data >> (i * 8)) & 0xFF);
        }

        self.regs
            .write32(LPC_REG_STARTUP_SIGNAL, STARTUP_SIGNAL_START);

        self.wait_finish()?;

        Ok(())
    }

    /// Performs the io read8 operation.
    pub fn io_read8(&self, port: u16) -> Result<u8, BusError> {
        self.lpc_read(port as u32, 1).map(|v| v as u8)
    }

    /// Performs the io write8 operation.
    pub fn io_write8(&self, port: u16, val: u8) -> Result<(), BusError> {
        self.lpc_write(port as u32, 1, val as u32)
    }

    /// Performs the io read16 operation.
    pub fn io_read16(&self, port: u16) -> Result<u16, BusError> {
        self.lpc_read(port as u32, 2).map(|v| v as u16)
    }

    /// Performs the io write16 operation.
    pub fn io_write16(&self, port: u16, val: u16) -> Result<(), BusError> {
        self.lpc_write(port as u32, 2, val as u32)
    }

    /// Performs the io read32 operation.
    pub fn io_read32(&self, port: u16) -> Result<u32, BusError> {
        self.lpc_read(port as u32, 4)
    }

    /// Performs the io write32 operation.
    pub fn io_write32(&self, port: u16, val: u32) -> Result<(), BusError> {
        self.lpc_write(port as u32, 4, val)
    }

    /// Performs the add child operation.
    pub fn add_child(&mut self, child: BusChild) {
        self.children.push(child);
    }
}

impl BusDriver for HisiLpc {
    /// Performs the name operation.
    fn name(&self) -> &str {
        "hisi-lpc"
    }

    /// Performs the compatible operation.
    fn compatible(&self) -> &[&str] {
        COMPATIBLE
    }

    /// Performs the init operation.
    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x30);
        self.wait_idle()?;
        self.power_state = PowerState::On;
        Ok(())
    }

    /// Performs the shutdown operation.
    fn shutdown(&mut self) -> Result<(), BusError> {
        self.power_state = PowerState::Off;
        Ok(())
    }

    /// Reads reg.
    fn read_reg(&self, offset: usize) -> Result<u32, BusError> {
        if !self.regs.is_valid() {
            return Err(BusError::InitFailed);
        }
        Ok(self.regs.read32(offset))
    }

    /// Writes reg.
    fn write_reg(&mut self, offset: usize, value: u32) -> Result<(), BusError> {
        if !self.regs.is_valid() {
            return Err(BusError::InitFailed);
        }
        self.regs.write32(offset, value);
        Ok(())
    }

    /// Performs the children operation.
    fn children(&self) -> Vec<BusChild> {
        self.children.clone()
    }
}
