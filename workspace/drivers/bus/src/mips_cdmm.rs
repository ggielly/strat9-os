use alloc::{string::String, vec::Vec};
use crate::{BusChild, BusDriver, BusError, PowerState};
use crate::mmio::MmioRegion;

const CDMM_DRB_SIZE: usize = 64;

const CDMM_ACSR_DEVTYPE_SHIFT: u32 = 24;
const CDMM_ACSR_DEVTYPE_MASK: u32 = 0xFF << CDMM_ACSR_DEVTYPE_SHIFT;
const CDMM_ACSR_DEVSIZE_SHIFT: u32 = 16;
const CDMM_ACSR_DEVSIZE_MASK: u32 = 0x1F << CDMM_ACSR_DEVSIZE_SHIFT;
const CDMM_ACSR_DEVREV_SHIFT: u32 = 12;
const CDMM_ACSR_DEVREV_MASK: u32 = 0xF << CDMM_ACSR_DEVREV_SHIFT;
const CDMM_ACSR_UW: u32 = 1 << 3;
const CDMM_ACSR_UR: u32 = 1 << 2;
const CDMM_ACSR_SW: u32 = 1 << 1;
const CDMM_ACSR_SR: u32 = 1 << 0;

const MAX_DRBS: usize = 256;

const COMPATIBLE: &[&str] = &["mti,mips-cdmm"];

#[derive(Debug, Clone)]
pub struct CdmmDevice {
    pub dev_type: u8,
    pub dev_size: u8,
    pub dev_rev: u8,
    pub drb_offset: usize,
    pub user_write: bool,
    pub user_read: bool,
    pub super_write: bool,
    pub super_read: bool,
}

pub struct MipsCdmm {
    regs: MmioRegion,
    devices: Vec<CdmmDevice>,
    total_drbs: usize,
    power_state: PowerState,
}

impl MipsCdmm {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            regs: MmioRegion::new(),
            devices: Vec::new(),
            total_drbs: 0,
            power_state: PowerState::Off,
        }
    }

    /// Performs the discover devices operation.
    pub fn discover_devices(&mut self) {
        self.devices.clear();
        if !self.regs.is_valid() { return; }

        let mut drb = 0;
        while drb < MAX_DRBS {
            let offset = drb * CDMM_DRB_SIZE;
            let acsr = self.regs.read32(offset);

            let dev_type = ((acsr & CDMM_ACSR_DEVTYPE_MASK) >> CDMM_ACSR_DEVTYPE_SHIFT) as u8;
            let dev_size = ((acsr & CDMM_ACSR_DEVSIZE_MASK) >> CDMM_ACSR_DEVSIZE_SHIFT) as u8;
            let dev_rev = ((acsr & CDMM_ACSR_DEVREV_MASK) >> CDMM_ACSR_DEVREV_SHIFT) as u8;

            if dev_type == 0 {
                break;
            }

            let block_count = if dev_size == 0 { 1 } else { dev_size as usize };

            self.devices.push(CdmmDevice {
                dev_type,
                dev_size,
                dev_rev,
                drb_offset: offset,
                user_write: (acsr & CDMM_ACSR_UW) != 0,
                user_read: (acsr & CDMM_ACSR_UR) != 0,
                super_write: (acsr & CDMM_ACSR_SW) != 0,
                super_read: (acsr & CDMM_ACSR_SR) != 0,
            });

            drb += block_count;
        }

        self.total_drbs = drb;
    }

    /// Performs the device read32 operation.
    pub fn device_read32(&self, dev_index: usize, offset: usize) -> Result<u32, BusError> {
        let dev = self.devices.get(dev_index).ok_or(BusError::DeviceNotFound)?;
        Ok(self.regs.read32(dev.drb_offset + offset))
    }

    /// Performs the device write32 operation.
    pub fn device_write32(&self, dev_index: usize, offset: usize, val: u32) -> Result<(), BusError> {
        let dev = self.devices.get(dev_index).ok_or(BusError::DeviceNotFound)?;
        self.regs.write32(dev.drb_offset + offset, val);
        Ok(())
    }
}

impl BusDriver for MipsCdmm {
    /// Performs the name operation.
    fn name(&self) -> &str { "mips-cdmm" }

    /// Performs the compatible operation.
    fn compatible(&self) -> &[&str] { COMPATIBLE }

    /// Performs the init operation.
    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, MAX_DRBS * CDMM_DRB_SIZE);
        self.discover_devices();
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
        if !self.regs.is_valid() { return Err(BusError::InitFailed); }
        Ok(self.regs.read32(offset))
    }

    /// Writes reg.
    fn write_reg(&mut self, offset: usize, value: u32) -> Result<(), BusError> {
        if !self.regs.is_valid() { return Err(BusError::InitFailed); }
        self.regs.write32(offset, value);
        Ok(())
    }

    /// Performs the children operation.
    fn children(&self) -> Vec<BusChild> {
        self.devices.iter().enumerate().map(|(i, d)| {
            BusChild {
                name: alloc::format!("cdmm-dev-{:02x}", d.dev_type),
                base_addr: d.drb_offset as u64,
                size: (d.dev_size.max(1) as u64) * (CDMM_DRB_SIZE as u64),
            }
        }).collect()
    }
}
