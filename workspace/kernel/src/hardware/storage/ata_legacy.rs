// Legacy ATA/IDE Driver (PIOS and DMA)
// Reference: ATA/ATAPI-7 Specification

use alloc::string::String;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use super::virtio_block::{BlockDevice, BlockError, SECTOR_SIZE};

const ATA_PRIMARY_IO: u16 = 0x1F0;
const ATA_SECONDARY_IO: u16 = 0x170;

const ATA_REG_DATA: usize = 0;
const ATA_REG_ERROR: usize = 1;
const ATA_REG_SECCOUNT: usize = 2;
const ATA_REG_LBA_LOW: usize = 3;
const ATA_REG_LBA_MID: usize = 4;
const ATA_REG_LBA_HIGH: usize = 5;
const ATA_REG_DEVICE: usize = 6;
const ATA_REG_STATUS: usize = 7;
const ATA_REG_COMMAND: usize = 7;

const ATA_SR_BSY: u8 = 0x80;
const ATA_SR_DRDY: u8 = 0x40;
const ATA_SR_DRQ: u8 = 0x08;
const ATA_SR_ERR: u8 = 0x01;

const ATA_CMD_IDENTIFY: u8 = 0xEC;

const ATA_DEVICE_MASTER: u8 = 0xA0;
const ATA_DEVICE_SLAVE: u8 = 0xB0;
const ATA_DEVICE_LBA: u8 = 0x40;

pub struct AtaChannel {
    io_base: u16,
    control_base: u16,
    bus: u8,
}

impl AtaChannel {
    fn new(io_base: u16, bus: u8) -> Self {
        Self {
            io_base,
            control_base: io_base + 0x206,
            bus,
        }
    }

    fn read8(&self, offset: usize) -> u8 {
        unsafe { x86_64::instructions::port::Port::new(self.io_base + offset as u16).read() }
    }

    fn write8(&self, offset: usize, value: u8) {
        unsafe { x86_64::instructions::port::Port::new(self.io_base + offset as u16).write(value) }
    }

    fn read16(&self) -> u16 {
        unsafe { x86_64::instructions::port::Port::new(self.io_base).read() }
    }

    fn write16(&self, value: u16) {
        unsafe { x86_64::instructions::port::Port::new(self.io_base).write(value) }
    }

    fn wait_ready(&self) -> Result<(), &'static str> {
        for _ in 0..100000 {
            let status = self.read8(ATA_REG_STATUS);
            if (status & ATA_SR_BSY) == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err("ATA timeout")
    }

    fn wait_drq(&self) -> Result<(), &'static str> {
        for _ in 0..100000 {
            let status = self.read8(ATA_REG_STATUS);
            if (status & ATA_SR_DRQ) != 0 {
                return Ok(());
            }
            if (status & ATA_SR_ERR) != 0 {
                return Err("ATA error");
            }
            core::hint::spin_loop();
        }
        Err("ATA timeout")
    }

    fn select_device(&self, device: u8, lba: u64) {
        let device_reg = ATA_DEVICE_MASTER | ATA_DEVICE_LBA | ((lba >> 24) & 0x0F) as u8;
        self.write8(ATA_REG_DEVICE, device_reg);
        self.read8(ATA_REG_STATUS);
        for _ in 0..4 {
            core::hint::spin_loop();
        }
    }

    fn identify(&self, device: u8) -> Option<AtaDriveInfo> {
        self.select_device(device, 0);
        self.write8(ATA_REG_SECCOUNT, 0);
        self.write8(ATA_REG_LBA_LOW, 0);
        self.write8(ATA_REG_LBA_MID, 0);
        self.write8(ATA_REG_LBA_HIGH, 0);
        self.write8(ATA_REG_COMMAND, ATA_CMD_IDENTIFY);

        let status = self.read8(ATA_REG_STATUS);
        if status == 0 {
            return None;
        }

        if let Err(_) = self.wait_ready() {
            return None;
        }

        if let Err(_) = self.wait_drq() {
            return None;
        }

        let mut buffer = [0u16; 256];
        for i in 0..256 {
            buffer[i] = self.read16();
        }

        let serial = Self::decode_identify_string(&buffer, 10, 20);
        let model = Self::decode_identify_string(&buffer, 27, 54);
        let capacity = (buffer[60] as u64) | ((buffer[61] as u64) << 16);

        Some(AtaDriveInfo { model, serial, capacity })
    }

    fn decode_identify_string(buffer: &[u16], start: usize, end: usize) -> String {
        use alloc::string::String;
        let mut s = String::new();
        for i in start..end {
            if i < buffer.len() {
                let c = buffer[i];
                s.push((c >> 8) as char);
                s.push((c & 0xFF) as char);
            }
        }
        s.trim().to_string()
    }

    fn read_sector_pio(&self, device: u8, lba: u64, buffer: &mut [u8]) -> Result<(), &'static str> {
        if buffer.len() < SECTOR_SIZE {
            return Err("Buffer too small");
        }

        self.wait_ready()?;
        self.select_device(device, lba);

        self.write8(ATA_REG_SECCOUNT, 1);
        self.write8(ATA_REG_LBA_LOW, (lba & 0xFF) as u8);
        self.write8(ATA_REG_LBA_MID, ((lba >> 8) & 0xFF) as u8);
        self.write8(ATA_REG_LBA_HIGH, ((lba >> 16) & 0xFF) as u8);

        self.write8(ATA_REG_COMMAND, 0x24);
        self.wait_drq()?;

        let buf_ptr = buffer.as_mut_ptr() as *mut u16;
        for i in 0..256 {
            unsafe {
                core::ptr::write_volatile(buf_ptr.add(i), self.read16());
            }
        }

        self.wait_ready()?;
        Ok(())
    }

    fn write_sector_pio(&self, device: u8, lba: u64, buffer: &[u8]) -> Result<(), &'static str> {
        if buffer.len() < SECTOR_SIZE {
            return Err("Buffer too small");
        }

        self.wait_ready()?;
        self.select_device(device, lba);

        self.write8(ATA_REG_SECCOUNT, 1);
        self.write8(ATA_REG_LBA_LOW, (lba & 0xFF) as u8);
        self.write8(ATA_REG_LBA_MID, ((lba >> 8) & 0xFF) as u8);
        self.write8(ATA_REG_LBA_HIGH, ((lba >> 16) & 0xFF) as u8);

        self.write8(ATA_REG_COMMAND, 0x34);
        self.wait_drq()?;

        let buf_ptr = buffer.as_ptr() as *const u16;
        for i in 0..256 {
            unsafe {
                self.write16(core::ptr::read_volatile(buf_ptr.add(i)));
            }
        }

        self.wait_ready()?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct AtaDriveInfo {
    pub model: String,
    pub serial: String,
    pub capacity: u64,
}

pub struct AtaDrive {
    channel: AtaChannel,
    device: u8,
    info: AtaDriveInfo,
    name: String,
}

unsafe impl Send for AtaDrive {}
unsafe impl Sync for AtaDrive {}

impl AtaDrive {
    pub fn new(channel: AtaChannel, device: u8) -> Option<Self> {
        let info = channel.identify(device)?;
        let name = format!("ata{}_{}", channel.bus, if device == ATA_DEVICE_MASTER { "master" } else { "slave" });
        Some(Self { channel, device, info, name })
    }

    pub fn info(&self) -> &AtaDriveInfo {
        &self.info
    }
}

impl BlockDevice for AtaDrive {
    fn read_sector(&self, sector: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.channel.read_sector_pio(self.device, sector, buf).map_err(|_| BlockError::IoError)
    }

    fn write_sector(&self, sector: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.channel.write_sector_pio(self.device, sector, buf).map_err(|_| BlockError::IoError)
    }

    fn sector_count(&self) -> u64 {
        self.info.capacity
    }
}

static ATA_DRIVES: Mutex<Vec<Arc<AtaDrive>>> = Mutex::new(Vec::new());
static ATA_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init() {
    log::info!("[ATA] Scanning for legacy ATA/IDE devices...");

    let channels = [
        AtaChannel::new(ATA_PRIMARY_IO, 0),
        AtaChannel::new(ATA_SECONDARY_IO, 1),
    ];

    for channel in &channels {
        for device in [ATA_DEVICE_MASTER, ATA_DEVICE_SLAVE] {
            if let Some(drive) = AtaDrive::new(channel.clone(), device) {
                log::info!(
                    "ATA: Found drive on bus{} device{}: {} ({} sectors)",
                    channel.bus,
                    if device == ATA_DEVICE_MASTER { "master" } else { "slave" },
                    drive.info().model,
                    drive.info().capacity
                );
                ATA_DRIVES.lock().push(Arc::new(drive));
            }
        }
    }

    ATA_INITIALIZED.store(true, Ordering::SeqCst);
    log::info!("[ATA] Found {} drive(s)", ATA_DRIVES.lock().len());
}

pub fn get_drive(index: usize) -> Option<Arc<AtaDrive>> {
    ATA_DRIVES.lock().get(index).cloned()
}

pub fn get_first_drive() -> Option<Arc<AtaDrive>> {
    ATA_DRIVES.lock().first().cloned()
}

pub fn is_available() -> bool {
    ATA_INITIALIZED.load(Ordering::Relaxed)
}
