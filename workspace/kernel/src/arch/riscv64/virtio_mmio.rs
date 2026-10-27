use super::boot::RiscvVirtioMmioDevice;

const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976;
const VIRTIO_MMIO_MAGIC_OFFSET: u64 = 0x000;
const VIRTIO_MMIO_VERSION_OFFSET: u64 = 0x004;
const VIRTIO_MMIO_DEVICE_ID: u64 = 0x008;
const VIRTIO_MMIO_VENDOR_ID: u64 = 0x00c;
const VIRTIO_MMIO_DEVICE_FEATURES: u64 = 0x010;
const VIRTIO_MMIO_QUEUE_NUM_MAX: u64 = 0x034;
const VIRTIO_MMIO_STATUS: u64 = 0x070;
const VIRTIO_MMIO_FEATURES_SELECT: u64 = 0x014;
const VIRTIO_MMIO_DRIVER_FEATURES: u64 = 0x020;
const VIRTIO_MMIO_DRIVER_FEATURES_SELECT: u64 = 0x024;
const VIRTIO_STATUS_ACKNOWLEDGE: u32 = 1;
const VIRTIO_STATUS_DRIVER: u32 = 2;
const VIRTIO_STATUS_FEATURES_OK: u32 = 8;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MmioDeviceInfo {
    pub base: u64,
    pub version: u32,
    pub device_id: u32,
    pub vendor_id: u32,
    pub device_features: u32,
    pub queue_num_max: u32,
}

impl MmioDeviceInfo {
    pub const EMPTY: Self = Self {
        base: 0,
        version: 0,
        device_id: 0,
        vendor_id: 0,
        device_features: 0,
        queue_num_max: 0,
    };
}

pub fn discover(devices: &[RiscvVirtioMmioDevice], out: &mut [MmioDeviceInfo]) -> usize {
    let mut count = 0usize;
    for device in devices {
        if count >= out.len() || device.size < 0x100 {
            continue;
        }
        if read32(device.base, VIRTIO_MMIO_MAGIC_OFFSET) != VIRTIO_MMIO_MAGIC {
            continue;
        }
        let version = read32(device.base, VIRTIO_MMIO_VERSION_OFFSET);
        if !(1..=2).contains(&version) {
            continue;
        }
        let device_id = read32(device.base, VIRTIO_MMIO_DEVICE_ID);
        if device_id == 0 {
            continue;
        }
        out[count] = MmioDeviceInfo {
            base: device.base,
            version,
            device_id,
            vendor_id: read32(device.base, VIRTIO_MMIO_VENDOR_ID),
            device_features: read32(device.base, VIRTIO_MMIO_DEVICE_FEATURES),
            queue_num_max: read32(device.base, VIRTIO_MMIO_QUEUE_NUM_MAX),
        };
        count += 1;
    }
    count
}

pub fn initialize(info: &MmioDeviceInfo) -> Result<(), &'static str> {
    write32(info.base, VIRTIO_MMIO_STATUS, 0);
    for _ in 0..10_000 {
        if read32(info.base, VIRTIO_MMIO_STATUS) == 0 {
            break;
        }
    }
    if read32(info.base, VIRTIO_MMIO_STATUS) != 0 {
        return Err("virtio reset timeout");
    }
    write32(
        info.base,
        VIRTIO_MMIO_STATUS,
        VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER,
    );
    write32(info.base, VIRTIO_MMIO_FEATURES_SELECT, 0);
    let _ = read32(info.base, VIRTIO_MMIO_DEVICE_FEATURES);
    write32(info.base, VIRTIO_MMIO_DRIVER_FEATURES, 0);
    write32(info.base, VIRTIO_MMIO_DRIVER_FEATURES_SELECT, 1);
    write32(info.base, VIRTIO_MMIO_DRIVER_FEATURES, 0);
    write32(
        info.base,
        VIRTIO_MMIO_STATUS,
        VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK,
    );
    if read32(info.base, VIRTIO_MMIO_STATUS) & VIRTIO_STATUS_FEATURES_OK == 0 {
        return Err("virtio features rejected");
    }
    Ok(())
}

fn write32(base: u64, offset: u64, value: u32) {
    unsafe { core::ptr::write_volatile((base + offset) as *mut u32, value) }
}

fn read32(base: u64, offset: u64) -> u32 {
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}
