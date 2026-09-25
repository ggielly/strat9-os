use super::boot::RiscvVirtioMmioDevice;

const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976;
const VIRTIO_MMIO_VERSION: u64 = 0x0000_0002;
const VIRTIO_MMIO_MAGIC_OFFSET: u64 = 0x000;
const VIRTIO_MMIO_VERSION_OFFSET: u64 = 0x004;
const VIRTIO_MMIO_DEVICE_ID: u64 = 0x008;
const VIRTIO_MMIO_VENDOR_ID: u64 = 0x00c;
const VIRTIO_MMIO_DEVICE_FEATURES: u64 = 0x010;
const VIRTIO_MMIO_QUEUE_NUM_MAX: u64 = 0x034;

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
        if version != VIRTIO_MMIO_VERSION as u32 {
            continue;
        }
        out[count] = MmioDeviceInfo {
            base: device.base,
            version,
            device_id: read32(device.base, VIRTIO_MMIO_DEVICE_ID),
            vendor_id: read32(device.base, VIRTIO_MMIO_VENDOR_ID),
            device_features: read32(device.base, VIRTIO_MMIO_DEVICE_FEATURES),
            queue_num_max: read32(device.base, VIRTIO_MMIO_QUEUE_NUM_MAX),
        };
        count += 1;
    }
    count
}

fn read32(base: u64, offset: u64) -> u32 {
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}
