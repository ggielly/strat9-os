use core::sync::atomic::{AtomicU64, Ordering};

const ECAM_BUS_STRIDE: u64 = 0x100000;
const ECAM_DEVICE_STRIDE: u64 = 0x1000;
const PCI_MAX_BUS: u8 = 1;
const PCI_MAX_DEVICE: u8 = 32;
const PCI_MAX_FUNCTION: u8 = 8;

static BASE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PciDeviceInfo {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision: u8,
    pub header_type: u8,
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
}

impl PciDeviceInfo {
    pub const EMPTY: Self = Self {
        bus: 0,
        device: 0,
        function: 0,
        vendor_id: 0xffff,
        device_id: 0xffff,
        class_code: 0,
        subclass: 0,
        prog_if: 0,
        revision: 0,
        header_type: 0,
        interrupt_line: 0,
        interrupt_pin: 0,
    };
}

pub fn init(base: u64) -> Result<(), &'static str> {
    if base == 0 || base % 0x1000 != 0 {
        return Err("invalid ECAM base");
    }
    BASE.store(base, Ordering::Release);
    Ok(())
}

pub fn enumerate(out: &mut [PciDeviceInfo]) -> usize {
    if out.is_empty() || base().is_none() {
        return 0;
    }
    let mut count = 0usize;
    for bus in 0..PCI_MAX_BUS {
        for device in 0..PCI_MAX_DEVICE {
            for function in 0..PCI_MAX_FUNCTION {
                let vendor_id = read_config_u16(bus, device, function, 0);
                if vendor_id == 0xffff || vendor_id == 0 {
                    if function > 0 {
                        break;
                    }
                    continue;
                }
                if count >= out.len() {
                    return count;
                }
                let class = read_config_u32(bus, device, function, 0x08);
                out[count] = PciDeviceInfo {
                    bus,
                    device,
                    function,
                    vendor_id,
                    device_id: read_config_u16(bus, device, function, 0x02),
                    class_code: (class >> 16) as u8,
                    subclass: (class >> 8) as u8,
                    prog_if: class as u8,
                    revision: (class >> 24) as u8,
                    header_type: read_config_u8(bus, device, function, 0x0e),
                    interrupt_line: read_config_u8(bus, device, function, 0x3c),
                    interrupt_pin: read_config_u8(bus, device, function, 0x3d),
                };
                count += 1;
            }
        }
    }
    count
}

pub fn read_config_u8(bus: u8, device: u8, function: u8, offset: u8) -> u8 {
    let value = read_config_u32(bus, device, function, offset & !3);
    (value >> ((offset & 3) * 8)) as u8
}

pub fn read_config_u16(bus: u8, device: u8, function: u8, offset: u8) -> u16 {
    let value = read_config_u32(bus, device, function, offset & !3);
    (value >> ((offset & 2) * 8)) as u16
}

pub fn read_config_u32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let Some(base) = base() else {
        return 0xffff_ffff;
    };
    let address = base
        + bus as u64 * ECAM_BUS_STRIDE
        + device as u64 * ECAM_DEVICE_STRIDE
        + function as u64 * 0x100
        + (offset & 0xfc) as u64;
    unsafe { core::ptr::read_volatile(address as *const u32) }
}

pub fn write_config_u32(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    let Some(base) = base() else {
        return;
    };
    let address = base
        + bus as u64 * ECAM_BUS_STRIDE
        + device as u64 * ECAM_DEVICE_STRIDE
        + function as u64 * 0x100
        + (offset & 0xfc) as u64;
    unsafe { core::ptr::write_volatile(address as *mut u32, value) }
}

fn base() -> Option<u64> {
    let value = BASE.load(Ordering::Acquire);
    (value != 0).then_some(value)
}
