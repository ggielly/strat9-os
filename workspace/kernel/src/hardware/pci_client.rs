use alloc::{format, string::String, vec::Vec};

pub use crate::arch::x86_64::pci::{
    class, command, config, device, intel_eth, net_subclass, sata_progif, storage_subclass, vendor,
};
use crate::vfs::{self, OpenFlags};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bar {
    Io { port: u16 },
    Memory32 { addr: u32, prefetchable: bool },
    Memory64 { addr: u64, prefetchable: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciAddress {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciAddress {
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PciDevice {
    pub address: PciAddress,
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

#[derive(Debug, Clone, Copy, Default)]
pub struct ProbeCriteria {
    pub vendor_id: Option<u16>,
    pub device_id: Option<u16>,
    pub class_code: Option<u8>,
    pub subclass: Option<u8>,
    pub prog_if: Option<u8>,
}

impl ProbeCriteria {
    pub const fn any() -> Self {
        Self {
            vendor_id: None,
            device_id: None,
            class_code: None,
            subclass: None,
            prog_if: None,
        }
    }

    fn matches(&self, dev: &PciDevice) -> bool {
        if self.vendor_id.is_some_and(|v| dev.vendor_id != v) {
            return false;
        }
        if self.device_id.is_some_and(|d| dev.device_id != d) {
            return false;
        }
        if self.class_code.is_some_and(|c| dev.class_code != c) {
            return false;
        }
        if self.subclass.is_some_and(|s| dev.subclass != s) {
            return false;
        }
        if self.prog_if.is_some_and(|p| dev.prog_if != p) {
            return false;
        }
        true
    }
}

fn open_read_all(path: &str) -> Option<Vec<u8>> {
    let fd = vfs::open(path, OpenFlags::READ).ok()?;
    let mut out = Vec::new();
    let mut chunk = [0u8; 256];
    loop {
        let n = match vfs::read(fd, &mut chunk) {
            Ok(n) => n,
            Err(_) => {
                let _ = vfs::close(fd);
                return None;
            }
        };
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
    }
    let _ = vfs::close(fd);
    Some(out)
}

fn open_write(path: &str, bytes: &[u8]) -> bool {
    let fd = match vfs::open(path, OpenFlags::WRITE) {
        Ok(fd) => fd,
        Err(_) => return false,
    };
    let ok = vfs::write(fd, bytes).is_ok();
    let _ = vfs::close(fd);
    ok
}

fn parse_hex_u8(s: &str) -> Option<u8> {
    u8::from_str_radix(s.trim_start_matches("0x"), 16).ok()
}

fn parse_hex_u16(s: &str) -> Option<u16> {
    u16::from_str_radix(s.trim_start_matches("0x"), 16).ok()
}

fn parse_inventory_line(line: &str) -> Option<PciDevice> {
    let mut parts = line.split_whitespace();
    let bdf = parts.next()?;
    let ids = parts.next()?;
    let class_sub = parts.next()?;
    let prog_if = parts.next()?;
    let rev = parts.next()?;
    let irq = parts.next()?;

    let (bus_s, rest) = bdf.split_once(':')?;
    let (dev_s, fun_s) = rest.split_once('.')?;
    let bus = parse_hex_u8(bus_s)?;
    let device = parse_hex_u8(dev_s)?;
    let function = fun_s.parse::<u8>().ok()?;

    let (ven_s, did_s) = ids.split_once(':')?;
    let vendor_id = parse_hex_u16(ven_s)?;
    let device_id = parse_hex_u16(did_s)?;

    let (class_s, sub_s) = class_sub.split_once(':')?;
    let class_code = parse_hex_u8(class_s)?;
    let subclass = parse_hex_u8(sub_s)?;

    let prog_if = parse_hex_u8(prog_if)?;
    let revision = parse_hex_u8(rev)?;
    let interrupt_line = irq.parse::<u8>().unwrap_or(0);

    Some(PciDevice {
        address: PciAddress::new(bus, device, function),
        vendor_id,
        device_id,
        class_code,
        subclass,
        prog_if,
        revision,
        header_type: 0,
        interrupt_line,
        interrupt_pin: 0,
    })
}

fn all_devices_from_bus_service() -> Vec<PciDevice> {
    let bytes = match open_read_all("/bus/pci/inventory") {
        Some(b) => b,
        None => return Vec::new(),
    };
    let text = match core::str::from_utf8(&bytes) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        if idx == 0 || line.trim().is_empty() {
            continue;
        }
        if let Some(dev) = parse_inventory_line(line) {
            out.push(dev);
        }
    }
    out
}

fn cfg_path(addr: PciAddress, offset: u8, width: u8) -> String {
    format!(
        "/bus/pci/cfg/{:02x}:{:02x}.{:x}/{:02x}/{}",
        addr.bus, addr.device, addr.function, offset, width
    )
}

fn cfg_read(addr: PciAddress, offset: u8, width: u8) -> Option<u32> {
    let bytes = open_read_all(&cfg_path(addr, offset, width))?;
    let text = core::str::from_utf8(&bytes).ok()?.trim();
    let hex = text.strip_prefix("0x")?;
    u32::from_str_radix(hex, 16).ok()
}

fn cfg_write(addr: PciAddress, offset: u8, width: u8, value: u32) -> bool {
    open_write(&cfg_path(addr, offset, width), &value.to_le_bytes())
}

impl PciDevice {
    pub fn read_config_u8(&self, offset: u8) -> u8 {
        cfg_read(self.address, offset, 1).map_or(0, |v| v as u8)
    }

    pub fn read_config_u16(&self, offset: u8) -> u16 {
        cfg_read(self.address, offset, 2).map_or(0, |v| v as u16)
    }

    pub fn read_config_u32(&self, offset: u8) -> u32 {
        cfg_read(self.address, offset, 4).unwrap_or(0)
    }

    pub fn write_config_u8(&self, offset: u8, value: u8) {
        let _ = cfg_write(self.address, offset, 1, value as u32);
    }

    pub fn write_config_u16(&self, offset: u8, value: u16) {
        let _ = cfg_write(self.address, offset, 2, value as u32);
    }

    pub fn write_config_u32(&self, offset: u8, value: u32) {
        let _ = cfg_write(self.address, offset, 4, value);
    }

    pub fn read_bar(&self, bar_index: u8) -> Option<Bar> {
        if bar_index > 5 {
            return None;
        }
        let offset = config::BAR0 + bar_index * 4;
        let low = self.read_config_u32(offset);
        if low == 0 {
            return None;
        }
        if (low & 1) != 0 {
            return Some(Bar::Io {
                port: (low & 0xFFFF_FFFC) as u16,
            });
        }
        let bar_type = (low >> 1) & 0x3;
        let prefetchable = ((low >> 3) & 1) != 0;
        match bar_type {
            0 => Some(Bar::Memory32 {
                addr: low & 0xFFFF_FFF0,
                prefetchable,
            }),
            2 => {
                if bar_index >= 5 {
                    return None;
                }
                let high = self.read_config_u32(offset + 4);
                Some(Bar::Memory64 {
                    addr: ((high as u64) << 32) | ((low & 0xFFFF_FFF0) as u64),
                    prefetchable,
                })
            }
            _ => None,
        }
    }

    pub fn read_bar_raw(&self, bar_index: u8) -> Option<u64> {
        match self.read_bar(bar_index) {
            Some(Bar::Io { port }) => Some(port as u64),
            Some(Bar::Memory32 { addr, .. }) => Some(addr as u64),
            Some(Bar::Memory64 { addr, .. }) => Some(addr),
            None => None,
        }
    }

    pub fn enable_bus_master(&self) {
        let mut cmd = self.read_config_u16(config::COMMAND);
        cmd |= command::BUS_MASTER;
        self.write_config_u16(config::COMMAND, cmd);
    }

    pub fn enable_memory_space(&self) {
        let mut cmd = self.read_config_u16(config::COMMAND);
        cmd |= command::MEMORY_SPACE;
        self.write_config_u16(config::COMMAND, cmd);
    }

    pub fn enable_io_space(&self) {
        let mut cmd = self.read_config_u16(config::COMMAND);
        cmd |= command::IO_SPACE;
        self.write_config_u16(config::COMMAND, cmd);
    }
}

pub fn all_devices() -> Vec<PciDevice> {
    // Blocking startup contract:
    // this strict client only uses /bus/pci/inventory.
    // If strate-bus is not started yet, enumeration is empty by design.
    all_devices_from_bus_service()
}

pub fn find_device(vendor_id: u16, device_id: u16) -> Option<PciDevice> {
    all_devices()
        .into_iter()
        .find(|d| d.vendor_id == vendor_id && d.device_id == device_id)
}

pub fn find_virtio_device(device_id: u16) -> Option<PciDevice> {
    find_device(vendor::VIRTIO, device_id)
}

pub fn find_virtio_devices() -> Vec<PciDevice> {
    find_devices_by_vendor(vendor::VIRTIO)
}

pub fn find_devices_by_vendor(vendor_id: u16) -> Vec<PciDevice> {
    all_devices()
        .into_iter()
        .filter(|d| d.vendor_id == vendor_id)
        .collect()
}

pub fn find_devices_by_class(class_code: u8, subclass: u8) -> Vec<PciDevice> {
    all_devices()
        .into_iter()
        .filter(|d| d.class_code == class_code && d.subclass == subclass)
        .collect()
}

pub fn probe_all(criteria: ProbeCriteria) -> Vec<PciDevice> {
    all_devices()
        .into_iter()
        .filter(|d| criteria.matches(d))
        .collect()
}

pub fn probe_first(criteria: ProbeCriteria) -> Option<PciDevice> {
    all_devices().into_iter().find(|d| criteria.matches(d))
}

pub fn invalidate_cache() {
    let _ = open_write("/bus/pci/rescan", &[1, 0, 0, 0]);
}
