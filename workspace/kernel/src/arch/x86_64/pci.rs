//! PCI Configuration Space Access
//!
//! Provides functions to scan the PCI bus and read/write configuration registers.
//! Used to discover VirtIO and other PCI devices.
//!
//! Reference: PCI Local Bus Specification 3.0

use super::io::{inl, outl};
use crate::serial_println;
use core::fmt;

/// PCI Configuration Address Port
const CONFIG_ADDRESS: u16 = 0xCF8;
/// PCI Configuration Data Port
const CONFIG_DATA: u16 = 0xCFC;

/// PCI Vendor IDs
pub mod vendor {
    pub const VIRTIO: u16 = 0x1AF4;
    pub const QEMU: u16 = 0x1234;
    pub const INTEL: u16 = 0x8086;
    pub const AMD: u16 = 0x1022;
}

/// PCI Device IDs (VirtIO legacy)
pub mod device {
    pub const VIRTIO_NET: u16 = 0x1000;
    pub const VIRTIO_BLOCK: u16 = 0x1001;
    pub const VIRTIO_CONSOLE: u16 = 0x1003;
    pub const VIRTIO_RNG: u16 = 0x1005;
    pub const VIRTIO_GPU: u16 = 0x1050;
    pub const VIRTIO_INPUT: u16 = 0x1052;
}

/// Intel Ethernet device IDs
pub mod intel_eth {
    pub const E1000_82540EM: u16 = 0x100E; // QEMU default e1000
    pub const E1000_82545EM: u16 = 0x100F;
    pub const E1000E_82574L: u16 = 0x10D3; // QEMU e1000e
    pub const I217_LM: u16 = 0x153A;
    pub const I211_AT: u16 = 0x1539;
}

/// PCI configuration register offsets
pub mod config {
    pub const VENDOR_ID: u8 = 0x00;
    pub const DEVICE_ID: u8 = 0x02;
    pub const COMMAND: u8 = 0x04;
    pub const STATUS: u8 = 0x06;
    pub const REVISION_ID: u8 = 0x08;
    pub const PROG_IF: u8 = 0x09;
    pub const SUBCLASS: u8 = 0x0A;
    pub const CLASS_CODE: u8 = 0x0B;
    pub const CACHE_LINE_SIZE: u8 = 0x0C;
    pub const LATENCY_TIMER: u8 = 0x0D;
    pub const HEADER_TYPE: u8 = 0x0E;
    pub const BIST: u8 = 0x0F;
    pub const BAR0: u8 = 0x10;
    pub const BAR1: u8 = 0x14;
    pub const BAR2: u8 = 0x18;
    pub const BAR3: u8 = 0x1C;
    pub const BAR4: u8 = 0x20;
    pub const BAR5: u8 = 0x24;
    pub const CARDBUS_CIS: u8 = 0x28;
    pub const SUBSYSTEM_VENDOR_ID: u8 = 0x2C;
    pub const SUBSYSTEM_ID: u8 = 0x2E;
    pub const ROM_BAR: u8 = 0x30;
    pub const CAPABILITIES: u8 = 0x34;
    pub const INTERRUPT_LINE: u8 = 0x3C;
    pub const INTERRUPT_PIN: u8 = 0x3D;
    pub const MIN_GNT: u8 = 0x3E;
    pub const MAX_LAT: u8 = 0x3F;
}

/// PCI command register bits
pub mod command {
    pub const IO_SPACE: u16 = 1 << 0;
    pub const MEMORY_SPACE: u16 = 1 << 1;
    pub const BUS_MASTER: u16 = 1 << 2;
    pub const SPECIAL_CYCLES: u16 = 1 << 3;
    pub const MWI_ENABLE: u16 = 1 << 4;
    pub const VGA_PALETTE_SNOOP: u16 = 1 << 5;
    pub const PARITY_ERROR_RESPONSE: u16 = 1 << 6;
    pub const STEPPING_CONTROL: u16 = 1 << 7;
    pub const SERR_ENABLE: u16 = 1 << 8;
    pub const FAST_BACK_TO_BACK: u16 = 1 << 9;
    pub const INTERRUPT_DISABLE: u16 = 1 << 10;
}

/// Base Address Register (BAR) types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bar {
    Io { port: u16 },
    Memory32 { addr: u32, prefetchable: bool },
    Memory64 { addr: u64, prefetchable: bool },
}

/// A PCI device location
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PciAddress {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl fmt::Debug for PciAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}:{:02x}.{}", self.bus, self.device, self.function)
    }
}

impl PciAddress {
    /// Create a new PCI address
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }

    /// Convert to configuration address format
    fn config_address(&self, offset: u8) -> u32 {
        let bus = self.bus as u32;
        let device = (self.device as u32) & 0x1F;
        let function = (self.function as u32) & 0x07;
        let offset = (offset as u32) & 0xFC;

        0x8000_0000 | (bus << 16) | (device << 11) | (function << 8) | offset
    }
}

/// PCI device information
#[derive(Clone, Copy)]
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

impl fmt::Debug for PciDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PciDevice({:?} ID {:04x}:{:04x} Class {:02x}:{:02x})",
            self.address, self.vendor_id, self.device_id, self.class_code, self.subclass
        )
    }
}

impl PciDevice {
    /// Read a configuration register (8-bit)
    pub fn read_config_u8(&self, offset: u8) -> u8 {
        let addr = self.address.config_address(offset & !0x03);
        let shift = (offset & 0x03) * 8;

        // SAFETY: PCI configuration space access via standard I/O ports
        // We ensure atomic 32-bit access which is standard for PCI config
        unsafe {
            outl(CONFIG_ADDRESS, addr);
            ((inl(CONFIG_DATA) >> shift) & 0xFF) as u8
        }
    }

    /// Read a configuration register (16-bit)
    pub fn read_config_u16(&self, offset: u8) -> u16 {
        let addr = self.address.config_address(offset & !0x03);
        let shift = (offset & 0x02) * 8;

        // SAFETY: PCI configuration space access via standard I/O ports
        unsafe {
            outl(CONFIG_ADDRESS, addr);
            ((inl(CONFIG_DATA) >> shift) & 0xFFFF) as u16
        }
    }

    /// Read a configuration register (32-bit)
    pub fn read_config_u32(&self, offset: u8) -> u32 {
        let addr = self.address.config_address(offset);

        // SAFETY: PCI configuration space access via standard I/O ports
        unsafe {
            outl(CONFIG_ADDRESS, addr);
            inl(CONFIG_DATA)
        }
    }

    /// Write to a configuration register (8-bit)
    pub fn write_config_u8(&self, offset: u8, value: u8) {
        let addr = self.address.config_address(offset & !0x03);
        let shift = (offset & 0x03) * 8;

        // SAFETY: PCI configuration space access via standard I/O ports
        // Read-modify-write cycle to preserve other bytes in the 32-bit word
        unsafe {
            outl(CONFIG_ADDRESS, addr);
            let old = inl(CONFIG_DATA);
            let mask = !(0xFF << shift);
            let new = (old & mask) | ((value as u32) << shift);
            outl(CONFIG_ADDRESS, addr);
            outl(CONFIG_DATA, new);
        }
    }

    /// Write to a configuration register (16-bit)
    pub fn write_config_u16(&self, offset: u8, value: u16) {
        let addr = self.address.config_address(offset & !0x03);
        let shift = (offset & 0x02) * 8;

        // SAFETY: PCI configuration space access via standard I/O ports
        unsafe {
            outl(CONFIG_ADDRESS, addr);
            let old = inl(CONFIG_DATA);
            let mask = !(0xFFFF << shift);
            let new = (old & mask) | ((value as u32) << shift);
            outl(CONFIG_ADDRESS, addr);
            outl(CONFIG_DATA, new);
        }
    }

    /// Write to a configuration register (32-bit)
    pub fn write_config_u32(&self, offset: u8, value: u32) {
        let addr = self.address.config_address(offset);

        // SAFETY: PCI configuration space access via standard I/O ports
        unsafe {
            outl(CONFIG_ADDRESS, addr);
            outl(CONFIG_DATA, value);
        }
    }

    /// Read a Base Address Register (BAR)
    pub fn read_bar(&self, bar_index: u8) -> Option<Bar> {
        if bar_index > 5 {
            return None;
        }

        let offset = config::BAR0 + (bar_index * 4);
        let bar_low = self.read_config_u32(offset);

        if bar_low == 0 {
            return None;
        }

        // Check if it's an I/O BAR (bit 0 set)
        if bar_low & 0x1 != 0 {
            // I/O space BAR
            // Bits 0-1 are reserved/type, address starts at bit 2
            let port = (bar_low & 0xFFFF_FFFC) as u16;
            Some(Bar::Io { port })
        } else {
            // Memory space BAR
            let bar_type = (bar_low >> 1) & 0x3;
            let prefetchable = (bar_low >> 3) & 0x1 != 0;

            match bar_type {
                0 => {
                    // 32-bit memory space
                    let addr = bar_low & 0xFFFF_FFF0;
                    Some(Bar::Memory32 { addr, prefetchable })
                }
                2 => {
                    // 64-bit memory space
                    if bar_index >= 5 {
                        return None; // Can't read next BAR as high part
                    }
                    let bar_high = self.read_config_u32(offset + 4);
                    let addr = ((bar_high as u64) << 32) | ((bar_low & 0xFFFF_FFF0) as u64);
                    Some(Bar::Memory64 { addr, prefetchable })
                }
                _ => None, // Reserved types
            }
        }
    }

    /// Get the raw BAR value (for legacy compatibility)
    pub fn read_bar_raw(&self, bar_index: u8) -> Option<u64> {
        match self.read_bar(bar_index) {
            Some(Bar::Io { port }) => Some(port as u64),
            Some(Bar::Memory32 { addr, .. }) => Some(addr as u64),
            Some(Bar::Memory64 { addr, .. }) => Some(addr),
            None => None,
        }
    }

    /// Enable bus mastering for this device
    pub fn enable_bus_master(&self) {
        let mut cmd = self.read_config_u16(config::COMMAND);
        cmd |= command::BUS_MASTER;
        self.write_config_u16(config::COMMAND, cmd);
    }

    /// Enable memory space access for this device
    pub fn enable_memory_space(&self) {
        let mut cmd = self.read_config_u16(config::COMMAND);
        cmd |= command::MEMORY_SPACE;
        self.write_config_u16(config::COMMAND, cmd);
    }

    /// Enable I/O space access for this device
    pub fn enable_io_space(&self) {
        let mut cmd = self.read_config_u16(config::COMMAND);
        cmd |= command::IO_SPACE;
        self.write_config_u16(config::COMMAND, cmd);
    }
}

/// Iterator for scanning PCI bus
pub struct PciScanner {
    bus: u16,
    device: u8,
    function: u8,
}

impl PciScanner {
    pub fn new() -> Self {
        Self {
            bus: 0,
            device: 0,
            function: 0,
        }
    }
}

impl Iterator for PciScanner {
    type Item = PciDevice;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.bus > 255 {
                // serial_println!("[PCI] Scan Complete");
                return None;
            }

            // if self.bus == 0 && self.device == 0 && self.function == 0 {
            //     serial_println!("[PCI] Starting Scan 00:00.0");
            // }

            let address = PciAddress::new(self.bus as u8, self.device, self.function);

            // Advance counters for next iteration
            let current_function = self.function;
            self.function += 1;
            if self.function >= 8 {
                self.function = 0;
                self.device += 1;
                if self.device >= 32 {
                    self.device = 0;
                    self.bus += 1;
                }
            }

            // Check if device exists at current address (before increment)
            let vendor_id = read_vendor_id(address);
            if vendor_id == 0xFFFF {
                // If function 0 doesn't exist, skip the rest of the functions for this device
                if current_function == 0 {
                    self.function = 0;
                    self.device += 1;
                    if self.device >= 32 {
                        self.device = 0;
                        self.bus += 1;
                    }
                }
                continue;
            }

            if let Some(dev) = probe_device(address, vendor_id) {
                // serial_println!("[PCI] Found device at {:?}", address);
                // Return found device
                // If it's not a multi-function device and we are at function 0, skip other functions
                if current_function == 0 && (dev.header_type & 0x80 == 0) {
                    self.function = 0;
                    self.device += 1;
                    if self.device >= 32 {
                        self.device = 0;
                        self.bus += 1;
                    }
                }
                return Some(dev);
            }
        }
    }
}

/// Read vendor ID at a specific PCI address
fn read_vendor_id(address: PciAddress) -> u16 {
    let addr = address.config_address(config::VENDOR_ID);

    // SAFETY: PCI configuration space access via standard I/O ports
    unsafe {
        outl(CONFIG_ADDRESS, addr);
        (inl(CONFIG_DATA) & 0xFFFF) as u16
    }
}

/// Probe a specific PCI address and return device info if present
fn probe_device(address: PciAddress, vendor_id: u16) -> Option<PciDevice> {
    let dev = PciDevice {
        address,
        vendor_id,
        device_id: 0, // Will read below
        class_code: 0,
        subclass: 0,
        prog_if: 0,
        revision: 0,
        header_type: 0,
        interrupt_line: 0,
        interrupt_pin: 0,
    };

    let device_id = dev.read_config_u16(config::DEVICE_ID);
    let class_rev_grp = dev.read_config_u32(config::REVISION_ID);
    let header_type = dev.read_config_u8(config::HEADER_TYPE);
    let int_grp = dev.read_config_u32(config::INTERRUPT_LINE);

    Some(PciDevice {
        address,
        vendor_id,
        device_id,
        class_code: ((class_rev_grp >> 24) & 0xFF) as u8,
        subclass: ((class_rev_grp >> 16) & 0xFF) as u8,
        prog_if: ((class_rev_grp >> 8) & 0xFF) as u8,
        revision: (class_rev_grp & 0xFF) as u8,
        header_type,
        interrupt_line: (int_grp & 0xFF) as u8,
        interrupt_pin: ((int_grp >> 8) & 0xFF) as u8,
    })
}

/// Helper to find a device by vendor and device ID
pub fn find_device(vendor_id: u16, device_id: u16) -> Option<PciDevice> {
    PciScanner::new().find(|dev| dev.vendor_id == vendor_id && dev.device_id == device_id)
}

/// Find all VirtIO devices on the PCI bus
pub fn find_virtio_devices() -> alloc::vec::Vec<PciDevice> {
    PciScanner::new()
        .filter(|dev| dev.vendor_id == vendor::VIRTIO)
        .collect()
}

/// Find a specific VirtIO device by device ID
pub fn find_virtio_device(device_id: u16) -> Option<PciDevice> {
    find_device(vendor::VIRTIO, device_id)
}
