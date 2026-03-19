//! PCI Configuration Space Access
//!
//! Provides functions to scan the PCI bus and read/write configuration registers.
//! Used to discover VirtIO and other PCI devices.
//!
//! Reference: PCI Local Bus Specification 3.0

use super::io::{inl, outl};
use crate::sync::SpinLock;
use alloc::vec::Vec;
use core::fmt;

/// PCI Configuration Address Port
const CONFIG_ADDRESS: u16 = 0xCF8;
/// PCI Configuration Data Port
const CONFIG_DATA: u16 = 0xCFC;

/// Global lock for PCI configuration space I/O.
///
/// CONFIG_ADDRESS and CONFIG_DATA form a two-step transaction that must be
/// atomic w.r.t. other CPUs. Every config read/write must hold this lock.
static PCI_IO_LOCK: SpinLock<()> = SpinLock::new(());

#[derive(Clone, Copy)]
struct PciLineQuirk {
    vendor_id: u16,
    device_id: u16,
}

const PCI_IRQ_LINE_ZERO_IF_FF: &[PciLineQuirk] = &[
    PciLineQuirk {
        vendor_id: vendor::INTEL,
        device_id: intel_eth::E1000_82540EM,
    },
    PciLineQuirk {
        vendor_id: vendor::INTEL,
        device_id: intel_eth::E1000_82545EM,
    },
    PciLineQuirk {
        vendor_id: vendor::INTEL,
        device_id: intel_eth::E1000E_82574L,
    },
    PciLineQuirk {
        vendor_id: vendor::VIRTIO,
        device_id: device::VIRTIO_NET,
    },
    PciLineQuirk {
        vendor_id: vendor::VIRTIO,
        device_id: device::VIRTIO_BLOCK,
    },
];

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

/// PCI base class codes
pub mod class {
    pub const MASS_STORAGE: u8 = 0x01;
    pub const NETWORK: u8 = 0x02;
}

/// PCI subclasses for mass storage controllers
pub mod storage_subclass {
    pub const SCSI: u8 = 0x00;
    pub const IDE: u8 = 0x01;
    pub const FLOPPY: u8 = 0x02;
    pub const IPI: u8 = 0x03;
    pub const RAID: u8 = 0x04;
    pub const ATA: u8 = 0x05;
    pub const SATA: u8 = 0x06;
    pub const SAS: u8 = 0x07;
    pub const NVM: u8 = 0x08;
    pub const OTHER: u8 = 0x80;
}

/// Programming interface codes for mass-storage SATA controllers
pub mod sata_progif {
    /// AHCI 1.0 (Advanced Host Controller Interface) — the standard modern mode
    pub const AHCI: u8 = 0x01;
    /// Vendor-specific / legacy IDE emulation
    pub const VENDOR: u8 = 0x00;
}

/// PCI subclasses for network controllers
pub mod net_subclass {
    pub const ETHERNET: u8 = 0x00;
    pub const OTHER: u8 = 0x80;
}

/// Intel Ethernet device IDs
pub mod intel_eth {
    pub const E1000_82540EM: u16 = 0x100E; // QEMU default e1000
    pub const E1000_82545EM: u16 = 0x100F;
    pub const E1000E_82574L: u16 = 0x10D3; // QEMU e1000e
    pub const I210_AT: u16 = 0x1533;
    pub const I350_AM2: u16 = 0x1521;
    pub const I350_AM4: u16 = 0x1523;
    pub const I217_LM: u16 = 0x153A;
    pub const I211_AT: u16 = 0x1539;
    pub const I219_LM: u16 = 0x15F9;
    pub const I219_V: u16 = 0x15FA;
    pub const I225_LM: u16 = 0x15F2;
    pub const I225_V: u16 = 0x15F3;
    pub const I226_LM: u16 = 0x125B;
    pub const I226_V: u16 = 0x125C;
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

        let _lock = PCI_IO_LOCK.lock();
        unsafe {
            outl(CONFIG_ADDRESS, addr);
            ((inl(CONFIG_DATA) >> shift) & 0xFF) as u8
        }
    }

    /// Read a configuration register (16-bit)
    pub fn read_config_u16(&self, offset: u8) -> u16 {
        let addr = self.address.config_address(offset & !0x03);
        let shift = (offset & 0x02) * 8;

        let _lock = PCI_IO_LOCK.lock();
        unsafe {
            outl(CONFIG_ADDRESS, addr);
            ((inl(CONFIG_DATA) >> shift) & 0xFFFF) as u16
        }
    }

    /// Read a configuration register (32-bit)
    pub fn read_config_u32(&self, offset: u8) -> u32 {
        let addr = self.address.config_address(offset);

        let _lock = PCI_IO_LOCK.lock();
        unsafe {
            outl(CONFIG_ADDRESS, addr);
            inl(CONFIG_DATA)
        }
    }

    /// Write to a configuration register (8-bit)
    pub fn write_config_u8(&self, offset: u8, value: u8) {
        let addr = self.address.config_address(offset & !0x03);
        let shift = (offset & 0x03) * 8;

        let _lock = PCI_IO_LOCK.lock();
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

        let _lock = PCI_IO_LOCK.lock();
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

        let _lock = PCI_IO_LOCK.lock();
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
            let port = (bar_low & 0xFFFF_FFFC) as u16;
            Some(Bar::Io { port })
        } else {
            let bar_type = (bar_low >> 1) & 0x3;
            let prefetchable = (bar_low >> 3) & 0x1 != 0;

            match bar_type {
                0 => {
                    let addr = bar_low & 0xFFFF_FFF0;
                    Some(Bar::Memory32 { addr, prefetchable })
                }
                2 => {
                    if bar_index >= 5 {
                        return None;
                    }
                    let bar_high = self.read_config_u32(offset + 4);
                    let addr = ((bar_high as u64) << 32) | ((bar_low & 0xFFFF_FFF0) as u64);
                    Some(Bar::Memory64 { addr, prefetchable })
                }
                _ => None,
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

// ---------------------------------------------------------------------------
// Fast PCI bus scanner (BFS with early-exit)
// ---------------------------------------------------------------------------
//
// Insipired by asterinas OS's PCI scanner:
//
//  1. For each (bus, device), probe function 0 first.
//     If vendor == 0xFFFF → skip all 8 functions (early exit).
//
//  2. Read the Header Type from the function-0 dword at offset 0x0C.
//     Bit 7 (multi-function flag) tells whether functions 1..7 can exist.
//     If bit 7 is clear → skip functions 1..7 entirely.
//
//  3. If header_type & 0x7F == 0x01 (PCI-to-PCI bridge), read the
//     secondary bus number and enqueue it.  The `seen_buses` bitmap
//     prevents re-scanning a bus already visited.
//
// This reduces the worst-case probes from 256 × 32 × 8 = 65 536 down to
// 256 × 32 × 1 = 8 192 for a topology with no multi-function devices
// (the common case on QEMU / VMware).
//
// I/O cost per probe:
//   Old: 4 dword reads under 4 separate lock acquisitions.
//   New: 1 dword read (vendor check, early exit) + 3 dword reads only
//        for devices that actually exist, all under a single lock hold
//        via `probe_device_full`.

/// Iterator for scanning PCI bus
pub struct PciScanner {
    bus_queue: [u8; 256],
    queue_head: usize,
    queue_tail: usize,
    seen_buses: [bool; 256],
    device: u8,
    function: u8,
    /// Cached multi-function flag for the current device (from function 0).
    /// When `function > 0`, this tells us whether to keep scanning.
    is_multi_function: bool,
}

impl PciScanner {
    pub fn new() -> Self {
        let mut s = Self {
            bus_queue: [0u8; 256],
            queue_head: 0,
            queue_tail: 1,
            seen_buses: [false; 256],
            device: 0,
            function: 0,
            is_multi_function: false,
        };
        s.seen_buses[0] = true;
        s
    }

    fn enqueue_bus(&mut self, bus: u8) {
        if !self.seen_buses[bus as usize] && self.queue_tail < 256 {
            self.seen_buses[bus as usize] = true;
            self.bus_queue[self.queue_tail] = bus;
            self.queue_tail += 1;
        }
    }

    #[inline]
    fn advance_to_next_device(&mut self) {
        self.function = 0;
        self.device += 1;
        self.is_multi_function = false;
    }
}

impl Iterator for PciScanner {
    type Item = PciDevice;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Advance to next bus if we exhausted all 32 devices.
            if self.queue_head >= self.queue_tail {
                return None;
            }
            let bus = self.bus_queue[self.queue_head];

            if self.device >= 32 {
                self.queue_head += 1;
                self.device = 0;
                self.function = 0;
                self.is_multi_function = false;
                continue;
            }

            let current_function = self.function;

            // --- Function 0: fast vendor check + early exit ---
            if current_function == 0 {
                // Single dword read: vendor+device at offset 0x00.
                // If 0xFFFF → no device at this slot, skip all 8 functions.
                let word00 = raw_config_read(bus, self.device, 0, 0x00);
                let vendor_id = (word00 & 0xFFFF) as u16;
                if is_absent_vendor(vendor_id) {
                    self.advance_to_next_device();
                    continue;
                }

                // Device exists at function 0 — do the full probe.
                let Some(dev) = probe_from_word00(PciAddress::new(bus, self.device, 0), word00)
                else {
                    self.advance_to_next_device();
                    continue;
                };

                // Cache multi-function status from header_type bit 7.
                self.is_multi_function = dev.header_type & 0x80 != 0;

                // If it's a PCI-to-PCI bridge, enqueue the secondary bus.
                if dev.header_type & 0x7F == 0x01 {
                    let secondary = raw_config_read_u8(bus, self.device, 0, 0x19);
                    self.enqueue_bus(secondary);
                }

                // Advance: if multi-function, move to function 1;
                // otherwise skip straight to the next device.
                if self.is_multi_function {
                    self.function = 1;
                } else {
                    self.advance_to_next_device();
                }

                return Some(dev);
            }

            // --- Functions 1..7 (only reached if multi-function) ---
            debug_assert!(self.is_multi_function);

            self.function += 1;
            if self.function >= 8 {
                self.advance_to_next_device();
            }

            let address = PciAddress::new(bus, self.device, current_function);
            let Some(dev) = probe_device_full(address) else {
                continue;
            };

            if dev.header_type & 0x7F == 0x01 {
                let secondary = raw_config_read_u8(bus, self.device, current_function, 0x19);
                self.enqueue_bus(secondary);
            }

            return Some(dev);
        }
    }
}

// ---------------------------------------------------------------------------
// Low-level config-space helpers
// ---------------------------------------------------------------------------

fn is_absent_vendor(vendor_id: u16) -> bool {
    vendor_id == 0xFFFF || vendor_id == 0x0000
}

fn quirk_zero_irq_line(vendor_id: u16, device_id: u16, irq_line: u8) -> u8 {
    if irq_line != 0xFF {
        return irq_line;
    }
    if PCI_IRQ_LINE_ZERO_IF_FF
        .iter()
        .any(|q| q.vendor_id == vendor_id && q.device_id == device_id)
    {
        return 0;
    }
    0
}

fn valid_header_type(header_type: u8) -> bool {
    matches!(header_type & 0x7F, 0x00..=0x02)
}

fn is_ghost_device(class_code: u8, subclass: u8, prog_if: u8) -> bool {
    class_code == 0xFF && subclass == 0xFF && prog_if == 0xFF
}

/// Single dword config read without building a PciDevice/PciAddress.
/// Acquires PCI_IO_LOCK once.
#[inline]
fn raw_config_read(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let addr = 0x8000_0000u32
        | ((bus as u32) << 16)
        | (((device as u32) & 0x1F) << 11)
        | (((function as u32) & 0x07) << 8)
        | ((offset as u32) & 0xFC);
    let _lock = PCI_IO_LOCK.lock();
    unsafe {
        outl(CONFIG_ADDRESS, addr);
        inl(CONFIG_DATA)
    }
}

/// Read a single byte from config space (derived from a dword read).
#[inline]
fn raw_config_read_u8(bus: u8, device: u8, function: u8, offset: u8) -> u8 {
    let dword = raw_config_read(bus, device, function, offset & !0x03);
    let shift = (offset & 0x03) * 8;
    ((dword >> shift) & 0xFF) as u8
}

/// Probe a PCI address using 4 batched dword reads under a single lock hold.
///
/// Reads: 0x00 (vendor+device), 0x08 (rev+progif+subclass+class),
///        0x0C (cacheline+latency+headertype+bist), 0x3C (intline+intpin).
fn probe_device_full(address: PciAddress) -> Option<PciDevice> {
    let _lock = PCI_IO_LOCK.lock();

    let word00 = unsafe {
        outl(CONFIG_ADDRESS, address.config_address(0x00));
        inl(CONFIG_DATA)
    };
    let vendor_id = (word00 & 0xFFFF) as u16;
    if is_absent_vendor(vendor_id) {
        return None;
    }
    let device_id = (word00 >> 16) as u16;
    if device_id == 0xFFFF || device_id == 0x0000 {
        return None;
    }

    let word08 = unsafe {
        outl(CONFIG_ADDRESS, address.config_address(0x08));
        inl(CONFIG_DATA)
    };
    let word0c = unsafe {
        outl(CONFIG_ADDRESS, address.config_address(0x0C));
        inl(CONFIG_DATA)
    };

    let header_type = ((word0c >> 16) & 0xFF) as u8;
    if !valid_header_type(header_type) {
        return None;
    }

    let class_code = ((word08 >> 24) & 0xFF) as u8;
    let subclass = ((word08 >> 16) & 0xFF) as u8;
    let prog_if = ((word08 >> 8) & 0xFF) as u8;
    if is_ghost_device(class_code, subclass, prog_if) {
        return None;
    }

    let word3c = unsafe {
        outl(CONFIG_ADDRESS, address.config_address(0x3C));
        inl(CONFIG_DATA)
    };
    let interrupt_line = quirk_zero_irq_line(vendor_id, device_id, (word3c & 0xFF) as u8);

    Some(PciDevice {
        address,
        vendor_id,
        device_id,
        class_code,
        subclass,
        prog_if,
        revision: (word08 & 0xFF) as u8,
        header_type,
        interrupt_line,
        interrupt_pin: ((word3c >> 8) & 0xFF) as u8,
    })
}

/// Build a PciDevice when `word00` (vendor+device dword) was already read
/// by the caller's fast-path vendor check, avoiding a redundant I/O cycle.
fn probe_from_word00(address: PciAddress, word00: u32) -> Option<PciDevice> {
    let vendor_id = (word00 & 0xFFFF) as u16;
    let device_id = (word00 >> 16) as u16;
    if device_id == 0xFFFF || device_id == 0x0000 {
        return None;
    }

    let _lock = PCI_IO_LOCK.lock();

    let word08 = unsafe {
        outl(CONFIG_ADDRESS, address.config_address(0x08));
        inl(CONFIG_DATA)
    };
    let word0c = unsafe {
        outl(CONFIG_ADDRESS, address.config_address(0x0C));
        inl(CONFIG_DATA)
    };

    let header_type = ((word0c >> 16) & 0xFF) as u8;
    if !valid_header_type(header_type) {
        return None;
    }

    let class_code = ((word08 >> 24) & 0xFF) as u8;
    let subclass = ((word08 >> 16) & 0xFF) as u8;
    let prog_if = ((word08 >> 8) & 0xFF) as u8;
    if is_ghost_device(class_code, subclass, prog_if) {
        return None;
    }

    let word3c = unsafe {
        outl(CONFIG_ADDRESS, address.config_address(0x3C));
        inl(CONFIG_DATA)
    };
    let interrupt_line = quirk_zero_irq_line(vendor_id, device_id, (word3c & 0xFF) as u8);

    Some(PciDevice {
        address,
        vendor_id,
        device_id,
        class_code,
        subclass,
        prog_if,
        revision: (word08 & 0xFF) as u8,
        header_type,
        interrupt_line,
        interrupt_pin: ((word3c >> 8) & 0xFF) as u8,
    })
}

// ---------------------------------------------------------------------------
// Cached device inventory
// ---------------------------------------------------------------------------

/// Cached PCI device inventory.
///
/// The first lookup performs a full bus scan, then all subsequent lookups reuse
/// this snapshot. Every query function borrows the cache through the lock and
/// operates on the `&[PciDevice]` directly — no `clone()` of the Vec.
static PCI_DEVICE_CACHE: SpinLock<Option<Vec<PciDevice>>> = SpinLock::new(None);

/// Populate the cache if empty, then run `f` on the device slice.
///
/// All query functions route through here so that only a single scan ever
/// happens, and the lock is held for the duration of the filter — not for
/// the entire boot.
fn with_cache<R>(f: impl FnOnce(&[PciDevice]) -> R) -> R {
    let mut cache = PCI_DEVICE_CACHE.lock();
    if cache.is_none() {
        // Debug: check stack before PCI scan
        let dummy = 0u64;
        let rsp = &dummy as *const u64 as u64;
        crate::serial_println!("[PCI] Scanning PCI bus, rsp={:#x}", rsp);
        *cache = Some(PciScanner::new().collect());
        crate::serial_println!(
            "[PCI] PCI scan complete, found {} devices",
            cache.as_ref().unwrap().len()
        );
    }
    f(cache.as_deref().unwrap_or(&[]))
}

/// Helper to find a device by vendor and device ID
pub fn find_device(vendor_id: u16, device_id: u16) -> Option<PciDevice> {
    with_cache(|devs| {
        devs.iter()
            .copied()
            .find(|dev| dev.vendor_id == vendor_id && dev.device_id == device_id)
    })
}

/// Find all VirtIO devices on the PCI bus
pub fn find_virtio_devices() -> Vec<PciDevice> {
    find_devices_by_vendor(vendor::VIRTIO)
}

/// Find a specific VirtIO device by device ID
pub fn find_virtio_device(device_id: u16) -> Option<PciDevice> {
    find_device(vendor::VIRTIO, device_id)
}

/// Return a snapshot of all discovered PCI devices.
pub fn all_devices() -> Vec<PciDevice> {
    with_cache(|devs| devs.to_vec())
}

/// Return all devices for a given vendor from the cached PCI inventory.
pub fn find_devices_by_vendor(vendor_id: u16) -> Vec<PciDevice> {
    with_cache(|devs| {
        devs.iter()
            .copied()
            .filter(|dev| dev.vendor_id == vendor_id)
            .collect()
    })
}

/// Return all devices matching a PCI class/subclass pair.
pub fn find_devices_by_class(class_code: u8, subclass: u8) -> Vec<PciDevice> {
    with_cache(|devs| {
        devs.iter()
            .copied()
            .filter(|dev| dev.class_code == class_code && dev.subclass == subclass)
            .collect()
    })
}

/// Full PCI probe criteria.
///
/// Any field left as `None` is treated as a wildcard.
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

/// Return all devices matching `criteria`.
pub fn probe_all(criteria: ProbeCriteria) -> Vec<PciDevice> {
    with_cache(|devs| {
        devs.iter()
            .copied()
            .filter(|dev| criteria.matches(dev))
            .collect()
    })
}

/// Return the first device matching `criteria`.
pub fn probe_first(criteria: ProbeCriteria) -> Option<PciDevice> {
    with_cache(|devs| devs.iter().copied().find(|dev| criteria.matches(dev)))
}

/// Invalidate PCI cache.
///
/// Useful when hotplug/re-enumeration support is added in the future.
pub fn invalidate_cache() {
    *PCI_DEVICE_CACHE.lock() = None;
}
