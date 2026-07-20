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

/// Cached ECAM MMIO base for extended config space access (offsets >= 0x100).
/// Set during `scan_ecam_devices()` when an MCFG table is present.
static ECAM_BASE: SpinLock<Option<usize>> = SpinLock::new(None);

// ---------------------------------------------------------------------------
// ECAM (PCIe Enhanced Configuration Access Mechanism) helpers
// ---------------------------------------------------------------------------

/// Read a 32-bit register from an ECAM-mapped PCI config space.
///
/// `ecam_base` is the MMIO base address of the ECAM region.
/// `bus`, `device`, `function` identify the device; `offset` is the register.
#[inline]
unsafe fn ecam_read32(ecam_base: usize, bus: u8, device: u8, function: u8, offset: u16) -> u32 {
    let addr = ecam_base
        + ((bus as usize) << 20)
        + ((device as usize) << 15)
        + ((function as usize) << 12)
        + ((offset as usize) & !0x03);
    core::ptr::read_volatile(addr as *const u32)
}

/// Write a 32-bit register to an ECAM-mapped PCI config space.
#[inline]
unsafe fn ecam_write32(ecam_base: usize, bus: u8, device: u8, function: u8, offset: u16, val: u32) {
    let addr = ecam_base
        + ((bus as usize) << 20)
        + ((device as usize) << 15)
        + ((function as usize) << 12)
        + ((offset as usize) & !0x03);
    core::ptr::write_volatile(addr as *mut u32, val);
}

/// Read a single byte from ECAM config space.
#[inline]
unsafe fn ecam_read8(ecam_base: usize, bus: u8, device: u8, function: u8, offset: u16) -> u8 {
    let dword = ecam_read32(ecam_base, bus, device, function, offset & !0x03);
    ((dword >> ((offset & 0x3) * 8)) & 0xFF) as u8
}

// ---------------------------------------------------------------------------
// Known device name lookup (for improved logging)
// ---------------------------------------------------------------------------

/// Known PCI device names for human-readable logging.
fn device_name(vendor: u16, device: u16) -> Option<&'static str> {
    match (vendor, device) {
        // Intel Ethernet
        (0x8086, 0x100E) => Some("Intel E1000 (QEMU)"),
        (0x8086, 0x100F) => Some("Intel E1000 (QEMU)"),
        (0x8086, 0x10D3) => Some("Intel E1000e (QEMU)"),
        (0x8086, 0x153A) => Some("Intel I217-LM"),
        (0x8086, 0x15F9) => Some("Intel I219-LM"),
        (0x8086, 0x15FA) => Some("Intel I219-V"),
        (0x8086, 0x15F2) => Some("Intel I225-LM"),
        (0x8086, 0x15F3) => Some("Intel I225-V"),
        (0x8086, 0x125B) => Some("Intel I226-LM"),
        (0x8086, 0x125C) => Some("Intel I226-V"),
        // VirtIO
        (0x1AF4, 0x1000) => Some("VirtIO Net"),
        (0x1AF4, 0x1001) => Some("VirtIO Block"),
        (0x1AF4, 0x1003) => Some("VirtIO Console"),
        (0x1AF4, 0x1005) => Some("VirtIO RNG"),
        (0x1AF4, 0x1050) => Some("VirtIO GPU"),
        (0x1AF4, 0x1052) => Some("VirtIO Input"),
        // QEMU
        (0x1234, 0x11E9) => Some("QEMU VGA"),
        _ => None,
    }
}

/// Human-readable PCI class name.
fn class_name(class: u8, subclass: u8) -> Option<&'static str> {
    match (class, subclass) {
        (0x00, 0x00) => Some("Legacy Device"),
        (0x00, 0x01) => Some("VGA-Compatible Device"),
        (0x01, 0x00) => Some("SCSI Controller"),
        (0x01, 0x01) => Some("IDE Controller"),
        (0x01, 0x06) => Some("SATA Controller"),
        (0x01, 0x08) => Some("NVMe Controller"),
        (0x02, 0x00) => Some("Ethernet Controller"),
        (0x02, 0x80) => Some("Network Controller"),
        (0x03, 0x00) => Some("VGA Controller"),
        (0x03, 0x02) => Some("3D Controller"),
        (0x04, 0x00) => Some("Multimedia Video"),
        (0x04, 0x03) => Some("Audio Device"),
        (0x06, 0x00) => Some("Host Bridge"),
        (0x06, 0x01) => Some("ISA Bridge"),
        (0x06, 0x04) => Some("PCI-to-PCI Bridge"),
        (0x0C, 0x03) => Some("USB Controller"),
        (0x08, 0x00) => Some("I20"),
        _ => None,
    }
}

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
    /// ATI/AMD display controller vendor ID (GPUs, APUs display)
    pub const AMD_DISPLAY: u16 = 0x1002;
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
    /// AHCI 1.0 (Advanced Host Controller Interface) : the standard modern mode
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
    pub const CAPABILITIES_PTR: u8 = 0x34;
}

/// PCI capability IDs
pub mod cap_id {
    /// MSI capability (PCI 2.2+)
    pub const MSI: u8 = 0x05;
    /// MSI-X capability (PCI 3.0+)
    pub const MSIX: u8 = 0x11;
}

/// PCIe Extended Capability IDs (offset >= 0x100)
pub mod ext_cap_id {
    /// Advanced Error Reporting (AER)
    pub const AER: u16 = 0x0001;
    /// Virtual Channel
    pub const VC: u16 = 0x0002;
    /// Device Serial Number
    pub const DSN: u16 = 0x0003;
    /// Power Budgeting
    pub const PB: u16 = 0x0004;
    /// Root Link Declaration
    pub const RLD: u16 = 0x0005;
    /// Root Complex Link Declaration
    pub const RCLD: u16 = 0x0006;
    /// Multi-Root I/O Virtualization
    pub const MRIOV: u16 = 0x0008;
    /// Single-Root I/O Virtualization (SR-IOV)
    pub const SRIOV: u16 = 0x0010;
    /// Resizable BAR
    pub const RBAR: u16 = 0x0015;
    /// Dynamic Power Allocation
    pub const DPA: u16 = 0x0016;
    /// TPH Requester
    pub const TPH: u16 = 0x0017;
    /// Latency Tolerance Reporting
    pub const LTR: u16 = 0x0018;
    /// Secondary PCIe Capability
    pub const SEC_PCIE: u16 = 0x0019;
    /// PMUX
    pub const PMUX: u16 = 0x001A;
    /// Process Address Space ID (PASID)
    pub const PASID: u16 = 0x001B;
    /// LNR (Layer 3 Routing)
    pub const LNR: u16 = 0x001C;
    /// Address Translation Services (ATS)
    pub const ATS: u16 = 0x001D;
    /// Page Request Interface (PRI)
    pub const PRI: u16 = 0x001E;
    /// Process Address Space ID (PASID) Extended Capability
    pub const PASID_EXT: u16 = 0x0020;
    /// Shared Virtual Memory (SVM)
    pub const SVM: u16 = 0x0021;
    /// L1 PM Substates
    pub const L1_PM: u16 = 0x0022;
    /// Precision Time Measurement (PTM)
    pub const PTM: u16 = 0x0023;
    /// PCIe Tunneling
    pub const TUNNEL: u16 = 0x0024;
    /// Access Control Services (ACS)
    pub const ACS: u16 = 0x0025;
    /// Alternative Routing ID Interpretation (ARI)
    pub const ARI: u16 = 0x0026;
    /// Address Translation Services (ATS) Extended Capability
    pub const ATS_EXT: u16 = 0x0027;
    /// Single Root I/O Virtualization (SR-IOV) Extended Capability
    pub const SRIOV_EXT: u16 = 0x0028;
    /// Physical Function (PF) SR-IOV Extended Capability
    pub const PF_SRIOV: u16 = 0x0029;
}

/// SR-IOV capability register offsets (relative to capability base).
pub mod sriov_cap {
    /// Capability register (16-bit)
    pub const CAP: u8 = 0x00;
    /// SR-IOV Control register (16-bit)
    pub const CONTROL: u8 = 0x02;
    /// SR-IOV Status register (16-bit)
    pub const STATUS: u8 = 0x04;
    /// SR-IOV PCIe Capability register (32-bit)
    pub const PCIE_CAP: u8 = 0x08;
    /// SR-IOV ARI Capability register (32-bit)
    pub const ARI_CAP: u8 = 0x0C;
    /// SR-IOV Initial VFs (16-bit)
    pub const INITIAL_VF: u8 = 0x10;
    /// SR-IOV Total VFs (16-bit)
    pub const TOTAL_VF: u8 = 0x12;
    /// SR-IOV Number of VFs (16-bit)
    pub const NUM_VF: u8 = 0x14;
    /// SR-IOV Function Dependency Link (8-bit)
    pub const FDL: u8 = 0x16;
    /// SR-IOV System Page Size (32-bit)
    pub const SYS_PAGE_SIZE: u8 = 0x18;
    /// SR-IOV BAR0 offset (32-bit)
    pub const BAR0_OFFSET: u8 = 0x1C;
    /// SR-IOV BAR1 offset (32-bit)
    pub const BAR1_OFFSET: u8 = 0x20;
    /// SR-IOV BAR2 offset (32-bit)
    pub const BAR2_OFFSET: u8 = 0x24;
    /// SR-IOV BAR3 offset (32-bit)
    pub const BAR3_OFFSET: u8 = 0x28;
    /// SR-IOV BAR4 offset (32-bit)
    pub const BAR4_OFFSET: u8 = 0x2C;
    /// SR-IOV BAR5 offset (32-bit)
    pub const BAR5_OFFSET: u8 = 0x30;
    /// SR-IOV VF Migration State Array Offset (32-bit)
    pub const VF_MIGRATION_STATE: u8 = 0x3C;
}

/// SR-IOV Control register bits
pub mod sriov_ctrl {
    /// Enable SR-IOV
    pub const ENABLE: u16 = 1 << 0;
    /// Enable MSE (Memory Space Enable) for VFs
    pub const MSE: u16 = 1 << 1;
    /// Enable ARI (Alternate Routing ID)
    pub const ARI_CAP: u16 = 1 << 2;
    /// Enable IMS (Interrupt Mask Set) for VFs
    pub const IMS_ENABLE: u16 = 1 << 4;
    /// Enable PFARI (PF ARI Capability)
    pub const PFARI_CAP: u16 = 1 << 5;
    /// Enable VFARI (VF ARI Capability)
    pub const VFARI_CAP: u16 = 1 << 6;
    /// Enable VF Migration
    pub const VF_MIGRATION: u16 = 1 << 7;
}

/// SR-IOV Status register bits
pub mod sriov_status {
    /// VF Memory Space Status
    pub const VF_MEMORY_SPACE: u16 = 1 << 0;
    /// VF ARI Capability Status
    pub const VF_ARI_CAP: u16 = 1 << 1;
    /// PF ARI Capability Status
    pub const PF_ARI_CAP: u16 = 1 << 2;
    /// VF Migration Status
    pub const VF_MIGRATION_STATUS: u16 = 1 << 3;
}

/// AER (Advanced Error Reporting) capability register offsets.
pub mod aer_cap {
    /// AER Capability register (32-bit)
    pub const CAP: u8 = 0x00;
    /// AER UnCorrectable Error Status (32-bit)
    pub const UNCERR_STATUS: u8 = 0x04;
    /// AER UnCorrectable Error Mask (32-bit)
    pub const UNCERR_MASK: u8 = 0x08;
    /// AER UnCorrectable Error Severity (32-bit)
    pub const UNCERR_SEVERITY: u8 = 0x0C;
    /// AER Correctable Error Status (32-bit)
    pub const CORERR_STATUS: u8 = 0x10;
    /// AER Correctable Error Mask (32-bit)
    pub const CORERR_MASK: u8 = 0x14;
    /// AER Advanced Error Capabilities and Control (32-bit)
    pub const ERR_CAP: u8 = 0x18;
    /// AER Header Log (128-bit)
    pub const HEADER_LOG: u8 = 0x1C;
}

/// Walk PCIe extended capabilities starting from `cap_ptr` (>= 0x100).
///
/// Returns a list of (capability_id, offset) pairs.
pub fn walk_ext_capabilities(dev: &PciDevice, cap_ptr: u16) -> Vec<(u16, u16)> {
    let mut caps = Vec::new();
    let mut offset = cap_ptr;

    while offset >= 0x100 && offset < 0xFFF {
        let dword = match dev.read_config_u32_ext(offset) {
            Some(v) => v,
            None => break,
        };
        let cap_id = (dword & 0xFFFF) as u16;
        let next_ptr = ((dword >> 20) & 0xFFC) as u16; // bits 31:20, aligned to 4

        if cap_id == 0 {
            break; // Invalid capability
        }

        caps.push((cap_id, offset));

        if next_ptr == 0 || next_ptr == offset {
            break; // End of list or self-loop
        }
        offset = next_ptr;
    }

    caps
}

/// Find the PCIe extended capability offset for a given capability ID.
///
/// Extended capabilities are always at offsets >= 0x100 in PCIe config space.
/// Requires ECAM support (MCFG ACPI table) to read.
pub fn find_ext_capability(dev: &PciDevice, cap_id: u16) -> Option<u16> {
    if ECAM_BASE.lock().is_none() {
        return None; // No ECAM available, cannot read extended config space
    }

    for (found_id, offset) in walk_ext_capabilities(dev, 0x100) {
        if found_id == cap_id {
            return Some(offset);
        }
    }
    None
}

/// Read SR-IOV capability information from a PCI device.
///
/// Returns `None` if the device doesn't have SR-IOV capability.
pub fn read_sriov_info(dev: &PciDevice) -> Option<SriovInfo> {
    let cap_offset = find_ext_capability(dev, ext_cap_id::SRIOV)?;
    let control = dev.read_config_u32_ext(cap_offset + sriov_cap::CONTROL as u16)? as u16;
    let status = dev.read_config_u32_ext(cap_offset + sriov_cap::STATUS as u16)? as u16;
    let initial_vf = dev.read_config_u32_ext(cap_offset + sriov_cap::INITIAL_VF as u16)? as u16;
    let total_vf = dev.read_config_u32_ext(cap_offset + sriov_cap::TOTAL_VF as u16)? as u16;
    let num_vf = dev.read_config_u32_ext(cap_offset + sriov_cap::NUM_VF as u16)? as u16;

    Some(SriovInfo {
        cap_offset,
        control,
        status,
        initial_vf,
        total_vf,
        num_vf,
        enabled: (control & sriov_ctrl::ENABLE) != 0,
    })
}

/// SR-IOV capability information.
#[derive(Debug, Clone, Copy)]
pub struct SriovInfo {
    /// Offset of the SR-IOV capability in config space.
    pub cap_offset: u16,
    /// SR-IOV Control register value.
    pub control: u16,
    /// SR-IOV Status register value.
    pub status: u16,
    /// Number of initial VFs at power-on.
    pub initial_vf: u16,
    /// Total number of VFs supported.
    pub total_vf: u16,
    /// Number of VFs currently enabled.
    pub num_vf: u16,
    /// Whether SR-IOV is currently enabled.
    pub enabled: bool,
}

/// Read AER (Advanced Error Reporting) capability information.
pub fn read_aer_info(dev: &PciDevice) -> Option<AerInfo> {
    let cap_offset = find_ext_capability(dev, ext_cap_id::AER)?;
    let uncerr_status = dev.read_config_u32_ext(cap_offset + aer_cap::UNCERR_STATUS as u16)?;
    let uncerr_mask = dev.read_config_u32_ext(cap_offset + aer_cap::UNCERR_MASK as u16)?;
    let corerr_status = dev.read_config_u32_ext(cap_offset + aer_cap::CORERR_STATUS as u16)?;
    let corerr_mask = dev.read_config_u32_ext(cap_offset + aer_cap::CORERR_MASK as u16)?;
    let err_cap = dev.read_config_u32_ext(cap_offset + aer_cap::ERR_CAP as u16)?;

    Some(AerInfo {
        cap_offset,
        uncerr_status,
        uncerr_mask,
        corerr_status,
        corerr_mask,
        first_error_pointer: ((err_cap >> 24) & 0x1F) as u8,
        ecrc_error_capable: (err_cap & 0x01) != 0,
        ecrc_generate_capable: (err_cap & 0x02) != 0,
    })
}

/// AER (Advanced Error Reporting) capability information.
#[derive(Debug, Clone, Copy)]
pub struct AerInfo {
    /// Offset of the AER capability in config space.
    pub cap_offset: u16,
    /// Uncorrectable error status bits.
    pub uncerr_status: u32,
    /// Uncorrectable error mask bits.
    pub uncerr_mask: u32,
    /// Correctable error status bits.
    pub corerr_status: u32,
    /// Correctable error mask bits.
    pub corerr_mask: u32,
    /// First error pointer (for error logging).
    pub first_error_pointer: u8,
    /// Whether ECRC error detection is supported.
    pub ecrc_error_capable: bool,
    /// Whether ECRC error generation is supported.
    pub ecrc_generate_capable: bool,
}

/// Offsets within an MSI capability block (relative to capability base).
pub mod msi_cap {
    /// Capability ID (1 byte) + next ptr (1 byte) = 2 bytes header
    /// Control register at +2 (16-bit)
    pub const CONTROL: u8 = 0x02;
    /// Message Address Register (32-bit) at +4
    pub const ADDR_LOW: u8 = 0x04;
    /// Message Upper Address Register (32-bit, 64-bit capable only) at +8
    pub const ADDR_HIGH: u8 = 0x08;
    /// Message Data Register (16-bit):
    ///   - 32-bit capable: at +8
    ///   - 64-bit capable: at +12
    pub const DATA: u8 = 0x08;
}

/// MSI control register bit definitions (16-bit at cap_base + 2).
pub mod msi_ctrl {
    /// MSI Enable
    pub const ENABLE: u16 = 1 << 0;
    /// Multiple Message Enable (bits 4:6) : number of vectors allocated
    pub const MME_MASK: u16 = 0b111 << 4;
    /// Multiple Message Capable (bits 1:3) : number of vectors the device wants
    pub const MMC_MASK: u16 = 0b111 << 1;
    /// 64-bit addressing supported
    pub const ADDR64: u16 = 1 << 7;
    /// Per-vector masking supported
    pub const PV_MASK: u16 = 1 << 8;
}

/// Offsets within an MSI-X capability block (relative to capability base).
pub mod msix_cap {
    /// Capability ID (1 byte) + next ptr (1 byte) = 2 bytes header
    /// Control register at +2 (16-bit)
    pub const CONTROL: u8 = 0x02;
    /// Table offset / BAR indicator (32-bit) at +4
    pub const TABLE: u8 = 0x04;
    /// Pending Bit Array offset / BAR indicator (32-bit) at +8
    pub const PBA: u8 = 0x08;
}

/// MSI-X control register bit definitions (16-bit at cap_base + 2).
pub mod msix_ctrl {
    /// MSI-X Enable
    pub const ENABLE: u16 = 1 << 15;
    /// Function Mask
    pub const FUNC_MASK: u16 = 1 << 14;
    /// Table size (bits 0:10) : number of entries minus 1
    pub const TABLE_SIZE_MASK: u16 = (1 << 11) - 1;
}

/// x86 MSI message address (delivers to LAPIC via system bus).
///
/// Format:
///   [31:20] = 0xFEE (fixed)
///   [19:12] = Destination LAPIC ID
///   [11:4]  = reserved
///   [3]     = Redirection Hint (0 = physical destination)
///   [2]     = Destination Mode (0 = physical)
///   [1:0]   = 0b00
pub const MSI_ADDR_BASE: u32 = 0xFEE0_0000;
pub const MSI_ADDR_DEST_SHIFT: u32 = 12;

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

    /// Read a 32-bit register from extended config space (offset >= 0x100).
    ///
    /// Uses ECAM MMIO when available. Returns `None` if ECAM is not mapped.
    pub fn read_config_u32_ext(&self, offset: u16) -> Option<u32> {
        let ecam = *ECAM_BASE.lock();
        Some(unsafe {
            ecam_read32(
                ecam,
                self.address.bus,
                self.address.device,
                self.address.function,
                offset,
            )
        })
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

                // Device exists at function 0 : do the full probe.
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
/// operates on the `&[PciDevice]` directly : no `clone()` of the Vec.
///
/// # Invariant
///
/// `PCI_DEVICE_CACHE` is populated once at boot and never invalidated during
/// normal operation. The `SpinLock<Option<Vec<PciDevice>>>` is held only for
/// the initial scan (which allocates the Vec) and for subsequent reads. No
/// code path re-scans the bus or reallocates under the lock. If PCI hotplug
/// or re-enumeration is added in the future, this must be changed to either :
///   - a `Mutex` (sleepable) to allow re-scanning, or
///   - a lock-free double-buffered snapshot model.
static PCI_DEVICE_CACHE: SpinLock<Option<Vec<PciDevice>>> = SpinLock::new(None);

// ---------------------------------------------------------------------------
// ECAM (PCIe Enhanced Configuration Access Mechanism) scanner
// ---------------------------------------------------------------------------

/// Scan PCI devices via ECAM (Memory-Mapped Configuration).
///
/// Uses MCFG ACPI table entries to discover MMIO-mapped PCI config spaces.
/// For each ECAM region, scans all bus/device/function combinations.
/// Returns only devices not already found by the I/O port scanner.
fn scan_ecam_devices() -> Vec<PciDevice> {
    use crate::{acpi::mcfg, memory};

    let mcfg_info = match mcfg::parse_mcfg() {
        Some(info) => info,
        None => {
            log::info!("[PCI-ECAM] No MCFG table found, skipping ECAM scan");
            return Vec::new();
        }
    };

    log::info!(
        "[PCI-ECAM] Found {} ECAM region(s)",
        mcfg_info.entries.len()
    );

    let mut devices = Vec::new();

    for entry in &mcfg_info.entries {
        let ecam_phys = entry.base_address;
        let start_bus = entry.start_bus;
        let end_bus = entry.end_bus;

        // Ensure the ECAM region is identity-mapped
        let region_size =
            ((end_bus as usize - start_bus as usize + 1) as u64) * (32 * 8 * 4096);
        memory::paging::ensure_identity_map_range(ecam_phys, region_size);
        let ecam_virt = crate::memory::phys_to_virt(ecam_phys) as usize;

        // Cache ECAM base for extended config space reads
        *ECAM_BASE.lock() = Some(ecam_virt);

        log::info!(
            "[PCI-ECAM] Region seg={} ecam={:#x} buses={}..{} virt={:#x}",
            entry.segment_group,
            ecam_phys,
            start_bus,
            end_bus,
            ecam_virt
        );

        // Scan each bus in the range
        for bus in start_bus..=end_bus {
            for dev in 0..32u8 {
                // Fast vendor check on function 0
                let word00 = unsafe { ecam_read32(ecam_virt, bus, dev, 0, 0x00) };
                let vendor_id = (word00 & 0xFFFF) as u16;
                if is_absent_vendor(vendor_id) {
                    continue;
                }

                // Probe function 0
                if let Some(device) = probe_ecam_device(ecam_virt, bus, dev, 0, word00) {
                    let is_multi = device.header_type & 0x80 != 0;
                    devices.push(device);

                    // Scan additional functions if multi-function
                    if is_multi {
                        for func in 1..8u8 {
                            if let Some(device) = probe_ecam_device(ecam_virt, bus, dev, func, 0) {
                                devices.push(device);
                            }
                        }
                    }
                }
            }
        }
    }

    log::info!("[PCI-ECAM] ECAM scan found {} device(s)", devices.len());
    devices
}

/// Probe a single PCI device via ECAM MMIO.
fn probe_ecam_device(
    ecam_base: usize,
    bus: u8,
    device: u8,
    function: u8,
    word00: u32,
) -> Option<PciDevice> {
    let vendor_id = (word00 & 0xFFFF) as u16;
    let device_id = (word00 >> 16) as u16;
    if is_absent_vendor(vendor_id) || device_id == 0xFFFF || device_id == 0x0000 {
        return None;
    }

    let address = PciAddress::new(bus, device, function);

    let word08 = unsafe { ecam_read32(ecam_base, bus, device, function, 0x08) };
    let word0c = unsafe { ecam_read32(ecam_base, bus, device, function, 0x0C) };

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

    let word3c = unsafe { ecam_read32(ecam_base, bus, device, function, 0x3C) };
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

/// Populate the cache if empty, then run `f` on the device slice.
///
/// All query functions route through here so that only a single scan ever
/// happens, and the lock is held for the duration of the filter : not for
/// the entire boot.
fn with_cache<R>(f: impl FnOnce(&[PciDevice]) -> R) -> R {
    let mut cache = PCI_DEVICE_CACHE.lock();
    if cache.is_none() {
        let dummy = 0u64;
        let rsp = &dummy as *const u64 as u64;
        crate::serial_println!("[PCI] Scanning PCI bus (rsp={:#x})...", rsp);

        // Phase 1: I/O port scan (0xCF8/0xCFC)
        let io_devices: Vec<PciDevice> = PciScanner::new().collect();
        crate::serial_println!("[PCI] I/O scan: {} device(s)", io_devices.len());

        // Phase 2: ECAM MMIO scan (via MCFG ACPI table)
        let ecam_devices: Vec<PciDevice> = scan_ecam_devices();
        crate::serial_println!("[PCI] ECAM scan: {} device(s)", ecam_devices.len());

        // Merge: ECAM devices that are NOT already in the I/O scan
        let mut devices = io_devices;
        for ecam_dev in &ecam_devices {
            let duplicate = devices.iter().any(|d| {
                d.address.bus == ecam_dev.address.bus
                    && d.address.device == ecam_dev.address.device
                    && d.address.function == ecam_dev.address.function
            });
            if !duplicate {
                devices.push(*ecam_dev);
            }
        }
        crate::serial_println!("[PCI] Total: {} device(s) after merge", devices.len());

        // Improved logging: human-readable names, IRQ, class
        for dev in &devices {
            let name = device_name(dev.vendor_id, dev.device_id).unwrap_or("Unknown");
            let class = class_name(dev.class_code, dev.subclass).unwrap_or("???");
            crate::serial_println!(
                "[PCI]   {:02x}:{:02x}.{:x} {:<24} {} (IRQ={})",
                dev.address.bus,
                dev.address.device,
                dev.address.function,
                name,
                class,
                dev.interrupt_line,
            );
        }
        *cache = Some(devices);
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
