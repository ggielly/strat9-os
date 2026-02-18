//! Boot information abstraction
//!
//! Provides safe abstractions for bootloader-provided information including:
//! - Memory map
//! - ACPI tables
//! - Module information
//!
//! Inspired by Asterinas and Theseus boot info abstractions.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

/// Memory region types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MemoryRegionType {
    /// Usable RAM
    Usable = 0,
    /// Reserved (in use or unusable)
    Reserved = 1,
    /// ACPI reclaimable memory
    AcpiReclaimable = 2,
    /// ACPI NVS memory
    AcpiNvs = 3,
    /// Bad memory (do not use)
    Bad = 4,
    /// Unknown type
    Unknown = 0xFF,
}

impl From<u32> for MemoryRegionType {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::Usable,
            1 => Self::Reserved,
            2 => Self::AcpiReclaimable,
            3 => Self::AcpiNvs,
            4 => Self::Bad,
            _ => Self::Unknown,
        }
    }
}

/// A memory region descriptor
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryRegion {
    /// Base physical address
    pub base: u64,
    /// Size in bytes
    pub size: u64,
    /// Region type
    pub region_type: MemoryRegionType,
}

impl MemoryRegion {
    /// Creates a new memory region
    pub const fn new(base: u64, size: u64, region_type: MemoryRegionType) -> Self {
        Self {
            base,
            size,
            region_type,
        }
    }

    /// Returns the end address (exclusive)
    pub const fn end(&self) -> u64 {
        self.base.wrapping_add(self.size)
    }

    /// Returns true if this region is usable RAM
    pub const fn is_usable(&self) -> bool {
        matches!(self.region_type, MemoryRegionType::Usable)
    }

    /// Returns true if this region is ACPI reclaimable
    pub const fn is_acpi_reclaimable(&self) -> bool {
        matches!(self.region_type, MemoryRegionType::AcpiReclaimable)
    }

    /// Returns true if this region is ACPI NVS
    pub const fn is_acpi_nvs(&self) -> bool {
        matches!(self.region_type, MemoryRegionType::AcpiNvs)
    }
}

/// Bootloader module information
#[derive(Debug, Clone)]
pub struct BootModule {
    /// Base physical address
    pub base: u64,
    /// Size in bytes
    pub size: u64,
    /// Module name/identifier
    pub name: alloc::string::String,
}

impl BootModule {
    /// Creates a new boot module descriptor
    pub fn new(base: u64, size: u64, name: alloc::string::String) -> Self {
        Self { base, size, name }
    }

    /// Returns the end address (exclusive)
    pub fn end(&self) -> u64 {
        self.base.wrapping_add(self.size)
    }
}

/// Boot information provided by the bootloader
#[derive(Debug, Clone)]
pub struct BootInfo {
    /// Memory map from bootloader
    pub memory_map: Vec<MemoryRegion>,
    /// Higher Half Direct Map offset (if applicable)
    pub hhdm_offset: u64,
    /// ACPI RSDP physical address
    pub acpi_rsdp: u64,
    /// Bootloader modules
    pub modules: Vec<BootModule>,
    /// Kernel command line
    pub cmdline: alloc::string::String,
}

impl BootInfo {
    /// Creates a new BootInfo
    pub fn new(
        memory_map: Vec<MemoryRegion>,
        hhdm_offset: u64,
        acpi_rsdp: u64,
        modules: Vec<BootModule>,
        cmdline: alloc::string::String,
    ) -> Self {
        Self {
            memory_map,
            hhdm_offset,
            acpi_rsdp,
            modules,
            cmdline,
        }
    }

    /// Returns an iterator over usable memory regions
    pub fn usable_regions(&self) -> impl Iterator<Item = &MemoryRegion> {
        self.memory_map.iter().filter(|r| r.is_usable())
    }

    /// Returns the total amount of usable RAM in bytes
    pub fn total_usable_ram(&self) -> u64 {
        self.usable_regions().map(|r| r.size).sum()
    }

    /// Returns the total amount of physical memory (including reserved)
    pub fn total_physical_memory(&self) -> u64 {
        self.memory_map.iter().map(|r| r.size).sum()
    }

    /// Finds a module by name
    pub fn find_module(&self, name: &str) -> Option<&BootModule> {
        self.modules.iter().find(|m| m.name == name)
    }
}

impl fmt::Display for BootInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Boot Information:")?;
        writeln!(f, "  HHDM Offset: 0x{:x}", self.hhdm_offset)?;
        writeln!(f, "  ACPI RSDP: 0x{:x}", self.acpi_rsdp)?;
        writeln!(f, "  Memory Regions:")?;
        for region in &self.memory_map {
            writeln!(
                f,
                "    0x{:016x}-0x{:016x}: {:?} ({} KB)",
                region.base,
                region.end(),
                region.region_type,
                region.size / 1024
            )?;
        }
        writeln!(f, "  Total Usable RAM: {} MB", self.total_usable_ram() / (1024 * 1024))?;
        writeln!(f, "  Modules: {}", self.modules.len())?;
        for module in &self.modules {
            writeln!(f, "    {}: 0x{:x} ({} bytes)", module.name, module.base, module.size)?;
        }
        if !self.cmdline.is_empty() {
            writeln!(f, "  Command Line: {}", self.cmdline)?;
        }
        Ok(())
    }
}
