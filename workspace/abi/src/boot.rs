//! Bootloader-to-kernel handoff ABI (v2).
//!
//! This module defines the data structures passed from the bootloader
//! to the kernel at entry point. The kernel reads these structures
//! to discover memory layout, ACPI tables, framebuffer configuration,
//! and kernel modules.
//!
//! # Boot flow
//!
//! ```text
//! UEFI firmware => strat9 UEFI bootloader => boot64.S (_start)
//!   => kmain(KernelArgs*) => kernel_main(&KernelArgs)
//! ```
//!
//! The bootloader populates `KernelArgs` in reserved memory, creates the
//! initial page tables, then jumps to the kernel entry point (`_start`)
//! with a pointer to this structure in RDI (System V AMD64 ABI first
//! argument). A value of 0 in RDI means "no arguments" (PVH boot).
//!
//! # ABI stability
//!
//! The `KernelArgs` layout is frozen per ABI version. Changing the layout
//! requires bumping [`STRAT9_BOOT_ABI_VERSION`] and updating both
//! bootloader and kernel simultaneously.
//!
//! # Virtual memory layout (BOOTBOOT-inspired)
//!
//! ```text
//! 0xFFFF_DEAD_0000_0000  => Framebuffer (read-only after boot)
//! 0xFFFF_BEEF_0000_0000  => Environment string (key=value)
//! 0xFFFFFFFF_8000_0000  => Kernel code/data
//! 0x0000_0000_0000_0000  => Identity map (first 8GB)
//! ```
//!
//! # Example (kernel side)
//!
//! ```ignore
//! unsafe fn kernel_main(args: *const KernelArgs) -> ! {
//!     let args = &*args;
//!     assert_eq!(args.magic, STRAT9_BOOT_MAGIC);
//!     assert_eq!(args.abi_version, STRAT9_BOOT_ABI_VERSION);
//!
//!     // Memory map
//!     for region in args.memory_regions() {
//!         match region.kind {
//!             MemoryKind::Free => { /* add to buddy allocator */ }
//!             _ => {}
//!         }
//!     }
//!
//!     // Framebuffer (already mapped at 0xFFFF_DEAD_0000_0000)
//!     let fb = args.framebuffer_addr as *mut u32;
//!
//!     // Environment (key=value pairs)
//!     if let Some(baud) = args.env_get("console.baud") {
//!         // baud = "115200"
//!     }
//!
//!     // Modules
//!     for module in args.modules() {
//!         // module.name_str(), module.base, module.size
//!     }
//! }
//! ```

use zerocopy::{FromBytes, IntoBytes};

/// ABI version for the boot handoff structure.
pub const STRAT9_BOOT_ABI_VERSION: u32 = 4;

/// Magic number validating the boot handoff (`"ST9B"` in ASCII).
pub const STRAT9_BOOT_MAGIC: u32 = 0x5354_3942; // "ST9B"

/// Bootloader-to-kernel handoff structure (132 bytes).
///
/// Field layout is ordered to avoid internal padding (`repr(C, packed)`):
/// - `magic`/`abi_version` (u32) first
/// - u64 fields next
/// - u32 fields, then the u16 field, then the u8 fields
///
/// # Field groups
///
/// ## Identity (8 bytes)
/// - `magic`: must equal [`STRAT9_BOOT_MAGIC`] (`0x5354_3942`)
/// - `abi_version`: must equal [`STRAT9_BOOT_ABI_VERSION`] (currently `4`)
///
/// ## Kernel memory (16 bytes)
/// - `kernel_base`: physical address of the kernel ELF image
/// - `kernel_size`: size of the kernel image in bytes
///
/// ## ACPI (8 bytes)
/// - `acpi_rsdp_base`: physical address of the RSDP
///
/// ## Memory map (16 bytes)
/// - `memory_map_base`: physical address of the [`MemoryRegion`] array
/// - `memory_map_size`: total size of the memory map in bytes
///
/// ## Framebuffer (8 bytes + masks)
/// - `framebuffer_addr`: **virtual** address (`0xFFFF_DEAD_0000_0000`)
///
/// ## HHDM (8 bytes)
/// - `hhdm_offset`: Higher Half Direct Map offset
///
/// ## Environment (16 bytes)
/// - `cmdline_ptr`: physical address of key=value string
/// - `cmdline_len`: length of the string in bytes
///
/// ## Modules (16 bytes)
/// - `modules_base`: physical address of the [`ModuleTable`]
/// - `modules_size`: total size of the module table in bytes
#[derive(Debug, FromBytes, IntoBytes)]
#[repr(C, packed)]
pub struct KernelArgs {
    // --- u64 fields (aligned to 8) ---
    pub magic: u32,
    pub abi_version: u32,
    pub kernel_base: u64,
    pub kernel_size: u64,
    pub acpi_rsdp_base: u64,
    pub memory_map_base: u64,
    pub memory_map_size: u64,
    pub framebuffer_addr: u64,
    pub hhdm_offset: u64,
    pub cmdline_ptr: u64,
    pub cmdline_len: u64,
    pub modules_base: u64,
    pub modules_size: u64,
    // --- u32 fields ---
    pub framebuffer_width: u32,
    pub framebuffer_height: u32,
    pub framebuffer_stride: u32,
    // --- u16 field ---
    pub framebuffer_bpp: u16,
    // --- u8 fields ---
    pub framebuffer_red_mask_size: u8,
    pub framebuffer_red_mask_shift: u8,
    pub framebuffer_green_mask_size: u8,
    pub framebuffer_green_mask_shift: u8,
    pub framebuffer_blue_mask_size: u8,
    pub framebuffer_blue_mask_shift: u8,
    // --- BSS region (16 bytes) ---
    /// Virtual address where the zero-initialized region begins
    /// (end of the loaded segments, rounded by the bootloader).
    pub bss_virt_base: u64,
    /// Size of the mapped-but-not-file-backed region the kernel must zero.
    pub bss_virt_size: u64,
}

// Ensure struct is exactly 132 bytes with no padding
const _: () = assert!(core::mem::size_of::<KernelArgs>() == 132);

impl KernelArgs {
    /// Iterator over the memory regions described by this boot handoff.
    pub fn memory_regions(&self) -> &[MemoryRegion] {
        if self.memory_map_base == 0 || self.memory_map_size == 0 {
            return &[];
        }
        let count = self.memory_map_size as usize / core::mem::size_of::<MemoryRegion>();
        let ptr = self.memory_map_base as *const MemoryRegion;
        unsafe { core::slice::from_raw_parts(ptr, count) }
    }

    /// Environment string as bytes (null-terminated key=value pairs).
    pub fn cmdline_bytes(&self) -> &[u8] {
        if self.cmdline_ptr == 0 || self.cmdline_len == 0 {
            return &[];
        }
        let ptr = self.cmdline_ptr as *const u8;
        let len = self.cmdline_len as usize;
        unsafe { core::slice::from_raw_parts(ptr, len) }
    }

    /// Environment string as `&str` (without null terminator).
    pub fn cmdline_str(&self) -> &str {
        let bytes = self.cmdline_bytes();
        let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
        core::str::from_utf8(bytes).unwrap_or("")
    }

    /// Get the value of an environment variable by key.
    ///
    /// # Example
    /// ```ignore
    /// if let Some(baud) = args.env_get("console.baud") {
    ///     // baud = "115200"
    /// }
    /// ```
    pub fn env_get(&self, key: &str) -> Option<&str> {
        for line in self.cmdline_str().lines() {
            if let Some((k, v)) = line.split_once('=') {
                if k == key {
                    return Some(v);
                }
            }
        }
        None
    }

    /// Iterator over the loaded modules.
    pub fn modules(&self) -> &[ModuleEntry] {
        if self.modules_base == 0 || self.modules_size == 0 {
            return &[];
        }
        let table = self.modules_base as *const ModuleTable;
        let count = unsafe { (*table).count } as usize;
        let ptr = unsafe { (*table).entries.as_ptr() };
        unsafe { core::slice::from_raw_parts(ptr, count) }
    }
}

/// Module table header + entries.
///
/// The bootloader builds this in physical memory and passes the
/// address via `KernelArgs::modules_base`.
#[repr(C)]
pub struct ModuleTable {
    pub count: u32,
    pub entries: [ModuleEntry; 64],
}

/// A single loaded module (userspace binary or config file).
#[repr(C)]
pub struct ModuleEntry {
    /// Module name (null-terminated, max 63 chars).
    pub name: [u8; 64],
    /// Physical address of the module data.
    pub base: u64,
    /// Size of the module data in bytes.
    pub size: u64,
}

impl ModuleEntry {
    /// Module name as a string slice.
    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(63);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }
}

/// Memory region descriptor for the bootloader memory map.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
    pub kind: MemoryKind,
}

/// Memory region type identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes)]
#[repr(transparent)]
pub struct MemoryKind(pub u64);

#[allow(non_upper_case_globals)]
impl MemoryKind {
    pub const Null: Self = Self(0);
    pub const Free: Self = Self(1);
    pub const Reclaim: Self = Self(2);
    pub const Reserved: Self = Self(3);
}

// ABI size assertions (packed: no padding, 132 bytes with BSS fields)
const _: () = assert!(core::mem::size_of::<KernelArgs>() == 132);
const _: () = assert!(core::mem::align_of::<KernelArgs>() == 1);
static_assertions::assert_eq_size!(MemoryRegion, [u8; 24]);
static_assertions::const_assert_eq!(core::mem::align_of::<MemoryRegion>(), 8);
static_assertions::assert_eq_size!(MemoryKind, [u8; 8]);
static_assertions::assert_eq_size!(ModuleEntry, [u8; 80]);
