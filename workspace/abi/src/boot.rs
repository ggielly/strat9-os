//! Bootloader-to-kernel handoff ABI.
//!
//! This module defines the data structures passed from the bootloader
//! (Limine) to the kernel at entry point. The kernel reads these structures
//! to discover memory layout, ACPI tables, framebuffer configuration, and
//! kernel modules.
//!
//! # Boot flow
//!
//! ```text
//! BIOS/UEFI → Limine bootloader → kernel_main(KernelArgs)
//! ```
//!
//! The bootloader populates `KernelArgs` on the initial stack or in a
//! reserved memory region, then jumps to the kernel entry point with a
//! pointer to this structure in a register (typically RDI on x86_64).
//!
//! # ABI stability
//!
//! The `KernelArgs` layout is frozen per ABI version. Changing the layout
//! requires bumping [`STRAT9_BOOT_ABI_VERSION`] and updating both
//! bootloader and kernel simultaneously.
//!
//! # Example (kernel side)
//!
//! ```ignore
//! // In kernel_main():
//! unsafe fn kernel_main(args: *const KernelArgs) -> ! {
//!     let args = &*args;
//!
//!     // Validate magic number
//!     assert_eq!(args.magic, STRAT9_BOOT_MAGIC);
//!
//!     // Validate ABI version
//!     assert_eq!(args.abi_version, STRAT9_BOOT_ABI_VERSION);
//!
//!     // Use memory map to initialize buddy allocator
//!     let mmap = core::slice::from_raw_parts(
//!         args.memory_map_base as *const MemoryRegion,
//!         args.memory_map_size as usize / core::mem::size_of::<MemoryRegion>(),
//!     );
//!
//!     // Use ACPI RSDP to find ACPI tables
//!     let rsdp = args.acpi_rsdp_base;
//!
//!     // Use framebuffer for early console
//!     let fb_addr = args.framebuffer_addr;
//!     let fb_w = args.framebuffer_width;
//!     let fb_h = args.framebuffer_height;
//! }
//! ```

use zerocopy::{FromBytes, IntoBytes};

/// ABI version for the boot handoff structure.
///
/// Increment this when `KernelArgs` layout changes.
pub const STRAT9_BOOT_ABI_VERSION: u32 = 1;

/// Magic number validating the boot handoff (`"ST9B"` in ASCII).
///
/// The kernel must check this value before trusting any `KernelArgs` data.
pub const STRAT9_BOOT_MAGIC: u32 = 0x5354_3942; // "ST9B"

/// Bootloader-to-kernel handoff structure.
///
/// Passed by the bootloader to the kernel at entry point.
/// Layout is `#[repr(C)]` for natural alignment across all fields.
/// Total size: 160 bytes, alignment: 8 bytes.
///
/// # Field groups
///
/// ## Identity (8 bytes)
/// - `magic`: must equal [`STRAT9_BOOT_MAGIC`] (`0x5354_3942`)
/// - `abi_version`: must equal [`STRAT9_BOOT_ABI_VERSION`] (currently `1`)
///
/// ## Kernel memory (16 bytes)
/// - `kernel_base`: physical address of the kernel ELF image
/// - `kernel_size`: size of the kernel image in bytes
///
/// ## Boot stack (16 bytes)
/// - `stack_base`: physical address of the initial kernel stack
/// - `stack_size`: size of the initial stack in bytes
///
/// ## Environment (16 bytes)
/// - `env_base`: physical address of the environment block
/// - `env_size`: size of the environment block in bytes
///
/// ## ACPI (16 bytes)
/// - `acpi_rsdp_base`: physical address of the RSDP (Root System Description Pointer)
/// - `acpi_rsdp_size`: size of the RSDP in bytes (typically 36 or 276)
///
/// ## Memory map (16 bytes)
/// - `memory_map_base`: physical address of the memory map array
/// - `memory_map_size`: total size of the memory map in bytes
///
/// ## Init filesystem (16 bytes)
/// - `initfs_base`: physical address of the init filesystem (cpio/tar archive)
/// - `initfs_size`: size of the init filesystem in bytes
///
/// ## Framebuffer (32 bytes)
/// - `framebuffer_addr`: physical address of the linear framebuffer
/// - `framebuffer_width`: width in pixels
/// - `framebuffer_height`: height in pixels
/// - `framebuffer_stride`: bytes per row (may include padding)
/// - `framebuffer_bpp`: bits per pixel (15, 16, 24, or 32)
/// - `framebuffer_*_mask_size/shift`: RGB channel mask layout
///
/// ## HHDM (8 bytes)
/// - `hhdm_offset`: Higher Half Direct Map offset (physical-to-virtual)
///
/// ## Command line (16 bytes)
/// - `cmdline_ptr`: pointer to null-terminated kernel command line string
/// - `cmdline_len`: length of the command line (including null terminator)
#[derive(Debug, FromBytes, IntoBytes)]
#[repr(C)]
pub struct KernelArgs {
    pub magic: u32,
    pub abi_version: u32,
    pub kernel_base: u64,
    pub kernel_size: u64,
    pub stack_base: u64,
    pub stack_size: u64,
    pub env_base: u64,
    pub env_size: u64,
    pub acpi_rsdp_base: u64,
    pub acpi_rsdp_size: u64,
    pub memory_map_base: u64,
    pub memory_map_size: u64,
    pub initfs_base: u64,
    pub initfs_size: u64,
    pub framebuffer_addr: u64,
    pub framebuffer_width: u32,
    pub framebuffer_height: u32,
    pub framebuffer_stride: u32,
    pub framebuffer_bpp: u16,
    pub framebuffer_red_mask_size: u8,
    pub framebuffer_red_mask_shift: u8,
    pub framebuffer_green_mask_size: u8,
    pub framebuffer_green_mask_shift: u8,
    pub framebuffer_blue_mask_size: u8,
    pub framebuffer_blue_mask_shift: u8,
    pub _padding1: [u8; 4], // Align hhdm_offset to 8-byte boundary
    pub hhdm_offset: u64,
    /// Pointer to the kernel command line string (null-terminated C string).
    pub cmdline_ptr: u64,
    /// Length of the kernel command line string (including null terminator).
    pub cmdline_len: u64,
}

impl KernelArgs {
    /// Iterator over the memory regions described by this boot handoff.
    ///
    /// The memory map is stored as a flat array at `memory_map_base` with
    /// `memory_map_size` bytes total. Each element is a [`MemoryRegion`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// for region in args.memory_regions() {
    ///     match region.kind {
    ///         MemoryKind::Free => { /* add to buddy allocator */ }
    ///         MemoryKind::Reserved => { /* skip */ }
    ///         _ => {}
    ///     }
    /// }
    /// ```
    pub fn memory_regions(&self) -> &[MemoryRegion] {
        if self.memory_map_base == 0 || self.memory_map_size == 0 {
            return &[];
        }
        let count = self.memory_map_size as usize / core::mem::size_of::<MemoryRegion>();
        let ptr = self.memory_map_base as *const MemoryRegion;
        // SAFETY: memory_map_base points to a valid array of MemoryRegion
        // written by the bootloader during boot. The array is static and
        // lives for the entire kernel lifetime.
        unsafe { core::slice::from_raw_parts(ptr, count) }
    }

    /// Kernel command line as a byte slice (null-terminated).
    ///
    /// Returns an empty slice if no command line was provided.
    pub fn cmdline_bytes(&self) -> &[u8] {
        if self.cmdline_ptr == 0 || self.cmdline_len == 0 {
            return &[];
        }
        let ptr = self.cmdline_ptr as *const u8;
        let len = self.cmdline_len as usize;
        // SAFETY: cmdline_ptr points to a valid null-terminated C string
        // written by the bootloader. The string is static and lives for
        // the entire kernel lifetime.
        unsafe { core::slice::from_raw_parts(ptr, len) }
    }

    /// Kernel command line as a `&str` (without null terminator).
    ///
    /// Returns an empty string if no command line was provided or if the
    /// bytes are not valid UTF-8.
    pub fn cmdline_str(&self) -> &str {
        let bytes = self.cmdline_bytes();
        // Strip trailing null byte if present
        let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
        core::str::from_utf8(bytes).unwrap_or("")
    }
}

/// Memory region descriptor for the bootloader memory map.
///
/// The memory map is an array of these descriptors, passed via
/// `KernelArgs::memory_map_base` and `KernelArgs::memory_map_size`.
/// Each descriptor is 24 bytes (aligned to 8).
///
/// # Example
///
/// ```text
/// Region 1: base=0x0000_0000, size=0x0009_F000, kind=Free     (conventional memory)
/// Region 2: base=0x0010_0000, size=0x7EF0_0000, kind=Free     (extended memory)
/// Region 3: base=0xFD00_0000, size=0x0200_0000, kind=Reserved (MMIO, framebuffer)
/// Region 4: base=0x7FE0_0000, size=0x0020_0000, kind=Reserved (ACPI NVS)
/// ```
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct MemoryRegion {
    /// Physical base address of the region.
    pub base: u64,
    /// Size of the region in bytes.
    pub size: u64,
    /// Region type (see [`MemoryKind`]).
    pub kind: MemoryKind,
}

/// Memory region type identifier.
///
/// Used by the bootloader to communicate the memory map to the kernel.
/// The kernel uses this to decide which regions can be used for the
/// buddy allocator, which are reserved for hardware, etc.
///
/// # Example
///
/// ```ignore
/// let regions = /* from KernelArgs */;
/// for region in regions {
///     match region.kind {
///         MemoryKind::Free => {
///             // Add to buddy allocator
///             buddy_init_region(region.base, region.size);
///         }
///         MemoryKind::Reserved => {
///             // Skip : hardware MMIO (framebuffer, APIC, etc.)
///         }
///         MemoryKind::Reclaim => {
///             // Bootloader code : can be freed after init
///             reclaim_region(region.base, region.size);
///         }
///         _ => {}
///     }
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes)]
#[repr(transparent)]
pub struct MemoryKind(pub u64);

#[allow(non_upper_case_globals)]
impl MemoryKind {
    /// Null/invalid region (should not appear in the memory map).
    pub const Null: Self = Self(0);

    /// Free usable memory : available for kernel allocation.
    pub const Free: Self = Self(1);

    /// Bootloader-reclaimable memory : free after boot, before first use.
    pub const Reclaim: Self = Self(2);

    /// Reserved memory : hardware MMIO, firmware, ACPI NVS, etc.
    /// Kernel must not allocate from these regions.
    pub const Reserved: Self = Self(3);
}

// ABI size assertions for bootloader structures
static_assertions::assert_eq_size!(KernelArgs, [u8; 160]);
static_assertions::const_assert_eq!(core::mem::align_of::<KernelArgs>(), 8);
static_assertions::assert_eq_size!(MemoryRegion, [u8; 24]);
static_assertions::const_assert_eq!(core::mem::align_of::<MemoryRegion>(), 8);
static_assertions::assert_eq_size!(MemoryKind, [u8; 8]);
