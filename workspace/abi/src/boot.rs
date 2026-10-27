//! Bootloader-to-kernel handoff ABI (v6).
//!
//! This module defines the data structures passed from the bootloader
//! to the kernel at entry point. The kernel reads these structures
//! to discover memory layout, ACPI tables, framebuffer configuration,
//! and kernel modules.
//!
//! # Boot flow
//!
//! ```text
//! UEFI/BIOS => bootloader => kernel_main(KernelArgs)
//! ```
//!
//! The bootloader populates `KernelArgs` in a reserved memory region,
//! then jumps to the kernel entry point with a pointer to this structure
//! in RDI (System V AMD64 ABI first argument).
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
//! 0x0000_0000_0000_0000  => Identity map (first 4GB)
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
//!     for region in unsafe { args.memory_regions() }.expect("invalid boot memory map") {
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
//!     for module in unsafe { args.modules() }.expect("invalid boot module table") {
//!         // module.name_str(), module.base, module.size
//!     }
//! }
//! ```

use zerocopy::{FromBytes, IntoBytes};

/// ABI version for the boot handoff structure.
///
/// Version 5 is reserved for the memory-kind extension (`Bad`, `AcpiNvs`)
/// developed on `fix/boot-abi-consistency`; this lineage skipped it so the
/// two layouts can never both claim to be v5. Version 6 adds the boot log ring.
pub const STRAT9_BOOT_ABI_VERSION: u32 = 6;

/// Magic number validating the boot handoff (`"ST9B"` in ASCII).
pub const STRAT9_BOOT_MAGIC: u32 = 0x5354_3942; // "ST9B"

/// Capacity of the fixed module table shared by the loader and kernel.
pub const MAX_BOOT_MODULES: usize = 64;
/// Maximum number of descriptors accepted by the kernel's boot-map work buffer.
pub const MAX_BOOT_MEMORY_REGIONS: usize = 1024;
pub const MODULE_TABLE_SIZE: usize = core::mem::size_of::<ModuleTable>();
const MODULE_TABLE_HEADER_SIZE: usize = core::mem::offset_of!(ModuleTable, entries);

/// Bootloader-to-kernel handoff structure (ABI v6, 156 bytes).
///
/// Field layout is ordered to avoid internal padding:
/// - u64 fields first (8-byte aligned)
/// - u32 fields next
/// - u16 field
/// - u8 fields last
///
/// # Field groups
///
/// ## Identity (8 bytes)
/// - `magic`: must equal [`STRAT9_BOOT_MAGIC`] (`0x5354_3942`)
/// - `abi_version`: must equal [`STRAT9_BOOT_ABI_VERSION`] (currently `6`)
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
///
/// ## Boot log ring (24 bytes, since v6)
/// - `boot_log_base`: physical address of the ring buffer
/// - `boot_log_size`: ring capacity in bytes (power of two)
/// - `boot_log_written`: total bytes ever appended, monotonically increasing.
///   Only the last `min(boot_log_written, boot_log_size)` bytes are valid; see
///   [`KernelArgs::boot_log_spans`] for the ordering after a wrap.
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
    // --- BSS region ---
    pub bss_virt_base: u64,
    pub bss_virt_size: u64,
    // --- Boot log ring (v6) ---
    pub boot_log_base: u64,
    pub boot_log_size: u64,
    pub boot_log_written: u64,
}

// Ensure struct is exactly 156 bytes with no padding
const _: () = assert!(core::mem::size_of::<KernelArgs>() == 156);

/// Upper bound on a handoff ring, so a corrupted size cannot make the kernel
/// scan an absurd physical range.
pub const MAX_BOOT_LOG_SIZE: u64 = 1 << 20;
/// Smallest ring accepted: one page, enough for the loader's own messages.
pub const MIN_BOOT_LOG_SIZE: u64 = 4096;

impl KernelArgs {
    /// Read the memory map, rejecting malformed lengths instead of truncating.
    ///
    /// # Safety
    /// Any range that passes the numeric checks must be readable through the
    /// current identity mapping, initialized and immutable for the returned
    /// slice's lifetime. These checks cannot establish physical memory ownership.
    pub unsafe fn memory_regions(&self) -> Result<&[MemoryRegion], &'static str> {
        if self.memory_map_base == 0 && self.memory_map_size == 0 {
            return Ok(&[]);
        }
        let size = checked_handoff_range(
            self.memory_map_base,
            self.memory_map_size,
            core::mem::align_of::<MemoryRegion>(),
        )?;
        let entry_size = core::mem::size_of::<MemoryRegion>();
        if size % entry_size != 0 {
            return Err("memory map contains a partial descriptor");
        }
        let count = size / entry_size;
        if count > MAX_BOOT_MEMORY_REGIONS {
            return Err("memory map exceeds kernel capacity");
        }
        let ptr = self.memory_map_base as *const MemoryRegion;
        Ok(unsafe { core::slice::from_raw_parts(ptr, count) })
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

    /// Read the fixed-capacity module table after checking its advertised extent.
    ///
    /// # Safety
    /// If the numeric extent checks succeed, the first MODULE_TABLE_SIZE bytes
    /// must be readable through the current identity mapping, initialized and
    /// immutable for the returned slice's lifetime. Module payloads are not read.
    pub unsafe fn modules(&self) -> Result<&[ModuleEntry], &'static str> {
        if self.modules_base == 0 && self.modules_size == 0 {
            return Ok(&[]);
        }
        let size = checked_handoff_range(
            self.modules_base,
            self.modules_size,
            core::mem::align_of::<ModuleTable>(),
        )?;
        if size < MODULE_TABLE_SIZE {
            return Err("truncated fixed module table");
        }
        // Do not manufacture a reference to a table until its extent is checked.
        let bytes = unsafe {
            core::slice::from_raw_parts(self.modules_base as *const u8, MODULE_TABLE_SIZE)
        };
        ModuleTable::read_from(bytes)
    }

    /// Geometry of the bootloader log ring, oldest byte first.
    ///
    /// The ring is a plain byte buffer: the loader appends at
    /// `boot_log_written % boot_log_size`, so only the last
    /// `min(boot_log_written, boot_log_size)` bytes are meaningful. After a
    /// wrap the oldest bytes sit at the end of the buffer and the newest at the
    /// beginning, which is why the valid window is returned as two spans.
    ///
    /// A pair of zeroes means "no log". Any other inconsistent or implausible
    /// geometry is rejected instead of being clamped.
    pub fn boot_log_spans(&self) -> Result<BootLogSpans, &'static str> {
        let base = self.boot_log_base;
        let size = self.boot_log_size;
        if base == 0 && size == 0 {
            return Ok(BootLogSpans::EMPTY);
        }
        if base == 0 || size == 0 {
            return Err("inconsistent boot log range");
        }
        if !size.is_power_of_two() || !(MIN_BOOT_LOG_SIZE..=MAX_BOOT_LOG_SIZE).contains(&size) {
            return Err("invalid boot log ring size");
        }
        if base % MIN_BOOT_LOG_SIZE != 0 {
            return Err("unaligned boot log ring");
        }
        let valid = self.boot_log_written.min(size) as usize;
        if valid == 0 {
            return Ok(BootLogSpans::EMPTY);
        }
        let start = ((self.boot_log_written - valid as u64) % size) as usize;
        let first = (size as usize - start).min(valid);
        Ok(BootLogSpans {
            start,
            first,
            second: valid - first,
        })
    }
}

/// Pure metadata validation, performed before dereferencing a handoff address.
fn checked_handoff_range(base: u64, size: u64, align: usize) -> Result<usize, &'static str> {
    if base == 0 || size == 0 {
        return Err("inconsistent empty handoff range");
    }
    let end = base.checked_add(size).ok_or("handoff address overflow")?;
    if base % align as u64 != 0 {
        return Err("unaligned handoff range");
    }
    if end > usize::MAX as u64 || size > isize::MAX as u64 {
        return Err("handoff range exceeds addressable size");
    }
    Ok(size as usize)
}

/// Valid window of the bootloader log ring, oldest byte first.
///
/// Read `first` bytes at `base + start`, then `second` bytes at `base`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootLogSpans {
    pub start: usize,
    pub first: usize,
    pub second: usize,
}

impl BootLogSpans {
    pub const EMPTY: Self = Self {
        start: 0,
        first: 0,
        second: 0,
    };

    /// Total number of bytes the reader must consume.
    pub fn len(&self) -> usize {
        self.first + self.second
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Module table header + entries.
///
/// The bootloader builds this in physical memory and passes the
/// address via `KernelArgs::modules_base`.
#[repr(C)]
pub struct ModuleTable {
    pub count: u32,
    pub entries: [ModuleEntry; MAX_BOOT_MODULES],
}

impl ModuleTable {
    /// Write the complete fixed table. All checks precede the first write.
    /// Bytes beyond MODULE_TABLE_SIZE, including allocation padding, are untouched.
    pub fn write_into(storage: &mut [u8], modules: &[ModuleEntry]) -> Result<(), &'static str> {
        if modules.len() > MAX_BOOT_MODULES {
            return Err("too many boot modules (maximum 64)");
        }
        if storage.len() < MODULE_TABLE_SIZE {
            return Err("module table allocation too small");
        }
        if storage.as_ptr() as usize % core::mem::align_of::<Self>() != 0 {
            return Err("unaligned module table allocation");
        }
        storage[..MODULE_TABLE_SIZE].fill(0);
        // SAFETY: extent/alignment are checked, all fields accept zero, and the
        // mutable byte slice supplies exclusive ownership for this borrow.
        let table = unsafe { &mut *storage.as_mut_ptr().cast::<Self>() };
        table.entries[..modules.len()].copy_from_slice(modules);
        table.count = modules.len() as u32;
        Ok(())
    }

    /// Validate the fixed table before forming a slice of initialized entries.
    /// A shortened header-plus-count representation is not this ABI's format.
    pub fn read_from(storage: &[u8]) -> Result<&[ModuleEntry], &'static str> {
        if storage.len() < MODULE_TABLE_SIZE {
            return Err("truncated fixed module table");
        }
        if storage.as_ptr() as usize % core::mem::align_of::<Self>() != 0 {
            return Err("unaligned module table");
        }
        let count = u32::from_ne_bytes([storage[0], storage[1], storage[2], storage[3]]) as usize;
        if count > MAX_BOOT_MODULES {
            return Err("module count exceeds table capacity");
        }
        let end = count
            .checked_mul(core::mem::size_of::<ModuleEntry>())
            .and_then(|size| MODULE_TABLE_HEADER_SIZE.checked_add(size))
            .ok_or("module table length overflow")?;
        if end > storage.len() {
            return Err("module entries exceed advertised table size");
        }
        // SAFETY: storage covers the fixed table, has the required alignment,
        // ModuleEntry contains only integers, and the checked slice stays inside it.
        let entries = unsafe {
            storage
                .as_ptr()
                .add(MODULE_TABLE_HEADER_SIZE)
                .cast::<ModuleEntry>()
        };
        Ok(unsafe { core::slice::from_raw_parts(entries, count) })
    }
}

/// A single loaded module (userspace binary or config file).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModuleEntry {
    /// Module name (null-terminated, max 63 chars).
    pub name: [u8; 64],
    /// Physical address of the module data.
    pub base: u64,
    /// Size of the module data in bytes.
    pub size: u64,
}

impl ModuleEntry {
    /// Validate a portable, single-component initfs name without normalization.
    pub fn checked_name(&self) -> Result<&str, &'static str> {
        let len = self
            .name
            .iter()
            .position(|&b| b == 0)
            .ok_or("module name is not NUL-terminated")?;
        validate_module_name(&self.name[..len])
    }

    /// Module name as a string slice.
    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(63);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }
}

/// Names shared by the ESP producer, loader and initfs consumer: 1..=63 ASCII
/// letters/digits, '.', '_' or '-'. Reject path components and FAT-ambiguous dots.
pub fn validate_module_name(name: &[u8]) -> Result<&str, &'static str> {
    if name.is_empty() || name.len() > 63 {
        return Err("module name must contain 1 to 63 bytes");
    }
    if name == b"."
        || name == b".."
        || name.last() == Some(&b'.')
        || !name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'.' | b'_' | b'-'))
    {
        return Err("module name must be a portable ASCII filename");
    }
    core::str::from_utf8(name).map_err(|_| "module name is not ASCII")
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

// ABI size assertions (packed: no padding, 156 bytes with the boot log ring)
const _: () = assert!(core::mem::size_of::<KernelArgs>() == 156);
const _: () = assert!(core::mem::align_of::<KernelArgs>() == 1);
static_assertions::assert_eq_size!(MemoryRegion, [u8; 24]);
static_assertions::const_assert_eq!(core::mem::align_of::<MemoryRegion>(), 8);
static_assertions::assert_eq_size!(MemoryKind, [u8; 8]);
static_assertions::assert_eq_size!(ModuleEntry, [u8; 80]);
static_assertions::assert_eq_size!(ModuleTable, [u8; 5128]);
static_assertions::const_assert_eq!(MODULE_TABLE_HEADER_SIZE, 8);
