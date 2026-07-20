//! Device Tree (FDT) parsing for the custom boot protocol.
//!
//! Parses the Flattened Device Tree to extract boot information:
//! - Memory map
//! - Framebuffer
//! - ACPI RSDP (via EFI System Table)
//! - Boot command line
//! - HHDM offset (derived from memory map)
//!
//! # FDT format
//!
//! The DTB is a binary blob with big-endian fields. Structure tokens:
//! - 0x1 = FDT_BEGIN_NODE
//! - 0x2 = FDT_END_NODE
//! - 0x3 = FDT_PROP
//! - 0x4 = FDT_NOP
//! - 0x9 = FDT_END
//!
//! # Cell sizes
//!
//! The root node defines `#address-cells` and `#size-cells` which determine
//! how many 32-bit cells are used for addresses and sizes in `reg` properties.
//! Default on most platforms: #address-cells=2, #size-cells=2 (8 bytes each).

use crate::boot::entry::{KernelArgs, MemoryKind, MemoryRegion};

/// Maximum number of memory regions supported from DTB
const MAX_DTB_MEMORY_REGIONS: usize = 128;

/// Maximum string length for FDT strings
const MAX_CSTRING_LEN: usize = 512;

/// Default HHDM offset for x86_64 (4 GiB). Used when DTB doesn't specify one.
const DEFAULT_HHDM_OFFSET: u64 = 0x1_0000_0000;

/// Static storage for memory map parsed from DTB.
///
/// Lives for the entire kernel lifetime. The slice is handed out via
/// [`KernelArgs::memory_regions`].
static mut DTB_MEMORY_MAP: [MemoryRegion; MAX_DTB_MEMORY_REGIONS] = [MemoryRegion {
    base: 0,
    size: 0,
    kind: MemoryKind::Reserved,
}; MAX_DTB_MEMORY_REGIONS];

/// Parse the Flattened Device Tree and build a KernelArgs structure.
///
/// # Safety
///
/// `dtb_ptr` must point to a valid flattened device tree in memory.
#[cfg_attr(not(test), allow(static_mut_refs))]
pub unsafe fn build_kernel_args_from_dtb(dtb_ptr: u64) -> KernelArgs {
    let mut args = KernelArgs {
        magic: strat9_abi::boot::STRAT9_BOOT_MAGIC,
        abi_version: strat9_abi::boot::STRAT9_BOOT_ABI_VERSION,
        kernel_base: 0,
        kernel_size: 0,
        acpi_rsdp_base: 0,
        memory_map_base: 0,
        memory_map_size: 0,
        framebuffer_addr: 0,
        framebuffer_width: 0,
        framebuffer_height: 0,
        framebuffer_stride: 0,
        framebuffer_bpp: 0,
        framebuffer_red_mask_size: 0,
        framebuffer_red_mask_shift: 0,
        framebuffer_green_mask_size: 0,
        framebuffer_green_mask_shift: 0,
        framebuffer_blue_mask_size: 0,
        framebuffer_blue_mask_shift: 0,
        hhdm_offset: 0,
        cmdline_ptr: 0,
        cmdline_len: 0,
        modules_base: 0,
        modules_size: 0,
    };

    if dtb_ptr == 0 {
        crate::serial_println!("[fdt] ERROR: null DTB pointer");
        return args;
    }

    let fdt = match parse_fdt_header(dtb_ptr) {
        Ok(fdt) => fdt,
        Err(e) => {
            crate::serial_println!("[fdt] ERROR: {}", e);
            return args;
        }
    };

    crate::serial_println!("[fdt] DTB at {:#x}, version {}", dtb_ptr, fdt.version);

    // Parse root node to get #address-cells and #size-cells
    let (addr_cells, size_cells) = parse_root_properties(&fdt);
    crate::serial_println!(
        "[fdt] Root: #address-cells={} #size-cells={}",
        addr_cells,
        size_cells
    );

    // Parse memory nodes → memory map
    let regions = parse_memory_nodes(&fdt, addr_cells, size_cells);
    let count = regions.len();
    args.memory_map_base = regions.as_ptr() as u64;
    args.memory_map_size = (count * core::mem::size_of::<MemoryRegion>()) as u64;

    // Derive HHDM offset from memory map
    args.hhdm_offset = derive_hhdm_offset(regions);

    // Parse /chosen node (bootargs, initrd, stdout-path, uefi-systab)
    let mut efi_systab_addr = 0u64;
    parse_chosen_node(&fdt, &mut args, &mut efi_systab_addr);

    // Parse framebuffer (from /chosen or framebuffer node)
    parse_framebuffer(&fdt, &mut args, addr_cells);

    // Resolve RSDP from EFI System Table if available
    if efi_systab_addr != 0 && args.acpi_rsdp_base == 0 {
        args.acpi_rsdp_base = find_rsdp_from_efi_systab(efi_systab_addr);
    }

    args
}

// ============================================================================
// FDT header
// ============================================================================

struct FdtHeader {
    off_dt_struct: u32,
    off_dt_strings: u32,
    version: u32,
    size_dt_struct: u32,
    base_ptr: u64,
}

unsafe fn parse_fdt_header(dtb_ptr: u64) -> Result<FdtHeader, &'static str> {
    let ptr = dtb_ptr as *const u8;

    if read_be32(ptr) != 0xd00dfeed {
        return Err("invalid FDT magic number");
    }

    Ok(FdtHeader {
        off_dt_struct: read_be32(ptr.add(8)),
        off_dt_strings: read_be32(ptr.add(12)),
        version: read_be32(ptr.add(20)),
        size_dt_struct: read_be32(ptr.add(32)),
        base_ptr: dtb_ptr,
    })
}

// ============================================================================
// Root properties
// ============================================================================

/// Parse root node properties to extract #address-cells and #size-cells.
unsafe fn parse_root_properties(fdt: &FdtHeader) -> (u32, u32) {
    let struct_base = fdt.base_ptr + fdt.off_dt_struct as u64;
    let strings_base = fdt.base_ptr + fdt.off_dt_strings as u64;
    let struct_end = struct_base + fdt.size_dt_struct as u64;

    let mut pos = struct_base;
    let mut addr_cells = 2u32;
    let mut size_cells = 2u32;
    let mut in_root = false;

    while pos < struct_end {
        let token = read_be32(pos as *const u8);
        pos += 4;

        match token {
            0x1 => {
                // FDT_BEGIN_NODE
                let name = read_cstring(pos as *const u8);
                let name_len = name.len() + 1;
                pos += (name_len as u64 + 3) & !3;

                if name.is_empty() {
                    in_root = true;
                } else {
                    break;
                }
            }
            0x2 if in_root => break,
            0x3 => {
                // FDT_PROP
                let prop_len = read_be32(pos as *const u8) as u64;
                pos += 4;
                let prop_nameoff = read_be32(pos as *const u8) as u64;
                pos += 4;
                let prop_ptr = pos as *const u8;
                pos += (prop_len + 3) & !3;

                if !in_root {
                    continue;
                }

                let prop_name = read_cstring((strings_base + prop_nameoff) as *const u8);
                match prop_name.as_bytes() {
                    b"#address-cells" if prop_len >= 4 => addr_cells = read_be32(prop_ptr),
                    b"#size-cells" if prop_len >= 4 => size_cells = read_be32(prop_ptr),
                    _ => {}
                }
            }
            0x4 => {} // FDT_NOP
            0x9 => break,
            _ => break,
        }
    }

    (addr_cells, size_cells)
}

// ============================================================================
// Memory map
// ============================================================================

/// Parse /memory nodes to build the memory map.
///
/// Returns a slice into the static [`DTB_MEMORY_MAP`].
unsafe fn parse_memory_nodes(
    fdt: &FdtHeader,
    addr_cells: u32,
    size_cells: u32,
) -> &'static [MemoryRegion] {
    let struct_base = fdt.base_ptr + fdt.off_dt_struct as u64;
    let strings_base = fdt.base_ptr + fdt.off_dt_strings as u64;
    let struct_end = struct_base + fdt.size_dt_struct as u64;

    let mut pos = struct_base;
    let mut count = 0usize;
    let mut depth = 0u32;
    let mut in_memory_node = false;

    crate::serial_println!("[fdt] Scanning for /memory nodes...");

    while pos < struct_end && count < MAX_DTB_MEMORY_REGIONS {
        let token = read_be32(pos as *const u8);
        pos += 4;

        match token {
            0x1 => {
                // FDT_BEGIN_NODE
                depth += 1;
                let name = read_cstring(pos as *const u8);
                let name_len = (name.len() + 1) as u64;
                pos += (name_len + 3) & !3;

                if depth == 1 && name.starts_with("memory") {
                    in_memory_node = true;
                    crate::serial_println!("[fdt] Found node: {}", name);
                }
            }
            0x2 => {
                if in_memory_node && depth == 1 {
                    in_memory_node = false;
                }
                depth = depth.saturating_sub(1);
            }
            0x3 => {
                // FDT_PROP
                let prop_len = read_be32(pos as *const u8) as u64;
                pos += 4;
                let prop_nameoff = read_be32(pos as *const u8) as u64;
                pos += 4;
                let prop_ptr = pos as *const u8;
                pos += (prop_len + 3) & !3;

                if in_memory_node {
                    let prop_name = read_cstring((strings_base + prop_nameoff) as *const u8);
                    if prop_name == "reg" {
                        let (base, size) =
                            read_reg_property(prop_ptr, prop_len, addr_cells, size_cells);
                        if base != 0 && size != 0 {
                            DTB_MEMORY_MAP[count] = MemoryRegion {
                                base,
                                size,
                                kind: MemoryKind::Free,
                            };
                            crate::serial_println!(
                                "[fdt] Memory region: base={:#x} size={:#x}",
                                base,
                                size
                            );
                            count += 1;
                        }
                    }
                }
            }
            0x4 => {}
            0x9 => break,
            _ => {
                crate::serial_println!("[fdt] Unknown token: {:#x}", token);
                break;
            }
        }
    }

    crate::serial_println!("[fdt] Found {} memory regions", count);

    // SAFETY: DTB_MEMORY_MAP is written above and never mutated after this point.
    unsafe { core::slice::from_raw_parts(DTB_MEMORY_MAP.as_ptr(), count) }
}

/// Read a `reg` property value using the correct cell sizes.
unsafe fn read_reg_property(
    ptr: *const u8,
    len: u64,
    addr_cells: u32,
    size_cells: u32,
) -> (u64, u64) {
    let addr_bytes = (addr_cells * 4) as usize;
    let size_bytes = (size_cells * 4) as usize;
    let total = addr_bytes + size_bytes;

    if (len as usize) < total {
        return (0, 0);
    }

    let mut base = 0u64;
    for i in 0..addr_bytes {
        base = (base << 8) | *ptr.add(i) as u64;
    }

    let mut size = 0u64;
    for i in addr_bytes..total {
        size = (size << 8) | *ptr.add(i) as u64;
    }

    (base, size)
}

// ============================================================================
// HHDM offset
// ============================================================================

/// Derive HHDM offset from the memory map.
///
/// On x86_64 with the custom bootloader, the HHDM is typically at 4 GiB (0x1_0000_0000).
fn derive_hhdm_offset(regions: &[MemoryRegion]) -> u64 {
    let max_addr = regions
        .iter()
        .filter(|r| matches!(r.kind, MemoryKind::Free))
        .map(|r| r.base + r.size)
        .max()
        .unwrap_or(0);

    crate::serial_println!(
        "[fdt] Memory map: max_addr={:#x}, default HHDM={:#x}",
        max_addr,
        DEFAULT_HHDM_OFFSET
    );

    DEFAULT_HHDM_OFFSET
}

// ============================================================================
// /chosen node
// ============================================================================

/// Parse /chosen node for bootargs, initrd, stdout-path, uefi-systab.
unsafe fn parse_chosen_node(
    fdt: &FdtHeader,
    args: &mut KernelArgs,
    efi_systab_addr: &mut u64,
) {
    let struct_base = fdt.base_ptr + fdt.off_dt_struct as u64;
    let strings_base = fdt.base_ptr + fdt.off_dt_strings as u64;
    let struct_end = struct_base + fdt.size_dt_struct as u64;

    let mut pos = struct_base;
    let mut depth = 0u32;
    let mut in_chosen = false;

    crate::serial_println!("[fdt] Scanning for /chosen node...");

    while pos < struct_end {
        let token = read_be32(pos as *const u8);
        pos += 4;

        match token {
            0x1 => {
                depth += 1;
                let name = read_cstring(pos as *const u8);
                let name_len = name.len() + 1;
                pos += (name_len as u64 + 3) & !3;

                if depth == 1 && name == "chosen" {
                    in_chosen = true;
                    crate::serial_println!("[fdt] Found /chosen node");
                }
            }
            0x2 => {
                if in_chosen && depth == 1 {
                    in_chosen = false;
                }
                depth = depth.saturating_sub(1);
            }
            0x3 => {
                // FDT_PROP
                let prop_len = read_be32(pos as *const u8) as u64;
                pos += 4;
                let prop_nameoff = read_be32(pos as *const u8) as u64;
                pos += 4;
                let prop_ptr = pos as *const u8;
                pos += (prop_len + 3) & !3;

                if !in_chosen {
                    continue;
                }

                let prop_name = read_cstring((strings_base + prop_nameoff) as *const u8);

                match prop_name.as_bytes() {
                    b"bootargs" => {
                        let bootargs = read_cstring(prop_ptr);
                        crate::serial_println!("[fdt] bootargs: '{}'", bootargs);
                        args.cmdline_ptr = prop_ptr as u64;
                        args.cmdline_len = bootargs.len() as u64 + 1;
                    }
                    b"linux,initrd-start" => {
                        let addr = read_prop_u64(prop_ptr, prop_len);
                        crate::serial_println!("[fdt] initrd-start: {:#x} (FDT boot, module table not yet supported)", addr);
                        // NOTE: FDT boot doesn't use the module table yet.
                        // The initrd is loaded but not registered as a module.
                    }
                    b"linux,initrd-end" => {
                        let addr = read_prop_u64(prop_ptr, prop_len);
                        crate::serial_println!("[fdt] initrd-end: {:#x}", addr);
                    }
                    b"stdout-path" => {
                        crate::serial_println!("[fdt] stdout-path: {}", read_cstring(prop_ptr));
                    }
                    b"uefi-systab" => {
                        // EFI System Table address, NOT RSDP.
                        let addr = read_prop_u64(prop_ptr, prop_len);
                        crate::serial_println!("[fdt] uefi-systab (EFI System Table): {:#x}", addr);
                        *efi_systab_addr = addr;
                    }
                    _ => {}
                }
            }
            0x4 => {}
            0x9 => break,
            _ => break,
        }
    }
}

// ============================================================================
// Framebuffer
// ============================================================================

/// Parse framebuffer information from DTB.
unsafe fn parse_framebuffer(fdt: &FdtHeader, args: &mut KernelArgs, addr_cells: u32) {
    let struct_base = fdt.base_ptr + fdt.off_dt_struct as u64;
    let strings_base = fdt.base_ptr + fdt.off_dt_strings as u64;
    let struct_end = struct_base + fdt.size_dt_struct as u64;

    let mut pos = struct_base;
    let mut depth = 0u32;
    let mut in_framebuffer = false;

    while pos < struct_end {
        let token = read_be32(pos as *const u8);
        pos += 4;

        match token {
            0x1 => {
                depth += 1;
                let name = read_cstring(pos as *const u8);
                let name_len = name.len() + 1;
                pos += (name_len as u64 + 3) & !3;

                if name.contains("framebuffer") || name.contains("display") {
                    in_framebuffer = true;
                    crate::serial_println!("[fdt] Found framebuffer node: {}", name);
                }
            }
            0x2 => {
                if in_framebuffer {
                    in_framebuffer = false;
                }
                depth = depth.saturating_sub(1);
            }
            0x3 => {
                let prop_len = read_be32(pos as *const u8) as u64;
                pos += 4;
                let prop_nameoff = read_be32(pos as *const u8) as u64;
                pos += 4;
                let prop_ptr = pos as *const u8;
                pos += (prop_len + 3) & !3;

                if !in_framebuffer {
                    continue;
                }

                let prop_name = read_cstring((strings_base + prop_nameoff) as *const u8);

                match prop_name.as_bytes() {
                    b"reg" => {
                        let addr_bytes = (addr_cells * 4) as u64;
                        if prop_len >= addr_bytes {
                            args.framebuffer_addr = read_be_int(prop_ptr, addr_bytes as usize);
                        }
                    }
                    b"width" if prop_len >= 4 => args.framebuffer_width = read_be32(prop_ptr),
                    b"height" if prop_len >= 4 => args.framebuffer_height = read_be32(prop_ptr),
                    b"stride" if prop_len >= 4 => args.framebuffer_stride = read_be32(prop_ptr),
                    b"bpp" if prop_len >= 4 => args.framebuffer_bpp = read_be32(prop_ptr) as u16,
                    _ => {}
                }
            }
            0x4 => {}
            0x9 => break,
            _ => break,
        }
    }

    // Default framebuffer format if not specified
    if args.framebuffer_bpp == 0 && args.framebuffer_addr != 0 {
        args.framebuffer_bpp = 32;
        args.framebuffer_red_mask_size = 8;
        args.framebuffer_red_mask_shift = 16;
        args.framebuffer_green_mask_size = 8;
        args.framebuffer_green_mask_shift = 8;
        args.framebuffer_blue_mask_size = 8;
        args.framebuffer_blue_mask_shift = 0;
    }
}

// ============================================================================
// RSDP via EFI System Table
// ============================================================================

/// Find RSDP from EFI System Table.
///
/// The EFI System Table contains a pointer to the EFI Configuration Table array.
/// Each entry has a 128-bit GUID and a pointer. The RSDP GUID is
/// `ac03114e-0409-47d4-a7c2-4596dd3ff5a1`.
unsafe fn find_rsdp_from_efi_systab(efi_systab_addr: u64) -> u64 {
    crate::serial_println!(
        "[fdt] Searching for RSDP via EFI System Table at {:#x}",
        efi_systab_addr
    );

    let systab = efi_systab_addr as *const u8;

    // EFI System Table layout (UEFI Spec 2.10, §4.3.1):
    //   +0x68: NumberOfTableEntries (uintn_t)
    //   +0x70: ConfigurationTable (EFI_CONFIGURATION_TABLE*)
    let num_entries = read_be64(systab.add(0x68));
    let config_table_ptr = read_be64(systab.add(0x70));

    crate::serial_println!(
        "[fdt] EFI Config Table: {} entries at {:#x}",
        num_entries,
        config_table_ptr
    );

    if config_table_ptr == 0 || num_entries == 0 {
        crate::serial_println!("[fdt] No EFI configuration tables found");
        return 0;
    }

    // RSDP GUID: ac03114e-0409-47d4-a7c2-4596dd3ff5a1
    let rsdp_guid: [u64; 2] = [0x47d4_0409_ac03_114e, 0xa1f5_d3dd_9645_c2a7];

    // Each EFI_CONFIGURATION_TABLE is 24 bytes: GUID (16) + pointer (8)
    let config_table = config_table_ptr as *const u8;

    for i in 0..num_entries as usize {
        let entry = config_table.add(i * 24);
        let guid_lo = read_be64(entry);
        let guid_hi = read_be64(entry.add(8));
        let table_ptr = read_be64(entry.add(16));

        if guid_lo == rsdp_guid[0] && guid_hi == rsdp_guid[1] && table_ptr != 0 {
            crate::serial_println!("[fdt] RSDP found at {:#x}", table_ptr);
            return table_ptr;
        }
    }

    crate::serial_println!("[fdt] RSDP not found in EFI configuration tables");
    0
}

// ============================================================================
// Helpers
// ============================================================================

/// Read a big-endian 32-bit value.
#[inline]
unsafe fn read_be32(ptr: *const u8) -> u32 {
    u32::from_be_bytes([
        core::ptr::read_volatile(ptr),
        core::ptr::read_volatile(ptr.add(1)),
        core::ptr::read_volatile(ptr.add(2)),
        core::ptr::read_volatile(ptr.add(3)),
    ])
}

/// Read a big-endian 64-bit value.
#[inline]
unsafe fn read_be64(ptr: *const u8) -> u64 {
    u64::from_be_bytes([
        core::ptr::read_volatile(ptr),
        core::ptr::read_volatile(ptr.add(1)),
        core::ptr::read_volatile(ptr.add(2)),
        core::ptr::read_volatile(ptr.add(3)),
        core::ptr::read_volatile(ptr.add(4)),
        core::ptr::read_volatile(ptr.add(5)),
        core::ptr::read_volatile(ptr.add(6)),
        core::ptr::read_volatile(ptr.add(7)),
    ])
}

/// Read a big-endian integer of `num_bytes` bytes (1–8).
unsafe fn read_be_int(ptr: *const u8, num_bytes: usize) -> u64 {
    let mut val = 0u64;
    for i in 0..num_bytes {
        val = (val << 8) | *ptr.add(i) as u64;
    }
    val
}

/// Read a property value as u64 (32 or 64 bit depending on prop_len).
unsafe fn read_prop_u64(ptr: *const u8, prop_len: u64) -> u64 {
    if prop_len >= 8 {
        read_be64(ptr)
    } else {
        read_be32(ptr) as u64
    }
}

/// Read a null-terminated string from memory.
unsafe fn read_cstring(ptr: *const u8) -> &'static str {
    let mut len = 0;
    while len < MAX_CSTRING_LEN && core::ptr::read_volatile(ptr.add(len)) != 0 {
        len += 1;
    }
    let slice = core::slice::from_raw_parts(ptr, len);
    core::str::from_utf8(slice).unwrap_or("")
}
