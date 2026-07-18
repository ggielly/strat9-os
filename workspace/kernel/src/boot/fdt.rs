//! Device Tree (FDT) parsing for U-Boot boot protocol.
//!
//! Parses the Flattened Device Tree to extract boot information:
//! - Memory map
//! - Framebuffer
//! - ACPI RSDP
//! - Boot command line
//! - Stdout path (serial console)

use crate::boot::entry::{KernelArgs, MemoryKind, MemoryRegion};

/// Maximum number of memory regions supported from DTB
const MAX_DTB_MEMORY_REGIONS: usize = 128;

/// Static storage for memory map parsed from DTB
static mut DTB_MEMORY_MAP: [MemoryRegion; MAX_DTB_MEMORY_REGIONS] = [MemoryRegion {
    base: 0,
    size: 0,
    kind: MemoryKind::Reserved,
}; MAX_DTB_MEMORY_REGIONS];
static mut DTB_MEMORY_MAP_LEN: usize = 0;

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
        stack_base: 0,
        stack_size: 0,
        env_base: 0,
        env_size: 0,
        acpi_rsdp_base: 0,
        acpi_rsdp_size: 0,
        memory_map_base: 0,
        memory_map_size: 0,
        initfs_base: 0,
        initfs_size: 0,
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
        _padding1: [0; 4],
        hhdm_offset: 0,
        cmdline_ptr: 0,
        cmdline_len: 0,
    };

    if dtb_ptr == 0 {
        crate::serial_println!("[fdt] ERROR: null DTB pointer");
        return args;
    }

    // Parse FDT header to validate
    let fdt = match parse_fdt_header(dtb_ptr) {
        Ok(fdt) => fdt,
        Err(e) => {
            crate::serial_println!("[fdt] ERROR: {}", e);
            return args;
        }
    };

    crate::serial_println!("[fdt] DTB at {:#x}, version {}", dtb_ptr, fdt.version);

    // Parse memory nodes → memory map
    let (map_base, map_size) = parse_memory_nodes(&fdt);
    args.memory_map_base = map_base;
    args.memory_map_size = map_size;

    // Parse /chosen node
    parse_chosen_node(&fdt, &mut args);

    // Parse framebuffer (from /chosen or framebuffer node)
    parse_framebuffer(&fdt, &mut args);

    // Parse ACPI RSDP (from /chosen or ACPI search)
    parse_acpi_rsdp(&fdt, &mut args);

    args
}

/// Parsed FDT header information
struct FdtHeader {
    _total_size: u32,
    _off_dt_struct: u32,
    _off_dt_strings: u32,
    _off_mem_rsvmap: u32,
    version: u32,
    _last_comp_version: u32,
    _boot_cpuid_phys: u32,
    _size_dt_struct: u32,
    _size_dt_strings: u32,
    base_ptr: u64,
}

/// Parse and validate the FDT header
///
/// # Safety
///
/// `dtb_ptr` must point to valid FDT data.
unsafe fn parse_fdt_header(dtb_ptr: u64) -> Result<FdtHeader, &'static str> {
    let ptr = dtb_ptr as *const u8;

    // Read magic number (should be 0xd00dfeed big-endian)
    let magic = read_be32(ptr);
    if magic != 0xd00dfeed {
        return Err("invalid FDT magic number");
    }

    let total_size = read_be32(ptr.add(4));
    let off_dt_struct = read_be32(ptr.add(8));
    let off_dt_strings = read_be32(ptr.add(12));
    let off_mem_rsvmap = read_be32(ptr.add(16));
    let version = read_be32(ptr.add(20));
    let last_comp_version = read_be32(ptr.add(24));
    let boot_cpuid_phys = read_be32(ptr.add(28));
    let size_dt_struct = read_be32(ptr.add(32));
    let size_dt_strings = read_be32(ptr.add(36));

    Ok(FdtHeader {
        _total_size: total_size,
        _off_dt_struct: off_dt_struct,
        _off_dt_strings: off_dt_strings,
        _off_mem_rsvmap: off_mem_rsvmap,
        version,
        _last_comp_version: last_comp_version,
        _boot_cpuid_phys: boot_cpuid_phys,
        _size_dt_struct: size_dt_struct,
        _size_dt_strings: size_dt_strings,
        base_ptr: dtb_ptr,
    })
}

/// Parse /memory nodes to build the memory map
unsafe fn parse_memory_nodes(fdt: &FdtHeader) -> (u64, u64) {
    let struct_base = fdt.base_ptr + fdt._off_dt_struct as u64;
    let strings_base = fdt.base_ptr + fdt._off_dt_strings as u64;
    let struct_end = struct_base + fdt._size_dt_struct as u64;

    let mut pos = struct_base;
    let mut count = 0usize;

    crate::serial_println!("[fdt] Scanning for /memory nodes...");

    while pos < struct_end && count < MAX_DTB_MEMORY_REGIONS {
        let token = read_be32(pos as *const u8);
        pos += 4;

        match token {
            // FDT_BEGIN_NODE
            0x1 => {
                // Read node name (null-terminated, 4-byte aligned)
                let name_ptr = pos as *const u8;
                let name = read_cstring(name_ptr);
                let name_len = (name.len() + 1) as u64; // include null terminator
                pos += (name_len + 3) & !3; // align to 4 bytes

                // Check if this is a memory node (name starts with "memory")
                if name.starts_with("memory") {
                    crate::serial_println!("[fdt] Found node: {}", name);
                    // Parse properties of this node
                    let (base, size) = parse_memory_node_properties(fdt, pos);
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
            // FDT_END_NODE
            0x2 => {}
            // FDT_PROP
            0x3 => {
                let prop_len = read_be32(pos as *const u8) as u64;
                pos += 4;
                let prop_nameoff = read_be32(pos as *const u8) as u64;
                pos += 4;
                // Skip property value (aligned to 4 bytes)
                pos += (prop_len + 3) & !3;
                // If we're inside a memory node, we already read the properties
                // (This is a simplified parser - for full FDT parsing we'd track depth)
                let _ = (strings_base, prop_nameoff);
            }
            // FDT_NOP
            0x4 => {}
            // FDT_END
            0x9 => break,
            _ => {
                crate::serial_println!("[fdt] Unknown token: {:#x}", token);
                break;
            }
        }
    }

    unsafe {
        DTB_MEMORY_MAP_LEN = count;
    }

    crate::serial_println!("[fdt] Found {} memory regions", count);

    if count > 0 {
        (
            DTB_MEMORY_MAP.as_ptr() as u64,
            (count * core::mem::size_of::<MemoryRegion>()) as u64,
        )
    } else {
        (0, 0)
    }
}

/// Parse properties of a /memory node to extract base and size
unsafe fn parse_memory_node_properties(fdt: &FdtHeader, start_pos: u64) -> (u64, u64) {
    let mut pos = start_pos;
    let struct_end = fdt.base_ptr + fdt._off_dt_struct as u64 + fdt._size_dt_struct as u64;
    let strings_base = fdt.base_ptr + fdt._off_dt_strings as u64;

    let mut reg_base = 0u64;
    let mut reg_size = 0u64;
    let mut found_reg = false;

    while pos < struct_end {
        let token = read_be32(pos as *const u8);
        pos += 4;

        match token {
            // FDT_PROP
            0x3 => {
                let prop_len = read_be32(pos as *const u8) as u64;
                pos += 4;
                let prop_nameoff = read_be32(pos as *const u8) as u64;
                pos += 4;

                // Get property name from strings table
                let prop_name = read_cstring((strings_base + prop_nameoff) as *const u8);

                if prop_name == "reg" && prop_len >= 16 {
                    // "reg" property contains (base, size) pairs
                    // For #address-cells=2, #size-cells=2: 8 bytes base + 8 bytes size
                    let val_ptr = pos as *const u8;
                    reg_base = ((read_be32(val_ptr) as u64) << 32) | read_be32(val_ptr.add(4)) as u64;
                    reg_size =
                        ((read_be32(val_ptr.add(8)) as u64) << 32) | read_be32(val_ptr.add(12)) as u64;
                    found_reg = true;
                    crate::serial_println!(
                        "[fdt]   reg property: base={:#x} size={:#x}",
                        reg_base,
                        reg_size
                    );
                }

                // Skip property value (aligned to 4 bytes)
                pos += (prop_len + 3) & !3;
            }
            // FDT_END_NODE - exit this node
            0x2 => break,
            // FDT_BEGIN_NODE - nested node, skip
            0x1 => {
                // Skip node name
                let name_len = read_cstring(pos as *const u8).len() + 1;
                pos += (name_len as u64 + 3) & !3;
                // Skip nested content until FDT_END_NODE
                let mut depth = 1u32;
                while pos < struct_end && depth > 0 {
                    let t = read_be32(pos as *const u8);
                    pos += 4;
                    match t {
                        0x1 => {
                            depth += 1;
                            let nl = read_cstring(pos as *const u8).len() + 1;
                            pos += (nl as u64 + 3) & !3;
                        }
                        0x2 => depth -= 1,
                        0x3 => {
                            let pl = read_be32(pos as *const u8) as usize;
                            pos += 4 + 4 + ((pl + 3) & !3) as u64;
                        }
                        0x4 => {}
                        _ => break,
                    }
                }
            }
            // FDT_NOP
            0x4 => {}
            // FDT_END
            0x9 => break,
            _ => break,
        }
    }

    if found_reg {
        (reg_base, reg_size)
    } else {
        (0, 0)
    }
}

/// Parse /chosen node for bootargs, initrd, stdout-path
unsafe fn parse_chosen_node(fdt: &FdtHeader, args: &mut KernelArgs) {
    let struct_base = fdt.base_ptr + fdt._off_dt_struct as u64;
    let strings_base = fdt.base_ptr + fdt._off_dt_strings as u64;
    let struct_end = struct_base + fdt._size_dt_struct as u64;

    let mut pos = struct_base;
    let mut in_chosen = false;

    crate::serial_println!("[fdt] Scanning for /chosen node...");

    while pos < struct_end {
        let token = read_be32(pos as *const u8);
        pos += 4;

        match token {
            0x1 => {
                // FDT_BEGIN_NODE
                let name = read_cstring(pos as *const u8);
                let name_len = name.len() + 1;
                pos += (name_len as u64 + 3) & !3;

                if name == "chosen" {
                    in_chosen = true;
                    crate::serial_println!("[fdt] Found /chosen node");
                }
            }
            0x2 => {
                // FDT_END_NODE
                if in_chosen {
                    break;
                }
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
                        let addr = read_be32(prop_ptr) as u64;
                        crate::serial_println!("[fdt] initrd-start: {:#x}", addr);
                        args.initfs_base = addr;
                    }
                    b"linux,initrd-end" => {
                        let addr = read_be32(prop_ptr) as u64;
                        crate::serial_println!("[fdt] initrd-end: {:#x}", addr);
                        if args.initfs_base != 0 && addr > args.initfs_base {
                            args.initfs_size = addr - args.initfs_base;
                        }
                    }
                    b"stdout-path" => {
                        let stdout = read_cstring(prop_ptr);
                        crate::serial_println!("[fdt] stdout-path: {}", stdout);
                    }
                    b"uefi-systab" => {
                        let addr = read_be64(prop_ptr);
                        crate::serial_println!("[fdt] uefi-systab: {:#x}", addr);
                        args.acpi_rsdp_base = addr;
                    }
                    _ => {}
                }
            }
            0x4 => {} // FDT_NOP
            0x9 => break, // FDT_END
            _ => break,
        }
    }
}

/// Parse framebuffer information from DTB
unsafe fn parse_framebuffer(fdt: &FdtHeader, args: &mut KernelArgs) {
    // On QEMU, framebuffer info may be in /chosen or /soc/framebuffer
    // For now, we use a basic search for common framebuffer properties
    let struct_base = fdt.base_ptr + fdt._off_dt_struct as u64;
    let strings_base = fdt.base_ptr + fdt._off_dt_strings as u64;
    let struct_end = struct_base + fdt._size_dt_struct as u64;

    let mut pos = struct_base;
    let mut in_framebuffer = false;

    while pos < struct_end {
        let token = read_be32(pos as *const u8);
        pos += 4;

        match token {
            0x1 => {
                // FDT_BEGIN_NODE
                let name = read_cstring(pos as *const u8);
                let name_len = name.len() + 1;
                pos += (name_len as u64 + 3) & !3;

                if name.contains("framebuffer") || name.contains("display") {
                    in_framebuffer = true;
                    crate::serial_println!("[fdt] Found framebuffer node: {}", name);
                }
            }
            0x2 => {
                // FDT_END_NODE
                in_framebuffer = false;
            }
            0x3 => {
                // FDT_PROP
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
                    b"reg" if prop_len >= 8 => {
                        args.framebuffer_addr = read_be32(prop_ptr) as u64;
                    }
                    b"width" if prop_len >= 4 => {
                        args.framebuffer_width = read_be32(prop_ptr);
                    }
                    b"height" if prop_len >= 4 => {
                        args.framebuffer_height = read_be32(prop_ptr);
                    }
                    b"stride" if prop_len >= 4 => {
                        args.framebuffer_stride = read_be32(prop_ptr);
                    }
                    b"bpp" if prop_len >= 4 => {
                        args.framebuffer_bpp = read_be32(prop_ptr) as u16;
                    }
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

/// Parse ACPI RSDP from DTB (fallback: search memory for RSDP signature)
unsafe fn parse_acpi_rsdp(fdt: &FdtHeader, args: &mut KernelArgs) {
    // If RSDP already found from /chosen/uefi-systab, skip
    if args.acpi_rsdp_base != 0 {
        crate::serial_println!(
            "[fdt] RSDP already found at {:#x}",
            args.acpi_rsdp_base
        );
        return;
    }

    // Try to find RSDP by scanning EFI configuration table
    // This is architecture-specific and may need to be refined
    crate::serial_println!("[fdt] RSDP not found in DTB, will be searched by kernel");
}

// ============================================================================
// Helper functions
// ============================================================================

/// Read a big-endian 32-bit value
///
/// # Safety
///
/// `ptr` must be valid for reading 4 bytes.
#[inline]
unsafe fn read_be32(ptr: *const u8) -> u32 {
    u32::from_be_bytes([
        core::ptr::read_volatile(ptr),
        core::ptr::read_volatile(ptr.add(1)),
        core::ptr::read_volatile(ptr.add(2)),
        core::ptr::read_volatile(ptr.add(3)),
    ])
}

/// Read a big-endian 64-bit value
///
/// # Safety
///
/// `ptr` must be valid for reading 8 bytes.
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

/// Read a null-terminated string from memory (up to 256 bytes)
///
/// # Safety
///
/// `ptr` must point to valid memory.
unsafe fn read_cstring(ptr: *const u8) -> &'static str {
    let mut len = 0;
    while len < 256 && core::ptr::read_volatile(ptr.add(len)) != 0 {
        len += 1;
    }
    let slice = core::slice::from_raw_parts(ptr, len);
    core::str::from_utf8(slice).unwrap_or("")
}

/// Return the memory map parsed from DTB
///
/// # Safety
///
/// Must only be called after `build_kernel_args_from_dtb`.
#[cfg_attr(not(test), allow(static_mut_refs))]
pub fn dtb_memory_map() -> Option<&'static [MemoryRegion]> {
    let len = unsafe { DTB_MEMORY_MAP_LEN };
    if len == 0 {
        return None;
    }
    let ptr = unsafe { DTB_MEMORY_MAP.as_ptr() };
    Some(unsafe { core::slice::from_raw_parts(ptr, len) })
}
