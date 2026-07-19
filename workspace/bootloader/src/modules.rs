//! Module loader - loads files from /boot/initfs/ on the FAT ESP.
//!
//! Following Plan 9 simplicity: each file is loaded individually, and we build
//! a simple table of {name, base, size} that the kernel can iterate over.

use alloc::vec::Vec;
use core::fmt::Write;
use uefi::proto::media::file::{File, FileAttribute, FileInfo, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::BootServices;

/// A loaded module: name + physical address + size
pub struct LoadedModule {
    pub name: [u8; 64],
    pub base: u64,
    pub size: u64,
}

/// Module table header + entries, as laid out in memory.
///
/// The kernel receives the base address of this structure and iterates
/// over entries. Simple, no archive format, no CPIO — just files.
#[repr(C)]
pub struct ModuleTable {
    pub count: u32,
    pub entries: [ModuleEntry; 64], // max 64 modules
}

/// A single module entry in the table.
#[repr(C)]
pub struct ModuleEntry {
    pub name: [u8; 64],
    pub base: u64,
    pub size: u64,
}

/// Calculate the size of the module table for a given count.
pub fn module_table_size(count: usize) -> u64 {
    let header_size = core::mem::size_of::<u32>() as u64;
    let entry_size = core::mem::size_of::<ModuleEntry>() as u64;
    header_size + entry_size * count as u64
}

/// Write the module table to a physical memory address.
pub fn write_module_table(modules: &[LoadedModule], base: u64) {
    unsafe {
        let table = base as *mut ModuleTable;
        (*table).count = modules.len() as u32;
        for (i, m) in modules.iter().enumerate() {
            if i >= 64 {
                break;
            }
            (*table).entries[i].name = m.name;
            (*table).entries[i].base = m.base;
            (*table).entries[i].size = m.size;
        }
    }
}

/// Load all files from /boot/initfs/ directory.
///
/// Each file is loaded into a separate physical memory region.
/// Returns the list of loaded modules with their names, bases, and sizes.
///
/// # Note
/// We take multiple root volume handles because uefi-rs doesn't allow
/// multiple File handles from the same volume simultaneously.
pub fn load_modules(
    bs: &BootServices,
    vol1: &mut SimpleFileSystem,
    vol2: &mut SimpleFileSystem,
    vol3: &mut SimpleFileSystem,
    vol4: &mut SimpleFileSystem,
    vol5: &mut SimpleFileSystem,
) -> Vec<LoadedModule> {
    let mut modules = Vec::new();
    let vols: [&mut SimpleFileSystem; 5] = [vol1, vol2, vol3, vol4, vol5];

    // Known module filenames to load
    let filenames: &[&str] = &[
        "init",
        "console-admin",
        "strate-net",
        "strate-bus",
        "strate-fs-ext4",
        "strate-fs-ramfs",
        "strate-wasm",
        "strate-webrtc",
        "display-server",
        "dhcp-client",
        "ping",
        "telnetd",
        "udp-tool",
        "web-admin",
        "test_pid",
        "test_syscalls",
        "test_mem",
    ];

    for (idx, &filename) in filenames.iter().enumerate() {
        let vol = &mut vols[idx % vols.len()];
        let mut root = match vol.open_volume() {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Build the path: \boot\initfs\<filename>
        let mut path_buf = [0u16; 64];
        let path = format_path(&mut path_buf, filename);

        let file = match root.open(path, FileMode::Read, FileAttribute::empty()) {
            Ok(f) => f,
            Err(_) => continue, // Module not found, skip
        };

        let mut file = match file.into_regular_file() {
            Ok(f) => f,
            Err(_) => continue, // Not a regular file, skip
        };

        // Get file size
        let mut info_buf = [0u8; 512];
        let file_info = match file.get_info::<FileInfo>(&mut info_buf) {
            Ok(info) => info,
            Err(_) => continue,
        };
        let file_size = file_info.file_size() as usize;

        if file_size == 0 {
            continue;
        }

        // Allocate buffer for the file content (page-aligned)
        let alloc_size = (file_size + 4095) & !4095;
        let buf = alloc::vec![0u8; alloc_size];
        let mut buf = core::mem::ManuallyDrop::new(buf);

        // Read file
        if file.read(&mut buf).is_err() {
            continue;
        }

        // Build module entry
        let mut name = [0u8; 64];
        let name_bytes = filename.as_bytes();
        let copy_len = name_bytes.len().min(63);
        name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let base = buf.as_ptr() as u64;

        // Leak the buffer so it stays valid until the kernel takes over
        // (We're in no_std after ExitBootServices, so there's no way to free it anyway)
        core::mem::forget(buf);

        modules.push(LoadedModule { name, base, size: file_size as u64 });
    }

    modules
}

/// Format a module path as a CStr16 for UEFI file operations.
fn format_path<'a>(buf: &'a mut [u16; 64], filename: &str) -> &'a uefi::CStr16 {
    let mut i = 0;
    // Prefix: \boot\initfs\
    let prefix = b"\\boot\\initfs\\";
    for &b in prefix {
        buf[i] = b as u16;
        i += 1;
    }
    // Filename
    for &b in filename.as_bytes() {
        if i >= 63 {
            break;
        }
        buf[i] = b as u16;
        i += 1;
    }
    // Null terminator
    buf[i] = 0;

    unsafe { uefi::CStr16::from_u16_unchecked(&buf[..=i]) }
}
