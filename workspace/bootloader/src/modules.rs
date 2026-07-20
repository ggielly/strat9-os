//! Module loader - loads files from /boot/initfs/ on the FAT ESP.
//!
//! Following Plan 9 simplicity: each file is loaded individually, and we build
//! a simple table of {name, base, size} that the kernel can iterate over.

use alloc::vec::Vec;
use uefi::prelude::*;
use uefi::proto::media::file::{File, FileAttribute, FileInfo, FileMode};

/// A loaded module: name + physical address + size
pub struct LoadedModule {
    pub name: [u8; 64],
    pub base: u64,
    pub size: u64,
}

/// Module table header + entries, as laid out in memory.
#[repr(C)]
pub struct ModuleTable {
    pub count: u32,
    pub entries: [ModuleEntry; 64],
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
pub fn load_modules(image_handle: Handle) -> Vec<LoadedModule> {
    let mut modules = Vec::new();

    let mut fs = match uefi::boot::get_image_file_system(image_handle) {
        Ok(fs) => fs,
        Err(_) => return modules,
    };

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

    for &filename in filenames {
        let mut volume = match fs.open_volume() {
            Ok(v) => v,
            Err(_) => continue,
        };

        let mut path_buf = [0u16; 64];
        let path_len = format_path(&mut path_buf, filename);

        let file = match volume.open(
            unsafe { uefi::CStr16::from_u16_with_nul_unchecked(&path_buf[..=path_len]) },
            FileMode::Read,
            FileAttribute::empty(),
        ) {
            Ok(f) => f,
            Err(_) => continue,
        };

        let mut file = match file.into_regular_file() {
            Some(f) => f,
            None => continue,
        };

        let mut info_buf = [0u8; 512];
        let file_size = match file.get_info::<FileInfo>(&mut info_buf) {
            Ok(info) => info.file_size() as usize,
            Err(_) => continue,
        };

        if file_size == 0 {
            continue;
        }

        let alloc_size = (file_size + 4095) & !4095;
        let buf = alloc::vec![0u8; alloc_size];
        let mut buf = core::mem::ManuallyDrop::new(buf);

        if file.read(&mut buf).is_err() {
            continue;
        }

        let mut name = [0u8; 64]; // zero-initialized = null-terminated
        let name_bytes = filename.as_bytes();
        let copy_len = name_bytes.len().min(63);
        name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        // name[copy_len] is already 0 from zero-initialization

        let base = buf.as_ptr() as u64;
        core::mem::forget(buf);

        modules.push(LoadedModule { name, base, size: file_size as u64 });
    }

    modules
}

/// Format a module path into a u16 buffer.
fn format_path(buf: &mut [u16; 64], filename: &str) -> usize {
    let mut i = 0;
    for &b in b"\\boot\\initfs\\" {
        buf[i] = b as u16;
        i += 1;
    }
    for &b in filename.as_bytes() {
        if i >= 63 {
            break;
        }
        buf[i] = b as u16;
        i += 1;
    }
    buf[i] = 0;
    i
}
