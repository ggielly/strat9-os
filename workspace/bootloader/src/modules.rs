use alloc::vec::Vec;
use uefi::{
    prelude::*,
    proto::media::file::{File, FileAttribute, FileInfo, FileMode},
};

/// Upper bound for a single initfs module file (bounded allocations).
pub const MAX_MODULE_FILE_SIZE: usize = 64 * 1024 * 1024; // 64 MiB

pub struct LoadedModule {
    pub name: [u8; 64],
    pub base: u64,
    pub size: u64,
}

#[repr(C)]
pub struct ModuleTable {
    pub count: u32,
    pub entries: [ModuleEntry; 64],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ModuleEntry {
    pub name: [u8; 64],
    pub base: u64,
    pub size: u64,
}

pub fn module_table_size(count: usize) -> u64 {
    let table_size = core::mem::size_of::<ModuleTable>() as u64;
    let entry_size = core::mem::size_of::<ModuleEntry>() as u64;
    let max_entries = 64u64;
    table_size - entry_size * max_entries + entry_size * count as u64
}

pub fn write_module_table(modules: &[LoadedModule], base: u64) {
    unsafe {
        let table = &mut *(base as *mut ModuleTable);
        table.count = modules.len() as u32;
        table.entries = [ModuleEntry {
            name: [0u8; 64],
            base: 0,
            size: 0,
        }; 64];
        for (i, m) in modules.iter().enumerate() {
            if i >= 64 {
                break;
            }
            table.entries[i].name = m.name;
            table.entries[i].base = m.base;
            table.entries[i].size = m.size;
        }
    }
}

pub fn load_modules(image_handle: Handle) -> Vec<LoadedModule> {
    let mut modules = Vec::new();

    let mut fs = match uefi::boot::get_image_file_system(image_handle) {
        Ok(fs) => fs,
        Err(_) => return modules,
    };

    let mut volume = match fs.open_volume() {
        Ok(v) => v,
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
        // Bound the allocation: a corrupted/huge file must not OOM the loader.
        if file_size > MAX_MODULE_FILE_SIZE {
            continue;
        }

        let alloc_size = (file_size + 4095) & !4095;
        let mut buf = alloc::vec![0u8; alloc_size];

        // Read fully: UEFI reads may be short. A truncated module is skipped
        // rather than passed to the kernel with zero-filled tail bytes.
        let mut total = 0usize;
        loop {
            match file.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(_) => break,
            }
            if total >= file_size {
                break;
            }
        }
        if total < file_size {
            continue;
        }

        let mut name = [0u8; 64];
        let name_bytes = filename.as_bytes();
        let copy_len = name_bytes.len().min(63);
        name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let base = buf.as_ptr() as u64;
        core::mem::forget(buf);

        modules.push(LoadedModule {
            name,
            base,
            size: file_size as u64,
        });
    }

    modules
}

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
