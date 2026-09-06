use alloc::vec::Vec;
use uefi::prelude::*;
use uefi::proto::media::file::{File, FileAttribute, FileInfo, FileMode};

/// E9 failure marker: '<letter>?' (bootloader-side diagnostics).
fn e9_fail(c: u8) {
    unsafe {
        core::arch::asm!("out 0xe9, al", in("al") c, options(nomem, nostack));
        core::arch::asm!("out 0xe9, al", in("al") b'?', options(nomem, nostack));
        core::arch::asm!("out 0xe9, al", in("al") b'\n', options(nomem, nostack));
    }
}

pub struct LoadedModule {
    pub name: [u8; 64],
    pub base: u64,
    pub size: u64,
}

#[repr(C)]
pub struct ModuleTable {
    pub count: u32,
    _pad: u32,
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
    let header_size = core::mem::size_of::<ModuleTable>() as u64;
    let entry_size = core::mem::size_of::<ModuleEntry>() as u64;
    header_size + entry_size * count as u64 - entry_size * 64
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

pub fn load_modules(
    volume: &mut uefi::proto::media::file::Directory,
) -> Vec<LoadedModule> {
    let mut modules = Vec::new();

    // Enumerate \boot\initfs dynamically: the module set is whatever the
    // build dropped on the ESP, so a hardcoded name list can only go stale.
    let mut dir_path = [0u16; 64];
    let dir_len = format_path(&mut dir_path, "");
    let mut dir = match volume.open(
        unsafe { uefi::CStr16::from_u16_with_nul_unchecked(&dir_path[..=dir_len]) },
        FileMode::Read,
        FileAttribute::empty(),
    ) {
        Ok(d) => d.into_type().ok(),
        Err(_) => {
            e9_fail(b'D');
            None
        }
    };
    let mut dir = match dir {
        Some(uefi::proto::media::file::FileType::Dir(d)) => d,
        _ => {
            e9_fail(b'O');
            return modules;
        }
    };

    let mut names: Vec<alloc::string::String> = Vec::new();
    {
        // 1 KiB covers typical entries (name + FileInfo layout). Entries with
        // very long names would need more; we retry once with 4 KiB.
        let mut buf: Vec<u8> = alloc::vec![0u8; 1024];
        loop {
            match dir.read_entry(&mut buf) {
                Ok(Some(info)) => {
                    if info.attribute().contains(FileAttribute::DIRECTORY) {
                        continue;
                    }
                    // ESP file names are ASCII here; decode u16 chars as bytes.
                    let mut s = alloc::string::String::new();
                    for ch in info.file_name().to_u16_slice() {
                        if *ch >= 0x20 && *ch < 0x7F {
                            s.push(*ch as u8 as char);
                        }
                    }
                    names.push(s);
                }
                Ok(None) => break,
                Err(e) => {
                    // uefi::Error data = Some(required buffer size) on overflow.
                    if let Some(needed) = e.data() {
                        if *needed <= 4096 && *needed > buf.len() {
                            buf = alloc::vec![0u8; *needed];
                            let _ = dir.reset_entry_readout();
                            continue;
                        }
                    }
                    break;
                }
            }
        }
    }
    dir.close();
    // Boot log: how many initfs entries were enumerated (raw E9, 'M#n').
    unsafe {
        core::arch::asm!("out 0xe9, al", in("al") b'M', options(nomem, nostack));
        let count = names.len();
        let tens = if count >= 10 { b'0' + (count / 10) as u8 } else { b' ' };
        core::arch::asm!("out 0xe9, al", in("al") tens, options(nomem, nostack));
        core::arch::asm!("out 0xe9, al", in("al") b'0' + (count % 10) as u8, options(nomem, nostack));
        core::arch::asm!("out 0xe9, al", in("al") b'\n', options(nomem, nostack));
    }

    for filename in names {
        let mut path_buf = [0u16; 64];
        let path_len = format_path(&mut path_buf, &filename);

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
        let mut buf = alloc::vec![0u8; alloc_size];

        if file.read(&mut buf).is_err() {
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
