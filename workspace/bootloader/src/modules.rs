use alloc::vec::Vec;
use uefi::{
    prelude::*,
    proto::media::file::{File, FileAttribute, FileInfo, FileMode},
};

use crate::{
    memory::{BootError, BootMemory, BootResult},
    memory_map::PhysicalRange,
};
pub use strat9_abi::boot::ModuleEntry as LoadedModule;
use strat9_abi::boot::{ModuleTable, MAX_BOOT_MODULES, MODULE_TABLE_SIZE};

/// E9 failure marker: '<letter>?' (bootloader-side diagnostics).
fn e9_fail(c: u8) {
    unsafe {
        core::arch::asm!("out 0xe9, al", in("al") c, options(nomem, nostack));
        core::arch::asm!("out 0xe9, al", in("al") b'?', options(nomem, nostack));
        core::arch::asm!("out 0xe9, al", in("al") b'\n', options(nomem, nostack));
    }
}

pub fn module_table_size() -> u64 {
    MODULE_TABLE_SIZE as u64
}

/// # Safety
/// `storage` must describe exclusively owned writable pages, disjoint from modules.
pub unsafe fn write_module_table(
    modules: &[LoadedModule],
    storage: PhysicalRange,
) -> BootResult<()> {
    if storage.base == 0 || storage.size < MODULE_TABLE_SIZE as u64 {
        return Err(BootError::invalid("module table allocation too small"));
    }
    storage.end().map_err(BootError::invalid)?;
    // SAFETY: the allocation has been checked before creating even a byte slice.
    let bytes =
        unsafe { core::slice::from_raw_parts_mut(storage.base as *mut u8, MODULE_TABLE_SIZE) };
    ModuleTable::write_into(bytes, modules).map_err(BootError::invalid)
}

pub fn load_modules(
    volume: &mut uefi::proto::media::file::Directory,
    memory: &mut BootMemory,
) -> BootResult<Vec<LoadedModule>> {
    let mut modules = Vec::new();

    // Enumerate \boot\initfs dynamically: the module set is whatever the
    // build dropped on the ESP, so a hardcoded name list can only go stale.
    let mut dir_path = [0u16; 64];
    let dir_len = format_path(&mut dir_path, "");
    let dir = match volume.open(
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
            return Ok(modules);
        }
    };

    let mut names: Vec<alloc::string::String> = Vec::new();
    {
        // 1 KiB covers typical entries (name + FileInfo layout). Entries with
        // very long names would need more; we retry once with 4 KiB.
        let mut buf: Vec<u8> = Vec::new();
        buf.try_reserve_exact(1024)
            .map_err(|_| BootError::out_of_resources("module directory buffer"))?;
        buf.resize(1024, 0);
        loop {
            match dir.read_entry(&mut buf) {
                Ok(Some(info)) => {
                    if info.attribute().contains(FileAttribute::DIRECTORY) {
                        continue;
                    }
                    // ESP file names are ASCII here; decode u16 chars as bytes.
                    let mut s = alloc::string::String::new();
                    s.try_reserve(info.file_name().to_u16_slice().len())
                        .map_err(|_| BootError::out_of_resources("module filename"))?;
                    for ch in info.file_name().to_u16_slice() {
                        if *ch >= 0x20 && *ch < 0x7F {
                            s.push(*ch as u8 as char);
                        }
                    }
                    if names.len() == MAX_BOOT_MODULES {
                        return Err(BootError::invalid("too many boot modules (maximum 64)"));
                    }
                    names
                        .try_reserve(1)
                        .map_err(|_| BootError::out_of_resources("module filename list"))?;
                    names.push(s);
                }
                Ok(None) => break,
                Err(e) => {
                    // uefi::Error data = Some(required buffer size) on overflow.
                    if let Some(needed) = e.data() {
                        if *needed <= 4096 && *needed > buf.len() {
                            buf.try_reserve_exact(*needed - buf.len()).map_err(|_| {
                                BootError::out_of_resources("module directory buffer")
                            })?;
                            buf.resize(*needed, 0);
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
        let tens = if count >= 10 {
            b'0' + (count / 10) as u8
        } else {
            b' '
        };
        core::arch::asm!("out 0xe9, al", in("al") tens, options(nomem, nostack));
        core::arch::asm!("out 0xe9, al", in("al") b'0' + (count % 10) as u8, options(nomem, nostack));
        core::arch::asm!("out 0xe9, al", in("al") b'\n', options(nomem, nostack));
    }

    modules
        .try_reserve_exact(names.len())
        .map_err(|_| BootError::out_of_resources("loaded module list"))?;
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

        let allocation = memory.allocate(file_size as u64, "module payload pages")?;
        // SAFETY: memory owns this zeroed page allocation exclusively. Only the
        // file's actual byte count is exposed to the read, not page padding.
        let buf = unsafe { core::slice::from_raw_parts_mut(allocation.base as *mut u8, file_size) };
        let read = file
            .read(buf)
            .map_err(|error| BootError::firmware("read module payload", error.status()))?;
        if read != file_size {
            return Err(BootError::invalid(
                "module payload ended before its advertised size",
            ));
        }

        let mut name = [0u8; 64];
        let name_bytes = filename.as_bytes();
        let copy_len = name_bytes.len().min(63);
        name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        modules.push(LoadedModule {
            name,
            base: allocation.base,
            size: file_size as u64,
        });
    }

    Ok(modules)
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
