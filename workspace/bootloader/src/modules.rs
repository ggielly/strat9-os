use alloc::vec::Vec;
use core::fmt::Write;
use uefi::{
    prelude::*,
    proto::media::file::{Directory, File, FileAttribute, FileInfo, FileMode, FileType},
    CStr16,
};

use crate::{
    memory::{BootError, BootMemory, BootResult},
    memory_map::PhysicalRange,
    module_name::ModuleFileName,
};
pub use strat9_abi::boot::ModuleEntry as LoadedModule;
use strat9_abi::boot::{ModuleTable, MAX_BOOT_MODULES, MODULE_TABLE_SIZE};

// FileInfo requires 8-byte alignment; a Vec<u8> or [u8; N] does not promise it.
// 4 KiB covers the FAT filename limit. Larger firmware entries fail explicitly.
#[repr(align(8))]
struct InfoBuffer([u8; 4096]);

struct E9;
impl core::fmt::Write for E9 {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        for byte in text.bytes() {
            unsafe { core::arch::asm!("out 0xe9, al", in("al") byte, options(nomem, nostack)) };
        }
        Ok(())
    }
}

fn module_error(name: &CStr16, error: BootError) -> BootError {
    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(
            stdout,
            "[boot] initfs '{}': {} ({:?})",
            name, error.operation, error.status
        );
    });
    let _ = writeln!(
        E9,
        "[boot] initfs '{}': {} ({:?})",
        name, error.operation, error.status
    );
    error
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
    volume: &mut Directory,
    memory: &mut BootMemory,
) -> BootResult<Vec<LoadedModule>> {
    let directory_path = cstr16!("\\boot\\initfs");
    let handle = volume
        .open(directory_path, FileMode::Read, FileAttribute::empty())
        .map_err(|e| {
            module_error(
                directory_path,
                BootError::firmware("open module directory", e.status()),
            )
        })?;
    let mut dir = match handle.into_type().map_err(|e| {
        module_error(
            directory_path,
            BootError::firmware("inspect module directory", e.status()),
        )
    })? {
        FileType::Dir(dir) => dir,
        _ => {
            return Err(module_error(
                directory_path,
                BootError::invalid("initfs is not a directory"),
            ))
        }
    };

    let mut names: Vec<ModuleFileName> = Vec::new();
    let mut entry_buffer = InfoBuffer([0; 4096]);
    loop {
        let info = match dir.read_entry(&mut entry_buffer.0) {
            Ok(Some(info)) => info,
            Ok(None) => break,
            Err(e) => {
                return Err(module_error(
                    directory_path,
                    BootError::firmware("enumerate module directory", e.status()),
                ))
            }
        };
        if info.attribute().contains(FileAttribute::DIRECTORY) {
            // This ABI represents a flat directory; subdirectories are not modules.
            if info.file_name() != cstr16!(".") && info.file_name() != cstr16!("..") {
                let _ = writeln!(
                    E9,
                    "[boot] initfs: skipping subdirectory '{}'",
                    info.file_name()
                );
            }
            continue;
        }
        let filename = ModuleFileName::new(info.file_name().to_u16_slice())
            .map_err(|reason| module_error(info.file_name(), BootError::invalid(reason)))?;
        if names
            .iter()
            .any(|previous| previous.as_str().eq_ignore_ascii_case(filename.as_str()))
        {
            return Err(module_error(
                info.file_name(),
                BootError::invalid("duplicate module filename"),
            ));
        }
        if names.len() == MAX_BOOT_MODULES {
            return Err(module_error(
                info.file_name(),
                BootError::invalid("too many boot modules (maximum 64)"),
            ));
        }
        names.try_reserve(1).map_err(|_| {
            module_error(
                info.file_name(),
                BootError::out_of_resources("module filename list"),
            )
        })?;
        names.push(filename);
    }
    dir.close();
    names.sort_unstable_by(|left, right| left.as_str().cmp(right.as_str()));
    if !names
        .iter()
        .any(|name| matches!(name.as_str(), "init" | "strate-init"))
    {
        return Err(module_error(
            directory_path,
            BootError::invalid("required init or strate-init module is missing"),
        ));
    }
    let _ = writeln!(E9, "[boot] initfs: {} files enumerated", names.len());

    let mut modules = Vec::new();
    modules.try_reserve_exact(names.len()).map_err(|_| {
        module_error(
            directory_path,
            BootError::out_of_resources("loaded module list"),
        )
    })?;
    let mut info_buffer = InfoBuffer([0; 4096]);
    for filename in names {
        // The validated path contains the original UCS-2 units and one NUL.
        let path = CStr16::from_u16_with_nul(filename.path())
            .map_err(|_| module_error(directory_path, BootError::invalid("invalid module path")))?;
        let handle = volume
            .open(path, FileMode::Read, FileAttribute::empty())
            .map_err(|e| module_error(path, BootError::firmware("open module", e.status())))?;
        let mut file = match handle.into_type().map_err(|e| {
            module_error(path, BootError::firmware("inspect module type", e.status()))
        })? {
            FileType::Regular(file) => file,
            _ => {
                return Err(module_error(
                    path,
                    BootError::invalid("module is not a regular file"),
                ))
            }
        };
        let size = file
            .get_info::<FileInfo>(&mut info_buffer.0)
            .map_err(|e| module_error(path, BootError::firmware("module metadata", e.status())))?
            .file_size();
        if size > isize::MAX as u64 {
            return Err(module_error(
                path,
                BootError::invalid("module exceeds addressable size"),
            ));
        }
        let file_size = usize::try_from(size)
            .map_err(|_| module_error(path, BootError::invalid("module size overflow")))?;
        if size == 0 && matches!(filename.as_str(), "init" | "strate-init") {
            return Err(module_error(
                path,
                BootError::invalid("init executable is empty"),
            ));
        }
        // Empty config/data files still get a valid owned pointer and a VFS entry.
        let allocation = memory
            .allocate(size.max(1), "module payload pages")
            .map_err(|e| module_error(path, e))?;
        if file_size != 0 {
            // SAFETY: the owned allocation covers the exact file extent. Read does
            // not expose page padding, and no module is published on partial data.
            let buf =
                unsafe { core::slice::from_raw_parts_mut(allocation.base as *mut u8, file_size) };
            let read = file.read(buf).map_err(|e| {
                module_error(path, BootError::firmware("read module payload", e.status()))
            })?;
            if read != file_size {
                return Err(module_error(
                    path,
                    BootError::invalid("module payload ended before its advertised size"),
                ));
            }
        }
        modules.push(LoadedModule {
            name: filename.abi_name(),
            base: allocation.base,
            size,
        });
        let _ = writeln!(
            E9,
            "[boot] initfs: loaded '{}' ({} bytes)",
            filename.as_str(),
            size
        );
    }
    Ok(modules)
}
