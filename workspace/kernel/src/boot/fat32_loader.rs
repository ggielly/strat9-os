//! FAT32 module loader for reading userspace ELFs from boot partition.
//!
//! Uses the `vfat-rs` crate (no_std compatible) to read files from FAT32.
//! Adapts the kernel's `BlockDevice` trait to the `vfat_rs::BlockDevice` trait.

use super::block_device::BlockDevice;
use vfat_rs::{SectorId, TimeManagerNoop, VfatFS};

/// Module information loaded from FAT32
#[derive(Debug, Clone, Copy)]
pub struct ModuleInfo {
    /// Physical address of the loaded module in memory
    pub base: u64,
    /// Size of the module in bytes
    pub size: u64,
}

/// Boot modules loaded from FAT32 partition
pub struct BootModules {
    pub init: Option<ModuleInfo>,
    pub console_admin: Option<ModuleInfo>,
    pub strate_net: Option<ModuleInfo>,
    pub strate_bus: Option<ModuleInfo>,
    pub fs_ext4: Option<ModuleInfo>,
    pub strate_fs_ramfs: Option<ModuleInfo>,
    pub strate_wasm: Option<ModuleInfo>,
    pub strate_webrtc: Option<ModuleInfo>,
    pub dhcp_client: Option<ModuleInfo>,
    pub ping: Option<ModuleInfo>,
    pub telnetd: Option<ModuleInfo>,
    pub udp_tool: Option<ModuleInfo>,
    pub web_admin: Option<ModuleInfo>,
}

impl Default for BootModules {
    fn default() -> Self {
        Self {
            init: None,
            console_admin: None,
            strate_net: None,
            strate_bus: None,
            fs_ext4: None,
            strate_fs_ramfs: None,
            strate_wasm: None,
            strate_webrtc: None,
            dhcp_client: None,
            ping: None,
            telnetd: None,
            udp_tool: None,
            web_admin: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Kernel BlockDevice → vfat_rs::BlockDevice adapter
// ---------------------------------------------------------------------------

/// Adapts the kernel's `BlockDevice` trait to `vfat_rs::BlockDevice`.
///
/// `vfat-rs` operates at sector granularity (512 bytes). This adapter
/// translates sector reads into LBA block reads via the underlying device.
pub struct VfatBlockDevice<'a, B: BlockDevice> {
    inner: &'a mut B,
}

impl<'a, B: BlockDevice> VfatBlockDevice<'a, B> {
    pub fn new(inner: &'a mut B) -> Self {
        Self { inner }
    }
}

impl<B: BlockDevice> vfat_rs::BlockDevice for VfatBlockDevice<'_, B> {
    fn sector_size(&self) -> usize {
        self.inner.block_size() as usize
    }

    fn read_sector_offset(
        &mut self,
        sector: SectorId,
        offset: usize,
        buf: &mut [u8],
    ) -> vfat_rs::Result<usize> {
        let block_size = self.inner.block_size() as usize;
        let byte_offset = u64::from(sector) * block_size as u64 + offset as u64;
        let lba = byte_offset / block_size as u64;
        let intra_offset = (byte_offset % block_size as u64) as usize;

        let mut block_buf = [0u8; 4096];
        self.inner
            .read_block(lba, &mut block_buf[..block_size])
            .map_err(|_| vfat_rs::VfatRsError::IoError)?;

        let available = block_size.saturating_sub(intra_offset);
        let to_copy = buf.len().min(available);
        buf[..to_copy].copy_from_slice(&block_buf[intra_offset..intra_offset + to_copy]);
        Ok(to_copy)
    }

    fn write_sector_offset(
        &mut self,
        _sector: SectorId,
        _offset: usize,
        _buf: &[u8],
    ) -> vfat_rs::Result<usize> {
        Err(vfat_rs::VfatRsError::IoError)
    }

    fn get_canonical_name() -> &'static str
    where
        Self: Sized,
    {
        "Strat9-OS BlockDevice"
    }
}

// ---------------------------------------------------------------------------
// Module loading
// ---------------------------------------------------------------------------

const MODULE_DIR: &str = "/modules";

const MODULE_NAMES: &[(&str, fn(&mut BootModules) -> &mut Option<ModuleInfo>)] = &[
    ("init", |m| &mut m.init),
    ("console_admin", |m| &mut m.console_admin),
    ("strate_net", |m| &mut m.strate_net),
    ("strate_bus", |m| &mut m.strate_bus),
    ("fs_ext4", |m| &mut m.fs_ext4),
    ("strate_fs_ramfs", |m| &mut m.strate_fs_ramfs),
    ("strate_wasm", |m| &mut m.strate_wasm),
    ("strate_webrtc", |m| &mut m.strate_webrtc),
    ("dhcp_client", |m| &mut m.dhcp_client),
    ("ping", |m| &mut m.ping),
    ("telnetd", |m| &mut m.telnetd),
    ("udp_tool", |m| &mut m.udp_tool),
    ("web_admin", |m| &mut m.web_admin),
];

/// Load all boot modules from the FAT32 boot partition.
///
/// Reads `/<MODULE_DIR>/*.elf` and loads each ELF into memory.
pub fn load_all_modules<B: BlockDevice>(block_dev: &mut B) -> BootModules {
    let mut modules = BootModules::default();

    let vfat_dev = VfatBlockDevice::new(block_dev);
    let mut fs = match VfatFS::new(vfat_dev, 0) {
        Ok(fs) => fs,
        Err(e) => {
            crate::serial_println!("[fat32] Failed to open filesystem: {:?}", e);
            return modules;
        }
    };

    crate::serial_println!(
        "[fat32] Filesystem opened: {} bytes/cluster",
        fs.bytes_per_cluster()
    );

    let module_dir = match fs.get_from_absolute_path(MODULE_DIR.into()) {
        Ok(entry) => entry.into_directory_unchecked(),
        Err(e) => {
            crate::serial_println!("[fat32] No {} directory: {:?}", MODULE_DIR, e);
            return modules;
        }
    };

    let contents = match module_dir.contents() {
        Ok(c) => c,
        Err(e) => {
            crate::serial_println!("[fat32] Failed to list {}: {:?}", MODULE_DIR, e);
            return modules;
        }
    };

    for entry in contents {
        if entry.is_dir() {
            continue;
        }

        let name = entry.metadata().name().to_string();
        let stem = name.strip_suffix(".elf").unwrap_or(&name);

        for &(mod_name, setter) in MODULE_NAMES {
            if stem.eq_ignore_ascii_case(mod_name) {
                let full_path = alloc::format!("{}/{}", MODULE_DIR, name);
                match load_elf_from_entry(&entry) {
                    Some(info) => {
                        crate::serial_println!(
                            "[fat32] Loaded {} at {:#x} ({} bytes)",
                            full_path,
                            info.base,
                            info.size
                        );
                        *setter(&mut modules) = Some(info);
                    }
                    None => {
                        crate::serial_println!("[fat32] Failed to load {}", full_path);
                    }
                }
                break;
            }
        }
    }

    modules
}

/// Load a single module from FAT32.
///
/// # Arguments
/// * `block_dev` - Block device to read from
/// * `path` - Absolute path to the module file on FAT32 (e.g. "/modules/init.elf")
///
/// # Returns
/// `Some(ModuleInfo)` if the module was loaded successfully, `None` otherwise.
pub fn load_module<B: BlockDevice>(block_dev: &mut B, path: &str) -> Option<ModuleInfo> {
    let vfat_dev = VfatBlockDevice::new(block_dev);
    let mut fs = VfatFS::new(vfat_dev, 0).ok()?;

    let entry = fs.get_from_absolute_path(path.into()).ok()?;
    if entry.is_dir() {
        return None;
    }

    load_elf_from_entry(&entry)
}

/// Load an ELF from a `vfat_rs::DirectoryEntry` into allocated memory.
fn load_elf_from_entry(entry: &vfat_rs::DirectoryEntry) -> Option<ModuleInfo> {
    let file_size = entry.metadata().size() as usize;
    if file_size == 0 {
        return None;
    }

    let mut file = entry.clone().into_file_unchecked();

    // Verify ELF magic
    let mut magic = [0u8; 4];
    let bytes_read = file.read(&mut magic).ok()?;
    if bytes_read < 4 || &magic != b"\x7fELF" {
        crate::serial_println!(
            "[fat32] {} is not an ELF file (bad magic)",
            entry.metadata().name()
        );
        return None;
    }

    // Allocate contiguous physical memory for the module
    let layout = core::alloc::Layout::from_size_align(file_size, 4096).ok()?;
    let ptr = unsafe { alloc::alloc::alloc(layout) };
    if ptr.is_null() {
        crate::serial_println!(
            "[fat32] Failed to allocate {} bytes for {}",
            file_size,
            entry.metadata().name()
        );
        return None;
    }

    // Rewind and read the entire file
    let _ = file.seek(vfat_rs::io::SeekFrom::Start(0));
    let buf = unsafe { core::slice::from_raw_parts_mut(ptr, file_size) };
    let mut total_read = 0usize;
    while total_read < file_size {
        match file.read(&mut buf[total_read..]) {
            Ok(0) => break,
            Ok(n) => total_read += n,
            Err(_) => {
                crate::serial_println!(
                    "[fat32] Failed to read {} from {}",
                    file_size,
                    entry.metadata().name()
                );
                unsafe {
                    alloc::alloc::dealloc(ptr, layout);
                }
                return None;
            }
        }
    }

    Some(ModuleInfo {
        base: ptr as u64,
        size: file_size as u64,
    })
}
