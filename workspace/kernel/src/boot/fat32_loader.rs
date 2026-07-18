//! FAT32 module loader for reading userspace ELFs from boot partition.
//!
//! Uses the `fatfs` crate (no_std compatible) to read files from FAT32.
//! This is a placeholder until the full FAT32 implementation is complete.

use super::block_device::BlockDevice;

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

/// Load all boot modules from the FAT32 boot partition.
///
/// TODO: Phase 4 - Implement full FAT32 loading
pub fn load_all_modules<B: BlockDevice>(_block_dev: &mut B) -> BootModules {
    crate::serial_println!("[fat32] Module loader not yet implemented");
    crate::serial_println!("[fat32] TODO: Use fatfs crate to read /modules/* from FAT32");
    BootModules::default()
}

/// Load a single module from FAT32.
///
/// # Arguments
/// * `block_dev` - Block device to read from
/// * `path` - Path to the module file on FAT32
///
/// # Returns
/// `Some(ModuleInfo)` if the module was loaded successfully, `None` otherwise.
pub fn load_module<B: BlockDevice>(_block_dev: &mut B, _path: &str) -> Option<ModuleInfo> {
    // TODO: Implement using fatfs crate
    crate::serial_println!("[fat32] load_module({}) - not yet implemented", _path);
    None
}
