//! Kernel boot configuration application.
//!
//! Parses `kernel.toml` and applies settings to the appropriate subsystems.
//! Called once during early boot, after the buddy allocator is initialized
//! and before VGA init.

/// Apply all kernel.toml configuration to their respective subsystems.
///
/// Call this once after `buddy::init_buddy_allocator()` and before VGA init.
///
/// TODO: Phase 4 - Load kernel.toml from FAT32 boot partition
pub fn apply_kernel_config() {
    // With U-Boot, kernel.toml will be loaded from the FAT32 boot partition.
    // For now, use defaults.
    crate::serial_println!("[config] Using default configuration (FAT32 loader pending)");
}
