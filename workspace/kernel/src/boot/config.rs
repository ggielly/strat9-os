/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

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
    // kernel.toml will be loaded from the FAT32 boot partition.
    // For now, use defaults.
    crate::serial_println!("[config] Using default configuration (FAT32 loader pending)");
}
