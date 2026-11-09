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

//! Storage drivers namespace.

pub mod ahci;
#[cfg(target_arch = "x86_64")]
pub mod ata_legacy;
pub mod nvme;
pub mod virtio_block;

/// Performs the init operation.
pub fn init() {
    ahci::init();
    nvme::init();
    #[cfg(target_arch = "x86_64")]
    ata_legacy::init();
    virtio_block::init();
}
