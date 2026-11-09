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

//! AMDGPU MMIO register offsets (GCN/RDNA display controller).

/// GPU identification
pub const CHIP_ID: u32 = 0x0000;

/// CRTC (CRT Controller)
pub const CRTC_CONTROL: u32 = 0x6000;
pub const CRTC_FB_BASE_LO: u32 = 0x6008;
pub const CRTC_FB_BASE_HI: u32 = 0x600C;
pub const CRTC_FB_PITCH: u32 = 0x6010;
pub const CRTC_FB_SIZE: u32 = 0x6014;
pub const CRTC_DIMENSIONS: u32 = 0x6018;
pub const CRTC_H_TOTAL: u32 = 0x6020;
pub const CRTC_V_TOTAL: u32 = 0x6024;
pub const CRTC_FORMAT: u32 = 0x6028;

/// GRBM (Graphics Register Bus Manager)
pub const GRBM_GPU_STATUS: u32 = 0x09C0;
pub const GRBM_RB_BACKEND_DISABLE: u32 = 0x09E8;
