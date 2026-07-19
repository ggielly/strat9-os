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
