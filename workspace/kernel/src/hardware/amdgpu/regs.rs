//! AMDGPU MMIO register offsets for GCN/SDNA display controller.
//!
//! These are the key registers for minimal framebuffer scanout.
//! Register layout varies by ASIC family but the display controller
//! registers are largely consistent across GCN generations.

pub mod mmio {
    // === GPU Identification ===
    /// Chip ID register (major/minor/revision in upper bits)
    pub const CHIP_ID: u32 = 0x0000;

    // === GRBM (Graphics Register Bus Manager) ===
    pub const GRBM_RB_BACKEND_DISABLE: u32 = 0x09E8;
    pub const GRBM_GPU_STATUS: u32 = 0x09C0;
    pub const GRBM_GFX_INDEX: u32 = 0x08C0;
    pub const GRBM_GFX_INDEX_SE: u32 = 0x08C8;

    // === DCE (Display and Compositing Engine) ===
    pub const DCE_VERSION: u32 = 0x0000;

    // === CRTC (CRT Controller) ===
    /// CRTC control register (enable/disable, stereo, etc.)
    pub const CRTC_CONTROL: u32 = 0x6000;
    /// Framebuffer base address (low 32 bits)
    pub const CRTC_FB_BASE_LO: u32 = 0x6008;
    /// Framebuffer base address (high 32 bits)
    pub const CRTC_FB_BASE_HI: u32 = 0x600C;
    /// Framebuffer pitch in pixels
    pub const CRTC_FB_PITCH: u32 = 0x6010;
    /// Framebuffer dimensions (width | height << 16)
    pub const CRTC_FB_SIZE: u32 = 0x6014;
    /// Display dimensions (width | height << 16)
    pub const CRTC_DIMENSIONS: u32 = 0x6018;
    /// Horizontal total (active + blanking)
    pub const CRTC_H_TOTAL: u32 = 0x6020;
    /// Vertical total (active + blanking)
    pub const CRTC_V_TOTAL: u32 = 0x6024;
    /// Pixel format configuration
    pub const CRTC_FORMAT: u32 = 0x6028;
    /// CRTC status (vsync, blanking)
    pub const CRTC_STATUS: u32 = 0x602C;

    // === LB (Liquid Crystal / Display Blend) ===
    pub const LB_FB_OVERFLOW: u32 = 0x1A00;
    pub const LB_BLACK_KEYER: u32 = 0x1A04;

    // === Mixer (Display Mixer) ===
    pub const MIXER_CONTROL: u32 = 0x4000;
    pub const MIXER_FB_BASE: u32 = 0x4008;
    pub const MIXER_FB_SIZE: u32 = 0x400C;

    // === HDMI/DP (Generic) ===
    pub const HDMI_CONTROL: u32 = 0x5000;
    pub const HDMI_STATUS: u32 = 0x5004;
    pub const DP_CONTROL: u32 = 0x5400;

    // === Interrupt Status ===
    pub const DC_IRQ_STATUS: u32 = 0x7000;
    pub const DC_IRQ_FORCE: u32 = 0x7004;

    // === MMIO Space Sizes ===
    /// Total MMIO BAR0 size (typically 16MB or 32MB)
    pub const BAR0_SIZE: u32 = 0x0100_0000;
}
