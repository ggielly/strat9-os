//! Minimal AMDGPU driver for boot display.
//!
//! Provides basic framebuffer output on AMD GPUs (GCN/SDNA) for
//! real hardware bring-up. Supports only linear scanout (no 3D,
//! no acceleration, no display pipeline management).

pub mod regs;

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::arch::x86_64::pci;
use crate::memory::address_space::VmaFlags;

/// AMD display vendor ID (ATI/AMD display controllers).
pub const AMD_DISPLAY_VENDOR: u16 = 0x1002;

/// PCI class code for display controllers.
const CLASS_DISPLAY: u8 = 0x03;
const SUBCLASS_VGA: u8 = 0x00;
const SUBCLASS_3D: u8 = 0x02;

/// MMIO register accessor.
struct MmioReg {
    base: usize,
}

impl MmioReg {
    /// # Safety
    /// `base` must be a valid MMIO-mapped address of sufficient size.
    unsafe fn new(base: usize) -> Self {
        Self { base }
    }

    fn read32(&self, offset: u32) -> u32 {
        unsafe { core::ptr::read_volatile((self.base + offset as usize) as *const u32) }
    }

    fn write32(&self, offset: u32, val: u32) {
        unsafe { core::ptr::write_volatile((self.base + offset as usize) as *mut u32, val) }
    }
}

/// Detected AMD GPU state.
pub struct AmdGpu {
    mmio: MmioReg,
    vram_phys: u64,
    vram_size: u64,
    fb_phys: u64,
    fb_virt: usize,
    fb_pitch: u32,
    fb_width: u32,
    fb_height: u32,
    fb_bpp: u32,
    fb_size: usize,
    bar0: u64,
}

static GPU_INSTANCE: Mutex<Option<AmdGpu>> = Mutex::new(None);
static GPU_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// Returns true if an AMD GPU was detected and initialized.
pub fn is_available() -> bool {
    GPU_AVAILABLE.load(Ordering::Relaxed)
}

/// Get GPU singleton reference.
pub fn get_gpu() -> Option<spin::MutexGuard<'static, Option<AmdGpu>>> {
    if GPU_AVAILABLE.load(Ordering::Relaxed) {
        Some(GPU_INSTANCE.lock())
    } else {
        None
    }
}

/// Initialize AMDGPU by scanning PCI for AMD display devices.
pub fn init() {
    crate::serial_println!("[amdgpu] Probing PCI for AMD display devices...");

    // Probe for AMD display controller (vendor 0x1002, class 0x03)
    let devices = pci::probe_all(pci::ProbeCriteria {
        vendor_id: Some(AMD_DISPLAY_VENDOR),
        class_code: Some(CLASS_DISPLAY),
        ..pci::ProbeCriteria::any()
    });

    if devices.is_empty() {
        crate::serial_println!("[amdgpu] No AMD display device found");
        return;
    }

    let dev = &devices[0];
    crate::serial_println!(
        "[amdgpu] Found AMD GPU: {:04X}:{:04X} (class {:02X}:{:02X})",
        dev.vendor_id,
        dev.device_id,
        dev.class_code,
        dev.subclass
    );

    // Read BAR0 for MMIO register access
    let bar0 = dev.read_bar(0);
    if bar0 == 0 {
        crate::serial_println!("[amdgpu] BAR0 not available");
        return;
    }

    // Map MMIO registers via HHDM
    let hhdm = crate::memory::get_hhdm_offset();
    let mmio_base = (bar0 + hhdm) as usize;
    let mmio = unsafe { MmioReg::new(mmio_base) };

    // Read GPU identifiers
    let chip_id = mmio.read32(regs::mmio::CHIP_ID);
    let rb_backend_disable = mmio.read32(regs::mmio::GRBM_RB_BACKEND_DISABLE);
    crate::serial_println!(
        "[amdgpu] CHIP_ID={:#x} RB_BACKEND_DISABLE={:#x}",
        chip_id,
        rb_backend_disable
    );

    // Detect VRAM size from VRAM_BANK configuration
    let vram_size = detect_vram_size(&mmio, chip_id);
    crate::serial_println!("[amdgpu] VRAM size: {} MB", vram_size / (1024 * 1024));

    // Allocate a linear framebuffer in VRAM (or stolen memory)
    let fb_width = 1024;
    let fb_height = 768;
    let fb_bpp = 32;
    let fb_pitch = fb_width * (fb_bpp / 8);
    let fb_size = (fb_pitch * fb_height) as usize;

    // Allocate framebuffer pages from the kernel allocator
    let fb_pages = (fb_size + 4095) / 4096;
    let fb_phys = match crate::memory::allocate_pages(fb_pages, VmaFlags {
        readable: true,
        writable: true,
        executable: false,
        user_accessible: false,
    }) {
        Ok(p) => p,
        Err(e) => {
            crate::serial_println!("[amdgpu] Failed to allocate framebuffer: {:?}", e);
            return;
        }
    };

    let fb_virt = (fb_phys + hhdm) as usize;

    // Zero the framebuffer
    unsafe {
        core::ptr::write_bytes(fb_virt as *mut u8, 0, fb_size);
    }

    let gpu = AmdGpu {
        mmio,
        vram_phys: 0,
        vram_size,
        fb_phys: fb_phys as u64,
        fb_virt,
        fb_pitch,
        fb_width,
        fb_height,
        fb_bpp,
        fb_size,
        bar0,
    };

    // Initialize the GPU display pipeline
    gpu.init_display();

    crate::serial_println!(
        "[amdgpu] Framebuffer: {}x{} @ {}bpp, {} bytes pitch, phys={:#x}",
        fb_width,
        fb_height,
        fb_bpp,
        fb_pitch,
        fb_phys
    );

    *GPU_INSTANCE.lock() = Some(gpu);
    GPU_AVAILABLE.store(true, Ordering::Relaxed);
    crate::serial_println!("[amdgpu] Display initialized successfully");
}

impl AmdGpu {
    /// Initialize the display pipeline (CRTC, scanout, timing).
    fn init_display(&self) {
        // 1. Read current display controller state
        let crtc_ctrl = self.mmio.read32(regs::mmio::CRTC_CONTROL);
        crate::serial_println!("[amdgpu] CRTC_CONTROL={:#x}", crtc_ctrl);

        // 2. Disable CRTC for reconfiguration
        self.mmio.write32(regs::mmio::CRTC_CONTROL, 0);

        // 3. Wait for any pending scanout to complete
        crate::arch::x86_64::timer::busy_wait_us(1000);

        // 4. Set framebuffer base address
        let fb_addr_lo = (self.fb_phys & 0xFFFF_FFFF) as u32;
        let fb_addr_hi = ((self.fb_phys >> 32) & 0xFFFF_FFFF) as u32;
        self.mmio
            .write32(regs::mmio::CRTC_FB_BASE_LO, fb_addr_lo);
        self.mmio
            .write32(regs::mmio::CRTC_FB_BASE_HI, fb_addr_hi);

        // 5. Set framebuffer parameters
        self.mmio
            .write32(regs::mmio::CRTC_FB_PITCH, self.fb_pitch / 4);
        self.mmio
            .write32(regs::mmio::CRTC_FB_SIZE, self.fb_width | (self.fb_height << 16));

        // 6. Set display timing (basic 1024x768@60Hz)
        self.mmio.write32(
            regs::mmio::CRTC_H_TOTAL,
            (self.fb_width + 160 - 1) | ((self.fb_width + 160 - 1) << 16),
        );
        self.mmio.write32(
            regs::mmio::CRTC_V_TOTAL,
            (self.fb_height + 30 - 1) | ((self.fb_height + 30 - 1) << 16),
        );

        // 7. Set pixel format (32bpp BGRA)
        self.mmio.write32(
            regs::mmio::CRTC_FORMAT,
            0 // FORMAT_32BPP = 0
        );

        // 8. Set display dimensions
        self.mmio.write32(
            regs::mmio::CRTC_DIMENSIONS,
            self.fb_width | (self.fb_height << 16),
        );

        // 9. Enable CRTC
        self.mmio.write32(regs::mmio::CRTC_CONTROL, 1 << 0); // CRTC_EN

        // 10. Wait for display pipeline to settle
        crate::arch::x86_64::timer::busy_wait_us(5000);

        crate::serial_println!("[amdgpu] Display pipeline configured");
    }

    /// Present a dirty rectangle to the display.
    pub fn present_region(&self, x: u32, y: u32, w: u32, h: u32) {
        // For a linear framebuffer, no explicit flush is needed on most AMD GPUs
        // because the CRTC scans directly from the framebuffer memory.
        // On some ASICs (e.g., GCN 3.0+), we may need to kick the display controller.
        // For now, the linear FB is directly scanned out.
        let _ = (x, y, w, h);
    }

    /// Get framebuffer information.
    pub fn framebuffer_info(&self) -> (u32, u32, u32, u32) {
        (self.fb_phys as u32, self.fb_width, self.fb_height, self.fb_pitch)
    }
}

/// Detect VRAM size from GPU registers (simplified).
fn detect_vram_size(mmio: &MmioReg, chip_id: u32) -> u64 {
    // Common AMD GPU VRAM sizes based on chip family
    // This is a simplified detection; real implementation would read
    // VRAM_BANK registers and FB_SIZE configurations.
    match (chip_id >> 24) & 0xFF {
        // GCN 1.0 (Hawaii, Pitcairn, etc.)
        0x26 | 0x27 | 0x28 | 0x2A | 0x2C => 1024 * 1024 * 1024, // 1GB default
        // GCN 2.0 (Tonga, Antigua)
        0x32 | 0x33 | 0x34 | 0x35 => 2048 * 1024 * 1024, // 2GB default
        // GCN 3.0 (Fiji, Bermuda, Antigua)
        0x38 | 0x3B | 0x3D => 4096 * 1024 * 1024, // 4GB default
        // GCN 4.0 (Polaris)
        0x4A | 0x4C | 0x4D => 4096 * 1024 * 1024, // 4GB default
        // GCN 5.0 (Vega)
        0x50 | 0x51 | 0x52 | 0x53 | 0x54 | 0x56 => 8192 * 1024 * 1024, // 8GB default
        // RDNA 1.0 (Navi 10, Navi 12, Navi 14)
        0x66 | 0x67 | 0x68 | 0x69 | 0x6A | 0x6B | 0x6C => 8192 * 1024 * 1024,
        // RDNA 2.0 (Navi 21, Navi 22, Navi 23)
        0x73 | 0x74 | 0x76 | 0x77 | 0x78 | 0x79 | 0x7A => 16384 * 1024 * 1024,
        // RDNA 3.0 (Navi 31, Navi 32, Navi 33)
        0x88 | 0x89 | 0x8A | 0x8B | 0x8C | 0x8D => 16384 * 1024 * 1024,
        _ => {
            crate::serial_println!(
                "[amdgpu] Unknown chip ID family: {:#x}, defaulting to 4GB",
                (chip_id >> 24) & 0xFF
            );
            4096 * 1024 * 1024
        }
    }
}
