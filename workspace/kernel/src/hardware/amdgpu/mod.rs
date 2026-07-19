//! Minimal AMDGPU driver for boot display.
//!
//! Provides basic framebuffer output on AMD GPUs (GCN/RDNA) for
//! real hardware bring-up. Supports only linear scanout (no 3D,
//! no acceleration, no display pipeline management).

pub mod regs;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::arch::x86_64::pci;
use crate::memory::{allocate_zeroed_frame, PhysFrame};

/// ATI/AMD display controller vendor ID.
pub const AMD_VENDOR: u16 = 0x1002;

/// PCI class code for display controllers.
const CLASS_DISPLAY: u8 = 0x03;

/// MMIO register accessor.
struct Mmio {
    base: usize,
}

impl Mmio {
    /// # Safety
    /// `base` must be a valid MMIO-mapped address.
    unsafe fn new(base: usize) -> Self {
        Self { base }
    }

    fn read32(&self, off: u32) -> u32 {
        unsafe { core::ptr::read_volatile((self.base + off as usize) as *const u32) }
    }

    fn write32(&self, off: u32, val: u32) {
        unsafe { core::ptr::write_volatile((self.base + off as usize) as *mut u32, val) }
    }
}

/// AMD GPU state.
pub struct AmdGpu {
    mmio: Mmio,
    fb_phys: u64,
    fb_virt: usize,
    fb_pitch: u32,
    fb_width: u32,
    fb_height: u32,
    fb_bpp: u32,
    fb_size: usize,
    _frames: Vec<PhysFrame>,
}

static GPU: Mutex<Option<AmdGpu>> = Mutex::new(None);
static AVAILABLE: AtomicBool = AtomicBool::new(false);

pub fn is_available() -> bool {
    AVAILABLE.load(Ordering::Relaxed)
}

pub fn get_gpu() -> Option<spin::MutexGuard<'static, Option<AmdGpu>>> {
    if AVAILABLE.load(Ordering::Relaxed) {
        Some(GPU.lock())
    } else {
        None
    }
}

/// Probe PCI for AMD display devices and initialize.
pub fn init() {
    crate::serial_println!("[amdgpu] Probing PCI for AMD display...");

    let devs = pci::probe_all(pci::ProbeCriteria {
        vendor_id: Some(AMD_VENDOR),
        class_code: Some(CLASS_DISPLAY),
        ..pci::ProbeCriteria::any()
    });

    if devs.is_empty() {
        crate::serial_println!("[amdgpu] No AMD display device found");
        return;
    }

    let dev = &devs[0];
    crate::serial_println!(
        "[amdgpu] Found: {:04X}:{:04X} (class {:02X}:{:02X})",
        dev.vendor_id, dev.device_id, dev.class_code, dev.subclass
    );

    let bar0 = match dev.read_bar_raw(0) {
        Some(addr) => addr,
        None => {
            crate::serial_println!("[amdgpu] BAR0 not available");
            return;
        }
    };

    let hhdm = crate::memory::hhdm_offset();
    let mmio = unsafe { Mmio::new((bar0 + hhdm) as usize) };

    let chip_id = mmio.read32(regs::CHIP_ID);
    crate::serial_println!("[amdgpu] CHIP_ID={:#x}", chip_id);

    let vram_mb = match (chip_id >> 24) & 0xFF {
        0x26..=0x2D => 1024,
        0x32..=0x3D => 2048,
        0x4A..=0x4D => 4096,
        0x50..=0x56 => 8192,
        0x66..=0x6C => 8192,
        0x73..=0x7A => 16384,
        0x88..=0x8D => 16384,
        _ => 4096,
    };
    crate::serial_println!("[amdgpu] VRAM: {} MB", vram_mb);

    // Allocate framebuffer
    let (w, h, bpp) = (1024u32, 768u32, 32u32);
    let pitch = w * (bpp / 8);
    let fb_size = (pitch * h) as usize;
    let fb_pages = (fb_size + 4095) / 4096;

    let mut frames = Vec::new();
    for _ in 0..fb_pages {
        match allocate_zeroed_frame() {
            Some(f) => frames.push(f),
            None => {
                crate::serial_println!("[amdgpu] FB alloc failed");
                return;
            }
        }
    }

    let fb_phys = frames[0].start_address.as_u64();
    let hhdm = crate::memory::hhdm_offset();
    let fb_virt = (fb_phys + hhdm) as usize;

    let gpu = AmdGpu {
        mmio,
        fb_phys: fb_phys as u64,
        fb_virt,
        fb_pitch: pitch,
        fb_width: w,
        fb_height: h,
        fb_bpp: bpp,
        fb_size,
        _frames: frames,
    };

    gpu.configure_crtc();

    *GPU.lock() = Some(gpu);
    AVAILABLE.store(true, Ordering::Relaxed);
    crate::serial_println!("[amdgpu] Display: {}x{} @ {}bpp", w, h, bpp);
}

impl AmdGpu {
    fn configure_crtc(&self) {
        self.mmio.write32(regs::CRTC_CONTROL, 0);
        // Brief delay for CRTC disable to take effect
        for _ in 0..10000 {
            core::hint::spin_loop();
        }

        self.mmio.write32(regs::CRTC_FB_BASE_LO, self.fb_phys as u32);
        self.mmio.write32(regs::CRTC_FB_BASE_HI, (self.fb_phys >> 32) as u32);
        self.mmio.write32(regs::CRTC_FB_PITCH, self.fb_pitch / 4);
        self.mmio.write32(regs::CRTC_FB_SIZE, self.fb_width | (self.fb_height << 16));
        self.mmio.write32(regs::CRTC_DIMENSIONS, self.fb_width | (self.fb_height << 16));
        self.mmio.write32(regs::CRTC_H_TOTAL, (self.fb_width + 160 - 1) | ((self.fb_width + 160 - 1) << 16));
        self.mmio.write32(regs::CRTC_V_TOTAL, (self.fb_height + 30 - 1) | ((self.fb_height + 30 - 1) << 16));
        self.mmio.write32(regs::CRTC_FORMAT, 0);
        self.mmio.write32(regs::CRTC_CONTROL, 1 << 0);
        // Brief delay for display pipeline to settle
        for _ in 0..50000 {
            core::hint::spin_loop();
        }

        crate::serial_println!("[amdgpu] CRTC configured");
    }

    pub fn present_region(&self, _x: u32, _y: u32, _w: u32, _h: u32) {}

    pub fn framebuffer_info(&self) -> (u32, u32, u32, u32) {
        (self.fb_phys as u32, self.fb_width, self.fb_height, self.fb_pitch)
    }
}
