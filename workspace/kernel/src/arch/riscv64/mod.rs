//! RISC-V (riscv64) backend for Strat9-OS
//!
//! Minimal bring-up backend targeting QEMU `virt` (riscv64), booted by
//! OpenSBI in S-mode at 0x80200000 with a0 = hartid, a1 = DTB pointer.
//!
//! Implements the same API surface as `arch::x86_64` for the subset used
//! during early boot (jalon R1 of the port plan). Modules are added
//! incrementally as call-sites are migrated.

pub mod serial;

// ---------------------------------------------------------------------------
// Transitional stubs (x86-only subsystems). Each is scheduled to become a
// per-arch gated module or a real driver in later jalons (R4-R6).
// ---------------------------------------------------------------------------

pub mod vga {
    pub use super::vga_shim::VGA_WRITER;
    pub use super::vga_text::{TextAlign, TextOptions, UiTheme};
    pub fn is_available() -> bool { false }
    #[allow(non_snake_case)]
    pub struct RgbColor;
    impl RgbColor {
        pub fn new(_r: u8, _g: u8, _b: u8) -> Self { RgbColor }
    }
    pub fn flush_display() {}
    pub enum UiScale {
        Compact,
        Normal,
        Large,
    }
    impl UiScale {
        pub fn as_str(self) -> &'static str {
            "normal"
        }
        pub fn next(self) -> Self {
            self
        }
    }
    pub fn ui_scale_px(_scale: UiScale) -> u32 {
        8
    }
    pub fn width() -> usize {
        0
    }
    pub fn height() -> usize {
        0
    }
    pub fn screen_size() -> (usize, usize) {
        (0, 0)
    }
    pub fn begin_frame() {}
    pub fn end_frame() {}
    pub fn fill_rect(_x: i32, _y: i32, _w: i32, _h: i32, _color: u32) {}
    pub fn text_rows() -> usize {
        0
    }
    pub fn text_cols() -> usize {
        0
    }
    pub fn set_double_buffer_mode(_b: bool) {}
    pub fn set_text_cursor(_col: usize, _row: usize) {}
    pub fn draw_text_cursor(_color: super::vga::RgbColor) {}
    pub fn hide_text_cursor() {}
    pub fn write_text(_s: &str) {}
    pub fn write_char(_c: char) {}
    pub fn scroll_view_up() {}
    pub fn scroll_view_down() {}
    pub fn scroll_to_live() {}
    pub fn start_selection(_x: usize, _y: usize) {}
    pub fn update_selection(_x: usize, _y: usize) {}
    pub fn end_selection() {}
    pub fn clear_selection() {}
    pub fn scrollbar_hit_test(_x: usize, _y: usize) -> bool {
        false
    }
    pub fn scrollbar_drag_to(_x: usize, _y: usize) {}
    pub fn scrollbar_click(_x: usize, _y: usize) {}
    pub fn update_mouse_cursor(_x: usize, _y: usize) {}
    pub fn panic_draw_direct(_msg: &str) {}
    pub fn vga_debug_writeln(_s: &str) {}

}


pub mod vga_shim {
    // Minimal writer that discards output: on riscv64 the console is serial-only.
    pub struct VgaWriterShim;
    impl core::fmt::Write for VgaWriterShim {
        fn write_str(&mut self, _s: &str) -> core::fmt::Result {
            Ok(())
        }
    }
    impl VgaWriterShim {
        pub fn clear(&mut self) {}
    }
    pub static VGA_WRITER: spin::Mutex<VgaWriterShim> = spin::Mutex::new(VgaWriterShim);
}

pub mod vgabuf {
    pub const VGABUF_LINE_LEN: usize = 256;
    pub fn vgabuf_write(_data: &[u8]) {}
    pub fn vgabuf_flush_to_framebuffer() {}
    pub fn vgabuf_flush_all() {}
}

pub mod boot_timestamp {
    static mut TSC_KHZ: u64 = 10_000; // QEMU virt timebase ~10 MHz
    pub fn init() {}
    pub fn tsc_khz() -> u64 { unsafe { core::ptr::addr_of!(TSC_KHZ).read() } }
    pub fn elapsed_ms() -> u64 { super::rdtsc() / 10_000 }
    pub fn elapsed_us() -> u64 { super::rdtsc() / 10 }
}

pub mod idt {
    // Trap handling arrives with jalon R2.1 (stvec).
    pub fn init() {}
    pub fn register_ahci_irq(_irq: u8) {}
    pub fn register_nvme_irq(_irq: u8) {}
    pub fn register_virtio_block_irq(_irq: u8) {}
    pub fn register_xhci_irq(_irq: u8) {}
    pub fn register_nic_irq(_irq: u8) {}
}

pub mod timer {
    pub const TIMER_HZ: u64 = 100;
    pub const NS_PER_TICK: u64 = 1_000_000_000 / TIMER_HZ;
    pub fn is_apic_timer_active() -> bool { false }
    pub fn apic_ticks_per_10ms() -> u32 { 0 }
    pub fn start_apic_timer_cached() {}
}


use core::arch::asm;

/// Halt the CPU until the next interrupt (wfi = wait for interrupt).
#[inline]
pub fn hlt() {
    unsafe { asm!("wfi", options(nomem, nostack)) }
}

/// Disable interrupts (clear SIE in sstatus).
#[inline]
pub fn cli() {
    unsafe {
        asm!(
            "csrci sstatus, 0x2",
            options(nomem, nostack)
        )
    }
}

/// Enable interrupts (set SIE in sstatus).
#[inline]
pub fn sti() {
    unsafe {
        asm!(
            "csrsi sstatus, 0x2",
            options(nomem, nostack)
        )
    }
}

/// Check if interrupts (SIE) are enabled.
#[inline]
pub fn interrupts_enabled() -> bool {
    let v: usize;
    unsafe {
        asm!(
            "csrr {}, sstatus",
            out(reg) v,
            options(nomem, nostack)
        );
    }
    (v >> 1) & 1 == 1
}

/// Save interrupt state and disable interrupts.
///
/// Returns the raw sstatus value; restore with [`restore_flags`].
#[inline]
pub fn save_flags_and_cli() -> u64 {
    let v: u64;
    unsafe {
        asm!(
            "csrrc {0}, sstatus, {1}",
            out(reg) v,
            in(reg) 0x2usize,
            options(nomem, nostack)
        );
    }
    v
}

/// Restore interrupt state from a previous [`save_flags_and_cli`].
#[inline]
pub fn restore_flags(flags: u64) {
    unsafe {
        asm!(
            "csrw sstatus, {0}",
            in(reg) flags,
            options(nomem, nostack)
        );
    }
}

/// Read the `time` CSR (rdtime equivalent) — cycle counter.
/// On QEMU virt this increments at a fixed frequency (~10 MHz via CLINT),
/// usable as an early monotonic timestamp source.
#[inline]
pub fn rdtsc() -> u64 {
    let v: u64;
    unsafe {
        asm!(
            "rdtime {0}",
            out(reg) v,
            options(nomem, nostack)
        );
    }
    v
}

/// No-op stubs for x86-only primitives kept temporarily at the facade
/// surface. These disappear as their call-sites are gated per-arch.

#[inline]
pub fn stac() {}
#[inline]
pub fn clac() {}

pub mod cpuid {
    /// Placeholder ISA-feature probe. Real implementation reads the
    /// `riscv,isa` device-tree property (jalon R1.4).
    #[derive(Default)]
    pub struct IsaFeatures;

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct CpuFeature;
    impl CpuFeature {
        pub const SMEP: CpuFeature = CpuFeature;
        pub const SMAP: CpuFeature = CpuFeature;
    }

    #[derive(Clone, Copy, Default)]
    pub struct CpuFeatures {
        bits: u32,
    }
    impl CpuFeatures {
        pub fn contains(self, _f: CpuFeature) -> bool {
            false
        }
    }

    pub fn init() {}

    pub fn host() -> IsaFeatures {
        IsaFeatures
    }
    pub fn host_uses_xsave() -> bool {
        false
    }
    pub fn host_default_xcr0() -> u64 {
        0
    }
    pub fn host_default_xcr0_fast() -> u64 {
        0
    }
    pub fn xsave_size_for_xcr0(_xcr0: u64) -> usize {
        512
    }
    pub fn xcr0_for_features(_f: &CpuFeatures) -> u64 {
        0
    }
    pub fn features_to_flags_string(_f: &IsaFeatures) -> alloc::string::String {
        alloc::string::String::new()
    }

}

pub mod speaker {
    /// PC speaker has no RISC-V equivalent: no-op.
    pub fn beep_phase(_n: u8) {}
    pub fn beep_startup() {}
    pub fn beep_panic() {}
}

pub mod cpuid_x86_shim {
    // Feature flags referenced by task.rs; all false on RISC-V.
    #[derive(Clone, Copy)]
    pub struct CpuFeatures;
    impl CpuFeatures {
        pub const SMEP: CpuFeatures = CpuFeatures;
        pub const SMAP: CpuFeatures = CpuFeatures;
    }
}

/// x86-only CPU extensions init — no-op on RISC-V.
pub fn init_cpu_extensions() {}

// VGA text options (serial-only console: no-ops)
pub mod vga_text {
    pub enum TextAlign {
        Left,
        Center,
        Right,
    }
    pub struct TextOptions;
    impl TextOptions {
        pub fn new() -> Self {
            TextOptions
        }
    }
    pub struct UiTheme;
}
