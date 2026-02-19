use core::panic::PanicInfo;

/// Panic handler for the kernel
pub fn panic_handler(info: &PanicInfo) -> ! {
    // Disable interrupts to prevent further issues
    crate::arch::x86_64::cli();

    // Best-effort panic display on framebuffer console (no legacy 0xB8000 access).
    if crate::arch::x86_64::vga::is_available() {
        if let Some(mut writer) = crate::arch::x86_64::vga::VGA_WRITER.try_lock() {
            use core::fmt::Write;
            writer.set_rgb_color(
                crate::arch::x86_64::vga::RgbColor::new(0xFF, 0xE7, 0xA0),
                crate::arch::x86_64::vga::RgbColor::new(0x3A, 0x1F, 0x00),
            );
            writer.clear();
            let _ = writeln!(writer, "=== KERNEL PANIC ===");
            if let Some(location) = info.location() {
                let _ = writeln!(
                    writer,
                    "Panic at {}:{}:{}",
                    location.file(),
                    location.line(),
                    location.column()
                );
            }
            let _ = writeln!(writer, "Message: {}", info.message());
        }
    }

    // Serial log (always works)
    crate::serial_println!("=== KERNEL PANiK ===");
    if let Some(location) = info.location() {
        crate::serial_println!(
            "Panic at {}:{}:{}",
            location.file(),
            location.line(),
            location.column()
        );
    }
    crate::serial_println!("Message: {}", info.message());
    crate::serial_println!("====================");

    // Halt the CPU
    loop {
        crate::arch::x86_64::hlt();
    }
}
