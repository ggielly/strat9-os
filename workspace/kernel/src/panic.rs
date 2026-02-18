use core::panic::PanicInfo;

/// Panic handler for the kernel
pub fn panic_handler(info: &PanicInfo) -> ! {
    // Disable interrupts to prevent further issues
    crate::arch::x86_64::cli();

    // Try to display panic on VGA (only if VGA is available)
    if crate::arch::x86_64::vga::is_available() {
        unsafe {
            let vga_ptr = crate::memory::phys_to_virt(0xB8000) as *mut u16;
            // Fill screen with yellow background (0xE = yellow bg)
            for i in 0..(80 * 25) {
                vga_ptr.add(i).write_volatile(0xEE20); // Yellow bg, yellow fg, space
            }

            // Write "KERNEL PANIC" in first line (red on yellow)
            let msg = b"KERNEL PANIC";
            for (i, &ch) in msg.iter().enumerate() {
                vga_ptr.add(i).write_volatile(0xEC00 | ch as u16); // Yellow bg, red fg
            }

            // Write location if available (line 2)
            if let Some(location) = info.location() {
                let mut row = 2;
                let mut col = 0;

                // Write file:line
                let file_msg = location.file().as_bytes();
                for &ch in file_msg.iter().take(70) {
                    if col >= 80 {
                        row += 1;
                        col = 0;
                    }
                    if row >= 25 {
                        break;
                    }
                    vga_ptr.add(row * 80 + col).write_volatile(0xE0 | ch as u16);
                    col += 1;
                }

                // Write line number marker
                if col < 75 {
                    let msg = b" @ line ";
                    for &ch in msg.iter() {
                        if col >= 80 {
                            break;
                        }
                        vga_ptr.add(row * 80 + col).write_volatile(0xE0 | ch as u16);
                        col += 1;
                    }
                }
            }
        }
    }

    // Serial log (always works)
    crate::serial_println!("=== KERNEL PANIC ===");
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
