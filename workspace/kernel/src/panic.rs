use core::{
    panic::PanicInfo,
    sync::atomic::{AtomicBool, Ordering},
};

use spin::Mutex;

type PanicHook = fn(&PanicInfo);
const MAX_PANIC_HOOKS: usize = 8;

static PANIC_HOOKS: Mutex<[Option<PanicHook>; MAX_PANIC_HOOKS]> =
    Mutex::new([None; MAX_PANIC_HOOKS]);
static PANIC_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

pub fn register_panic_hook(hook: PanicHook) -> bool {
    let mut hooks = PANIC_HOOKS.lock();
    for slot in hooks.iter_mut() {
        if slot.is_none() {
            *slot = Some(hook);
            return true;
        }
    }
    false
}

fn run_panic_hooks(info: &PanicInfo) {
    let hooks = PANIC_HOOKS.lock();
    for hook in hooks.iter().flatten() {
        hook(info);
    }
}

fn panic_hook_dump_context(_info: &PanicInfo) {
    let ticks = crate::process::scheduler::ticks();
    let cr3 = crate::memory::paging::active_page_table().as_u64();
    crate::serial_println!("panic-hook: ticks={} cr3=0x{:x}", ticks, cr3);
    if let Some(task) = crate::process::current_task_clone() {
        crate::serial_println!(
            "panic-hook: current_task id={} name={}",
            task.id.as_u64(),
            task.name
        );
    } else {
        crate::serial_println!("panic-hook: current_task none");
    }
    let fb = crate::arch::x86_64::vga::framebuffer_info();
    crate::serial_println!(
        "panic-hook: fb={}x{} {}bpp pitch={} text={}x{}",
        fb.width,
        fb.height,
        fb.bpp,
        fb.pitch,
        fb.text_cols,
        fb.text_rows
    );
}

pub fn install_default_panic_hooks() {
    let _ = register_panic_hook(panic_hook_dump_context);
}

/// Panic handler for the kernel
pub fn panic_handler(info: &PanicInfo) -> ! {
    if PANIC_IN_PROGRESS.swap(true, Ordering::SeqCst) {
        loop {
            crate::arch::x86_64::hlt();
        }
    }

    // Disable interrupts to prevent further issues
    crate::arch::x86_64::cli();

    // Run custom panic hooks before trying complex rendering.
    run_panic_hooks(info);

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
