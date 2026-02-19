use core::{
    panic::PanicInfo,
    sync::atomic::{AtomicBool, Ordering},
};

use spin::Mutex;
use x86_64::VirtAddr;

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

#[inline(always)]
fn read_rbp() -> u64 {
    let rbp: u64;
    unsafe {
        core::arch::asm!("mov {}, rbp", out(reg) rbp, options(nomem, nostack, preserves_flags));
    }
    rbp
}

#[inline(always)]
fn read_rsp() -> u64 {
    let rsp: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
    }
    rsp
}

fn addr_readable(addr: u64) -> bool {
    crate::memory::paging::translate(VirtAddr::new(addr)).is_some()
}

fn panic_hook_backtrace(_info: &PanicInfo) {
    let mut rbp = read_rbp();
    let rsp = read_rsp();
    crate::serial_println!("panic-hook: stack rsp=0x{:x} rbp=0x{:x}", rsp, rbp);
    crate::serial_println!("panic-hook: backtrace (frame-pointer)");

    // [rbp + 0] = previous rbp, [rbp + 8] = return address
    for i in 0..16 {
        if rbp == 0 || (rbp & 0x7) != 0 {
            crate::serial_println!("  #{:02}: stop (invalid rbp=0x{:x})", i, rbp);
            break;
        }
        if !addr_readable(rbp) || !addr_readable(rbp.saturating_add(8)) {
            crate::serial_println!("  #{:02}: stop (unmapped rbp=0x{:x})", i, rbp);
            break;
        }

        let prev = unsafe { *(rbp as *const u64) };
        let ret = unsafe { *((rbp + 8) as *const u64) };
        crate::serial_println!("  #{:02}: rip=0x{:x} rbp=0x{:x}", i, ret, rbp);

        // Stop on corrupted/non-progressing chains.
        if prev <= rbp || prev.saturating_sub(rbp) > 1024 * 1024 {
            break;
        }
        rbp = prev;
    }
}

pub fn install_default_panic_hooks() {
    let _ = register_panic_hook(panic_hook_dump_context);
    let _ = register_panic_hook(panic_hook_backtrace);
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
