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

pub fn panic_in_progress() -> bool {
    PANIC_IN_PROGRESS.load(Ordering::SeqCst)
}

/// Performs the register panic hook operation.
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

/// Performs the run panic hooks operation.
fn run_panic_hooks(info: &PanicInfo) {
    // In case of panic, we try to lock hooks but if it fails (deadlock during panic)
    // we might skip them or use a more aggressive approach.
    // For now, we try_lock to be safe.
    if let Some(hooks) = PANIC_HOOKS.try_lock() {
        for hook in hooks.iter().flatten() {
            hook(info);
        }
    }
}

/// Performs the panic hook dump context operation.
fn panic_hook_dump_context(_info: &PanicInfo) {
    let cpu = crate::arch::x86_64::percpu::current_cpu_index();
    let ticks = crate::process::scheduler::ticks();
    let cr3 = crate::memory::paging::active_page_table().as_u64();
    crate::serial_println!("panic-hook: cpu={} ticks={} cr3=0x{:x}", cpu, ticks, cr3);
    // Use try_lock variant to avoid deadlocking when the panic occurs while
    // the scheduler lock is already held (e.g. during a context switch).
    if let Some(task) = crate::process::scheduler::current_task_clone_try() {
        crate::serial_println!(
            "panic-hook: current_task id={} name={}",
            task.id.as_u64(),
            task.name
        );
    } else {
        crate::serial_println!("panic-hook: current_task none (scheduler locked or idle)");
    }
    let sched = crate::process::scheduler::state_snapshot();
    if cpu < sched.cpu_count {
        crate::serial_println!(
            "panic-hook: sched cpu={} current_tid={} need_resched={} rq(rt/fair/idle)={}/{}/{} blocked={} init={} phase={}",
            cpu,
            sched.current_task[cpu],
            sched.need_resched[cpu],
            sched.rq_rt[cpu],
            sched.rq_fair[cpu],
            sched.rq_idle[cpu],
            sched.blocked_tasks,
            sched.initialized,
            sched.boot_phase
        );
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

/// Reads rbp.
#[inline(always)]
fn read_rbp() -> u64 {
    let rbp: u64;
    unsafe {
        core::arch::asm!("mov {}, rbp", out(reg) rbp, options(nomem, nostack, preserves_flags));
    }
    rbp
}

/// Reads rsp.
#[inline(always)]
fn read_rsp() -> u64 {
    let rsp: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
    }
    rsp
}

/// Performs the addr readable operation.
fn addr_readable(addr: u64) -> bool {
    crate::memory::paging::translate(VirtAddr::new(addr)).is_some()
}

/// Performs the panic hook backtrace operation.
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

/// Performs the install default panic hooks operation.
pub fn install_default_panic_hooks() {
    let _ = register_panic_hook(panic_hook_dump_context);
    let _ = register_panic_hook(panic_hook_backtrace);
}

/// Panic handler for the kernel
pub fn panic_handler(info: &PanicInfo) -> ! {
    // 1. Enter emergency mode for serial output immediately.
    // This allows serial_println! to bypass locks.
    crate::arch::x86_64::serial::enter_emergency_mode();

    // 2. Prevent recursive panics.
    if PANIC_IN_PROGRESS.swap(true, Ordering::SeqCst) {
        loop {
            crate::arch::x86_64::hlt();
        }
    }

    // 3. Disable interrupts on the current CPU first.
    crate::arch::x86_64::cli();

    // 4. Print the panic location/message before halting sibling CPUs so that
    // NMI-based panic-stop traffic cannot obscure the root cause.
    crate::serial_println!("\n\x1b[31;1m!!! KERNEL PANIC !!!\x1b[0m");
    crate::serial_println!("=== GURU MEDIATiON :: KERNEL PANiK ===");
    if let Some(location) = info.location() {
        crate::serial_println!(
            "not kalm :: panik at {}:{}:{}",
            location.file(),
            location.line(),
            location.column()
        );
    }
    crate::serial_println!("Message: {}", info.message());
    crate::serial_println!("====================");

    // 5. Stop all other CPUs only after the root-cause lines are emitted.
    crate::arch::x86_64::smp::broadcast_panic_halt();

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
            let _ = writeln!(writer, "=== GURU MEDIATiON :: KERNEL PANiK ===");
            if let Some(location) = info.location() {
                let _ = writeln!(
                    writer,
                    "not kalm :: panik at {}:{}:{}",
                    location.file(),
                    location.line(),
                    location.column()
                );
            }
            let _ = writeln!(writer, "Message: {}", info.message());
        }
    }

    // Halt the CPU
    loop {
        crate::arch::x86_64::hlt();
    }
}
