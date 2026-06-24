use alloc::string::String;
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

/// Returns true if a kernel panic is currently in progress.
pub fn panic_in_progress() -> bool {
    PANIC_IN_PROGRESS.load(Ordering::SeqCst)
}

/// Register a function to be called during a panic (serial-only hooks).
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

/// Run all registered panic hooks (serial output only : no framebuffer access).
fn run_panic_hooks(info: &PanicInfo) {
    if let Some(hooks) = PANIC_HOOKS.try_lock() {
        for hook in hooks.iter().flatten() {
            hook(info);
        }
    }
}

/// Dump CPU/scheduler context to serial.
fn panic_hook_dump_context(_info: &PanicInfo) {
    let cpu = crate::arch::x86_64::percpu::current_cpu_index();
    let ticks = crate::process::scheduler::ticks();
    let cr3 = crate::memory::paging::active_page_table().as_u64();
    crate::serial_println!("panic-hook: cpu={} ticks={} cr3=0x{:x}", cpu, ticks, cr3);
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
}

// -----------------------------------------------------------------------
// Register / stack helpers
// -----------------------------------------------------------------------

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

/// Read CR0, CR2, CR3, CR4 into the provided mutable references.
fn read_cr_regs() -> (u64, u64, u64, u64) {
    let cr0: u64;
    let cr2: u64;
    let cr3: u64;
    let cr4: u64;
    unsafe {
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    (cr0, cr2, cr3, cr4)
}

/// Dump backtrace via frame-pointer unwinding, returning the lines.
fn collect_backtrace() -> alloc::vec::Vec<alloc::string::String> {
    use alloc::format;
    let mut lines = alloc::vec::Vec::new();
    let mut rbp = read_rbp();
    let rsp = read_rsp();
    lines.push(format!("RSP=0x{:016X} RBP=0x{:016X}", rsp, rbp));
    lines.push("Backtrace (frame-pointer):".into());

    for i in 0..16 {
        if rbp == 0 || (rbp & 0x7) != 0 {
            lines.push(format!("  #{:02}: stop (invalid rbp)", i));
            break;
        }
        if !addr_readable(rbp) || !addr_readable(rbp.saturating_add(8)) {
            lines.push(format!("  #{:02}: stop (unmapped)", i));
            break;
        }

        let prev = unsafe { *(rbp as *const u64) };
        let ret = unsafe { *((rbp + 8) as *const u64) };
        lines.push(format!("  #{:02}: RIP=0x{:016X}", i, ret));

        if prev <= rbp || prev.saturating_sub(rbp) > 1024 * 1024 {
            break;
        }
        rbp = prev;
    }
    lines
}

/// Collect comprehensive debug info lines for the panic screen.
fn collect_panic_lines(info: &PanicInfo) -> alloc::vec::Vec<alloc::string::String> {
    use alloc::format;
    let mut lines = alloc::vec::Vec::new();

    // --- Title ---
    lines.push("=== GURU MEDITATION :: KERNEL PANIC ===".into());
    lines.push(String::new());

    // --- Panic location ---
    if let Some(loc) = info.location() {
        lines.push(format!(
            "File: {}:{}:{}",
            loc.file(),
            loc.line(),
            loc.column()
        ));
    } else {
        lines.push("File: (unknown)".into());
    }
    lines.push(format!("Message: {}", info.message()));
    lines.push(String::new());

    // --- CPU state ---
    let cpu = crate::arch::x86_64::percpu::current_cpu_index();
    let (cr0, cr2, cr3, cr4) = read_cr_regs();
    let rsp = read_rsp();
    let rbp = read_rbp();

    lines.push(format!("CPU={}  CR0={:#X}  CR2={:#X}", cpu, cr0, cr2));
    lines.push(format!("CR3={:#X}  CR4={:#X}", cr3, cr4));
    lines.push(format!("RSP={:#018X}  RBP={:#018X}", rsp, rbp));
    lines.push(String::new());

    // --- Backtrace ---
    let bt = collect_backtrace();
    lines.extend(bt);
    lines.push(String::new());

    // --- Scheduler state (best-effort) ---
    let ticks = crate::process::scheduler::ticks();
    lines.push(format!("Ticks={}", ticks));
    if let Some(task) = crate::process::scheduler::current_task_clone_try() {
        lines.push(format!("Task: id={} name={}", task.id.as_u64(), task.name));
    } else {
        lines.push("Task: (scheduler locked / idle)".into());
    }

    let sched = crate::process::scheduler::state_snapshot();
    if cpu < sched.cpu_count {
        lines.push(format!(
            "Sched: tid={} rt={} fair={} idle={} blocked={} init={}",
            sched.current_task[cpu],
            sched.rq_rt[cpu],
            sched.rq_fair[cpu],
            sched.rq_idle[cpu],
            sched.blocked_tasks,
            sched.initialized,
        ));
    }
    lines.push(String::new());

    // --- Timestamp if available ---
    let ts = crate::arch::x86_64::boot_timestamp::elapsed_ms();
    lines.push(format!("Uptime: {} ms", ts));

    lines
}

/// Print all panic lines to the serial port (emergency mode already active).
fn panic_serial_dump(lines: &[alloc::string::String]) {
    crate::serial_println!("\n\x1b[31;1m!!! KERNEL PANIC !!!\x1b[0m");
    for line in lines {
        crate::serial_println!("{}", line);
    }
}

// -----------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------

/// Install the default panic hooks (serial context + backtrace dumps).
pub fn install_default_panic_hooks() {
    let _ = register_panic_hook(panic_hook_dump_context);
}

/// Main kernel panic handler.
///
/// Always emits full debug info to the serial port.  Tries to display it
/// on the framebuffer via the normal VGA_WRITER path.  If VGA_WRITER is
/// locked (e.g. the fault happened inside a write to the console), falls
/// back to a direct framebuffer draw that bypasses all locks.
///
/// After all output is delivered, halts the current CPU forever.
pub fn panic_handler(info: &PanicInfo) -> ! {
    // 1. Emergency serial mode : serial_println! bypasses all locks.
    crate::arch::x86_64::serial::enter_emergency_mode();

    // 2. Guard against recursive panics.
    if PANIC_IN_PROGRESS.swap(true, Ordering::SeqCst) {
        loop {
            crate::arch::x86_64::hlt();
        }
    }

    // 3. Disable interrupts so nothing disturbs the dump.
    crate::arch::x86_64::cli();

    // 3b. Panic beep : audible signal before we halt.
    crate::arch::x86_64::speaker::beep_panic();

    // 4. Collect all debug information into a line list.
    let lines = collect_panic_lines(info);

    // 5. Dump everything to serial first (always works).
    panic_serial_dump(&lines);

    // 6. Run custom panic hooks (serial-only).
    run_panic_hooks(info);

    // 7. Stop all other CPUs.
    crate::arch::x86_64::smp::broadcast_panic_halt();

    // 7b. Flush the VGA circular buffer so any buffered log lines appear.
    crate::arch::x86_64::vgabuf::vgabuf_flush_all();

    // 8. Display panic info on framebuffer : two paths with fallback.
    if crate::arch::x86_64::vga::is_available() {
        // Path A: try the normal VGA_WRITER terminal (needs the Mutex).
        let writer_locked = {
            if let Some(mut writer) = crate::arch::x86_64::vga::VGA_WRITER.try_lock() {
                use core::fmt::Write;
                writer.set_rgb_color(
                    crate::arch::x86_64::vga::RgbColor::new(0xFF, 0xE7, 0xA0),
                    crate::arch::x86_64::vga::RgbColor::new(0x3A, 0x1F, 0x00),
                );
                writer.clear();
                for line in &lines {
                    let _ = writeln!(writer, "{}", line);
                }
                true
            } else {
                false
            }
        };

        if !writer_locked {
            // Path B: VGA_WRITER is locked : draw directly to the
            // framebuffer using saved raw params.
            let str_lines: alloc::vec::Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
            crate::arch::x86_64::vga::panic_draw_direct(&str_lines);
        }
    }

    // 9. Halt forever.
    loop {
        crate::arch::x86_64::hlt();
    }
}
