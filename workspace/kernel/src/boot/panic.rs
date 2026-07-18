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
    match PANIC_HOOKS.try_lock() {
        Some(hooks) => {
            for hook in hooks.iter().flatten() {
                hook(info);
            }
        }
        None => {
            crate::serial_force_println!("[panic] WARNING: panic hooks skipped (lock held by panicking context)");
        }
    }
}

/// Dump CPU/scheduler context to serial.
fn panic_hook_dump_context(_info: &PanicInfo) {
    let cpu = crate::arch::x86_64::percpu::current_cpu_index();
    let ticks = crate::process::scheduler::ticks();
    let cr3 = crate::memory::paging::active_page_table().as_u64();
    crate::serial_force_println!("panic-hook: cpu={} ticks={} cr3=0x{:x}", cpu, ticks, cr3);
    if let Some(task) = crate::process::scheduler::current_task_clone_try() {
        crate::serial_force_println!(
            "panic-hook: current_task id={} name={}",
            task.id.as_u64(),
            task.name
        );
    } else {
        crate::serial_force_println!("panic-hook: current_task none (scheduler locked or idle)");
    }
    let sched = crate::process::scheduler::state_snapshot();
    if cpu < sched.cpu_count {
        crate::serial_force_println!(
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

/// Dump backtrace via frame-pointer unwinding, printing directly to serial.
fn dump_backtrace() {
    crate::serial_force_println!("RSP=0x{:016X} RBP=0x{:016X}", read_rsp(), read_rbp());
    crate::serial_force_println!("Backtrace (frame-pointer):");
    let mut rbp = read_rbp();
    for i in 0..16 {
        if rbp == 0 || (rbp & 0x7) != 0 {
            crate::serial_force_println!("  #{:02}: stop (invalid rbp)", i);
            break;
        }
        if !addr_readable(rbp) || !addr_readable(rbp.saturating_add(8)) {
            crate::serial_force_println!("  #{:02}: stop (unmapped)", i);
            break;
        }
        let prev = unsafe { *(rbp as *const u64) };
        let ret = unsafe { *((rbp + 8) as *const u64) };

        // Try symbol resolution
        if let Some((name, offset)) = super::symbols::lookup(ret) {
            if offset == 0 {
                crate::serial_force_println!("  #{:02}: RIP=0x{:016X}  {}", i, ret, name);
            } else {
                crate::serial_force_println!(
                    "  #{:02}: RIP=0x{:016X}  {}+0x{:x}",
                    i,
                    ret,
                    name,
                    offset
                );
            }
        } else {
            crate::serial_force_println!("  #{:02}: RIP=0x{:016X}", i, ret);
        }

        if prev <= rbp || prev.saturating_sub(rbp) > 1024 * 1024 {
            break;
        }
        rbp = prev;
    }
}

/// Collect comprehensive debug info and print directly to serial (heap-safe).
fn dump_panic_info(info: &PanicInfo) {
    crate::serial_force_println!("\n\x1b[31;1m!!! KERNEL PANIC !!!\x1b[0m");
    crate::serial_force_println!("=== GURU MEDiTATiON :: KERNEL PANiK ===");
    crate::serial_force_println!("");

    // Panic location
    if let Some(loc) = info.location() {
        crate::serial_force_println!("File: {}:{}:{}", loc.file(), loc.line(), loc.column());
    } else {
        crate::serial_force_println!("File: (unknown)");
    }
    crate::serial_force_println!("Message: {}", info.message());
    crate::serial_force_println!("");

    // CPU state
    let cpu = crate::arch::x86_64::percpu::current_cpu_index();
    let (cr0, cr2, cr3, cr4) = read_cr_regs();
    let rsp = read_rsp();
    let rbp = read_rbp();
    crate::serial_force_println!("CPU={}  CR0={:#X}  CR2={:#X}", cpu, cr0, cr2);
    crate::serial_force_println!("CR3={:#X}  CR4={:#X}", cr3, cr4);
    crate::serial_force_println!("RSP={:#018X}  RBP={:#018X}", rsp, rbp);
    crate::serial_force_println!("");

    // Backtrace
    dump_backtrace();
    crate::serial_force_println!("");

    // Scheduler state
    let ticks = crate::process::scheduler::ticks();
    crate::serial_force_println!("Ticks={}", ticks);
    if let Some(task) = crate::process::scheduler::current_task_clone_try() {
        crate::serial_force_println!("Task: id={} name={}", task.id.as_u64(), task.name);
    } else {
        crate::serial_force_println!("Task: (scheduler locked / idle)");
    }

    let sched = crate::process::scheduler::state_snapshot();
    if cpu < sched.cpu_count {
        crate::serial_force_println!(
            "Sched: tid={} rt={} fair={} idle={} blocked={} init={}",
            sched.current_task[cpu],
            sched.rq_rt[cpu],
            sched.rq_fair[cpu],
            sched.rq_idle[cpu],
            sched.blocked_tasks,
            sched.initialized,
        );
    }
    crate::serial_force_println!("");

    // Uptime
    let ts = crate::arch::x86_64::boot_timestamp::elapsed_ms();
    crate::serial_force_println!("Uptime: {} ms", ts);
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
        // SeqCst provides a full barrier; add explicit fence for clarity.
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // Double panic: dump as much as we can with stack-only formatting.
        crate::arch::x86_64::cli();
        crate::serial_force_println!("\n\x1b[31;1m!!! DOUBLE PANIC !!!\x1b[0m");
        if let Some(loc) = info.location() {
            crate::serial_force_println!("panic at {}:{}", loc.file(), loc.line());
        }
        crate::serial_force_println!("Message: {}", info.message());
        let cpu = crate::arch::x86_64::percpu::current_cpu_index();
        let (cr0, cr2, cr3, cr4) = read_cr_regs();
        crate::serial_force_println!(
            "CPU={}  CR0={:#X}  CR2={:#X}  CR3={:#X}  CR4={:#X}",
            cpu, cr0, cr2, cr3, cr4
        );
        crate::serial_force_println!("RSP={:#018X}  RBP={:#018X}", read_rsp(), read_rbp());
        dump_backtrace();
        loop {
            crate::arch::x86_64::hlt();
        }
    }

    // 3. Disable interrupts so nothing disturbs the dump.
    crate::arch::x86_64::cli();

    // 3b. Panic beep : audible signal before we halt.
    crate::arch::x86_64::speaker::beep_panic();

    // 4. Dump all debug information directly to serial (heap-free).
    dump_panic_info(info);

    // 5. Run custom panic hooks (serial-only).
    run_panic_hooks(info);

    // 6. Stop all other CPUs and wait for them to halt.
    crate::arch::x86_64::smp::broadcast_panic_halt();
    // Brief delay to let other CPUs observe the NMI/halt IPI before we
    // touch shared framebuffer memory.
    for _ in 0..100_000 {
        core::hint::spin_loop();
    }

    // 7. Flush the VGA circular buffer so any buffered log lines appear.
    crate::arch::x86_64::vgabuf::vgabuf_flush_all();

    // 8. Display panic info on framebuffer (best-effort, may use heap for String formatting).
    if crate::arch::x86_64::vga::is_available() {
        if let Some(mut writer) = crate::arch::x86_64::vga::VGA_WRITER.try_lock() {
            use core::fmt::Write;
            writer.set_rgb_color(
                crate::arch::x86_64::vga::RgbColor::new(0xFF, 0xE7, 0xA0),
                crate::arch::x86_64::vga::RgbColor::new(0x3A, 0x1F, 0x00),
            );
            writer.clear();
            let _ = writeln!(writer, "=== GURU MEDiTATiON :: KERNEL PANiK ===");
            if let Some(loc) = info.location() {
                let _ = writeln!(writer, "File: {}:{}:{}", loc.file(), loc.line(), loc.column());
            }
            let _ = writeln!(writer, "Message: {}", info.message());
            let _ = writeln!(writer, "");
            let _ = writeln!(writer, "See serial output for full backtrace.");
        } else {
            // VGA_WRITER locked : draw directly to the framebuffer.
            let title = "=== GURU MEDiTATiON :: KERNEL PANiK ===";
            let serial_hint = "See serial output for full backtrace.";
            let str_lines: [&str; 2] = [title, serial_hint];
            crate::arch::x86_64::vga::panic_draw_direct(&str_lines);
        }
    }

    // 9. Halt forever.
    loop {
        crate::arch::x86_64::hlt();
    }
}
