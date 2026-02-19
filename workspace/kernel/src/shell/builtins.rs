//! Built-in shell commands
//!
//! Implements the core commands for the Chevron shell.

use super::{output::format_bytes, ShellError};
use alloc::{string::String, vec, vec::Vec};

// Import the shell output macros
use crate::shell_println;

/// Display help information
pub fn cmd_help(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("Strat9-OS shell (Chevron) - available commands:");
    shell_println!("");
    shell_println!("  help              - Display this help message");
    shell_println!("  version           - Display kernel version");
    shell_println!("  clear             - Clear the screen");
    shell_println!("  mem               - Display memory status");
    shell_println!("  mem zones         - Display detailed zone information");
    shell_println!("  ps                - List all tasks");
    shell_println!("  silo ls           - List all silos (to be implemented)");
    shell_println!("  scheme ls         - List mounted schemes");
    shell_println!("  cpuinfo           - Display CPU information");
    shell_println!("  reboot            - Reboot the system");
    shell_println!("  gfx help          - Show gfx command help");
    shell_println!("  gfx info          - Display framebuffer/console info");
    shell_println!("  gfx mode on|off   - Enable/disable double-buffer mode");
    shell_println!("  gfx ui <scale>    - Set UI scale: compact|normal|large");
    shell_println!("  gfx test          - Draw graphics validation screen");
    shell_println!("  gfx-demo          - Draw a graphics console UI demo");
    shell_println!("");
    Ok(())
}

/// Display kernel version
pub fn cmd_version(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("Strat9-OS v0.1.0 (Bedrock)");
    shell_println!("Build: x86_64-unknown-none");
    shell_println!("Features: SMP, APIC, VirtIO, IPC, Schemes");
    Ok(())
}

/// Clear the screen
pub fn cmd_clear(_args: &[String]) -> Result<(), ShellError> {
    super::output::clear_screen();
    Ok(())
}

/// Display memory status
pub fn cmd_mem(args: &[String]) -> Result<(), ShellError> {
    if args.len() > 0 && args[0] == "zones" {
        return cmd_mem_zones();
    }

    // Use page_totals() which doesn't allocate - avoids deadlock
    let (total_pages, allocated_pages) = {
        let allocator_guard = crate::memory::buddy::get_allocator().lock();
        if let Some(ref allocator) = *allocator_guard {
            allocator.page_totals()
        } else {
            shell_println!("  Memory allocator not initialized");
            return Ok(());
        }
    }; // Release lock before printing

    let total_bytes = total_pages * 4096;
    let used_bytes = allocated_pages * 4096;
    let free_bytes = total_bytes - used_bytes;

    let (total_val, total_unit) = format_bytes(total_bytes);
    let (used_val, used_unit) = format_bytes(used_bytes);
    let (free_val, free_unit) = format_bytes(free_bytes);

    shell_println!("Memory status:");
    shell_println!(
        "  Total:     {} {} ({} pages)",
        total_val,
        total_unit,
        total_pages
    );
    shell_println!(
        "  Used:      {} {} ({} pages)",
        used_val,
        used_unit,
        allocated_pages
    );
    shell_println!(
        "  Free:      {} {} ({} pages)",
        free_val,
        free_unit,
        total_pages - allocated_pages
    );
    shell_println!("");

    Ok(())
}

/// Display detailed memory zone information
fn cmd_mem_zones() -> Result<(), ShellError> {
    // Collect zone info while holding lock, then release before printing
    const MAX_ZONES: usize = 4;
    let mut zones_info = [(0u8, 0u64, 0usize, 0usize); MAX_ZONES]; // (type, base, pages, allocated)
    let mut zone_count = 0;

    {
        let allocator_guard = crate::memory::buddy::get_allocator().lock();
        if let Some(ref allocator) = *allocator_guard {
            zone_count = allocator.zone_snapshot(&mut zones_info);
        } else {
            shell_println!("  Memory allocator not initialized");
            return Ok(());
        }
    } // Release lock before printing

    shell_println!("Memory zones:");
    for i in 0..zone_count {
        let (zone_type, base, page_count, allocated) = zones_info[i];
        let total_bytes = page_count * 4096;
        let free_bytes = (page_count - allocated) * 4096;

        let (total_val, total_unit) = format_bytes(total_bytes);
        let (free_val, free_unit) = format_bytes(free_bytes);

        shell_println!("  Zone {:?}:", zone_type_from_u8(zone_type));
        shell_println!("    Base:      0x{:016x}", base);
        shell_println!(
            "    Total:     {} {} ({} pages)",
            total_val,
            total_unit,
            page_count
        );
        shell_println!(
            "    Free:      {} {} ({} pages)",
            free_val,
            free_unit,
            page_count - allocated
        );
        shell_println!("    Used:      {} pages", allocated);
        shell_println!("");
    }

    Ok(())
}

/// Convert u8 back to ZoneType (helper for cmd_mem_zones)
fn zone_type_from_u8(val: u8) -> crate::memory::zone::ZoneType {
    match val {
        0 => crate::memory::zone::ZoneType::DMA,
        1 => crate::memory::zone::ZoneType::Normal,
        2 => crate::memory::zone::ZoneType::HighMem,
        _ => crate::memory::zone::ZoneType::DMA,
    }
}

/// List all tasks
pub fn cmd_ps(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("PID    Name              State      Priority");
    shell_println!("────────────────────────────────────────────────");

    if let Some(tasks) = crate::process::get_all_tasks() {
        for task in tasks {
            let state = unsafe { *task.state.get() };
            let state_str = match state {
                crate::process::TaskState::Ready => "Ready",
                crate::process::TaskState::Running => "Running",
                crate::process::TaskState::Blocked => "Blocked",
                crate::process::TaskState::Dead => "Dead",
            };

            let priority_str = match task.priority {
                crate::process::TaskPriority::Idle => "Idle",
                crate::process::TaskPriority::Low => "Low",
                crate::process::TaskPriority::Normal => "Normal",
                crate::process::TaskPriority::High => "High",
                crate::process::TaskPriority::Realtime => "Realtime",
            };

            shell_println!(
                "{:<6} {:<17} {:<10} {}",
                task.id.as_u64(),
                task.name,
                state_str,
                priority_str
            );
        }
    } else {
        shell_println!("  No tasks available");
    }

    shell_println!("");
    Ok(())
}

/// List mounted schemes
pub fn cmd_scheme(args: &[String]) -> Result<(), ShellError> {
    if args.len() == 0 || args[0] != "ls" {
        shell_println!("Usage: scheme ls");
        return Ok(());
    }

    shell_println!("Mounted Schemes:");
    shell_println!("Path         Type");
    shell_println!("────────────────────────────────────");

    let schemes = crate::vfs::list_schemes();
    for scheme in schemes {
        shell_println!("  {:<12} {}", scheme, "Kernel");
    }

    shell_println!("");
    Ok(())
}

/// Display CPU information
pub fn cmd_cpuinfo(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("CPU information:");

    // Check if APIC is initialized
    if crate::arch::x86_64::apic::is_initialized() {
        let lapic_id = crate::arch::x86_64::apic::lapic_id();
        let cpu_count = crate::arch::x86_64::percpu::cpu_count();
        shell_println!("  Current LAPIC ID:  {}", lapic_id);
        shell_println!("  CPU count:         {}", cpu_count);
        shell_println!("  APIC:              Active");
    } else {
        shell_println!("  APIC:              Not initialized");
        shell_println!("  Mode:              Legacy PIC");
    }

    shell_println!("");
    Ok(())
}

/// Reboot the system
pub fn cmd_reboot(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("Rebooting system...");

    // Triple fault method (most reliable on x86_64)
    unsafe {
        // Disable interrupts
        crate::arch::x86_64::cli();

        // Try keyboard controller reset (0x64 port, command 0xFE)
        crate::arch::x86_64::io::outb(0x64, 0xFE);

        // If that fails, try ACPI reset (requires FADT parsing - not implemented yet)
        // For now, just halt
        loop {
            crate::arch::x86_64::hlt();
        }
    }
}

/// Graphics console commands
pub fn cmd_gfx(args: &[String]) -> Result<(), ShellError> {
    fn print_gfx_help() {
        shell_println!("Usage: gfx <subcommand>");
        shell_println!("  help                 Show this help");
        shell_println!("  info                 Show framebuffer/text console info");
        shell_println!("  mode on|off          Enable/disable double-buffer mode");
        shell_println!("  ui compact|normal|large");
        shell_println!("                       Set UI scaling preset");
        shell_println!("  test                 Draw graphics validation screen");
    }

    if args.is_empty() {
        print_gfx_help();
        return Ok(());
    }
    match args[0].as_str() {
        "help" => {
            print_gfx_help();
            Ok(())
        }
        "info" => {
            let info = crate::arch::x86_64::vga::framebuffer_info();
            if !info.available {
                shell_println!("Graphics console: unavailable");
                return Ok(());
            }

            shell_println!("Graphics console:");
            shell_println!(
                "  Framebuffer: {}x{} {}bpp pitch={}",
                info.width,
                info.height,
                info.bpp,
                info.pitch
            );
            shell_println!(
                "  RGB masks: R({}:{}) G({}:{}) B({}:{})",
                info.red_size,
                info.red_shift,
                info.green_size,
                info.green_shift,
                info.blue_size,
                info.blue_shift
            );
            shell_println!(
                "  Text grid: {}x{} (glyph={}x{})",
                info.text_cols,
                info.text_rows,
                info.glyph_w,
                info.glyph_h
            );
            shell_println!(
                "  Double buffer mode: {}",
                if info.double_buffer_mode { "on" } else { "off" }
            );
            shell_println!(
                "  Double buffer active: {}",
                if info.double_buffer_enabled { "yes" } else { "no" }
            );
            let scale = match info.ui_scale {
                crate::arch::x86_64::vga::UiScale::Compact => "compact",
                crate::arch::x86_64::vga::UiScale::Normal => "normal",
                crate::arch::x86_64::vga::UiScale::Large => "large",
            };
            shell_println!("  UI scale: {}", scale);
            Ok(())
        }
        "mode" => {
            if args.len() < 2 {
                print_gfx_help();
                return Ok(());
            }
            match args[1].as_str() {
                "on" => {
                    crate::arch::x86_64::vga::set_double_buffer_mode(true);
                    shell_println!("gfx: double-buffer mode enabled");
                }
                "off" => {
                    crate::arch::x86_64::vga::set_double_buffer_mode(false);
                    shell_println!("gfx: double-buffer mode disabled");
                }
                _ => print_gfx_help(),
            }
            Ok(())
        }
        "ui" => {
            if args.len() < 2 {
                print_gfx_help();
                return Ok(());
            }
            let scale = match args[1].as_str() {
                "compact" => crate::arch::x86_64::vga::UiScale::Compact,
                "normal" => crate::arch::x86_64::vga::UiScale::Normal,
                "large" => crate::arch::x86_64::vga::UiScale::Large,
                _ => {
                    print_gfx_help();
                    return Ok(());
                }
            };
            crate::arch::x86_64::vga::set_ui_scale(scale);
            shell_println!("gfx: ui scale updated");
            Ok(())
        }
        "test" => cmd_gfx_test(),
        _ => {
            print_gfx_help();
            Ok(())
        }
    }
}

fn cmd_gfx_test() -> Result<(), ShellError> {
    use crate::arch::x86_64::vga::{self, RgbColor, TextAlign, TextOptions, UiTheme};

    if !vga::is_available() {
        shell_println!("gfx-test: framebuffer console unavailable");
        return Ok(());
    }

    let (w, h) = vga::screen_size();
    let canvas = vga::Canvas::new(RgbColor::new(0xE2, 0xE8, 0xF0), RgbColor::new(0x12, 0x16, 0x1E));
    canvas.begin_frame();
    canvas.clear();

    for y in (0..h).step_by(40) {
        vga::draw_line(0, y as isize, w.saturating_sub(1) as isize, y as isize, RgbColor::new(0x22, 0x2E, 0x3A));
    }
    for x in (0..w).step_by(40) {
        vga::draw_line(x as isize, 0, x as isize, h.saturating_sub(1) as isize, RgbColor::new(0x22, 0x2E, 0x3A));
    }

    let bw = w.saturating_sub(120).min(560);
    let bh = h.saturating_sub(220).min(240);
    let bx = 60;
    let by = 80;
    vga::fill_rect(bx, by, bw, bh, RgbColor::new(0x1A, 0x22, 0x2C));
    vga::draw_rect(bx, by, bw, bh, RgbColor::new(0x4F, 0xB3, 0xB3));
    vga::fill_rect_alpha(
        bx + 24,
        by + 24,
        bw.saturating_sub(48),
        bh.saturating_sub(48),
        RgbColor::new(0x7E, 0xC1, 0xFF),
        96,
    );
    vga::set_clip_rect(bx + 12, by + 12, bw.saturating_sub(24), bh.saturating_sub(24));
    vga::fill_rect(bx, by, bw, bh, RgbColor::new(0x1B, 0x4D, 0x8A));
    vga::reset_clip_rect();

    vga::draw_text(
        bx + 18,
        by + 16,
        "GFX TEST: alpha / clip / text",
        TextOptions {
            fg: RgbColor::new(0xF5, 0xFA, 0xFF),
            bg: RgbColor::new(0x1A, 0x22, 0x2C),
            align: TextAlign::Left,
            wrap: false,
            max_width: Some(bw.saturating_sub(36)),
        },
    );
    vga::draw_text(
        bx + 18,
        by + bh.saturating_sub(32),
        "Unicode fallback: ---- || ++++",
        TextOptions {
            fg: RgbColor::new(0xD0, 0xE4, 0xFF),
            bg: RgbColor::new(0x1A, 0x22, 0x2C),
            align: TextAlign::Left,
            wrap: false,
            max_width: Some(bw.saturating_sub(36)),
        },
    );

    canvas.system_status_line(UiTheme::OCEAN_STATUS);
    canvas.end_frame();
    vga::set_text_cursor(0, vga::text_rows().saturating_sub(2));
    shell_println!("gfx-test: rendered");
    Ok(())
}

/// Silo management commands
pub fn cmd_silo(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: silo <ls|info|create|kill> [args]");
        return Ok(());
    }

    match args[0].as_str() {
        "ls" => cmd_silo_ls(&args[1..]),
        "info" => {
            if args.len() < 2 {
                shell_println!("Usage: silo info <id>");
                Ok(())
            } else {
                cmd_silo_info(&args[1..])
            }
        }
        _ => {
            shell_println!("Unknown silo subcommand: {}", args[0]);
            shell_println!("Available: ls, info");
            Ok(())
        }
    }
}

/// Draw a UI demo using the graphics console widgets/layout.
pub fn cmd_gfx_demo(_args: &[String]) -> Result<(), ShellError> {
    use crate::arch::x86_64::vga::{
        self, DockEdge, RgbColor, TerminalWidget, TextAlign, UiDockLayout, UiLabel, UiPanel,
        UiProgressBar, UiRect, UiTable, UiTheme,
    };

    if !vga::is_available() {
        shell_println!("gfx-demo: framebuffer console unavailable");
        return Ok(());
    }

    let mut layout = UiDockLayout::from_screen();
    let top = layout.dock(DockEdge::Top, vga::ui_scale_px(56));
    let bottom = layout.dock(DockEdge::Bottom, vga::ui_scale_px(120));
    let left = layout.dock(DockEdge::Left, vga::ui_scale_px(360));
    let center = layout.remaining();

    let theme = UiTheme::SLATE;
    let canvas = vga::Canvas::new(theme.text, theme.background);
    canvas.begin_frame();
    canvas.ui_clear(theme);

    vga::ui_draw_panel_widget(&UiPanel {
        rect: top,
        title: "Strat9 Graphics Console",
        body: "Dock layout + widgets + terminal demo",
        theme,
    });

    canvas.ui_label(&UiLabel {
        rect: UiRect::new(
            top.x + vga::ui_scale_px(8),
            top.y + vga::ui_scale_px(30),
            top.w.saturating_sub(vga::ui_scale_px(16)),
            vga::ui_scale_px(24),
        ),
        text: "layout: top + bottom + left + center",
        fg: RgbColor::new(0xD0, 0xE4, 0xFF),
        bg: theme.panel_bg,
        align: TextAlign::Left,
    });

    canvas.ui_panel(
        left.x,
        left.y,
        left.w,
        left.h,
        "System",
        "Progress bars and data table",
        theme,
    );

    canvas.ui_progress_bar(UiProgressBar {
        rect: UiRect::new(
            left.x + vga::ui_scale_px(12),
            left.y + vga::ui_scale_px(46),
            left.w.saturating_sub(vga::ui_scale_px(24)),
            vga::ui_scale_px(16),
        ),
        value: 72,
        fg: RgbColor::new(0x58, 0xD6, 0xA3),
        bg: RgbColor::new(0x12, 0x16, 0x1E),
        border: theme.panel_border,
    });
    canvas.ui_progress_bar(UiProgressBar {
        rect: UiRect::new(
            left.x + vga::ui_scale_px(12),
            left.y + vga::ui_scale_px(68),
            left.w.saturating_sub(vga::ui_scale_px(24)),
            vga::ui_scale_px(16),
        ),
        value: 43,
        fg: RgbColor::new(0x7E, 0xC1, 0xFF),
        bg: RgbColor::new(0x12, 0x16, 0x1E),
        border: theme.panel_border,
    });

    let headers = vec![
        String::from("Metric"),
        String::from("Value"),
        String::from("Status"),
    ];
    let rows: Vec<Vec<String>> = vec![
        vec![String::from("CPU"), String::from("72%"), String::from("ok")],
        vec![String::from("Memory"), String::from("43%"), String::from("ok")],
        vec![String::from("Disk"), String::from("12%"), String::from("ok")],
    ];
    canvas.ui_table(&UiTable {
        rect: UiRect::new(
            left.x + vga::ui_scale_px(12),
            left.y + vga::ui_scale_px(96),
            left.w.saturating_sub(vga::ui_scale_px(24)),
            left.h.saturating_sub(vga::ui_scale_px(108)),
        ),
        headers,
        rows,
        theme,
    });

    let mut term = TerminalWidget::new(bottom, 64);
    term.title = String::from("Kernel Terminal");
    term.push_ansi_line("\u{1b}[36m[boot]\u{1b}[0m ui widgets initialized");
    term.push_ansi_line("\u{1b}[32m[ok]\u{1b}[0m renderer online");
    term.push_ansi_line("\u{1b}[33m[warn]\u{1b}[0m demo values are synthetic");
    term.push_line("type 'help' to list shell commands");
    term.draw();

    canvas.ui_panel(
        center.x,
        center.y,
        center.w,
        center.h,
        "Workspace",
        "Use this area for future dashboards, logs, and widgets.",
        theme,
    );

    canvas.system_status_line(UiTheme::OCEAN_STATUS);
    canvas.end_frame();
    // Keep shell prompt in lower text area so it does not overwrite top-left widgets.
    let row = vga::text_rows().saturating_sub(2);
    vga::set_text_cursor(0, row);
    Ok(())
}

/// List all silos
/// TODO: implement actual silo management and replace this stub with real functionality
fn cmd_silo_ls(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("Silo management not yet fully implemented.");
    shell_println!("Coming in v2: silo ls, silo info, silo create, silo kill");
    Ok(())
}

/// Display silo information
/// TODO: implement actual silo management and replace this stub with real functionality
fn cmd_silo_info(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("Silo info not yet implemented.");
    Ok(())
}
