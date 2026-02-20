//! Graphical top command - inspired by htop
//!
//! Provides a real-time system monitoring interface using the VGA framebuffer.

use crate::shell_println;
use crate::shell::ShellError;
use alloc::{string::String, vec, vec::Vec, format};
use core::sync::atomic::Ordering;
use crate::arch::x86_64::vga::{self, RgbColor, UiTheme, UiRect, UiProgressBar, UiTable, UiDockLayout, DockEdge};

/// Top command main loop
pub fn cmd_top(_args: &[alloc::string::String]) -> Result<(), ShellError> {
    if !vga::is_available() {
        shell_println!("Error: 'top' requires a graphical framebuffer console.");
        return Ok(());
    }

    shell_println!("Starting graphical top (htop-style)... Press 'q' to exit.");
    
    // Switch to double buffering for flicker-free updates if possible
    let was_db = vga::double_buffer_mode();
    vga::set_double_buffer_mode(true);

    loop {
        // 1. Gather system data
        let ticks = crate::process::scheduler::ticks();
        let cpu_count = crate::arch::x86_64::percpu::cpu_count();
        let (total_pages, used_pages) = {
            let guard = crate::memory::buddy::get_allocator().lock();
            guard.as_ref().map(|a| a.page_totals()).unwrap_or((0, 0))
        };
        
        // 2. Clear screen and prepare layout
        let theme = UiTheme::SLATE;
        let canvas = vga::Canvas::new(theme.text, theme.background);
        canvas.begin_frame();
        canvas.ui_clear(theme);

        let mut layout = UiDockLayout::from_screen();
        let header_area = layout.dock(DockEdge::Top, vga::ui_scale_px(100));
        let footer_area = layout.dock(DockEdge::Bottom, vga::ui_scale_px(30));
        let body_area = layout.remaining();

        // 3. Draw Header: CPU and Memory status
        canvas.ui_panel(header_area.x, header_area.y, header_area.w, header_area.h, "System Health", "", theme);
        
        // Memory Bar (Left half of header)
        let mem_usage = if total_pages > 0 { (used_pages * 100) / total_pages } else { 0 };
        canvas.ui_label(&vga::UiLabel {
            rect: UiRect::new(header_area.x + vga::ui_scale_px(12), header_area.y + vga::ui_scale_px(35), vga::ui_scale_px(100), vga::ui_scale_px(20)),
            text: "Memory:",
            fg: theme.text, bg: theme.panel_bg, align: vga::TextAlign::Left
        });
        canvas.ui_progress_bar(UiProgressBar {
            rect: UiRect::new(header_area.x + vga::ui_scale_px(80), header_area.y + vga::ui_scale_px(38), vga::ui_scale_px(200), vga::ui_scale_px(14)),
            value: mem_usage as u8,
            fg: RgbColor::new(0x7E, 0xC1, 0xFF), bg: RgbColor::new(0x12, 0x16, 0x1E), border: theme.panel_border
        });

        // CPU Bars (Right half of header)
        for i in 0..cpu_count.min(4) {
            let row_y = header_area.y + vga::ui_scale_px(35 + i * 16);
            canvas.ui_label(&vga::UiLabel {
                rect: UiRect::new(header_area.x + vga::ui_scale_px(300), row_y, vga::ui_scale_px(60), vga::ui_scale_px(16)),
                text: &format!("CPU{}:", i),
                fg: theme.text, bg: theme.panel_bg, align: vga::TextAlign::Left
            });
            // Synthetic load for now (todo: per-cpu scheduler load)
            let cpu_load = if i == 0 { 15 + (ticks % 20) } else { 5 }; 
            canvas.ui_progress_bar(UiProgressBar {
                rect: UiRect::new(header_area.x + vga::ui_scale_px(360), row_y + vga::ui_scale_px(2), vga::ui_scale_px(150), vga::ui_scale_px(12)),
                value: cpu_load as u8,
                fg: RgbColor::new(0x58, 0xD6, 0xA3), bg: RgbColor::new(0x12, 0x16, 0x1E), border: theme.panel_border
            });
        }

        // 4. Draw Task List (Body)
        let mut table = UiTable {
            rect: body_area,
            headers: vec![String::from("PID"), String::from("Name"), String::from("State"), String::from("Prio"), String::from("Ticks")],
            rows: Vec::new(),
            theme,
        };

        if let Some(tasks) = crate::process::get_all_tasks() {
            for task in tasks {
                let state = unsafe { *task.state.get() };
                let state_str = match state {
                    crate::process::TaskState::Ready => "Ready",
                    crate::process::TaskState::Running => "Running",
                    crate::process::TaskState::Blocked => "Blocked",
                    crate::process::TaskState::Dead => "Dead",
                };
                let task_ticks = task.ticks.load(Ordering::Relaxed);

                table.rows.push(vec![
                    format!("{}", task.id.as_u64()),
                    String::from(task.name),
                    String::from(state_str),
                    format!("{:?}", task.priority),
                    format!("{}", task_ticks),
                ]);
            }
        }
        canvas.ui_table(&table);

        // 5. Draw Footer
        canvas.ui_label(&vga::UiLabel {
            rect: footer_area,
            text: " [q] Exit   [s] Sort   [k] Kill   Strat9-OS Microkernel ",
            fg: theme.status_text, bg: theme.status_bg, align: vga::TextAlign::Left
        });

        canvas.end_frame();

        // 6. Check for exit
        if let Some(ch) = crate::arch::x86_64::keyboard::read_char() {
            if ch == b'q' {
                break;
            }
        }

        // 7. Wait and Yield
        crate::process::yield_task();
    }

    vga::set_double_buffer_mode(was_db);
    // Restore shell prompt after exit
    crate::shell::output::clear_screen();
    Ok(())
}
