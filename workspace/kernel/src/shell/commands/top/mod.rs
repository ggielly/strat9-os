//! Graphical top command - inspired by htop
//!
//! Provides a real-time system monitoring interface using the VGA framebuffer.

use crate::{
    arch::x86_64::vga::{
        self, DockEdge, RgbColor, UiDockLayout, UiProgressBar, UiRect, UiTable, UiTheme,
    },
    shell::ShellError,
    shell_println,
};
use alloc::{format, string::String, vec, vec::Vec};
use core::sync::atomic::Ordering;

/// Top command main loop
pub fn cmd_top(_args: &[alloc::string::String]) -> Result<(), ShellError> {
    if !vga::is_available() {
        shell_println!("Error: 'top' requires a graphical framebuffer console.");
        return Ok(());
    }

    // Switch to double buffering for flicker-free updates
    let was_db = vga::double_buffer_mode();
    vga::set_double_buffer_mode(true);

    let theme = UiTheme::SLATE;
    let mut last_refresh_tick = 0;

    loop {
        let ticks = crate::process::scheduler::ticks();

        // Only refresh every 100ms (assuming 100Hz timer)
        if ticks.saturating_sub(last_refresh_tick) < 10 {
            // Still check for input to stay responsive
            if let Some(ch) = crate::arch::x86_64::keyboard::read_char() {
                if ch == b'q' {
                    break;
                }
            }
            crate::process::yield_task();
            continue;
        }
        last_refresh_tick = ticks;

        // 1. Gather system data
        let cpu_count = crate::arch::x86_64::percpu::cpu_count();
        let (total_pages, used_pages) = {
            let guard = crate::memory::buddy::get_allocator().lock();
            guard.as_ref().map(|a| a.page_totals()).unwrap_or((0, 0))
        };

        // 2. Prepare Canvas and Layout
        let canvas = vga::Canvas::new(theme.text, theme.background);
        canvas.begin_frame();
        // Force a full clear with background color to remove shell remnants
        canvas.ui_clear(theme);

        let mut layout = UiDockLayout::from_screen();
        // Give the header more height to avoid crowding (120px instead of 100px)
        let header_area = layout.dock(DockEdge::Top, vga::ui_scale_px(120));
        let footer_area = layout.dock(DockEdge::Bottom, vga::ui_scale_px(24));
        let body_area = layout.remaining();

        // 3. Draw Header: System Info
        canvas.ui_panel(
            header_area.x,
            header_area.y,
            header_area.w,
            header_area.h,
            " Strat9 System Monitor ",
            "",
            theme,
        );

        // --- Memory Bar ---
        let mem_usage = if total_pages > 0 {
            (used_pages * 100) / total_pages
        } else {
            0
        };
        let mem_label_x = header_area.x + vga::ui_scale_px(16);
        let mem_label_y = header_area.y + vga::ui_scale_px(40);

        canvas.ui_label(&vga::UiLabel {
            rect: UiRect::new(
                mem_label_x,
                mem_label_y,
                vga::ui_scale_px(80),
                vga::ui_scale_px(16),
            ),
            text: "Memory:",
            fg: theme.accent,
            bg: theme.panel_bg,
            align: vga::TextAlign::Left,
        });

        canvas.ui_progress_bar(UiProgressBar {
            rect: UiRect::new(
                mem_label_x + vga::ui_scale_px(70),
                mem_label_y + vga::ui_scale_px(2),
                vga::ui_scale_px(180),
                vga::ui_scale_px(12),
            ),
            value: mem_usage as u8,
            fg: RgbColor::new(0x7E, 0xC1, 0xFF),
            bg: RgbColor::new(0x12, 0x16, 0x1E),
            border: theme.panel_border,
        });

        // --- CPU Bars (Dynamic grid) ---
        let cpu_base_x = mem_label_x + vga::ui_scale_px(280);
        for i in 0..cpu_count.min(8) {
            let col = i / 4;
            let row = i % 4;
            let x_off = col * vga::ui_scale_px(180);
            let y_off = row * vga::ui_scale_px(18);

            let bar_x = cpu_base_x + x_off;
            let bar_y = header_area.y + vga::ui_scale_px(40) + y_off;

            canvas.ui_label(&vga::UiLabel {
                rect: UiRect::new(bar_x, bar_y, vga::ui_scale_px(45), vga::ui_scale_px(16)),
                text: &format!("CPU{}:", i),
                fg: theme.accent,
                bg: theme.panel_bg,
                align: vga::TextAlign::Left,
            });

            // Synthetic load for visualization until per-cpu metrics are available
            let i_u64 = i as u64;
            let cpu_load = if i == 0 {
                10 + (ticks % 30)
            } else {
                5 + (i_u64 * 3) % 15
            };
            canvas.ui_progress_bar(UiProgressBar {
                rect: UiRect::new(
                    bar_x + vga::ui_scale_px(45),
                    bar_y + vga::ui_scale_px(2),
                    vga::ui_scale_px(100),
                    vga::ui_scale_px(10),
                ),
                value: cpu_load as u8,
                fg: RgbColor::new(0x58, 0xD6, 0xA3),
                bg: RgbColor::new(0x12, 0x16, 0x1E),
                border: theme.panel_border,
            });
        }

        // 4. Draw Task List (Body)
        let mut table = UiTable {
            rect: body_area,
            headers: vec![
                String::from("PID"),
                String::from("Name"),
                String::from("State"),
                String::from("Prio"),
                String::from("Ticks"),
            ],
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

        // 5. Draw Footer (Shortcut hints)
        canvas.ui_label(&vga::UiLabel {
            rect: footer_area,
            text: " [q] Exit   [k] Kill   [+/-] Scale   Strat9-OS Microkernel ",
            fg: theme.status_text,
            bg: theme.status_bg,
            align: vga::TextAlign::Left,
        });

        canvas.end_frame();

        // 6. Non-blocking check for user input
        if let Some(ch) = crate::arch::x86_64::keyboard::read_char() {
            if ch == b'q' {
                break;
            }
        }

        // 7. Prevent CPU hogging
        crate::process::yield_task();
    }

    // 8. Clean Exit
    vga::set_double_buffer_mode(was_db);
    // Fully clear screen before returning to shell text mode
    crate::shell::output::clear_screen();
    // Reset cursor to a sensible position
    vga::set_text_cursor(0, 0);
    shell_println!("Top exited.");
    Ok(())
}
