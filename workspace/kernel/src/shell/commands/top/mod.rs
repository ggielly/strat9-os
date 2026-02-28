//! Top command with Ratatui no_std backend.
//!
//! This command keeps Chevron shell as default UX and only uses Ratatui while `top`
//! is running.

mod ratatui_backend;

use crate::{arch::x86_64::vga, shell::ShellError, shell_println};
use alloc::{format, string::String, vec, vec::Vec};
use core::sync::atomic::Ordering;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, TableState},
    Terminal,
};
use ratatui_backend::Strat9RatatuiBackend;

const TOP_REFRESH_TICKS: u64 = 10; // 100ms at 100Hz
const MAX_CPU_GAUGES: usize = 8;

#[derive(Clone)]
struct TaskRowData {
    pid: String,
    name: String,
    state: &'static str,
    priority: String,
    ticks: u64,
}

struct TopSnapshot {
    cpu_count: usize,
    total_pages: usize,
    used_pages: usize,
    tasks: Vec<TaskRowData>,
}

#[derive(Clone, Copy)]
struct CpuUsageWindow {
    per_cpu_ratio: [f64; crate::arch::x86_64::percpu::MAX_CPUS],
    avg_ratio: f64,
}

fn collect_snapshot() -> TopSnapshot {
    let cpu_count = crate::arch::x86_64::percpu::cpu_count();
    let (total_pages, used_pages) = {
        let guard = crate::memory::buddy::get_allocator().lock();
        guard.as_ref().map(|a| a.page_totals()).unwrap_or((0, 0))
    };

    let mut tasks = Vec::new();
    if let Some(all_tasks) = crate::process::get_all_tasks() {
        for task in all_tasks {
            let state = unsafe { *task.state.get() };
            let state_str = match state {
                crate::process::TaskState::Ready => "Ready",
                crate::process::TaskState::Running => "Running",
                crate::process::TaskState::Blocked => "Blocked",
                crate::process::TaskState::Dead => "Dead",
            };
            tasks.push(TaskRowData {
                pid: format!("{}", task.pid),
                name: String::from(task.name),
                state: state_str,
                priority: format!("{:?}", task.priority),
                ticks: task.ticks.load(Ordering::Relaxed),
            });
        }
    }

    // Top-like behavior: most CPU-consumed tasks first.
    tasks.sort_by(|a, b| b.ticks.cmp(&a.ticks));

    TopSnapshot {
        cpu_count,
        total_pages,
        used_pages,
        tasks,
    }
}

fn compute_cpu_usage_window(
    prev: &crate::process::CpuUsageSnapshot,
    now: &crate::process::CpuUsageSnapshot,
) -> CpuUsageWindow {
    let cpu_count = now.cpu_count.min(crate::arch::x86_64::percpu::MAX_CPUS);
    let mut ratios = [0.0f64; crate::arch::x86_64::percpu::MAX_CPUS];
    let mut sum = 0.0;

    for i in 0..cpu_count {
        let delta_total = now.total_ticks[i].saturating_sub(prev.total_ticks[i]);
        let delta_idle = now.idle_ticks[i].saturating_sub(prev.idle_ticks[i]);
        let ratio = if delta_total == 0 {
            0.0
        } else {
            let busy = delta_total.saturating_sub(delta_idle);
            (busy as f64 / delta_total as f64).clamp(0.0, 1.0)
        };
        ratios[i] = ratio;
        sum += ratio;
    }

    CpuUsageWindow {
        per_cpu_ratio: ratios,
        avg_ratio: if cpu_count == 0 {
            0.0
        } else {
            (sum / cpu_count as f64).clamp(0.0, 1.0)
        },
    }
}

/// Top command main loop
pub fn cmd_top(_args: &[alloc::string::String]) -> Result<(), ShellError> {
    if !vga::is_available() {
        shell_println!("Error: 'top' requires a graphical framebuffer console.");
        return Ok(());
    }

    // Switch to double buffering for flicker-free updates.
    let was_db = vga::double_buffer_mode();
    vga::set_double_buffer_mode(true);
    let backend = Strat9RatatuiBackend::new().map_err(|_| ShellError::ExecutionFailed)?;
    let mut terminal = Terminal::new(backend).map_err(|_| ShellError::ExecutionFailed)?;
    terminal.clear().map_err(|_| ShellError::ExecutionFailed)?;

    let mut last_refresh_tick = crate::process::scheduler::ticks();
    let boot_tick = last_refresh_tick;
    let mut prev_cpu_sample = crate::process::cpu_usage_snapshot();
    let mut selected_task: usize = 0;

    loop {
        let ticks = crate::process::scheduler::ticks();

        // Keep input responsive even between render ticks.
        if let Some(ch) = crate::arch::x86_64::keyboard::read_char() {
            match ch {
                b'q' | 0x1B => break,
                crate::arch::x86_64::keyboard::KEY_UP => {
                    selected_task = selected_task.saturating_sub(1);
                }
                crate::arch::x86_64::keyboard::KEY_DOWN => {
                    selected_task = selected_task.saturating_add(1);
                }
                _ => {}
            }
        }

        // Refresh every 100ms with a 100Hz timer.
        if ticks.saturating_sub(last_refresh_tick) < TOP_REFRESH_TICKS {
            crate::process::yield_task();
            continue;
        }
        last_refresh_tick = ticks;
        let snapshot = collect_snapshot();
        let cpu_sample = crate::process::cpu_usage_snapshot();
        let cpu_window = compute_cpu_usage_window(&prev_cpu_sample, &cpu_sample);
        prev_cpu_sample = cpu_sample;
        let mem_ratio = if snapshot.total_pages > 0 {
            (snapshot.used_pages as f64) / (snapshot.total_pages as f64)
        } else {
            0.0
        };

        let rows: Vec<Row> = snapshot
            .tasks
            .iter()
            .map(|task| {
                Row::new(vec![
                    Cell::from(task.pid.as_str()),
                    Cell::from(task.name.as_str()),
                    Cell::from(task.state),
                    Cell::from(task.priority.as_str()),
                    Cell::from(format!("{}", task.ticks)),
                ])
            })
            .collect();
        let row_count = rows.len();
        if row_count == 0 {
            selected_task = 0;
        } else if selected_task >= row_count {
            selected_task = row_count - 1;
        }
        let mut table_state = TableState::default();
        if row_count > 0 {
            table_state.select(Some(selected_task));
        }

        let uptime_secs = ticks.saturating_sub(boot_tick) / 100;

        let frame_started = vga::begin_frame();
        // Our custom backend is intentionally simple; forcing full redraw avoids
        // stale-cell artifacts from terminal diffing on no_std VGA backends.
        terminal.clear().map_err(|_| ShellError::ExecutionFailed)?;
        terminal
            .draw(|frame| {
                let title_style = Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD);
                let primary_text = Style::default().fg(Color::White);
                let muted_text = Style::default().fg(Color::Gray);
                let header_style = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD);

                let area = frame.area();
                let vertical = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(2),
                        Constraint::Length(3),
                        Constraint::Length(6),
                        Constraint::Min(10),
                        Constraint::Length(1),
                    ])
                    .split(area);

                let title = Paragraph::new("Strat9 System Monitor (Ratatui no_std)")
                    .style(title_style)
                    .block(Block::default().borders(Borders::BOTTOM).title("Top"));
                frame.render_widget(title, vertical[0]);

                let stats_line = Paragraph::new(format!(
                    "CPUs: {} | Tasks: {} | CPU(avg): {:>3}% | Uptime: {}s",
                    snapshot.cpu_count,
                    snapshot.tasks.len(),
                    (cpu_window.avg_ratio * 100.0) as u16,
                    uptime_secs
                ))
                .style(primary_text)
                .block(Block::default().borders(Borders::BOTTOM).title("Stats"));
                frame.render_widget(stats_line, vertical[1]);

                let cpu_split = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(vertical[2]);

                let mem_gauge = Gauge::default()
                    .block(
                        Block::default()
                            .borders(Borders::TOP | Borders::BOTTOM)
                            .title(format!(
                                "Memory {} / {} pages",
                                snapshot.used_pages, snapshot.total_pages
                            )),
                    )
                    .gauge_style(Style::default().fg(Color::Blue))
                    .use_unicode(false)
                    .ratio(mem_ratio.clamp(0.0, 1.0))
                    .label(format!("{:.1}%", mem_ratio * 100.0));
                frame.render_widget(mem_gauge, cpu_split[0]);

                let cpu_gauge_count = snapshot.cpu_count.min(MAX_CPU_GAUGES);
                if cpu_gauge_count > 0 {
                    let mut constraints = Vec::with_capacity(cpu_gauge_count);
                    for _ in 0..cpu_gauge_count {
                        constraints.push(Constraint::Length(1));
                    }
                    let cpu_rows = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints(constraints)
                        .split(cpu_split[1]);

                    for i in 0..cpu_gauge_count {
                        let ratio = cpu_window.per_cpu_ratio[i];
                        let gauge = Gauge::default()
                            .block(Block::default().title(format!("CPU{}", i)).borders(Borders::NONE))
                            .gauge_style(Style::default().fg(Color::Green))
                            .use_unicode(false)
                            .ratio(ratio)
                            .label(format!("{:>3}%", (ratio * 100.0) as u16));
                        frame.render_widget(gauge, cpu_rows[i]);
                    }
                }

                let table = Table::new(
                    rows.iter().cloned(),
                    [
                        Constraint::Length(5),  // PID
                        Constraint::Min(18),    // Name (takes remaining width)
                        Constraint::Length(9),  // State
                        Constraint::Length(8),  // Prio
                        Constraint::Length(10), // Ticks
                    ],
                )
                .header(
                    Row::new(vec!["PID", "Name", "State", "Prio", "Ticks"]).style(header_style),
                )
                .column_spacing(1)
                .style(primary_text)
                .row_highlight_style(
                    Style::default()
                        .bg(Color::White)
                        .fg(Color::Black)
                        .add_modifier(Modifier::BOLD),
                )
                .block(
                    Block::default()
                        .borders(Borders::TOP)
                        .title("Tasks (sorted by ticks)"),
                );
                frame.render_stateful_widget(table, vertical[3], &mut table_state);

                let footer = Paragraph::new("[Up/Down] Select process | [q|Esc] Exit")
                    .style(muted_text)
                    .block(Block::default().borders(Borders::TOP));
                frame.render_widget(footer, vertical[4]);
            })
            .map_err(|_| ShellError::ExecutionFailed)?;

        if frame_started {
            vga::end_frame();
        } else {
            vga::present();
        }

        crate::process::yield_task();
    }

    // Clean exit.
    vga::set_double_buffer_mode(was_db);
    crate::shell::output::clear_screen();
    vga::set_text_cursor(0, 0);
    shell_println!("Top exited.");
    Ok(())
}
