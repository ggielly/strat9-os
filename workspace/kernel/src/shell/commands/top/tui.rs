//! Ratatui presenter for `top`, drawn on the VGA framebuffer.
//!
//! The TUI owns the whole terminal while it runs, so every entry point restores
//! the console it borrowed: [`TuiGuard`] puts back the double buffer mode, the
//! caret and the screen even when the render loop returns early on an error.

use super::{
    cpu_spread_line, format_uptime, memory_bytes, memory_label, memory_ratio, scheduler_lines,
    silo_memory_label, silo_state_label, task_state_label, Strat9RatatuiBackend, TopView,
};
use crate::{arch::vga, shell::ShellError, shell_println};
use alloc::{format, string::String, vec, vec::Vec};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, TableState},
    Frame, Terminal,
};

/// Upper bound on per-CPU gauges, so a large machine cannot eat the screen.
const MAX_CPU_GAUGES: usize = 8;
/// Caret color, same as the shell prompt (`shell::output::print_prompt`).
const PROMPT_CURSOR: vga::RgbColor = vga::RgbColor::new(0x4F, 0xB3, 0xB3);
/// Row budget of the fixed chrome: title, stats and footer.
const TITLE_ROWS: u16 = 2;
const STATS_ROWS: u16 = 2;
const FOOTER_ROWS: u16 = 2;
/// Rows the tables keep at all costs.
const MIN_MAIN_ROWS: u16 = 6;

/// Restores the console state borrowed by the TUI, on every exit path.
struct TuiGuard {
    was_double_buffer: bool,
}

impl TuiGuard {
    /// Takes over the screen. `None` when there is no framebuffer console.
    fn enter() -> Option<Self> {
        if !vga::is_available() {
            return None;
        }
        let was_double_buffer = vga::double_buffer_mode();
        vga::set_double_buffer_mode(true);
        // The caret is a framebuffer overlay re-drawn on every present: it
        // would otherwise be re-presented on top of the UI.
        vga::hide_text_cursor();
        Some(Self { was_double_buffer })
    }
}

impl Drop for TuiGuard {
    fn drop(&mut self) {
        vga::set_double_buffer_mode(self.was_double_buffer);
        vga::draw_text_cursor(PROMPT_CURSOR);
        crate::shell::output::clear_screen();
        vga::set_text_cursor(0, 0);
    }
}

/// Runs the `top` TUI until the user quits.
pub(super) fn run() -> Result<(), ShellError> {
    let Some(guard) = TuiGuard::enter() else {
        shell_println!("Error: 'top' requires a graphical framebuffer console.");
        return Ok(());
    };

    let result = run_loop();
    drop(guard);

    match result {
        Ok(()) => {
            shell_println!("Top exited.");
            Ok(())
        }
        Err(err) => Err(err),
    }
}

fn run_loop() -> Result<(), ShellError> {
    let backend = Strat9RatatuiBackend::new().map_err(|_| ShellError::ExecutionFailed)?;
    let mut terminal = Terminal::new(backend).map_err(|_| ShellError::ExecutionFailed)?;
    terminal.clear().map_err(|_| ShellError::ExecutionFailed)?;

    let mut table_state = TableState::default();
    super::run_presenter(|view, selected| {
        sync_table_state(&mut table_state, view, selected);

        // Present before propagating a draw error, so a failed frame still
        // leaves a consistent screen behind.
        let frame_started = vga::begin_frame();
        let drawn = terminal.draw(|frame| render(frame, view, &mut table_state));
        if frame_started {
            vga::end_frame();
        } else {
            vga::present();
        }
        drawn.map(|_| ()).map_err(|_| ShellError::ExecutionFailed)
    })
}

/// Keeps the selection and the scroll offset inside the current task list.
///
/// The table widget scrolls to reveal the selection, but the offset is only
/// advanced from its previous value, so it has to survive across frames.
fn sync_table_state(state: &mut TableState, view: &TopView, selected: usize) {
    let rows = view.snapshot.tasks.len();
    if rows == 0 {
        *state = TableState::default();
        return;
    }
    let selected = selected.min(rows - 1);
    state.select(Some(selected));
    let offset = state.offset_mut();
    if *offset > selected {
        *offset = selected;
    }
    if *offset + 1 >= rows {
        *offset = rows - 1;
    }
}

fn render(frame: &mut Frame<'_>, view: &TopView, table_state: &mut TableState) {
    let snapshot = &view.snapshot;
    let cpus = snapshot.cpu_count();

    let title_style = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
    let primary_text = Style::default().fg(Color::White);
    let muted_text = Style::default().fg(Color::DarkGray);
    let header_style = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);

    let area = frame.area();

    // Budget the rows left after the chrome and the minimum table area between
    // the gauge column and the scheduler block, so neither can starve the other
    // nor push the tables off screen.
    let body = area
        .height
        .saturating_sub(TITLE_ROWS + STATS_ROWS + FOOTER_ROWS + MIN_MAIN_ROWS);
    let gauge_budget = body.saturating_sub(2).max(1) as usize;
    let cpu_gauge_rows = cpus.min(MAX_CPU_GAUGES).min(gauge_budget).max(1);
    // + 2 rows: the memory panel border above and below its bar.
    let gauge_rows = (cpu_gauge_rows + 2) as u16;

    let sched_capacity = body.saturating_sub(gauge_rows).max(2) as usize;
    let mut sched_lines = scheduler_lines(view, area.width as usize);
    // The CPU detail lines are the only elastic part of the scheduler block, so
    // they are what gets clipped on a short screen.
    let hidden_cpu_lines = sched_lines.len().saturating_sub(sched_capacity);
    if hidden_cpu_lines > 0 {
        sched_lines.truncate(sched_capacity - 1);
        sched_lines.push(String::from("... more CPU lines hidden"));
    }
    // + 1 row for the block's bottom border.
    let sched_rows = (sched_lines.len() as u16 + 1).max(3);

    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(TITLE_ROWS),
            Constraint::Length(STATS_ROWS),
            Constraint::Length(gauge_rows),
            Constraint::Length(sched_rows),
            Constraint::Min(MIN_MAIN_ROWS),
            Constraint::Length(FOOTER_ROWS),
        ])
        .split(area);

    frame.render_widget(
        Paragraph::new("Strat9 system monitor")
            .style(title_style)
            .block(Block::default().borders(Borders::BOTTOM).title("Top")),
        vertical[0],
    );

    let stats = format!(
        "CPUs: {} | Tasks: {} | Silos: {} | Strates: {} | CPU(avg): {:>3}% | Up: {}\nMem: {} ({:.1}%) | {}",
        cpus,
        snapshot.tasks.len(),
        snapshot.silos.len(),
        snapshot.strates.len(),
        (view.cpu.avg_ratio * 100.0) as u16,
        format_uptime(view.uptime_secs),
        memory_label(snapshot),
        memory_ratio(snapshot) * 100.0,
        cpu_spread_line(view, cpu_gauge_rows),
    );
    frame.render_widget(Paragraph::new(stats).style(primary_text), vertical[1]);

    render_gauges(frame, view, vertical[2], cpu_gauge_rows, &muted_text);

    frame.render_widget(
        Paragraph::new(sched_lines.join("\n"))
            .style(primary_text)
            .block(Block::default().borders(Borders::BOTTOM).title("Scheduler")),
        vertical[3],
    );

    render_tables(
        frame,
        view,
        vertical[4],
        table_state,
        primary_text,
        header_style,
    );

    let mut footer = String::from("[Up/Down] Select task | [q|Esc|Ctrl-C] Exit");
    let hidden_gauges = cpus.saturating_sub(cpu_gauge_rows);
    if hidden_gauges > 0 {
        footer.push_str(&format!(" | +{} CPU gauges hidden", hidden_gauges));
    }
    if hidden_cpu_lines > 0 {
        footer.push_str(&format!(" | +{} CPU lines hidden", hidden_cpu_lines));
    }
    frame.render_widget(
        Paragraph::new(footer)
            .style(muted_text)
            .block(Block::default().borders(Borders::TOP)),
        vertical[5],
    );
}

/// Memory bar on the left, one gauge per visible CPU on the right.
fn render_gauges(
    frame: &mut Frame<'_>,
    view: &TopView,
    area: Rect,
    cpu_gauge_rows: usize,
    muted_text: &Style,
) {
    let snapshot = &view.snapshot;
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let ratio = memory_ratio(snapshot);
    let (used_bytes, _) = memory_bytes(snapshot);
    frame.render_widget(
        Gauge::default()
            .block(
                Block::default()
                    .borders(Borders::TOP | Borders::BOTTOM)
                    .title(format!("Memory {}", memory_label(snapshot)))
                    .border_style(*muted_text),
            )
            .gauge_style(Style::default().fg(Color::Blue))
            .use_unicode(false)
            .ratio(ratio)
            .label(format!(
                "{:.1}% {}",
                ratio * 100.0,
                crate::shell::output::human_bytes(used_bytes)
            )),
        columns[0],
    );

    if cpu_gauge_rows == 0 {
        return;
    }
    let rows: Vec<Constraint> = (0..cpu_gauge_rows).map(|_| Constraint::Length(1)).collect();
    let cpu_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(rows)
        .split(columns[1]);

    for i in 0..cpu_gauge_rows {
        let ratio = view.cpu.per_cpu_ratio[i];
        // No block title: on a single row it would collide with the gauge bar
        // and with the centered label.
        frame.render_widget(
            Gauge::default()
                .gauge_style(Style::default().fg(Color::Green))
                .use_unicode(false)
                .ratio(ratio)
                .label(format!("cpu{} {:>3}%", i, (ratio * 100.0) as u16)),
            cpu_rows[i],
        );
    }
}

fn render_tables(
    frame: &mut Frame<'_>,
    view: &TopView,
    area: Rect,
    table_state: &mut TableState,
    primary_text: Style,
    header_style: Style,
) {
    let snapshot = &view.snapshot;

    // The silo table needs ~43 columns, so the right pane takes a bit more than
    // a third: on a 128-column console both panes fit without clipping.
    let main_split = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
        .split(area);

    let task_rows: Vec<Row> = snapshot
        .tasks
        .iter()
        .map(|task| {
            Row::new(vec![
                Cell::from(format!("{}", task.pid)),
                Cell::from(task.name),
                Cell::from(task_state_label(task.state)),
                Cell::from(format!("{:?}", task.priority)),
                Cell::from(format!("{}", task.ticks)),
            ])
        })
        .collect();
    let task_table = Table::new(
        task_rows,
        [
            Constraint::Length(5),  // PID
            Constraint::Min(18),    // Name (takes remaining width)
            Constraint::Length(9),  // State
            Constraint::Length(8),  // Prio
            Constraint::Length(10), // Ticks
        ],
    )
    .header(Row::new(vec!["PID", "Name", "State", "Prio", "Ticks"]).style(header_style))
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
    frame.render_stateful_widget(task_table, main_split[0], table_state);

    let right_split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(56), Constraint::Percentage(44)])
        .split(main_split[1]);

    let silo_rows: Vec<Row> = snapshot
        .silos
        .iter()
        .map(|silo| {
            Row::new(vec![
                Cell::from(format!("{}", silo.sid)),
                Cell::from(silo.name.as_str()),
                Cell::from(silo_state_label(silo.state)),
                Cell::from(format!("{}", silo.tasks)),
                Cell::from(crate::shell::output::human_bytes(silo.mem_used)),
                Cell::from(silo_memory_label(silo.mem_max)),
                Cell::from(silo.strate.as_str()),
            ])
        })
        .collect();
    let silo_table = Table::new(
        silo_rows,
        [
            Constraint::Length(4), // SID
            Constraint::Length(9), // Name
            Constraint::Length(8), // State
            Constraint::Length(2), // Tasks
            Constraint::Length(6), // Mem used
            Constraint::Length(8), // Mem max
            Constraint::Min(6),    // Strate
        ],
    )
    .header(
        Row::new(vec!["SID", "Name", "State", "T", "Mem", "Max", "Strate"]).style(
            Style::default()
                .fg(Color::LightGreen)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .column_spacing(1)
    .style(primary_text)
    .block(Block::default().borders(Borders::TOP).title("Silos"));
    frame.render_widget(silo_table, right_split[0]);

    let strate_rows: Vec<Row> = snapshot
        .strates
        .iter()
        .map(|strate| {
            Row::new(vec![
                Cell::from(strate.name.as_str()),
                Cell::from(strate.silos.as_str()),
            ])
        })
        .collect();
    let strate_table = Table::new(strate_rows, [Constraint::Length(14), Constraint::Min(8)])
        .header(
            Row::new(vec!["Strate", "BelongsTo"]).style(
                Style::default()
                    .fg(Color::LightCyan)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .column_spacing(1)
        .style(primary_text)
        .block(Block::default().borders(Borders::TOP).title("Strates"));
    frame.render_widget(strate_table, right_split[1]);
}
