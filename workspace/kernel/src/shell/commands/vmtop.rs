/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! `vmtop` : s9vm virtual-machine monitor.
//!
//! A deliberately small TUI in the spirit of [`super::top`]: it answers the two
//! questions an operator asks about a running virtualisation engine :
//!
//! * **is the engine alive?** (VT-x detected, active CPUs, number of worlds);
//! * **does my VM still exist?** Every world lives in the *kernel* registry,
//!   independently of the policy process that created it: a world created by
//!   `s9vm-vmm` keeps its vCPUs, guest memory and counters after that process
//!   exits. The table shows the worlds the kernel still owns, and the details
//!   pane shows their vCPUs, exit counters, mapped pages and exit latency, so a
//!   silent VM is visible instead of guessed.
//!
//! Data is read from the kernel registry (`s9vm::vm::{list, stats, …}`): no
//! syscall round-trip, no `/proc` dependency. Rendering goes through the
//! framebuffer console with the in-tree `ratatui` stack, like `top`.
//!
//! Keys: `q`/`Esc` quit, `↑`/`↓`/`Home`/`End` select a world, `r` refresh now.

#[cfg(target_arch = "x86_64")]
use super::top::{Strat9RatatuiBackend, TuiGuard};
use super::*;
use crate::{
    arch::timer::TIMER_HZ,
    s9vm::vm::{self, VcpuSnapshot, WorldStats, WorldTimingSnapshot},
    shell_println,
};
use alloc::{format, string::String, vec, vec::Vec};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Terminal,
};

/// Palette shared with `top` so the two monitors look like one family.
const ACCENT: Color = Color::Rgb(0x4F, 0xB3, 0xB3);
const OK: Color = Color::Rgb(0x55, 0xFF, 0x55);
const WARN: Color = Color::Rgb(0xFF, 0xFF, 0x55);
const CRIT: Color = Color::Rgb(0xFF, 0x55, 0x55);
const DIM: Color = Color::Rgb(0x88, 0x88, 0x88);
const MID: Color = Color::Rgb(0xCC, 0xCC, 0xCC);

/// One row of the world table, snapshotted once per refresh.
struct WorldRow {
    id: u64,
    name: String,
    silo_id: u32,
    state: u32,
    vcpu_count: u32,
    mapped_pages: u64,
    paused: bool,
    disk_sectors: u64,
    stats: WorldStats,
    snapshots: Vec<VcpuSnapshot>,
    timing: Option<WorldTimingSnapshot>,
}

impl WorldRow {
    /// Human-readable state, matching `strat9_abi::vmm::state`.
    fn state_name(&self) -> &'static str {
        match self.state {
            strat9_abi::vmm::state::CREATED => "created",
            strat9_abi::vmm::state::RUNNING => "running",
            strat9_abi::vmm::state::PAUSED => "paused",
            strat9_abi::vmm::state::STOPPED => "stopped",
            strat9_abi::vmm::state::FAILED => "failed",
            _ => "?",
        }
    }

    /// `true` when at least one vCPU has executed guest code.
    fn has_run(&self) -> bool {
        self.stats.runs > 0 || self.snapshots.iter().any(|slot| slot.runs > 0)
    }

    /// `true` while a vCPU is inside the guest right now.
    fn executing(&self) -> bool {
        self.snapshots
            .iter()
            .any(|slot| slot.executing || slot.in_guest)
    }

    fn state_color(&self) -> Color {
        if self.executing() {
            OK
        } else if self.paused {
            WARN
        } else if self.state == strat9_abi::vmm::state::FAILED {
            CRIT
        } else if self.has_run() {
            ACCENT
        } else {
            DIM
        }
    }

    fn live_label(&self) -> &'static str {
        if self.executing() {
            "RUNNING"
        } else if self.has_run() {
            "IDLE"
        } else {
            "COLD"
        }
    }
}

/// Collects the registry state of every world.
fn snapshot_worlds() -> Vec<WorldRow> {
    let mut rows = Vec::new();
    for record in vm::list() {
        let id = record.id;
        let name = String::from_utf8_lossy(record.name_slice()).into_owned();
        rows.push(WorldRow {
            id,
            name,
            silo_id: record.silo_id,
            state: record.state,
            vcpu_count: vm::vcpu_count(id).unwrap_or(record.vcpu_count),
            mapped_pages: record.mapped_pages,
            paused: vm::is_paused(id),
            disk_sectors: vm::disk_sectors(id).unwrap_or(0),
            stats: vm::stats(id).unwrap_or_default(),
            snapshots: vm::vcpu_snapshots(id).unwrap_or_default(),
            timing: vm::timing(id),
        });
    }
    rows.sort_by_key(|row| row.id);
    rows
}

fn state_of_caps() -> String {
    if crate::s9vm::detected() {
        let active = crate::s9vm::active_cpu_count();
        match crate::s9vm::detect() {
            Some(caps) => format!(
                "engine: active (VT-x/EPT, {active} cpu(s), ept2M={} ept1G={} vpid={})",
                caps.ept_2mb, caps.ept_1gb, caps.vpid
            ),
            None => format!("engine: active ({active} cpu(s))"),
        }
    } else {
        format!("engine: inactive ({})", crate::s9vm::unavailable_reason())
    }
}

fn row_cells(row: &WorldRow) -> Vec<Cell<'static>> {
    vec![
        Cell::from(format!("{:>3}", row.id)),
        Cell::from(row.name.clone()),
        Cell::from(format!("{}", row.silo_id)),
        Cell::from(row.state_name()),
        Cell::from(format!("{}", row.vcpu_count)),
        Cell::from(format!("{}", row.stats.emulated_exits)),
        Cell::from(format!("{}", row.stats.policy_exits)),
        Cell::from(format!("{}", row.mapped_pages)),
        Cell::from(if row.disk_sectors == 0 {
            String::from("-")
        } else {
            format!("{}", row.disk_sectors)
        }),
        Cell::from(row.live_label()),
    ]
}

/// Builds the details pane for the selected world.
fn details_lines(row: Option<&WorldRow>, ticks: u64) -> Vec<Line<'static>> {
    let Some(row) = row else {
        return vec![Line::from(Span::styled(
            "No world in the kernel registry: nothing is virtualised right now.",
            Style::default().fg(DIM),
        ))];
    };
    let mut lines = Vec::new();
    lines.push(Line::from(vec![
        Span::styled(
            format!("#{} {}", row.id, row.name),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!("[{}]", row.state_name()),
            Style::default().fg(row.state_color()),
        ),
        if row.paused {
            Span::styled("  paused", Style::default().fg(WARN))
        } else {
            Span::raw("")
        },
    ]));
    lines.push(Line::from(vec![
        Span::styled("persistence: ", Style::default().fg(DIM)),
        Span::styled(
            "world owned by the kernel registry (survives the policy process)",
            Style::default().fg(MID),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("memory:      ", Style::default().fg(DIM)),
        Span::raw(format!(
            "{} guest page(s), {} disk sector(s)",
            row.mapped_pages, row.disk_sectors
        )),
        Span::styled("   activity: ", Style::default().fg(DIM)),
        Span::raw(format!(
            "runs={} emulated={} policy={} injected={}",
            row.stats.runs,
            row.stats.emulated_exits,
            row.stats.policy_exits,
            row.stats.injected_interrupts
        )),
    ]));
    let vcpus: Vec<String> = row
        .snapshots
        .iter()
        .map(|slot| {
            format!(
                "cpu{} apic={} hw={} run={} guest={}",
                slot.id,
                slot.apic_id,
                u8::from(slot.hardware_ready),
                slot.runs,
                u8::from(slot.in_guest)
            )
        })
        .collect();
    lines.push(Line::from(vec![
        Span::styled("vCPUs:       ", Style::default().fg(DIM)),
        Span::raw(if vcpus.is_empty() {
            String::from("none")
        } else {
            vcpus.join("  ")
        }),
    ]));
    match &row.timing {
        Some(timing) => lines.push(Line::from(vec![
            Span::styled("exit timing: ", Style::default().fg(DIM)),
            Span::raw(format!(
                "n={} mean={}cy p95={}cy min={} max={} handler_mean={}cy",
                timing.exits,
                timing.mean_cycles,
                timing.p95_cycles,
                timing.min_cycles,
                timing.max_cycles,
                timing.handler_mean_cycles
            )),
        ])),
        None => lines.push(Line::from(vec![
            Span::styled("exit timing: ", Style::default().fg(DIM)),
            Span::raw("no exit measured yet"),
        ])),
    }
    // Uptime is a kernel-wide fact, not a per-world one: the registry has no
    // world creation stamp, so report how long the kernel has been observing
    // the world instead of inventing an age.
    lines.push(Line::from(vec![
        Span::styled("observed:    ", Style::default().fg(DIM)),
        Span::raw(format!("{}s of kernel uptime", ticks / TIMER_HZ.max(1))),
        Span::styled("   exit_count=", Style::default().fg(DIM)),
        Span::raw(format!(
            "{}",
            row.timing.as_ref().map(|t| t.exits).unwrap_or(0)
        )),
    ]));
    lines
}

fn render(
    frame: &mut ratatui::Frame<'_>,
    rows: &[WorldRow],
    selected: usize,
    ticks: u64,
    state: &mut TableState,
) {
    let area = frame.area();
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(6),
            Constraint::Length(9),
            Constraint::Length(1),
        ])
        .split(area);

    let header = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                " s9vm VM monitor ",
                Style::default()
                    .fg(Color::Rgb(0, 0, 0))
                    .bg(ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "  {} world(s)   uptime {}s   refresh {}s",
                rows.len(),
                ticks / TIMER_HZ.max(1),
                1
            )),
        ]),
        Line::from(Span::styled(state_of_caps(), Style::default().fg(MID))),
    ])
    .block(Block::default().borders(Borders::ALL).title(" engine "));
    frame.render_widget(header, vertical[0]);

    let header_row = Row::new(vec![
        Cell::from("ID"),
        Cell::from("NAME"),
        Cell::from("SILO"),
        Cell::from("STATE"),
        Cell::from("VCPU"),
        Cell::from("EMUL"),
        Cell::from("POLICY"),
        Cell::from("PAGES"),
        Cell::from("DISK"),
        Cell::from("LIVE"),
    ])
    .style(
        Style::default()
            .fg(Color::Rgb(0, 0, 0))
            .bg(ACCENT)
            .add_modifier(Modifier::BOLD),
    );
    let body: Vec<Row> = rows
        .iter()
        .map(|row| Row::new(row_cells(row)).style(Style::default().fg(row.state_color())))
        .collect();
    let table = Table::new(
        body,
        [
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(5),
            Constraint::Length(8),
            Constraint::Length(5),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(6),
            Constraint::Length(8),
        ],
    )
    .header(header_row)
    .block(Block::default().borders(Borders::ALL).title(" worlds "))
    .row_highlight_style(
        Style::default()
            .bg(Color::Rgb(0x20, 0x30, 0x30))
            .add_modifier(Modifier::BOLD),
    );
    *state = TableState::default();
    if !rows.is_empty() {
        state.select(Some(selected.min(rows.len() - 1)));
    }
    frame.render_stateful_widget(table, vertical[1], state);

    let details = Paragraph::new(details_lines(rows.get(selected), ticks)).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" selected world "),
    );
    frame.render_widget(details, vertical[2]);

    let footer = Paragraph::new(Line::from(vec![
        Span::styled("q", Style::default().fg(ACCENT)),
        Span::styled("/Esc quit   ", Style::default().fg(DIM)),
        Span::styled("↑↓", Style::default().fg(ACCENT)),
        Span::styled(" select   ", Style::default().fg(DIM)),
        Span::styled("r", Style::default().fg(ACCENT)),
        Span::styled(" refresh now", Style::default().fg(DIM)),
    ]));
    frame.render_widget(footer, vertical[3]);
}

/// `vmtop` : live monitor of the s9vm worlds held by the kernel.
#[cfg(target_arch = "x86_64")]
pub fn cmd_vmtop(_args: &[alloc::string::String]) -> Result<(), ShellError> {
    if crate::arch::x86_64::vga::is_lite() {
        shell_println!(
            "Error: 'vmtop' needs the graphical console. Reboot with console.mode=full \
             (see /boot/strat9.cfg)."
        );
        return Ok(());
    }
    let Some(guard) = TuiGuard::enter() else {
        shell_println!("Error: 'vmtop' requires a graphical framebuffer console.");
        return Ok(());
    };

    let backend = Strat9RatatuiBackend::new().map_err(|_| ShellError::ExecutionFailed)?;
    let mut terminal = Terminal::new(backend).map_err(|_| ShellError::ExecutionFailed)?;
    terminal.clear().map_err(|_| ShellError::ExecutionFailed)?;

    let mut rows = snapshot_worlds();
    let mut selected = 0usize;
    let mut table_state = TableState::default();
    let mut last_refresh = crate::process::scheduler::ticks();

    loop {
        let ticks = crate::process::scheduler::ticks();
        while let Some(ch) = crate::arch::keyboard::read_char() {
            match ch {
                b'q' | 0x1B | 0x03 => {
                    drop(guard);
                    shell_println!("vmtop exited.");
                    return Ok(());
                }
                crate::arch::keyboard::KEY_UP => selected = selected.saturating_sub(1),
                crate::arch::keyboard::KEY_DOWN => {
                    if selected + 1 < rows.len() {
                        selected += 1;
                    }
                }
                crate::arch::keyboard::KEY_HOME => selected = 0,
                crate::arch::keyboard::KEY_END => selected = rows.len().saturating_sub(1),
                b'r' => {
                    rows = snapshot_worlds();
                    last_refresh = ticks;
                    if selected >= rows.len() {
                        selected = rows.len().saturating_sub(1);
                    }
                }
                _ => {}
            }
        }

        if ticks.saturating_sub(last_refresh) < TIMER_HZ {
            terminal
                .draw(|frame| render(frame, &rows, selected, ticks, &mut table_state))
                .map_err(|_| ShellError::ExecutionFailed)?;
            crate::process::sleep_current_task_ticks(TIMER_HZ / 4);
            continue;
        }
        last_refresh = ticks;
        rows = snapshot_worlds();
        if selected >= rows.len() {
            selected = rows.len().saturating_sub(1);
        }
        terminal
            .draw(|frame| render(frame, &rows, selected, ticks, &mut table_state))
            .map_err(|_| ShellError::ExecutionFailed)?;
    }
}
