//! `top` — system monitor.
//!
//! Layout inspiration: rrtop (small panels, sparklines, big numbers) for the
//! metrics half, vtui (inventory tree with fold/unfold and a details pane) for
//! the management half.
//!
//! Everything is drawn with the in-tree `ratatui` (no_std) stack on the
//! framebuffer console through [`Strat9RatatuiBackend`].
//!
//! Data sources are kernel-side (no `/proc` round-trip for the metrics):
//! * `process::cpu_usage_snapshot()` — per-CPU total/idle ticks (lock-free).
//! * `process::scheduler_metrics_snapshot()` — per-class runtime + counters.
//! * `process::get_all_tasks()` — tasks, states and per-task tick counters.
//! * `/proc/silos` (fallback: `silo::list_silos_snapshot()`) — inventory.

#[cfg(target_arch = "x86_64")]
pub(crate) mod ratatui_backend;

use crate::{arch::vga, shell::ShellError, shell_println};
use alloc::{format, string::String, vec, vec::Vec};
use core::sync::atomic::Ordering;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    symbols::bar::Set,
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Sparkline, Table, TableState},
    Terminal,
};
#[cfg(target_arch = "x86_64")]
pub(crate) use ratatui_backend::Strat9RatatuiBackend;

/// Samples kept for the sparklines (one per refresh).
const HIST_LEN: usize = 60;
/// Refresh period, in timer ticks. Derived from the real tick rate instead of
/// assuming 100 Hz, so `top` keeps its 1 s cadence if `TIMER_HZ` changes.
const TOP_REFRESH_TICKS: u64 = crate::arch::timer::TIMER_HZ;
/// More gauges than that and the panel would eat the whole screen.
const MAX_CPU_GAUGES: usize = 8;

// ---------------------------------------------------------------------------
// Palette (mapped 1:1 to the framebuffer by the backend).
// ---------------------------------------------------------------------------
const ACCENT: Color = Color::Rgb(0x4F, 0xB3, 0xB3);
const OK: Color = Color::Rgb(0x55, 0xFF, 0x55);
const WARN: Color = Color::Rgb(0xFF, 0xFF, 0x55);
const CRIT: Color = Color::Rgb(0xFF, 0x55, 0x55);
const DIM: Color = Color::Rgb(0x88, 0x88, 0x88);
const MID: Color = Color::Rgb(0xCC, 0xCC, 0xCC);
/// Unfilled part of a gauge, so empty bars still read as a track.
const TRACK: Color = Color::Rgb(0x18, 0x18, 0x18);

/// Sparkline levels: true eighth-height blocks. The console font only ships
/// `█`, so `vga` derives `▁`..`▇` from it at load time (`synthesize_block_glyphs`).
const SPARK_SET: Set<'static> = Set {
    full: "█",
    seven_eighths: "▇",
    three_quarters: "▆",
    five_eighths: "▅",
    half: "▄",
    three_eighths: "▃",
    one_quarter: "▂",
    one_eighth: "▁",
    empty: " ",
};

/// `f64::round` lives in `std`; core only has truncation.
fn pct_u16(ratio: f64) -> u16 {
    (ratio.clamp(0.0, 1.0) * 100.0 + 0.5) as u16
}

fn load_color(ratio: f64) -> Color {
    if ratio >= 0.85 {
        CRIT
    } else if ratio >= 0.60 {
        WARN
    } else {
        OK
    }
}

// ---------------------------------------------------------------------------
// Snapshot
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct TaskRowData {
    pid: String,
    tid: String,
    name: String,
    state: &'static str,
    priority: String,
    /// Cumulative ticks since task creation.
    ticks: u64,
    /// CPU usage over the last refresh window, in percent of one CPU.
    cpu_pct: f64,
}

#[derive(Clone)]
struct SiloRowData {
    sid: String,
    sid_num: u32,
    name: String,
    state: String,
    tasks: String,
    label: String,
    memory: String,
}

#[derive(Clone)]
struct StrateRowData {
    name: String,
    silos: String,
}

struct TopSnapshot {
    cpu_count: usize,
    total_pages: usize,
    used_pages: usize,
    tasks: Vec<TaskRowData>,
    silos: Vec<SiloRowData>,
    strates: Vec<StrateRowData>,
    scheduler: crate::process::SchedulerStateSnapshot,
}

fn task_state_str(state: crate::process::TaskState) -> &'static str {
    match state {
        crate::process::TaskState::Ready => "Ready",
        crate::process::TaskState::Running => "Running",
        crate::process::TaskState::Blocked => "Blocked",
        crate::process::TaskState::Dead => "Dead",
    }
}

/// Parse `/proc/silos`.
///
/// Tolerant by design: a malformed line is skipped instead of discarding the
/// whole inventory (the previous `fields.next()?` made one short row silently
/// disable the procfs path).
fn collect_silos_from_proc_scheme() -> Option<(Vec<SiloRowData>, Vec<StrateRowData>)> {
    let fd = crate::vfs::open("/proc/silos", crate::vfs::OpenFlags::READ).ok()?;
    let bytes = match crate::vfs::read_all(fd) {
        Ok(b) => b,
        Err(_) => {
            let _ = crate::vfs::close(fd);
            return None;
        }
    };
    let _ = crate::vfs::close(fd);
    let body = core::str::from_utf8(&bytes).ok()?;

    let mut silos = Vec::new();
    // name -> silo names it runs in (deduplicated and sorted at the end).
    let mut strates: Vec<(String, Vec<String>)> = Vec::new();

    for (line_idx, line) in body.lines().enumerate() {
        if line_idx == 0 || line.is_empty() {
            continue;
        }
        let mut fields = line.split('\t');
        // sid, state, tasks, mem_used, mem_min, mem_max, gfx*, label, name, instances
        let Some(sid) = fields.next() else { continue };
        let Some(state) = fields.next() else { continue };
        let Some(tasks) = fields.next() else { continue };
        let mem_used = fields.next().unwrap_or("0");
        let _mem_min = fields.next();
        let _mem_max = fields.next();
        let _gfx_flags = fields.next();
        let _gfx_sessions = fields.next();
        let _gfx_ttl = fields.next();
        let label = fields.next().unwrap_or("-");
        let Some(name) = fields.next() else { continue };
        let instances = fields.next().unwrap_or("");

        let sid_num = sid.parse::<u32>().unwrap_or(u32::MAX);
        for strate_name in instances.split(',').filter(|n| !n.is_empty()) {
            match strates.iter_mut().find(|(n, _)| n == strate_name) {
                Some((_, owners)) => {
                    if !owners.iter().any(|o| o == name) {
                        owners.push(String::from(name));
                    }
                }
                None => strates.push((String::from(strate_name), vec![String::from(name)])),
            }
        }

        silos.push(SiloRowData {
            sid: String::from(sid),
            sid_num,
            name: String::from(name),
            state: String::from(state),
            tasks: String::from(tasks),
            label: String::from(label),
            memory: format!("{} KB", mem_used.parse::<u64>().unwrap_or(0) / 1024),
        });
    }

    silos.sort_by_key(|s| s.sid_num);
    Some((silos, strates_to_rows(strates)))
}

fn strates_to_rows(mut strates: Vec<(String, Vec<String>)>) -> Vec<StrateRowData> {
    strates.sort_by(|a, b| a.0.cmp(&b.0));
    strates
        .into_iter()
        .map(|(name, owners)| {
            let mut silos = String::new();
            for (i, owner) in owners.iter().enumerate() {
                if i != 0 {
                    silos.push_str(", ");
                }
                silos.push_str(owner);
            }
            StrateRowData { name, silos }
        })
        .collect()
}

fn collect_snapshot() -> TopSnapshot {
    let cpu_count = crate::arch::percpu::cpu_count();
    let (total_pages, used_pages) = {
        let guard = crate::memory::buddy::get_allocator().lock();
        guard.as_ref().map(|a| a.page_totals()).unwrap_or((0, 0))
    };

    let mut tasks = Vec::new();
    if let Some(all_tasks) = crate::process::get_all_tasks() {
        for task in all_tasks {
            tasks.push(TaskRowData {
                pid: format!("{}", task.pid),
                tid: format!("{}", task.tid),
                name: task.name.clone(),
                state: task_state_str(task.get_state()),
                priority: format!("{:?}", task.priority),
                ticks: task.ticks.load(Ordering::Relaxed),
                cpu_pct: 0.0,
            });
        }
    }

    let (silos, strates) = collect_silos_from_proc_scheme().unwrap_or_else(|| {
        let mut strates: Vec<(String, Vec<String>)> = Vec::new();
        let mut silos = Vec::new();
        let mut silo_snapshots = crate::silo::list_silos_snapshot();
        silo_snapshots.sort_by_key(|s| s.id);
        for s in silo_snapshots {
            let label = s.strate_label.unwrap_or_default();
            for instance in s.runtime_strates {
                match strates.iter_mut().find(|(n, _)| *n == instance) {
                    Some((_, owners)) => owners.push(s.name.clone()),
                    None => strates.push((instance, vec![s.name.clone()])),
                }
            }
            silos.push(SiloRowData {
                sid: format!("{}", s.id),
                sid_num: s.id,
                name: s.name,
                state: format!("{:?}", s.state),
                tasks: format!("{}", s.task_count),
                label: if label.is_empty() {
                    String::from("-")
                } else {
                    label
                },
                memory: format!("{} KB", s.mem_usage_bytes / 1024),
            });
        }
        (silos, strates_to_rows(strates))
    });

    TopSnapshot {
        cpu_count,
        total_pages,
        used_pages,
        tasks,
        silos,
        strates,
        scheduler: crate::process::scheduler_state_snapshot(),
    }
}

// ---------------------------------------------------------------------------
// Windows (delta between two samples)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct CpuUsageWindow {
    per_cpu_ratio: [f64; crate::arch::percpu::MAX_CPUS],
    avg_ratio: f64,
    /// Ticks elapsed on the busiest CPU, used as the per-window time base.
    window_ticks: u64,
}

fn compute_cpu_usage_window(
    prev: &crate::process::CpuUsageSnapshot,
    now: &crate::process::CpuUsageSnapshot,
) -> CpuUsageWindow {
    let cpu_count = now.cpu_count.min(crate::arch::percpu::MAX_CPUS);
    let mut ratios = [0.0f64; crate::arch::percpu::MAX_CPUS];
    let mut sum = 0.0;
    let mut window_ticks = 0u64;

    for i in 0..cpu_count {
        let delta_total = now.total_ticks[i].saturating_sub(prev.total_ticks[i]);
        let delta_idle = now.idle_ticks[i].saturating_sub(prev.idle_ticks[i]);
        window_ticks = window_ticks.max(delta_total);
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
        window_ticks,
    }
}

#[derive(Clone, Copy)]
struct SchedulerMetricsWindow {
    rt_ratio: f64,
    fair_ratio: f64,
    idle_ratio: f64,
    switch_delta: u64,
    preempt_delta: u64,
    steal_in_delta: u64,
    steal_out_delta: u64,
    deferred_raised_delta: u32,
    deferred_processed_delta: u32,
}

fn compute_scheduler_metrics_window(
    prev: &crate::process::SchedulerMetricsSnapshot,
    now: &crate::process::SchedulerMetricsSnapshot,
) -> SchedulerMetricsWindow {
    let cpu_count = now.cpu_count.min(crate::arch::percpu::MAX_CPUS);
    let mut rt_delta = 0u64;
    let mut fair_delta = 0u64;
    let mut idle_delta = 0u64;
    let mut switch_delta = 0u64;
    let mut preempt_delta = 0u64;
    let mut steal_in_delta = 0u64;
    let mut steal_out_delta = 0u64;
    let mut deferred_raised_delta = 0u32;
    let mut deferred_processed_delta = 0u32;
    for i in 0..cpu_count {
        rt_delta = rt_delta
            .saturating_add(now.rt_runtime_ticks[i].saturating_sub(prev.rt_runtime_ticks[i]));
        fair_delta = fair_delta
            .saturating_add(now.fair_runtime_ticks[i].saturating_sub(prev.fair_runtime_ticks[i]));
        idle_delta = idle_delta
            .saturating_add(now.idle_runtime_ticks[i].saturating_sub(prev.idle_runtime_ticks[i]));
        switch_delta =
            switch_delta.saturating_add(now.switch_count[i].saturating_sub(prev.switch_count[i]));
        preempt_delta = preempt_delta
            .saturating_add(now.preempt_count[i].saturating_sub(prev.preempt_count[i]));
        steal_in_delta = steal_in_delta
            .saturating_add(now.steal_in_count[i].saturating_sub(prev.steal_in_count[i]));
        steal_out_delta = steal_out_delta
            .saturating_add(now.steal_out_count[i].saturating_sub(prev.steal_out_count[i]));
        deferred_raised_delta = deferred_raised_delta.saturating_add(
            now.deferred_work_raised[i].saturating_sub(prev.deferred_work_raised[i]),
        );
        deferred_processed_delta = deferred_processed_delta.saturating_add(
            now.deferred_work_processed[i].saturating_sub(prev.deferred_work_processed[i]),
        );
    }
    let total = rt_delta
        .saturating_add(fair_delta)
        .saturating_add(idle_delta);
    let to_ratio = |v: u64| {
        if total == 0 {
            0.0
        } else {
            (v as f64 / total as f64).clamp(0.0, 1.0)
        }
    };
    SchedulerMetricsWindow {
        rt_ratio: to_ratio(rt_delta),
        fair_ratio: to_ratio(fair_delta),
        idle_ratio: to_ratio(idle_delta),
        switch_delta,
        preempt_delta,
        steal_in_delta,
        steal_out_delta,
        deferred_raised_delta,
        deferred_processed_delta,
    }
}

// ---------------------------------------------------------------------------
// History ring for the sparklines
// ---------------------------------------------------------------------------

struct History {
    cpu: Vec<u64>,
    mem: Vec<u64>,
    /// One series per CPU, so each row can show its own trend.
    per_cpu: Vec<Vec<u64>>,
}

impl History {
    fn new() -> Self {
        Self {
            cpu: Vec::with_capacity(HIST_LEN),
            mem: Vec::with_capacity(HIST_LEN),
            per_cpu: Vec::new(),
        }
    }

    fn push(&mut self, cpu_pct: u64, mem_pct: u64, per_cpu: &[f64]) {
        if self.cpu.len() == HIST_LEN {
            self.cpu.remove(0);
            self.mem.remove(0);
            for series in &mut self.per_cpu {
                series.remove(0);
            }
        }
        self.cpu.push(cpu_pct.min(100));
        self.mem.push(mem_pct.min(100));

        while self.per_cpu.len() < per_cpu.len() {
            self.per_cpu.push(Vec::with_capacity(HIST_LEN));
        }
        for (i, ratio) in per_cpu.iter().enumerate() {
            self.per_cpu[i].push(pct_u16(*ratio) as u64);
        }
    }

    fn cpu_series(&self, cpu: usize) -> &[u64] {
        self.per_cpu.get(cpu).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

// ---------------------------------------------------------------------------
// Inventory tree (vtui-inspired)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum NodeKind {
    Silo,
    Strate,
    Task,
}

#[derive(Clone)]
struct Node {
    /// Stable identity across refreshes (`s103`, `s103/strate-net`, `s103/…/t14`).
    key: String,
    kind: NodeKind,
    depth: u8,
    label: String,
    /// Right-aligned suffix: state, size or CPU%.
    right: String,
    color: Color,
    children: Vec<String>,
}

struct Tree {
    nodes: Vec<Node>,
    roots: Vec<String>,
    /// Flattened keys of the currently visible nodes, in display order.
    visible: Vec<String>,
    /// Fold state, persisted across refreshes so the tree does not re-open.
    collapsed: alloc::collections::BTreeMap<String, bool>,
    selected: usize,
}

impl Tree {
    fn new() -> Self {
        Self {
            nodes: Vec::new(),
            roots: Vec::new(),
            visible: Vec::new(),
            collapsed: alloc::collections::BTreeMap::new(),
            selected: 0,
        }
    }

    /// Rebuild from the snapshot, keeping fold state and selection.
    fn refresh(&mut self, snapshot: &TopSnapshot) {
        let previous = self.visible.get(self.selected).cloned();

        self.nodes.clear();
        self.roots.clear();

        for silo in &snapshot.silos {
            let silo_key = format!("s{}", silo.sid);
            let mut children = Vec::new();

            // Strates running in this silo: match `/proc/silos` owners, then any
            // task whose name is `silo-<sid>/...`.
            let prefix = format!("silo-{}/", silo.sid);
            for strate in &snapshot.strates {
                if strate.silos.split(", ").any(|o| o == silo.name) {
                    let key = format!("{}/{}", silo_key, strate.name);
                    let mut task_children = Vec::new();
                    for task in snapshot.tasks.iter().filter(|t| t.name.starts_with(&prefix)) {
                        if task.name.ends_with(&strate.name) || task.name.contains(&strate.name) {
                            let tkey = format!("{}/t{}", key, task.tid);
                            task_children.push(tkey.clone());
                            self.nodes.push(Node {
                                key: tkey,
                                kind: NodeKind::Task,
                                depth: 3,
                                label: format!("task {} {}", task.tid, task.name),
                                right: format!("{} · {:.1}%", task.state, task.cpu_pct),
                                color: if task.cpu_pct >= 25.0 { WARN } else { MID },
                                children: Vec::new(),
                            });
                        }
                    }
                    self.nodes.push(Node {
                        key: key.clone(),
                        kind: NodeKind::Strate,
                        depth: 2,
                        label: strate.name.clone(),
                        right: format!("{} task(s)", task_children.len()),
                        color: MID,
                        children: task_children,
                    });
                    children.push(key);
                }
            }

            self.nodes.push(Node {
                key: silo_key.clone(),
                kind: NodeKind::Silo,
                depth: 1,
                label: format!("{} #{}", silo.name, silo.sid),
                right: format!("{} · {} · {}t", silo.state, silo.memory, silo.tasks),
                color: ACCENT,
                children: children.clone(),
            });
            self.roots.push(silo_key);
        }

        self.rebuild_visible();

        // Keep the cursor on the same node when possible, else clamp.
        self.selected = previous
            .and_then(|key| self.visible.iter().position(|k| *k == key))
            .unwrap_or(self.selected)
            .min(self.visible.len().saturating_sub(1));
    }

    fn is_expanded(&self, key: &str) -> bool {
        !self.collapsed.get(key).copied().unwrap_or(false)
    }

    fn node(&self, key: &str) -> Option<&Node> {
        self.nodes.iter().find(|n| n.key == key)
    }

    fn rebuild_visible(&mut self) {
        let mut out = Vec::with_capacity(self.nodes.len());
        let roots = self.roots.clone();
        for key in roots {
            self.visit(&key, &mut out);
        }
        self.visible = out;
    }

    fn visit(&self, key: &str, out: &mut Vec<String>) {
        let Some(node) = self.node(key) else { return };
        out.push(node.key.clone());
        if self.is_expanded(key) {
            for child in &node.children {
                self.visit(child, out);
            }
        }
    }

    fn toggle(&mut self) {
        let Some(key) = self.visible.get(self.selected).cloned() else {
            return;
        };
        let expanded = self.is_expanded(&key);
        self.collapsed.insert(key, expanded);
        self.rebuild_visible();
        self.selected = self.selected.min(self.visible.len().saturating_sub(1));
    }

    fn move_up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    fn move_down(&mut self) {
        if self.selected + 1 < self.visible.len() {
            self.selected += 1;
        }
    }

    fn collapse(&mut self) {
        let Some(key) = self.visible.get(self.selected).cloned() else {
            return;
        };
        if !self.collapsed.get(&key).copied().unwrap_or(false) {
            self.collapsed.insert(key, true);
            self.rebuild_visible();
            self.selected = self.selected.min(self.visible.len().saturating_sub(1));
        }
    }

    fn expand(&mut self) {
        let Some(key) = self.visible.get(self.selected).cloned() else {
            return;
        };
        if self.collapsed.get(&key).copied().unwrap_or(false) {
            self.collapsed.insert(key, false);
            self.rebuild_visible();
        }
    }

    fn selected_node(&self) -> Option<&Node> {
        self.visible.get(self.selected).and_then(|k| self.node(k))
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

/// Task id (`tid`) of the tree selection, when it points at a task.
fn selected_task_tid(tree: &Tree) -> Option<u64> {
    let node = tree.selected_node()?;
    if node.kind != NodeKind::Task {
        return None;
    }
    node.key.rsplit("/t").next()?.parse::<u64>().ok()
}

fn format_uptime(total_secs: u64) -> String {
    let h = total_secs / 3600;
    let m = (total_secs % 3600) / 60;
    let s = total_secs % 60;
    if h > 0 {
        format!("{}h{:02}m{:02}s", h, m, s)
    } else {
        format!("{:02}m{:02}s", m, s)
    }
}

fn memory_ratio(snapshot: &TopSnapshot) -> f64 {
    if snapshot.total_pages == 0 {
        0.0
    } else {
        (snapshot.used_pages as f64 / snapshot.total_pages as f64).clamp(0.0, 1.0)
    }
}

fn memory_label(snapshot: &TopSnapshot) -> String {
    let used = snapshot.used_pages * 4;
    let total = snapshot.total_pages * 4;
    format!("{} / {} MB", used / 1024, total / 1024)
}

// ---------------------------------------------------------------------------
// Console guard
// ---------------------------------------------------------------------------

/// Restores the console state borrowed by the TUI, on every exit path.
///
/// `cmd_top` used to enable double buffering and only restore it at the end of
/// the render loop; any early `?` left the shell writing into a back buffer
/// that is never presented (blank console until reboot).
struct TuiGuard {
    was_double_buffer: bool,
}

impl TuiGuard {
    fn enter() -> Option<Self> {
        if !vga::is_available() {
            return None;
        }
        let was_double_buffer = vga::double_buffer_mode();
        vga::set_double_buffer_mode(true);
        vga::hide_text_cursor();
        Some(Self {
            was_double_buffer,
        })
    }
}

impl Drop for TuiGuard {
    fn drop(&mut self) {
        vga::set_double_buffer_mode(self.was_double_buffer);
        crate::shell::output::clear_screen();
        vga::set_text_cursor(0, 0);
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

struct View<'a> {
    snapshot: &'a TopSnapshot,
    cpu: &'a CpuUsageWindow,
    sched: &'a SchedulerMetricsWindow,
    history: &'a History,
    tree: &'a Tree,
    tasks: &'a [TaskRowData],
    uptime_secs: u64,
    /// `(tid, name)` of a task awaiting a kill confirmation.
    pending_kill: Option<&'a (u64, String)>,
}

fn panel(title: &'static str, color: Color) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(0x44, 0x44, 0x44)))
        .title(Span::styled(
            title,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ))
}

fn render_header(frame: &mut ratatui::Frame<'_>, view: &View<'_>, area: ratatui::layout::Rect) {
    let avg_pct = pct_u16(view.cpu.avg_ratio);
    let line = Line::from(vec![
        Span::styled(
            " Strat9 ",
            Style::default()
                .fg(Color::Black)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            " system monitor ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(
                "│ up {} │ {} tasks │ {} silos │ {} strates │ ",
                format_uptime(view.uptime_secs),
                view.snapshot.tasks.len(),
                view.snapshot.silos.len(),
                view.snapshot.strates.len(),
            ),
            Style::default().fg(DIM),
        ),
        Span::styled(
            format!("CPU {:>3}% ", avg_pct),
            Style::default()
                .fg(load_color(view.cpu.avg_ratio))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("MEM {:>3}%", pct_u16(memory_ratio(view.snapshot))),
            Style::default()
                .fg(load_color(memory_ratio(view.snapshot)))
                .add_modifier(Modifier::BOLD),
        ),
    ]);
    frame.render_widget(Paragraph::new(line).style(Style::default()), area);
}

fn render_cpu_panel(frame: &mut ratatui::Frame<'_>, view: &View<'_>, area: ratatui::layout::Rect) {
    let block = panel("CPU", OK);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height == 0 || inner.width == 0 {
        return;
    }

    let gauges = view.snapshot.cpu_count.min(MAX_CPU_GAUGES);
    // One row for the history sparkline, the rest for per-CPU bars.
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1)])
        .split(inner);

    let spark = Sparkline::default()
        .data(view.history.cpu.iter().copied())
        .max(100)
        .bar_set(SPARK_SET)
        .style(Style::default().fg(load_color(view.cpu.avg_ratio)));
    frame.render_widget(spark, rows[0]);

    if gauges == 0 {
        return;
    }
    let mut constraints = Vec::with_capacity(gauges);
    for _ in 0..gauges {
        constraints.push(Constraint::Length(1));
    }
    let cpu_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(rows[1]);

    for i in 0..gauges {
        let ratio = view.cpu.per_cpu_ratio[i];
        let row = cpu_rows[i];
        // Label on the left, bar on the right: a Gauge's own title would steal
        // the only line available for the bar.
        let split = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(6),
                Constraint::Length(5),
                Constraint::Min(8),
                Constraint::Length(18),
            ])
            .split(row);
        frame.render_widget(
            Paragraph::new(format!("cpu{}", i)).style(Style::default().fg(DIM)),
            split[0],
        );
        frame.render_widget(
            Paragraph::new(format!("{:>3}%", pct_u16(ratio)))
                .style(Style::default().fg(load_color(ratio))),
            split[1],
        );
        // No in-bar label: on a saturated bar it would be drawn in the bar's
        // own colour and become unreadable.
        let gauge = Gauge::default()
            .ratio(ratio)
            .label("")
            .style(Style::default().bg(TRACK))
            .gauge_style(Style::default().fg(load_color(ratio)))
            .use_unicode(true);
        frame.render_widget(gauge, split[2]);
        if split[3].width > 2 {
            frame.render_widget(
                Sparkline::default()
                    .data(view.history.cpu_series(i).iter().copied())
                    .max(100)
                    .bar_set(SPARK_SET)
                    .style(Style::default().fg(load_color(ratio))),
                split[3],
            );
        }
    }
}

fn render_mem_panel(frame: &mut ratatui::Frame<'_>, view: &View<'_>, area: ratatui::layout::Rect) {
    let block = panel("Memory", Color::Rgb(0x55, 0x88, 0xFF));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height == 0 {
        return;
    }
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(1)])
        .split(inner);
    let ratio = memory_ratio(view.snapshot);
    frame.render_widget(
        Gauge::default()
            .ratio(ratio)
            .label(format!(
                "{} ({:.1}%)",
                memory_label(view.snapshot),
                ratio * 100.0
            ))
            .style(Style::default().bg(TRACK))
            .gauge_style(Style::default().fg(load_color(ratio)))
            .use_unicode(true),
        rows[0],
    );
    frame.render_widget(
        Sparkline::default()
            .data(view.history.mem.iter().copied())
            .max(100)
            .bar_set(SPARK_SET)
            .style(Style::default().fg(Color::Rgb(0x55, 0x88, 0xFF))),
        rows[1],
    );
}

fn render_sched_panel(frame: &mut ratatui::Frame<'_>, view: &View<'_>, area: ratatui::layout::Rect) {
    let s = &view.snapshot.scheduler;
    let w = view.sched;
    let cpu_count = s.cpu_count.min(crate::arch::percpu::MAX_CPUS);
    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::from(vec![
        Span::styled("RT ", Style::default().fg(DIM)),
        Span::styled(
            format!("{:>3}% ", pct_u16(w.rt_ratio)),
            Style::default().fg(WARN),
        ),
        Span::styled("FAIR ", Style::default().fg(DIM)),
        Span::styled(
            format!("{:>3}% ", pct_u16(w.fair_ratio)),
            Style::default().fg(OK),
        ),
        Span::styled("IDLE ", Style::default().fg(DIM)),
        Span::styled(
            format!("{:>3}%", pct_u16(w.idle_ratio)),
            Style::default().fg(MID),
        ),
    ]));
    lines.push(Line::from(Span::styled(
        format!(
            "sw {}  pre {}  st+{} st-{}  blocked {}",
            w.switch_delta, w.preempt_delta, w.steal_in_delta, w.steal_out_delta, s.blocked_tasks
        ),
        Style::default().fg(DIM),
    )));
    lines.push(Line::from(Span::styled(
        format!(
            "deferred +{} / +{}  pick {}>{}>{}",
            w.deferred_raised_delta,
            w.deferred_processed_delta,
            s.pick_order[0].as_str(),
            s.pick_order[1].as_str(),
            s.pick_order[2].as_str()
        ),
        Style::default().fg(DIM),
    )));

    // One compact line per CPU, so a 4+ CPU box is fully visible (the previous
    // implementation hard-coded cpu0 and cpu1).
    let mut cpu_line: Vec<Span> = Vec::new();
    for i in 0..cpu_count {
        cpu_line.push(Span::styled(
            format!(
                "c{}:{}/{}/{}{} ",
                i,
                s.rq_rt[i],
                s.rq_fair[i],
                s.rq_idle[i],
                if s.need_resched[i] { "*" } else { "" }
            ),
            Style::default().fg(if s.need_resched[i] { WARN } else { DIM }),
        ));
    }
    if !cpu_line.is_empty() {
        lines.push(Line::from(cpu_line));
    }

    frame.render_widget(
        Paragraph::new(lines).block(panel("Scheduler", ACCENT)),
        area,
    );
}

fn render_tree(frame: &mut ratatui::Frame<'_>, view: &View<'_>, area: ratatui::layout::Rect) {
    let block = panel("Inventory", Color::Rgb(0xBB, 0x88, 0xFF));
    let inner = block.inner(area);
    let inner_height = inner.height as usize;
    frame.render_widget(block, area);
    if inner_height == 0 {
        return;
    }

    // Scroll window around the selection so the cursor stays visible.
    let total = view.tree.visible.len();
    let selected = view.tree.selected.min(total.saturating_sub(1));
    let start = if selected >= inner_height {
        selected + 1 - inner_height
    } else {
        0
    };
    let end = (start + inner_height).min(total);

    let mut lines: Vec<Line> = Vec::with_capacity(inner_height);
    for idx in start..end {
        let Some(node) = view.tree.visible.get(idx).and_then(|k| view.tree.node(k)) else {
            continue;
        };
        let mut spans: Vec<Span> = Vec::new();
        // Indentation with box-drawing guides.
        for _ in 1..node.depth {
            spans.push(Span::styled("│ ", Style::default().fg(Color::Rgb(0x44, 0x44, 0x44))));
        }
        let marker = if node.children.is_empty() {
            "· "
        } else if view.tree.is_expanded(&node.key) {
            "- "
        } else {
            "+ "
        };
        spans.push(Span::styled(marker, Style::default().fg(node.color)));
        spans.push(Span::styled(
            node.label.clone(),
            Style::default().fg(if idx == selected { Color::White } else { node.color }),
        ));
        spans.push(Span::styled(
            format!("  {}", node.right),
            Style::default().fg(DIM),
        ));
        let mut line = Line::from(spans);
        if idx == selected {
            line = line.style(
                Style::default()
                    .bg(Color::Rgb(0x22, 0x33, 0x33))
                    .add_modifier(Modifier::BOLD),
            );
        }
        lines.push(line);
    }

    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_details(frame: &mut ratatui::Frame<'_>, view: &View<'_>, area: ratatui::layout::Rect) {
    let Some(node) = view.tree.selected_node() else {
        frame.render_widget(
            Paragraph::new("no selection").style(Style::default().fg(DIM)),
            area,
        );
        return;
    };

    let (kind, meta): (&str, String) = match node.kind {
        NodeKind::Silo => ("silo", {
            let sid = node.key.trim_start_matches('s');
            let silo = view.snapshot.silos.iter().find(|s| s.sid == sid);
            match silo {
                Some(s) => format!(
                    "state {}   mem {}   tasks {}   label {}",
                    s.state, s.memory, s.tasks, s.label
                ),
                None => String::from("-"),
            }
        }),
        NodeKind::Strate => ("strate", format!("{} task(s) below", node.children.len())),
        NodeKind::Task => ("task", {
            let tid = node.key.rsplit("/t").next().unwrap_or("");
            let task = view.snapshot.tasks.iter().find(|t| t.tid == tid);
            match task {
                Some(t) => format!(
                    "pid {}   tid {}   state {}   prio {}   ticks {}   win {:>5.1}%",
                    t.pid, t.tid, t.state, t.priority, t.ticks, t.cpu_pct
                ),
                None => String::from("-"),
            }
        }),
    };

    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                format!(" {} ", kind.to_uppercase()),
                Style::default().fg(Color::Black).bg(node.color),
            ),
            Span::styled(format!(" {}", node.label), Style::default().fg(Color::White)),
        ]),
        Line::from(Span::styled(meta, Style::default().fg(MID))),
    ];
    if node.kind == NodeKind::Task {
        lines.push(Line::from(vec![
            Span::styled("  k", Style::default().fg(CRIT).add_modifier(Modifier::BOLD)),
            Span::styled(" kill   ", Style::default().fg(DIM)),
            Span::styled("s", Style::default().fg(WARN).add_modifier(Modifier::BOLD)),
            Span::styled(" suspend   ", Style::default().fg(DIM)),
            Span::styled("r", Style::default().fg(OK).add_modifier(Modifier::BOLD)),
            Span::styled(" resume", Style::default().fg(DIM)),
        ]));
    }
    frame.render_widget(
        Paragraph::new(lines).block(panel("Details", node.color)),
        area,
    );
}

fn render_tasks(
    frame: &mut ratatui::Frame<'_>,
    view: &View<'_>,
    area: ratatui::layout::Rect,
    state: &mut TableState,
) {
    let rows: Vec<Row> = view
        .tasks
        .iter()
        .map(|t| {
            let color = if t.cpu_pct >= 50.0 {
                CRIT
            } else if t.cpu_pct >= 10.0 {
                WARN
            } else {
                MID
            };
            Row::new(vec![
                Cell::from(t.pid.as_str()),
                Cell::from(t.name.as_str()),
                Cell::from(t.state),
                Cell::from(format!("{:.1}%", t.cpu_pct)).style(Style::default().fg(color)),
                Cell::from(format!("{}", t.ticks)),
            ])
        })
        .collect();

    if rows.is_empty() {
        *state = TableState::default();
    } else {
        let selected = state.selected().unwrap_or(0).min(rows.len() - 1);
        state.select(Some(selected));
    }

    let width = area.width.saturating_sub(2);
    let name_w = width.saturating_sub(5 + 9 + 8 + 10);
    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Min(name_w.max(10)),
            Constraint::Length(9),
            Constraint::Length(8),
            Constraint::Length(10),
        ],
    )
    .header(
        Row::new(vec!["PID", "Name", "State", "%CPU", "Ticks"])
            .style(Style::default().fg(WARN).add_modifier(Modifier::BOLD)),
    )
    .column_spacing(1)
    .style(Style::default().fg(MID))
    .row_highlight_style(
        Style::default()
            .bg(Color::Rgb(0x22, 0x33, 0x33))
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    )
    .block(panel("Tasks (by CPU this window)", OK));

    frame.render_stateful_widget(table, area, state);
}

fn render(frame: &mut ratatui::Frame<'_>, view: &View<'_>, table_state: &mut TableState) {
    // The last row belongs to the kernel status line (`status-line` task draws
    // it directly on the framebuffer): never paint over it.
    let full = frame.area();
    let area = ratatui::layout::Rect {
        height: full.height.saturating_sub(1),
        ..full
    };
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // header
            Constraint::Length(9), // cpu + mem/sched
            Constraint::Min(8),    // tree + details/tasks
            Constraint::Length(1), // footer
        ])
        .split(area);

    render_header(frame, view, vertical[0]);

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
        .split(vertical[1]);
    render_cpu_panel(frame, view, top[0]);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(4)])
        .split(top[1]);
    render_mem_panel(frame, view, right[0]);
    render_sched_panel(frame, view, right[1]);

    let main = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
        .split(vertical[2]);
    render_tree(frame, view, main[0]);

    let side = Layout::default()
        .direction(Direction::Vertical)
        // Details needs 3 inner rows: title, metadata, action hints.
        .constraints([Constraint::Length(5), Constraint::Min(5)])
        .split(main[1]);
    render_details(frame, view, side[0]);
    render_tasks(frame, view, side[1], table_state);

    let footer = if let Some((tid, name)) = view.pending_kill {
        Line::from(vec![
            Span::styled(
                " KILL ",
                Style::default()
                    .fg(Color::Black)
                    .bg(CRIT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" task {} ({}) ? ", tid, name),
                Style::default().fg(CRIT).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" y ", Style::default().fg(Color::Black).bg(CRIT)),
            Span::styled(" confirm   ", Style::default().fg(DIM)),
            Span::styled(" n ", Style::default().fg(Color::Black).bg(ACCENT)),
            Span::styled(" cancel", Style::default().fg(DIM)),
        ])
    } else {
        Line::from(vec![
            Span::styled(" Up/Dn ", Style::default().fg(Color::Black).bg(ACCENT)),
            Span::styled(" nav  ", Style::default().fg(DIM)),
            Span::styled(" L/R ", Style::default().fg(Color::Black).bg(ACCENT)),
            Span::styled(" fold  ", Style::default().fg(DIM)),
            Span::styled(" space ", Style::default().fg(Color::Black).bg(ACCENT)),
            Span::styled(" toggle  ", Style::default().fg(DIM)),
            Span::styled(" k ", Style::default().fg(Color::Black).bg(CRIT)),
            Span::styled(" kill  ", Style::default().fg(DIM)),
            Span::styled(" s/r ", Style::default().fg(Color::Black).bg(ACCENT)),
            Span::styled(" susp/resume  ", Style::default().fg(DIM)),
            Span::styled(" q ", Style::default().fg(Color::Black).bg(ACCENT)),
            Span::styled(" quit", Style::default().fg(DIM)),
        ])
    };
    frame.render_widget(Paragraph::new(footer), vertical[3]);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Top command main loop
#[cfg(target_arch = "x86_64")]
pub fn cmd_top(_args: &[alloc::string::String]) -> Result<(), ShellError> {
    let Some(_guard) = TuiGuard::enter() else {
        shell_println!("Error: 'top' requires a graphical framebuffer console.");
        return Ok(());
    };

    let backend = Strat9RatatuiBackend::new().map_err(|_| ShellError::ExecutionFailed)?;
    let mut terminal = Terminal::new(backend).map_err(|_| ShellError::ExecutionFailed)?;
    terminal.clear().map_err(|_| ShellError::ExecutionFailed)?;

    let start_tick = crate::process::scheduler::ticks();
    let mut last_refresh_tick = start_tick;
    let mut prev_cpu_sample = crate::process::cpu_usage_snapshot();
    let mut prev_sched_sample = crate::process::scheduler_metrics_snapshot();
    let mut prev_task_ticks: Vec<(String, u64)> = Vec::new();
    // Task table highlight is tracked by PID: the table is re-sorted by %CPU on
    // every refresh, so a row index would point at a different process each time.
    let mut selected_task_pid: Option<String> = None;
    // `(tid, label)` waiting for a kill confirmation (vtui-style management).
    let mut pending_kill: Option<(u64, String)> = None;
    let mut history = History::new();
    let mut tree = Tree::new();
    let mut table_state = TableState::default();

    loop {
        let ticks = crate::process::scheduler::ticks();

        // Input stays responsive between refreshes.
        while let Some(ch) = crate::arch::keyboard::read_char() {
            // A pending confirmation swallows the next keystroke.
            if let Some((tid, _)) = pending_kill.clone() {
                match ch {
                    b'y' | b'Y' => {
                        let _ = crate::process::kill_task(
                            crate::process::task::TaskId::from_u64(tid),
                        );
                        pending_kill = None;
                    }
                    b'n' | b'N' => pending_kill = None,
                    _ => {}
                }
                continue;
            }
            match ch {
                b'q' | 0x1B | 0x03 => {
                    drop(_guard);
                    shell_println!("Top exited.");
                    return Ok(());
                }
                crate::arch::keyboard::KEY_UP => tree.move_up(),
                crate::arch::keyboard::KEY_DOWN => tree.move_down(),
                crate::arch::keyboard::KEY_RIGHT => tree.expand(),
                crate::arch::keyboard::KEY_LEFT => tree.collapse(),
                b' ' | b'\r' | b'\n' => tree.toggle(),
                b'k' => {
                    if let Some(tid) = selected_task_tid(&tree) {
                        if let Some(node) = tree.selected_node() {
                            pending_kill = Some((tid, node.label.clone()));
                        }
                    }
                }
                b's' => {
                    if let Some(tid) = selected_task_tid(&tree) {
                        let _ = crate::process::suspend_task(
                            crate::process::task::TaskId::from_u64(tid),
                        );
                    }
                }
                b'r' => {
                    if let Some(tid) = selected_task_tid(&tree) {
                        let _ = crate::process::resume_task(
                            crate::process::task::TaskId::from_u64(tid),
                        );
                    }
                }
                _ => {}
            }
        }

        if ticks.saturating_sub(last_refresh_tick) < TOP_REFRESH_TICKS {
            // Block instead of spinning: `yield_task()` returns immediately
            // when nothing else is runnable (the old loop burned a full core),
            // and `hlt` would still be accounted as a busy Fair task. Sleeping
            // parks the task on the wake queue, so the CPU really goes idle and
            // `top` stops inflating the very number it displays.
            crate::process::sleep_current_task_ticks(TOP_REFRESH_TICKS / 4);
            continue;
        }
        let elapsed = ticks.saturating_sub(last_refresh_tick);
        last_refresh_tick = ticks;

        let mut snapshot = collect_snapshot();

        // --- CPU / scheduler windows -------------------------------------
        let cpu_sample = crate::process::cpu_usage_snapshot();
        let cpu_window = compute_cpu_usage_window(&prev_cpu_sample, &cpu_sample);
        prev_cpu_sample = cpu_sample;
        let sched_sample = crate::process::scheduler_metrics_snapshot();
        let sched_window = compute_scheduler_metrics_window(&prev_sched_sample, &sched_sample);
        prev_sched_sample = sched_sample;

        // --- per-task CPU% over the window -------------------------------
        // One CPU-second equals one tick per CPU, so a task that hogged a core
        // for the whole window scores 100%.
        let base = cpu_window.window_ticks.max(elapsed).max(1) as f64;
        for task in &mut snapshot.tasks {
            let prev = prev_task_ticks
                .iter()
                .find(|(tid, _)| *tid == task.tid)
                .map(|(_, t)| *t)
                .unwrap_or(task.ticks);
            let delta = task.ticks.saturating_sub(prev);
            task.cpu_pct = (delta as f64 / base) * 100.0;
        }
        prev_task_ticks = snapshot
            .tasks
            .iter()
            .map(|t| (t.tid.clone(), t.ticks))
            .collect();
        snapshot
            .tasks
            .sort_by(|a, b| b.cpu_pct.partial_cmp(&a.cpu_pct).unwrap_or(core::cmp::Ordering::Equal));

        let mem_pct = pct_u16(memory_ratio(&snapshot)) as u64;
        history.push(
            pct_u16(cpu_window.avg_ratio) as u64,
            mem_pct,
            &cpu_window.per_cpu_ratio[..snapshot.cpu_count.min(crate::arch::percpu::MAX_CPUS)],
        );

        tree.refresh(&snapshot);
        // Re-locate the highlighted task after the re-sort.
        if let Some(pid) = selected_task_pid.as_deref() {
            if let Some(idx) = snapshot.tasks.iter().position(|t| t.pid == pid) {
                table_state.select(Some(idx));
            }
        }
        // Selecting a task node in the tree drives the table.
        if let Some(node) = tree.selected_node() {
            if node.kind == NodeKind::Task {
                let tid = node.key.rsplit("/t").next().unwrap_or("");
                if let Some(idx) = snapshot.tasks.iter().position(|t| t.tid == tid) {
                    table_state.select(Some(idx));
                    selected_task_pid = Some(snapshot.tasks[idx].pid.clone());
                }
            }
        }

        let view = View {
            snapshot: &snapshot,
            cpu: &cpu_window,
            sched: &sched_window,
            history: &history,
            tree: &tree,
            tasks: &snapshot.tasks,
            uptime_secs: ticks / crate::arch::timer::TIMER_HZ,
            pending_kill: pending_kill.as_ref(),
        };

        let frame_started = vga::begin_frame();
        let drawn = terminal.draw(|frame| render(frame, &view, &mut table_state));
        // Present before propagating a draw error, so a failed frame still
        // leaves the screen in a consistent state.
        if frame_started {
            vga::end_frame();
        } else {
            vga::present();
        }
        drawn.map_err(|_| ShellError::ExecutionFailed)?;

        let _ = start_tick;
    }
}

/// Serial-only fallback for `top` on non-x86 targets (R6: full TUI via virtio).
#[cfg(not(target_arch = "x86_64"))]
pub fn cmd_top(_args: &[alloc::string::String]) -> Result<(), ShellError> {
    shell_println!("top: TUI requires a framebuffer console (not available yet)");
    Ok(())
}
