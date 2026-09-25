//! `top` — Strat9 system monitor.
//!
//! Data collection is architecture independent: one [`TopSnapshot`] is built
//! from the kernel's own snapshot APIs (scheduler counters, task list, silo
//! registry, buddy allocator) and handed to a presenter.
//!
//! - x86_64 with a framebuffer: a Ratatui TUI ([`tui`]) that owns the screen
//!   while it runs, double buffered, and restores the console on exit.
//! - otherwise: a serial text view built from the same [`TopSnapshot`], so the
//!   data stays reachable on targets without VGA (see R6: virtio console TUI).
//!
//! The shell stays the default UX: Ratatui is only alive while `top` runs.

#[cfg(target_arch = "x86_64")]
pub(crate) mod ratatui_backend;
#[cfg(target_arch = "x86_64")]
mod tui;

#[cfg(target_arch = "x86_64")]
pub(crate) use ratatui_backend::Strat9RatatuiBackend;

use crate::shell::ShellError;
#[cfg(not(target_arch = "x86_64"))]
use crate::shell_println;
use alloc::{collections::BTreeMap, format, string::String, vec::Vec};
use core::sync::atomic::Ordering;

/// Target UI refresh rate in Hz. The tick period is derived from the kernel
/// timer frequency so the cadence stays constant on any `TIMER_HZ`.
const REFRESH_HZ: u64 = 10;

/// Tick period between two refreshes, never below one tick.
const fn refresh_ticks() -> u64 {
    let ticks = crate::arch::timer::TIMER_HZ / REFRESH_HZ;
    if ticks == 0 {
        1
    } else {
        ticks
    }
}

const REFRESH_TICKS: u64 = refresh_ticks();

/// Maximum number of keystrokes consumed per loop iteration. Input is drained
/// in a bounded batch so a key flood cannot starve rendering.
const MAX_KEYS_PER_ROUND: usize = 32;
/// Assumed width for the serial presenter.
#[cfg(not(target_arch = "x86_64"))]
const SERIAL_COLS: usize = 80;
/// Separator width when joining silo names in the strate table.
const STRATE_JOIN: &str = ", ";

#[derive(Clone)]
struct TaskRowData {
    pid: crate::process::Pid,
    name: &'static str,
    state: crate::process::TaskState,
    priority: crate::process::TaskPriority,
    ticks: u64,
}

#[derive(Clone)]
struct SiloRowData {
    sid: u32,
    name: String,
    /// Strate this silo belongs to: its declared label, or its own name when
    /// no label was declared.
    strate: String,
    state: crate::silo::SiloState,
    tasks: usize,
    mem_used: u64,
    /// `0` means the silo declared no upper bound.
    mem_max: u64,
}

struct StrateRowData {
    name: String,
    silos: String,
}

struct TopSnapshot {
    total_pages: usize,
    used_pages: usize,
    tasks: Vec<TaskRowData>,
    silos: Vec<SiloRowData>,
    strates: Vec<StrateRowData>,
    scheduler: crate::process::SchedulerStateSnapshot,
}

impl TopSnapshot {
    /// Number of CPUs the scheduler accounts for, clamped to the per-CPU
    /// counter arrays. Single source of truth: the scheduler's own count, so
    /// the gauges, the usage window and the state lines always agree.
    fn cpu_count(&self) -> usize {
        self.scheduler.cpu_count.min(crate::arch::percpu::MAX_CPUS)
    }
}

/// One refresh worth of data: a fresh snapshot plus the deltas against the
/// previous one. Every presenter consumes this, so the TUI and the serial view
/// can never drift apart.
struct TopView {
    snapshot: TopSnapshot,
    cpu: CpuUsageWindow,
    sched: SchedulerMetricsWindow,
    uptime_secs: u64,
}

#[derive(Clone, Copy)]
struct CpuUsageWindow {
    per_cpu_ratio: [f64; crate::arch::percpu::MAX_CPUS],
    avg_ratio: f64,
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
    try_lock_fail_delta: u64,
}

/// Collects silos and their strate grouping straight from the silo registry.
///
/// The shell lives inside the kernel, so there is no reason to serialize the
/// registry to `/proc/silos` and parse it back: `list_silos_snapshot` is the
/// structured equivalent of that file, without the fd churn, the per-chunk
/// regeneration of the procfs text, or the positional field parsing.
fn collect_silos() -> (Vec<SiloRowData>, Vec<StrateRowData>) {
    let mut registry = crate::silo::list_silos_snapshot();
    registry.sort_by_key(|s| s.id);

    let mut silos = Vec::with_capacity(registry.len());
    // BTreeMap keeps the strate list sorted by name without a second pass.
    let mut by_strate: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for s in registry {
        // An empty label means "no strate declared": the silo then belongs to
        // the strate that shares its name (same convention as `/proc/silos`,
        // which renders a missing label as `-`).
        let strate = s.strate_label.as_deref().unwrap_or(&s.name);
        by_strate
            .entry(String::from(strate))
            .or_default()
            .push(s.name.clone());

        silos.push(SiloRowData {
            sid: s.id,
            strate: String::from(strate),
            name: s.name,
            state: s.state,
            tasks: s.task_count,
            mem_used: s.mem_usage_bytes,
            mem_max: s.mem_max_bytes,
        });
    }

    let strates = by_strate
        .into_iter()
        .map(|(name, silos)| StrateRowData {
            name,
            silos: silos.join(STRATE_JOIN),
        })
        .collect();

    (silos, strates)
}

fn collect_snapshot() -> TopSnapshot {
    let (total_pages, used_pages) = {
        let guard = crate::memory::buddy::get_allocator().lock();
        guard.as_ref().map(|a| a.page_totals()).unwrap_or((0, 0))
    };

    let mut tasks = Vec::new();
    if let Some(all_tasks) = crate::process::get_all_tasks() {
        tasks.reserve(all_tasks.len());
        for task in all_tasks {
            tasks.push(TaskRowData {
                pid: task.pid,
                name: task.name,
                state: task.get_state(),
                priority: task.priority,
                ticks: task.ticks.load(Ordering::Relaxed),
            });
        }
    }

    // Top-like behavior: most CPU-consumed tasks first.
    tasks.sort_by_key(|task| core::cmp::Reverse(task.ticks));

    let (silos, strates) = collect_silos();

    TopSnapshot {
        total_pages,
        used_pages,
        tasks,
        silos,
        strates,
        scheduler: crate::process::scheduler_state_snapshot(),
    }
}

/// Turns consecutive counter samples into a per-CPU busy ratio window.
fn compute_cpu_usage_window(
    prev: &crate::process::CpuUsageSnapshot,
    now: &crate::process::CpuUsageSnapshot,
    cpus: usize,
) -> CpuUsageWindow {
    let cpus = cpus.min(now.cpu_count).min(crate::arch::percpu::MAX_CPUS);
    let mut ratios = [0.0f64; crate::arch::percpu::MAX_CPUS];
    let mut sum = 0.0;

    for (i, slot) in ratios.iter_mut().enumerate().take(cpus) {
        let delta_total = now.total_ticks[i].saturating_sub(prev.total_ticks[i]);
        let delta_idle = now.idle_ticks[i].saturating_sub(prev.idle_ticks[i]);
        let ratio = if delta_total == 0 {
            0.0
        } else {
            let busy = delta_total.saturating_sub(delta_idle);
            (busy as f64 / delta_total as f64).clamp(0.0, 1.0)
        };
        *slot = ratio;
        sum += ratio;
    }

    CpuUsageWindow {
        per_cpu_ratio: ratios,
        avg_ratio: if cpus == 0 {
            0.0
        } else {
            (sum / cpus as f64).clamp(0.0, 1.0)
        },
    }
}

/// Aggregates the per-CPU scheduler counters into a single window.
fn compute_scheduler_metrics_window(
    prev: &crate::process::SchedulerMetricsSnapshot,
    now: &crate::process::SchedulerMetricsSnapshot,
    cpus: usize,
) -> SchedulerMetricsWindow {
    let cpus = cpus.min(now.cpu_count).min(crate::arch::percpu::MAX_CPUS);
    let mut rt_delta = 0u64;
    let mut fair_delta = 0u64;
    let mut idle_delta = 0u64;
    let mut switch_delta = 0u64;
    let mut preempt_delta = 0u64;
    let mut steal_in_delta = 0u64;
    let mut steal_out_delta = 0u64;
    let mut try_lock_fail_delta = 0u64;
    for i in 0..cpus {
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
        try_lock_fail_delta = try_lock_fail_delta
            .saturating_add(now.try_lock_fail_count[i].saturating_sub(prev.try_lock_fail_count[i]));
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
        try_lock_fail_delta,
    }
}

/// Runtime distribution and context-switch counters for the elapsed window.
fn scheduler_window_line(w: &SchedulerMetricsWindow) -> String {
    format!(
        "Win: RT {:>3}% | FAIR {:>3}% | IDLE {:>3}% | sw {} | pre {} | st+ {} | st- {} | tlm {}",
        (w.rt_ratio * 100.0) as u16,
        (w.fair_ratio * 100.0) as u16,
        (w.idle_ratio * 100.0) as u16,
        w.switch_delta,
        w.preempt_delta,
        w.steal_in_delta,
        w.steal_out_delta,
        w.try_lock_fail_delta
    )
}

/// Static scheduler configuration: boot phase, class orders, blocked tasks.
fn scheduler_config_line(s: &crate::process::SchedulerStateSnapshot) -> String {
    format!(
        "Cfg: init={} phase={} blocked={} pick=[{},{},{}] steal=[{},{}]",
        s.initialized,
        s.boot_phase,
        s.blocked_tasks,
        s.pick_order[0].as_str(),
        s.pick_order[1].as_str(),
        s.pick_order[2].as_str(),
        s.steal_order[0].as_str(),
        s.steal_order[1].as_str()
    )
}

/// One entry per CPU: current task and the three run-queue depths.
fn scheduler_cpu_entry(s: &crate::process::SchedulerStateSnapshot, cpu: usize) -> String {
    format!(
        "cpu{} cur={} rq={}/{}/{} nr={}",
        cpu,
        s.current_task[cpu],
        s.rq_rt[cpu],
        s.rq_fair[cpu],
        s.rq_idle[cpu],
        if s.need_resched[cpu] { 1 } else { 0 }
    )
}

/// Packs the per-CPU entries into lines that fit `width` columns.
fn scheduler_cpu_lines(
    s: &crate::process::SchedulerStateSnapshot,
    cpus: usize,
    width: usize,
) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();

    for cpu in 0..cpus {
        let entry = scheduler_cpu_entry(s, cpu);
        if !current.is_empty() && current.chars().count() + 3 + entry.chars().count() > width {
            lines.push(core::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push_str(" | ");
        }
        current.push_str(&entry);
    }
    if !current.is_empty() {
        lines.push(current);
    }

    lines
}

/// The full scheduler block: runtime window, configuration, then CPU detail.
fn scheduler_lines(view: &TopView, width: usize) -> Vec<String> {
    let mut lines = scheduler_cpu_lines(&view.snapshot.scheduler, view.snapshot.cpu_count(), width);
    lines.insert(0, scheduler_config_line(&view.snapshot.scheduler));
    lines.insert(0, scheduler_window_line(&view.sched));
    lines
}

/// Memory ratio used by both presenters; 0 when the allocator is not up yet.
fn memory_ratio(snapshot: &TopSnapshot) -> f64 {
    if snapshot.total_pages == 0 {
        0.0
    } else {
        (snapshot.used_pages as f64 / snapshot.total_pages as f64).clamp(0.0, 1.0)
    }
}

/// Buddy page counters converted to bytes.
fn memory_bytes(snapshot: &TopSnapshot) -> (u64, u64) {
    let page = crate::memory::frame::PAGE_SIZE;
    (
        (snapshot.used_pages as u64).saturating_mul(page),
        (snapshot.total_pages as u64).saturating_mul(page),
    )
}

/// One line summarizing the per-CPU ratios: how many are shown, and the
/// spread between the least and the most loaded of them.
fn cpu_spread_line(view: &TopView, shown: usize) -> String {
    let count = shown.min(view.snapshot.cpu_count());
    if count == 0 {
        return String::from("CPU: n/a");
    }
    let mut min = f64::MAX;
    let mut max = 0.0f64;
    let mut sum = 0.0;
    for i in 0..count {
        let ratio = view.cpu.per_cpu_ratio[i];
        min = min.min(ratio);
        max = max.max(ratio);
        sum += ratio;
    }
    let avg = sum / count as f64;
    format!(
        "CPU: {} shown | min {:>3}% | avg {:>3}% | max {:>3}%",
        count,
        (min * 100.0) as u16,
        (avg * 100.0) as u16,
        (max * 100.0) as u16
    )
}

/// Per-CPU busy ratios, packed into lines that fit `width` columns.
///
/// Only the serial presenter needs this: the TUI has a gauge per CPU.
#[cfg(not(target_arch = "x86_64"))]
fn cpu_usage_lines(view: &TopView, width: usize) -> Vec<String> {
    let cpus = view.snapshot.cpu_count();
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();

    for cpu in 0..cpus {
        let entry = format!(
            "cpu{} {:>3}%",
            cpu,
            (view.cpu.per_cpu_ratio[cpu] * 100.0) as u16
        );
        if !current.is_empty() && current.chars().count() + 1 + entry.chars().count() > width {
            lines.push(core::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(&entry);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// `used/total` memory in human readable units.
fn memory_label(snapshot: &TopSnapshot) -> String {
    let (used, total) = memory_bytes(snapshot);
    format!(
        "{}/{}",
        crate::shell::output::human_bytes(used),
        crate::shell::output::human_bytes(total)
    )
}

/// Human readable silo memory budget, `mem_max == 0` meaning unlimited.
fn silo_memory_label(mem_max: u64) -> String {
    crate::shell::output::human_bytes_or_unlimited(mem_max)
}

/// System uptime, formatted the same way as the `uptime` command.
fn format_uptime(total_secs: u64) -> String {
    format!(
        "{:02}:{:02}:{:02}",
        total_secs / 3600,
        (total_secs % 3600) / 60,
        total_secs % 60
    )
}

/// Collects one view: a fresh snapshot plus the deltas since the last sample.
fn collect_view(
    prev_cpu: &mut crate::process::CpuUsageSnapshot,
    prev_sched: &mut crate::process::SchedulerMetricsSnapshot,
) -> TopView {
    let snapshot = collect_snapshot();
    let cpus = snapshot.cpu_count();

    let cpu_sample = crate::process::cpu_usage_snapshot();
    let cpu = compute_cpu_usage_window(prev_cpu, &cpu_sample, cpus);
    *prev_cpu = cpu_sample;

    let sched_sample = crate::process::scheduler_metrics_snapshot();
    let sched = compute_scheduler_metrics_window(prev_sched, &sched_sample, cpus);
    *prev_sched = sched_sample;

    let uptime_secs = crate::process::scheduler::ticks() / crate::arch::timer::TIMER_HZ;

    TopView {
        snapshot,
        cpu,
        sched,
        uptime_secs,
    }
}

/// Drains pending keystrokes, bounded so a key flood cannot starve rendering.
///
/// Returns `true` when the user asked to leave.
fn poll_input(selected: &mut usize) -> bool {
    if crate::shell::is_interrupted() {
        return true;
    }
    for _ in 0..MAX_KEYS_PER_ROUND {
        let Some(ch) = crate::arch::keyboard::read_char() else {
            return false;
        };
        match ch {
            b'q' | 0x1B | 0x03 => return true,
            crate::arch::keyboard::KEY_UP => *selected = selected.saturating_sub(1),
            crate::arch::keyboard::KEY_DOWN => *selected = selected.saturating_add(1),
            _ => {}
        }
    }
    false
}

/// Refresh loop shared by every presenter: input is polled on every pass so it
/// stays responsive between two frames, and a view is sampled every
/// `REFRESH_TICKS` ticks and handed to `present`.
fn run_presenter(
    mut present: impl FnMut(&TopView, usize) -> Result<(), ShellError>,
) -> Result<(), ShellError> {
    let mut prev_cpu = crate::process::cpu_usage_snapshot();
    let mut prev_sched = crate::process::scheduler_metrics_snapshot();
    let mut last_refresh = crate::process::scheduler::ticks();
    let mut selected = 0usize;

    loop {
        if poll_input(&mut selected) {
            break;
        }

        let ticks = crate::process::scheduler::ticks();
        if ticks.saturating_sub(last_refresh) < REFRESH_TICKS {
            crate::process::yield_task();
            continue;
        }
        last_refresh = ticks;

        let view = collect_view(&mut prev_cpu, &mut prev_sched);
        // The task list is resorted every frame, so the selection is only
        // meaningful once clamped to the rows that actually exist.
        selected = selected.min(view.snapshot.tasks.len().saturating_sub(1));
        present(&view, selected)?;

        crate::process::yield_task();
    }

    Ok(())
}

/// `top` main entry point.
pub fn cmd_top(_args: &[String]) -> Result<(), ShellError> {
    #[cfg(target_arch = "x86_64")]
    {
        tui::run()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        run_serial()
    }
}

/// Serial presenter for targets without a framebuffer console (R6: the virtio
/// console will get a TUI; until then the same view is printed as text).
#[cfg(not(target_arch = "x86_64"))]
fn run_serial() -> Result<(), ShellError> {
    shell_println!("top: framebuffer console unavailable, streaming to serial (q to quit)");
    run_presenter(|view, selected| {
        render_serial(view, selected);
        Ok(())
    })
}

/// Renders one serial frame.
#[cfg(not(target_arch = "x86_64"))]
fn render_serial(view: &TopView, selected: usize) {
    let s = &view.snapshot;
    let ratio = memory_ratio(s);

    shell_println!(
        "== Strat9 top | cpus {} | tasks {} | silos {} | strates {} | cpu(avg) {:>3}% | up {} ==",
        s.cpu_count(),
        s.tasks.len(),
        s.silos.len(),
        s.strates.len(),
        (view.cpu.avg_ratio * 100.0) as u16,
        format_uptime(view.uptime_secs)
    );
    shell_println!(
        "Mem: {} ({:.1}%) | {}",
        memory_label(s),
        ratio * 100.0,
        cpu_spread_line(view, s.cpu_count())
    );
    for line in cpu_usage_lines(view, SERIAL_COLS) {
        shell_println!("{}", line);
    }
    for line in scheduler_lines(view, SERIAL_COLS) {
        shell_println!("{}", line);
    }

    shell_println!(
        "{:>5} {:<18} {:<8} {:<5} {:>10}",
        "PID",
        "NAME",
        "STATE",
        "PRIO",
        "TICKS"
    );
    for (i, task) in s.tasks.iter().enumerate() {
        shell_println!(
            "{:>5} {:<18} {:<8} {:<5} {:>10}{}",
            task.pid,
            task.name,
            task_state_label(task.state),
            format!("{:?}", task.priority),
            task.ticks,
            if i == selected { "  <" } else { "" }
        );
    }

    if !s.silos.is_empty() {
        shell_println!(
            "{:>4} {:<12} {:<9} {:>4} {:>8} {:<10} {}",
            "SID",
            "NAME",
            "STATE",
            "T",
            "MEM",
            "MAX",
            "STRATE"
        );
        for silo in &s.silos {
            shell_println!(
                "{:>4} {:<12} {:<9} {:>4} {:>8} {:<10} {}",
                silo.sid,
                silo.name,
                silo_state_label(silo.state),
                silo.tasks,
                crate::shell::output::human_bytes(silo.mem_used),
                silo_memory_label(silo.mem_max),
                silo.strate
            );
        }
    }

    if !s.strates.is_empty() {
        shell_println!("{:<14} {}", "STRATE", "BELONGS TO");
        for strate in &s.strates {
            shell_println!("{:<14} {}", strate.name, strate.silos);
        }
    }
}

/// Shared task state label, so both presenters render the same words.
fn task_state_label(state: crate::process::TaskState) -> &'static str {
    match state {
        crate::process::TaskState::Ready => "Ready",
        crate::process::TaskState::Running => "Running",
        crate::process::TaskState::Blocked => "Blocked",
        crate::process::TaskState::Dead => "Dead",
    }
}

/// Shared silo state label, so both presenters render the same words.
fn silo_state_label(state: crate::silo::SiloState) -> &'static str {
    match state {
        crate::silo::SiloState::Created => "Created",
        crate::silo::SiloState::Loading => "Loading",
        crate::silo::SiloState::Ready => "Ready",
        crate::silo::SiloState::Running => "Running",
        crate::silo::SiloState::Paused => "Paused",
        crate::silo::SiloState::Stopping => "Stopping",
        crate::silo::SiloState::Stopped => "Stopped",
        crate::silo::SiloState::Crashed => "Crashed",
        crate::silo::SiloState::Zombie => "Zombie",
        crate::silo::SiloState::Destroyed => "Destroyed",
    }
}
