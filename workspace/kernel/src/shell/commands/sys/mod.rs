//! System management commands
mod clear;
mod cpuinfo;
mod frame_meta;
mod health;
mod heap;
mod reboot;
mod scheduler;
mod shutdown;
mod silo_attach;
#[path = "silo.rs"]
mod silo_cmd;
mod silo_limit;
mod silos;
mod strate;
mod test_exec;
mod test_mem;
mod test_mem_region;
mod test_mem_region_proc;
mod test_mem_stressed;
mod test_pid;
mod test_syscalls;
mod trace;
mod version;
mod wasm_run;
pub use clear::cmd_clear;
pub use cpuinfo::cmd_cpuinfo;
pub use frame_meta::cmd_frame_meta;
pub use health::cmd_health;
pub use heap::cmd_heap;
pub use reboot::cmd_reboot;
pub use scheduler::cmd_scheduler;
pub use shutdown::cmd_shutdown;
pub use silo_cmd::cmd_silo;
pub use silos::cmd_silos;
pub use strate::cmd_strate;
pub use test_exec::cmd_test_exec;
pub use test_mem::cmd_test_mem;
pub use test_mem_region::cmd_test_mem_region;
pub use test_mem_region_proc::cmd_test_mem_region_proc;
pub use test_mem_stressed::cmd_test_mem_stressed;
pub use test_pid::cmd_test_pid;
pub use test_syscalls::cmd_test_syscalls;
pub use trace::cmd_trace;
pub use version::cmd_version;
pub use wasm_run::cmd_wasm_run;

#[cfg(target_arch = "x86_64")]
use crate::shell::commands::top::Strat9RatatuiBackend;
use silo_attach::cmd_silo_attach;
use silo_limit::cmd_silo_limit;

#[cfg(target_arch = "x86_64")]
use crate::arch::vga;
use crate::{
    memory,
    process::elf::load_and_run_elf,
    shell::{output::clear_screen, ShellError},
    shell_println, silo, vfs,
};
use alloc::{string::String, vec::Vec};
#[cfg(target_arch = "x86_64")]
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Terminal,
};

/// Top-level command a subcommand was reached through.
///
/// `silo <x>` and `strate <x>` share one implementation, so messages and usage
/// have to name the command the user actually typed: `strate pledge` used to
/// answer "silo pledge: ..." because the literal was baked into the function.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Cmd {
    Silo,
    Strate,
}

impl Cmd {
    fn name(self) -> &'static str {
        match self {
            Cmd::Silo => "silo",
            Cmd::Strate => "strate",
        }
    }
}
const DEFAULT_MANAGED_SILO_TOML: &str = r#"
[[silos]]
name = "console-admin"
family = "SYS"
mode = "700"
sid = 42
[[silos.strates]]
name = "console-admin"
binary = "/initfs/console-admin"
type = "elf"

[[silos]]
name = "bus"
family = "DRV"
mode = "076"
sid = 42
[[silos.strates]]
name = "strate-bus"
binary = "/initfs/strate-bus"
type = "elf"

[[silos]]
name = "network"
family = "NET"
mode = "076"
sid = 42
[[silos.strates]]
name = "strate-net"
binary = "/initfs/strate-net"
type = "elf"

[[silos]]
name = "dhcp-client"
family = "NET"
mode = "076"
sid = 42
[[silos.strates]]
name = "dhcp-client"
binary = "/initfs/bin/dhcp-client"
type = "elf"

[[silos]]
name = "telnet"
family = "NET"
mode = "076"
sid = 42
[[silos.strates]]
name = "telnetd"
binary = "/initfs/bin/telnetd"
type = "elf"

[[silos]]
name = "web-admin"
family = "NET"
mode = "076"
sid = 42
graphics_enabled = true
graphics_mode = "webrtc-native"
graphics_max_sessions = 1
graphics_session_ttl_sec = 1800
graphics_turn_policy = "auto"
[[silos.strates]]
name = "web-admin"
binary = "/initfs/bin/web-admin"
type = "elf"

[[silos]]
name = "graphics-webrtc"
family = "NET"
mode = "076"
sid = 42
[[silos.strates]]
name = "strate-webrtc"
binary = "/initfs/strate-webrtc"
type = "elf"
"#;

#[derive(Clone)]
struct ManagedStrateDef {
    name: String,
    binary: String,
    stype: String,
    target: String,
    /// Extra key read by `strate-bus` out of the boot config. The shell never
    /// interprets it, but it must survive the parse/emit round-trip: dropping
    /// it would silently reset the bus probe mode on `silo config add`.
    probe_mode: String,
}

#[derive(Clone)]
struct ManagedSiloDef {
    name: String,
    sid: u32,
    family: String,
    mode: String,
    cpu_features: String,
    graphics_enabled: bool,
    graphics_mode: String,
    graphics_read_only: bool,
    graphics_max_sessions: u16,
    graphics_session_ttl_sec: u32,
    graphics_turn_policy: String,
    strates: Vec<ManagedStrateDef>,
}

/// Parses silo toml.
fn parse_silo_toml(data: &str) -> Vec<ManagedSiloDef> {
    #[derive(Clone, Copy)]
    enum Section {
        Silo,
        Strate,
    }

    /// Performs the push default strate operation.
    fn push_default_strate(silo: &mut ManagedSiloDef) {
        silo.strates.push(ManagedStrateDef {
            name: String::new(),
            binary: String::new(),
            stype: String::from("elf"),
            target: String::from("default"),
            probe_mode: String::new(),
        });
    }

    let mut silos = Vec::new();
    let mut current_silo: Option<ManagedSiloDef> = None;
    let mut section = Section::Silo;

    for raw_line in data.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[silos]]" {
            if let Some(s) = current_silo.take() {
                silos.push(s);
            }
            current_silo = Some(ManagedSiloDef {
                name: String::new(),
                sid: 42,
                family: String::from("USR"),
                mode: String::from("000"),
                cpu_features: String::new(),
                graphics_enabled: false,
                graphics_mode: String::new(),
                graphics_read_only: false,
                graphics_max_sessions: 0,
                graphics_session_ttl_sec: 0,
                graphics_turn_policy: String::from("auto"),
                strates: Vec::new(),
            });
            section = Section::Silo;
            continue;
        }
        if line == "[[silos.strates]]" {
            if let Some(ref mut s) = current_silo {
                push_default_strate(s);
            }
            section = Section::Strate;
            continue;
        }
        if let Some(idx) = line.find('=') {
            let key = line[..idx].trim();
            let val = line[idx + 1..].trim().trim_matches('"');
            if let Some(ref mut s) = current_silo {
                match section {
                    Section::Silo => match key {
                        "name" => s.name = String::from(val),
                        "sid" => s.sid = val.parse().unwrap_or(CONFIG_SID_PLACEHOLDER),
                        "family" => s.family = String::from(val),
                        "mode" => s.mode = String::from(val),
                        "cpu_features" => s.cpu_features = String::from(val),
                        "graphics_enabled" => {
                            s.graphics_enabled = matches!(val, "true" | "True" | "TRUE" | "1")
                        }
                        "graphics_mode" => s.graphics_mode = String::from(val),
                        "graphics_read_only" => {
                            s.graphics_read_only = matches!(val, "true" | "True" | "TRUE" | "1")
                        }
                        "graphics_max_sessions" => {
                            s.graphics_max_sessions = val.parse().unwrap_or(0)
                        }
                        "graphics_session_ttl_sec" => {
                            s.graphics_session_ttl_sec = val.parse().unwrap_or(0)
                        }
                        "graphics_turn_policy" => s.graphics_turn_policy = String::from(val),
                        _ => {}
                    },
                    Section::Strate => {
                        if s.strates.is_empty() {
                            push_default_strate(s);
                        }
                        if let Some(st) = s.strates.last_mut() {
                            match key {
                                "name" => st.name = String::from(val),
                                "binary" => st.binary = String::from(val),
                                "type" => st.stype = String::from(val),
                                "target_strate" => st.target = String::from(val),
                                "probe_mode" => st.probe_mode = String::from(val),
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    }

    if let Some(s) = current_silo {
        silos.push(s);
    }
    silos
}

/// Performs the render silo toml operation.
fn render_silo_toml(silos: &[ManagedSiloDef]) -> String {
    use core::fmt::Write;
    let mut out = String::new();
    for (i, s) in silos.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let _ = writeln!(out, "[[silos]]");
        let _ = writeln!(out, "name = \"{}\"", s.name);
        let _ = writeln!(out, "sid = {}", s.sid);
        let _ = writeln!(out, "family = \"{}\"", s.family);
        let _ = writeln!(out, "mode = \"{}\"", s.mode);
        if !s.cpu_features.is_empty() {
            let _ = writeln!(out, "cpu_features = \"{}\"", s.cpu_features);
        }
        if s.graphics_enabled {
            let _ = writeln!(out, "graphics_enabled = true");
            let mode = if s.graphics_mode.is_empty() {
                "webrtc-native"
            } else {
                s.graphics_mode.as_str()
            };
            let _ = writeln!(out, "graphics_mode = \"{}\"", mode);
            if s.graphics_read_only {
                let _ = writeln!(out, "graphics_read_only = true");
            }
            if s.graphics_max_sessions != 0 {
                let _ = writeln!(out, "graphics_max_sessions = {}", s.graphics_max_sessions);
            }
            if s.graphics_session_ttl_sec != 0 {
                let _ = writeln!(
                    out,
                    "graphics_session_ttl_sec = {}",
                    s.graphics_session_ttl_sec
                );
            }
            if s.graphics_turn_policy != "auto" && !s.graphics_turn_policy.is_empty() {
                let _ = writeln!(out, "graphics_turn_policy = \"{}\"", s.graphics_turn_policy);
            }
        }
        for st in &s.strates {
            out.push('\n');
            let _ = writeln!(out, "[[silos.strates]]");
            let _ = writeln!(out, "name = \"{}\"", st.name);
            let _ = writeln!(out, "binary = \"{}\"", st.binary);
            let _ = writeln!(out, "type = \"{}\"", st.stype);
            let _ = writeln!(out, "target_strate = \"{}\"", st.target);
            if !st.probe_mode.is_empty() {
                let _ = writeln!(out, "probe_mode = \"{}\"", st.probe_mode);
            }
        }
    }
    out
}

/// Boot config path, and the label reported when it is the effective source.
const CONFIG_PATH: &str = "/initfs/silo.toml";
/// Source label when the effective config is the embedded fallback.
const CONFIG_SOURCE_EMBEDDED: &str = "embedded-default";
/// Config `sid` value meaning "let userspace allocate the runtime id".
const CONFIG_SID_PLACEHOLDER: u32 = 42;

/// Reads silo toml from initfs.
fn read_silo_toml_from_initfs() -> Result<String, ShellError> {
    match vfs::open(CONFIG_PATH, vfs::OpenFlags::READ) {
        Ok(fd) => {
            let data = vfs::read_all(fd).map_err(|_| ShellError::ExecutionFailed)?;
            let _ = vfs::close(fd);
            let text = core::str::from_utf8(&data).map_err(|_| ShellError::ExecutionFailed)?;
            Ok(String::from(text))
        }
        Err(crate::syscall::error::SyscallError::NotFound) => Ok(String::new()),
        Err(_) => Err(ShellError::ExecutionFailed),
    }
}

/// Loads the effective managed-silo config and names the source it came from.
///
/// Single entry point for every command that reports or edits the config
/// (`list`, `config show`, `config add`, `config remove`, selector resolution),
/// so they cannot disagree about what the config is.
fn load_managed_silos_with_source() -> (Vec<ManagedSiloDef>, &'static str) {
    let parsed = read_silo_toml_from_initfs().map(|text| parse_silo_toml(&text));
    match parsed {
        Ok(silos) if !silos.is_empty() => (silos, CONFIG_PATH),
        _ => (
            parse_silo_toml(DEFAULT_MANAGED_SILO_TOML),
            CONFIG_SOURCE_EMBEDDED,
        ),
    }
}

/// Families the kernel accepts, from `silo::StrateFamily`.
///
/// The config stores the family as a string, so an unknown value used to be
/// written straight into the boot config and only failed much later, when
/// userspace tried to resolve it.
const CONFIG_FAMILIES: &[&str] = &["SYS", "DRV", "FS", "NET", "WASM", "USR"];

/// Strate binary types the boot config understands.
const CONFIG_STRATE_TYPES: &[&str] = &["elf", "wasm"];

/// True when a family is allocated from the system sid range.
///
/// Mirrors `strate-init`'s allocator: the two must agree or the shell points
/// commands at the wrong silo.
fn family_uses_system_sid(family: &str) -> bool {
    matches!(family, "SYS" | "DRV" | "NET" | "FS")
}

fn compute_managed_runtime_sids(managed: &[ManagedSiloDef]) -> Vec<(String, u32)> {
    // Sort references, not clones: the deep clone of the whole config model
    // (every String and every Vec) is pure waste for a read-only pass.
    let mut ordered: Vec<&ManagedSiloDef> = managed.iter().collect();
    ordered.sort_by_key(|s| if s.name == "bus" { 0u8 } else { 1u8 });

    let mut next_sys_sid = 100u32;
    let mut next_usr_sid = 1000u32;
    let mut mappings = Vec::with_capacity(ordered.len());

    for silo in ordered {
        let sid = if silo.sid == CONFIG_SID_PLACEHOLDER {
            if family_uses_system_sid(&silo.family) {
                let id = next_sys_sid;
                next_sys_sid += 1;
                id
            } else {
                let id = next_usr_sid;
                next_usr_sid += 1;
                id
            }
        } else {
            silo.sid
        };
        mappings.push((silo.name.clone(), sid));
    }

    mappings
}

fn managed_name_for_runtime_sid(
    managed_runtime_sids: &[(String, u32)],
    sid: u32,
) -> Option<String> {
    managed_runtime_sids
        .iter()
        .find(|(_, mapped_sid)| *mapped_sid == sid)
        .map(|(name, _)| name.clone())
}

/// Runtime sid a config entry was allocated, if the allocator assigned one.
fn managed_sid_for(managed_runtime_sids: &[(String, u32)], name: &str) -> Option<u32> {
    managed_runtime_sids
        .iter()
        .find(|(mapped_name, _)| mapped_name == name)
        .map(|(_, sid)| *sid)
}

/// Config entry that owns a runtime silo, resolved through the name→sid map.
///
/// This is the single rule used by `silo list`, `strate list` and `silo info`:
/// matching a runtime silo by config *name* instead would silently pick the
/// wrong entry, since userspace allocates the runtime sid.
fn managed_def_for_runtime_sid<'a>(
    managed: &'a [ManagedSiloDef],
    managed_runtime_sids: &[(String, u32)],
    sid: u32,
) -> Option<&'a ManagedSiloDef> {
    let name = managed_name_for_runtime_sid(managed_runtime_sids, sid)?;
    managed.iter().find(|m| m.name == name)
}

/// Strates declared by the config entry that owns a runtime silo.
fn config_strates_for_sid(
    managed: &[ManagedSiloDef],
    managed_runtime_sids: &[(String, u32)],
    sid: u32,
) -> Vec<String> {
    let Some(def) = managed_def_for_runtime_sid(managed, managed_runtime_sids, sid) else {
        return Vec::new();
    };
    let mut strates = Vec::with_capacity(def.strates.len());
    for st in &def.strates {
        if !st.name.is_empty() {
            push_unique(&mut strates, &st.name);
        }
    }
    strates
}

fn normalize_silo_selector(selector: &str, managed_runtime_sids: &[(String, u32)]) -> String {
    if selector.parse::<u32>().is_ok() {
        return String::from(selector);
    }

    managed_runtime_sids
        .iter()
        .find(|(name, _)| name == selector)
        .map(|(_, sid)| alloc::format!("{}", sid))
        .unwrap_or_else(|| String::from(selector))
}

/// Maps a user-typed selector onto something the kernel can resolve.
///
/// A numeric selector is already a runtime sid: pass it straight through
/// without reading and re-parsing the boot config. Only a name needs the
/// config→runtime-sid map, because the kernel does not know the config names.
///
/// Note the config map is a shell-side *guess* at the ids userspace allocated
/// at boot (`compute_managed_runtime_sids` mirrors `strate-init`'s allocator);
/// anything not numeric is also handed to the kernel, which resolves by id or
/// by `strate_label`.
fn normalize_current_silo_selector(selector: &str) -> String {
    if selector.parse::<u32>().is_ok() {
        return String::from(selector);
    }
    let (managed, _) = load_managed_silos_with_source();
    let managed_runtime_sids = compute_managed_runtime_sids(&managed);
    normalize_silo_selector(selector, &managed_runtime_sids)
}

/// Performs the push unique operation.
fn push_unique(values: &mut Vec<String>, item: &str) {
    if !values.iter().any(|v| v == item) {
        values.push(String::from(item));
    }
}

/// Performs the join csv operation.
fn join_csv(values: &[String]) -> String {
    if values.is_empty() {
        return String::from("-");
    }
    let mut out = String::new();
    for (i, v) in values.iter().enumerate() {
        if i != 0 {
            out.push_str(", ");
        }
        out.push_str(v);
    }
    out
}

/// `used / max` memory cell, `mem_max == 0` meaning "no upper bound".
fn memory_cell(mem_used: u64, mem_max: u64) -> String {
    alloc::format!(
        "{} / {}",
        crate::shell::output::human_bytes(mem_used),
        crate::shell::output::human_bytes_or_unlimited(mem_max)
    )
}

/// Silo state label, so every command spells a state the same way.
fn silo_state_str(state: silo::SiloState) -> &'static str {
    match state {
        silo::SiloState::Created => "Created",
        silo::SiloState::Loading => "Loading",
        silo::SiloState::Ready => "Ready",
        silo::SiloState::Running => "Running",
        silo::SiloState::Paused => "Paused",
        silo::SiloState::Stopping => "Stopping",
        silo::SiloState::Stopped => "Stopped",
        silo::SiloState::Crashed => "Crashed",
        silo::SiloState::Zombie => "Zombie",
        silo::SiloState::Destroyed => "Destroyed",
    }
}

/// Silo tier label.
fn silo_tier_str(tier: silo::SiloTier) -> &'static str {
    match tier {
        silo::SiloTier::Critical => "Critical",
        silo::SiloTier::System => "System",
        silo::SiloTier::User => "User",
    }
}

/// Strate family label.
fn strate_family_str(family: silo::StrateFamily) -> &'static str {
    match family {
        silo::StrateFamily::SYS => "SYS",
        silo::StrateFamily::DRV => "DRV",
        silo::StrateFamily::FS => "FS",
        silo::StrateFamily::NET => "NET",
        silo::StrateFamily::WASM => "WASM",
        silo::StrateFamily::USR => "USR",
    }
}

/// Graphics mode decoded from the silo flag bitmask, using the kernel's own
/// flag names instead of hardcoded shifts.
fn graphics_mode_str(graphics_flags: u64) -> &'static str {
    if graphics_flags & silo::SILO_FLAG_WEBRTC_NATIVE != 0 {
        "webrtc-native"
    } else if graphics_flags & silo::SILO_FLAG_GRAPHICS != 0 {
        "graphics-raw"
    } else {
        "disabled"
    }
}

fn flag_str(set: bool) -> &'static str {
    if set {
        "true"
    } else {
        "false"
    }
}

/// Row of the runtime silo table.
///
/// Holds raw `Copy` values and defers every formatting to the presenter, so
/// switching presenter costs no `format!` per row per field.
struct SiloListRow {
    sid: u32,
    name: String,
    state: silo::SiloState,
    tasks: usize,
    mem_used: u64,
    /// `0` means the silo declared no upper bound.
    mem_max: u64,
    mode: u16,
    /// Declared strate label, `None` when the silo has none.
    label: Option<String>,
    /// Strates this silo runs, from the boot config.
    strates: Vec<String>,
    /// Set when the kernel reports a label that the boot config does not know
    /// about, so the row is rendered as incomplete instead of silently blank.
    kernel_only_strate: bool,
}

struct RuntimeStrateRow {
    strate: String,
    belongs_to: String,
    status: &'static str,
}

struct ConfigStrateRow {
    strate: String,
    belongs_to: String,
}

struct ConfigListRow {
    sid: u32,
    name: String,
    family: String,
    mode: String,
    cpu_features: String,
    strates: Vec<String>,
}

/// The strates of a silo as they will be displayed, or `None` when the silo
/// has none at all (used to pick the "incomplete" colour).
fn silo_strates_cell(row: &SiloListRow) -> String {
    if !row.strates.is_empty() {
        return join_csv(&row.strates);
    }
    if row.kernel_only_strate {
        return match row.label.as_deref() {
            Some(label) => alloc::format!("{} (kernel)", label),
            None => String::from("-"),
        };
    }
    String::from("-")
}

/// Performs the render silo table ratatui operation.
#[cfg(target_arch = "x86_64")]
fn render_silo_table_ratatui(
    runtime_rows: &[SiloListRow],
    config_rows: &[ConfigListRow],
    config_source: &str,
) -> Result<bool, ShellError> {
    if !vga::is_available() {
        return Ok(false);
    }

    let backend = Strat9RatatuiBackend::new().map_err(|_| ShellError::ExecutionFailed)?;
    let mut terminal = Terminal::new(backend).map_err(|_| ShellError::ExecutionFailed)?;
    terminal.clear().map_err(|_| ShellError::ExecutionFailed)?;

    let runtime_table_rows: Vec<Row> = runtime_rows
        .iter()
        .map(|r| {
            let strates = silo_strates_cell(r);
            // Red: the silo has no strate the boot config knows about.
            let style = if r.strates.is_empty() {
                Style::default().fg(Color::LightRed)
            } else {
                Style::default().fg(Color::LightGreen)
            };
            Row::new(alloc::vec![
                Cell::from(alloc::format!("{}", r.sid)),
                Cell::from(r.name.as_str()),
                Cell::from(silo_state_str(r.state)),
                Cell::from(alloc::format!("{}", r.tasks)),
                Cell::from(memory_cell(r.mem_used, r.mem_max)),
                Cell::from(alloc::format!("{:o}", r.mode)),
                Cell::from(r.label.as_deref().unwrap_or("-")),
                Cell::from(strates),
            ])
            .style(style)
        })
        .collect();
    let config_table_rows: Vec<Row> = config_rows
        .iter()
        .map(|r| {
            Row::new(alloc::vec![
                Cell::from(alloc::format!("{}", r.sid)),
                Cell::from(r.name.as_str()),
                Cell::from(r.family.as_str()),
                Cell::from(r.mode.as_str()),
                Cell::from(r.cpu_features.as_str()),
                Cell::from(join_csv(&r.strates)),
            ])
            .style(Style::default().fg(Color::LightCyan))
        })
        .collect();

    let frame_started = vga::begin_frame();
    terminal
        .draw(|f| {
            let area = f.area();
            let vertical = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(2),
                    Constraint::Min(10),
                    Constraint::Length(10),
                    Constraint::Length(1),
                ])
                .split(area);

            let title = Paragraph::new("Silo List")
                .style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
                .block(Block::default().borders(Borders::BOTTOM).title("Strat9"));
            f.render_widget(title, vertical[0]);

            let widths = [
                Constraint::Length(6),
                Constraint::Length(12),
                Constraint::Length(10),
                Constraint::Length(7),
                Constraint::Length(18),
                Constraint::Length(6),
                Constraint::Length(12),
                Constraint::Min(20),
            ];
            let runtime_table = Table::new(runtime_table_rows, widths)
                .header(
                    Row::new(alloc::vec![
                        Cell::from("SID"),
                        Cell::from("Name"),
                        Cell::from("State"),
                        Cell::from("Tasks"),
                        Cell::from("Memory"),
                        Cell::from("Mode"),
                        Cell::from("Label"),
                        Cell::from("Strates"),
                    ])
                    .style(
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                )
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Runtime")
                        .border_style(Style::default().fg(Color::Green)),
                )
                .column_spacing(1);
            f.render_widget(runtime_table, vertical[1]);

            let config_widths = [
                Constraint::Length(6),
                Constraint::Length(14),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(11),
                Constraint::Min(20),
            ];
            let config_table = Table::new(config_table_rows, config_widths)
                .header(
                    Row::new(alloc::vec![
                        Cell::from("SID"),
                        Cell::from("Name"),
                        Cell::from("Family"),
                        Cell::from("Mode"),
                        Cell::from("CPU feats"),
                        Cell::from("Strates"),
                    ])
                    .style(
                        Style::default()
                            .fg(Color::Magenta)
                            .add_modifier(Modifier::BOLD),
                    ),
                )
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(alloc::format!("Config ({})", config_source))
                        .border_style(Style::default().fg(Color::Magenta)),
                )
                .column_spacing(1);
            f.render_widget(config_table, vertical[2]);

            let footer = Paragraph::new("runtime vert=associe | runtime rouge=incomplet")
                .style(Style::default().fg(Color::DarkGray));
            f.render_widget(footer, vertical[3]);
        })
        .map_err(|_| ShellError::ExecutionFailed)?;
    if frame_started {
        vga::end_frame();
    } else {
        vga::present();
    }
    Ok(true)
}

#[cfg(not(target_arch = "x86_64"))]
fn render_silo_table_ratatui(
    _runtime_rows: &[SiloListRow],
    _config_rows: &[ConfigListRow],
    _config_source: &str,
) -> Result<bool, ShellError> {
    Ok(false)
}

/// Performs the render strate table ratatui operation.
#[cfg(target_arch = "x86_64")]
fn render_strate_table_ratatui(
    runtime_rows: &[RuntimeStrateRow],
    config_rows: &[ConfigStrateRow],
    config_source: &str,
) -> Result<bool, ShellError> {
    if !vga::is_available() {
        return Ok(false);
    }

    let backend = Strat9RatatuiBackend::new().map_err(|_| ShellError::ExecutionFailed)?;
    let mut terminal = Terminal::new(backend).map_err(|_| ShellError::ExecutionFailed)?;
    terminal.clear().map_err(|_| ShellError::ExecutionFailed)?;

    let runtime_table_rows: Vec<Row> = runtime_rows
        .iter()
        .map(|r| {
            let style = if r.status == "config+runtime" {
                Style::default().fg(Color::LightGreen)
            } else {
                Style::default().fg(Color::LightYellow)
            };
            Row::new(alloc::vec![
                Cell::from(r.strate.as_str()),
                Cell::from(r.belongs_to.as_str()),
                Cell::from(r.status),
            ])
            .style(style)
        })
        .collect();
    let config_table_rows: Vec<Row> = config_rows
        .iter()
        .map(|r| {
            Row::new(alloc::vec![
                Cell::from(r.strate.as_str()),
                Cell::from(r.belongs_to.as_str()),
            ])
            .style(Style::default().fg(Color::LightCyan))
        })
        .collect();

    let frame_started = vga::begin_frame();
    terminal
        .draw(|f| {
            let area = f.area();
            let vertical = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(2),
                    Constraint::Min(8),
                    Constraint::Length(8),
                    Constraint::Length(1),
                ])
                .split(area);

            let title = Paragraph::new("Strate List")
                .style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
                .block(Block::default().borders(Borders::BOTTOM).title("Strat9"));
            f.render_widget(title, vertical[0]);

            let runtime_widths = [
                Constraint::Length(22),
                Constraint::Min(24),
                Constraint::Length(16),
            ];
            let runtime_table = Table::new(runtime_table_rows, runtime_widths)
                .header(
                    Row::new(alloc::vec![
                        Cell::from("Strate"),
                        Cell::from("BelongsTo"),
                        Cell::from("Status"),
                    ])
                    .style(
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                )
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Runtime")
                        .border_style(Style::default().fg(Color::Green)),
                )
                .column_spacing(2);
            f.render_widget(runtime_table, vertical[1]);

            let config_widths = [Constraint::Length(22), Constraint::Min(24)];
            let config_table = Table::new(config_table_rows, config_widths)
                .header(
                    Row::new(alloc::vec![Cell::from("Strate"), Cell::from("BelongsTo")]).style(
                        Style::default()
                            .fg(Color::Magenta)
                            .add_modifier(Modifier::BOLD),
                    ),
                )
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(alloc::format!("Config ({})", config_source))
                        .border_style(Style::default().fg(Color::Magenta)),
                )
                .column_spacing(2);
            f.render_widget(config_table, vertical[2]);

            let footer = Paragraph::new("vert=config+runtime, jaune=runtime-only")
                .style(Style::default().fg(Color::DarkGray));
            f.render_widget(footer, vertical[3]);
        })
        .map_err(|_| ShellError::ExecutionFailed)?;
    if frame_started {
        vga::end_frame();
    } else {
        vga::present();
    }
    Ok(true)
}

#[cfg(not(target_arch = "x86_64"))]
fn render_strate_table_ratatui(
    _runtime_rows: &[RuntimeStrateRow],
    _config_rows: &[ConfigStrateRow],
    _config_source: &str,
) -> Result<bool, ShellError> {
    Ok(false)
}

/// Writes silo toml to initfs.
fn write_silo_toml_to_initfs(text: &str) -> Result<(), ShellError> {
    let fd = vfs::open(
        CONFIG_PATH,
        vfs::OpenFlags::WRITE | vfs::OpenFlags::CREATE | vfs::OpenFlags::TRUNCATE,
    )
    .map_err(|_| ShellError::ExecutionFailed)?;
    let bytes = text.as_bytes();
    let mut written = 0usize;
    while written < bytes.len() {
        let n = vfs::write(fd, &bytes[written..]).map_err(|_| ShellError::ExecutionFailed)?;
        if n == 0 {
            let _ = vfs::close(fd);
            return Err(ShellError::ExecutionFailed);
        }
        written += n;
    }
    let _ = vfs::close(fd);
    Ok(())
}

/// Performs the print strate state for sid operation.
fn print_strate_state_for_sid(sid: u32) {
    match silo::silo_state_by_id(sid) {
        Some(state) => shell_println!("state: {}", silo_state_str(state)),
        None => shell_println!("state: <unknown>"),
    }
}

/// Subcommands shared by `silo` and `strate`: verb group, then its arguments.
const SHARED_SUBCOMMANDS: &[(&str, &str)] = &[
    ("list", "[--gui]"),
    (
        "spawn",
        "<path|strate-name> [--label <l>] [--dev <p>] [--type elf|wasm]",
    ),
    ("start", "<id|label|name>"),
    ("stop|kill|destroy", "<id|label|name>"),
    ("rename", "<id|label|name> <new_label>"),
    (
        "config",
        "show [silo] | add <silo> <name> <binary> [opts] | remove <silo> <name>",
    ),
    ("info", "<id|label|name>"),
    ("suspend|resume", "<id|label|name>"),
    ("events", "[id|label|name]"),
    ("pledge", "<id|label|name> <octal_mode>"),
    ("unveil", "<id|label|name> <path> <rwx>"),
    ("sandbox", "<id|label|name>"),
    (
        "limit",
        "<id|label|name> <mem_max|mem_min|max_tasks|cpu_shares> <value>",
    ),
    ("attach", "<id|label|name>"),
    ("top", "[--sort mem|tasks]"),
    ("logs", "<id|label|name>"),
];

/// Usage for `silo` and `strate`.
///
/// Both expose the same subcommand set, so the list lives in one place: the two
/// former `*_USAGE` constants were byte-identical, and `print_strate_usage` had
/// drifted by omitting `limit` and `attach` even though both were dispatched.
fn print_cmd_usage(cmd: Cmd) {
    let name = cmd.name();
    let mut verbs: Vec<&str> = Vec::with_capacity(SHARED_SUBCOMMANDS.len());
    for (group, _) in SHARED_SUBCOMMANDS {
        verbs.extend(group.split('|'));
    }
    shell_println!("Usage: {} <{}> ...", name, verbs.join("|"));
    for (group, shape) in SHARED_SUBCOMMANDS {
        if shape.is_empty() {
            shell_println!("  {} {}", name, group);
        } else {
            shell_println!("  {} {} {}", name, group, shape);
        }
    }
}

pub(super) fn cmd_silo_impl(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        print_cmd_usage(Cmd::Silo);
        return Err(ShellError::InvalidArguments);
    }
    match args[0].as_str() {
        "list" => cmd_silo_list(args, Cmd::Silo),
        "info" => cmd_silo_info(args, Cmd::Silo),
        "suspend" => cmd_silo_suspend(args, Cmd::Silo),
        "resume" => cmd_silo_resume(args, Cmd::Silo),
        "events" => cmd_silo_events(args, Cmd::Silo),
        "pledge" => cmd_silo_pledge(args, Cmd::Silo),
        "unveil" => cmd_silo_unveil(args, Cmd::Silo),
        "sandbox" => cmd_silo_sandbox(args, Cmd::Silo),
        "limit" => cmd_silo_limit(args, Cmd::Silo),
        "attach" => cmd_silo_attach(args, Cmd::Silo),
        "top" => cmd_silo_top(args, Cmd::Silo),
        "logs" => cmd_silo_logs(args, Cmd::Silo),
        "spawn" | "start" | "stop" | "kill" | "destroy" | "rename" | "config" => {
            cmd_strate_impl(args, Cmd::Silo)
        }
        _ => {
            print_cmd_usage(Cmd::Silo);
            Err(ShellError::InvalidArguments)
        }
    }
}

/// `silos` is an alias for `silo list`.
///
/// Args are forwarded as-is (`cmd_silo_list` skips the command word), so
/// `silos --gui` works and no argument vector is rebuilt.
pub(super) fn cmd_silos_impl(args: &[String]) -> Result<(), ShellError> {
    cmd_silo_list(args, Cmd::Silo)
}

/// Display kernel version
pub(super) fn cmd_version_impl(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("Strat9-OS v0.1.0 (Bedrock)");
    shell_println!("Build: x86_64-unknown-none");
    shell_println!("Features: SMP, APIC, VirtIO, IPC, Schemes");
    Ok(())
}

/// Clear the screen
pub(super) fn cmd_clear_impl(_args: &[String]) -> Result<(), ShellError> {
    clear_screen();
    Ok(())
}

/// Display CPU information
pub(super) fn cmd_cpuinfo_impl(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("CPU information:");

    if crate::arch::apic::is_initialized() {
        let lapic_id = crate::arch::apic::lapic_id();
        let cpu_count = crate::arch::percpu::cpu_count();
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

/// Reboot the system.
pub(super) fn cmd_reboot_impl(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("Rebooting system...");
    #[cfg(target_arch = "x86_64")]
    unsafe {
        crate::arch::cli();
        crate::arch::io::outb(0x64, 0xFE);
        loop {
            crate::arch::hlt();
        }
    }
    #[cfg(target_arch = "riscv64")]
    {
        crate::arch::cli();
        crate::arch::io::outb(0x64, 0xFE);
        loop {
            crate::arch::hlt();
        }
    }
}

/// trace mem on|off|dump [n]|clear|serial on|off|mask
pub(super) fn cmd_trace_impl(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() || args[0].as_str() != "mem" {
        shell_println!("Usage: trace mem on|off|dump [n]|clear|serial on|off|mask");
        return Err(ShellError::InvalidArguments);
    }

    if args.len() < 2 {
        shell_println!("Usage: trace mem on|off|dump [n]|clear|serial on|off|mask");
        return Err(ShellError::InvalidArguments);
    }

    match args[1].as_str() {
        "on" => {
            crate::trace::enable(crate::trace::category::MEM_ALL);
            shell_println!(
                "trace mem: on (mask={:#x}, mode={})",
                crate::trace::mask(),
                crate::trace::mask_human(crate::trace::mask())
            );
            Ok(())
        }
        "off" => {
            crate::trace::disable(crate::trace::category::MEM_ALL);
            shell_println!(
                "trace mem: off (mask={:#x}, mode={})",
                crate::trace::mask(),
                crate::trace::mask_human(crate::trace::mask())
            );
            Ok(())
        }
        "mask" => {
            let stats = crate::trace::stats();
            shell_println!(
                "trace mem: mask={:#x} mode={} serial={} stored={} dropped={}",
                crate::trace::mask(),
                crate::trace::mask_human(crate::trace::mask()),
                if crate::trace::serial_echo() {
                    "on"
                } else {
                    "off"
                },
                stats.stored,
                stats.dropped
            );
            Ok(())
        }
        "clear" => {
            crate::trace::clear_all();
            shell_println!("trace mem: buffers cleared");
            Ok(())
        }
        "serial" => {
            if args.len() != 3 {
                shell_println!("Usage: trace mem serial on|off");
                return Err(ShellError::InvalidArguments);
            }
            match args[2].as_str() {
                "on" => {
                    crate::trace::set_serial_echo(true);
                    shell_println!("trace mem serial: on");
                    Ok(())
                }
                "off" => {
                    crate::trace::set_serial_echo(false);
                    shell_println!("trace mem serial: off");
                    Ok(())
                }
                _ => {
                    shell_println!("Usage: trace mem serial on|off");
                    Err(ShellError::InvalidArguments)
                }
            }
        }
        "dump" => {
            let limit = if args.len() >= 3 {
                args[2].parse::<usize>().unwrap_or(64)
            } else {
                64
            };
            let events = crate::trace::snapshot_all(limit);
            let stats = crate::trace::stats();
            shell_println!(
                "trace mem dump: events={} stored={} dropped={}",
                events.len(),
                stats.stored,
                stats.dropped
            );
            for e in events.iter() {
                shell_println!(
                    "  seq={} t={} cpu={} kind={} pid={} tid={} cr3={:#x} rip={:#x} vaddr={:#x} fl={:#x} a0={:#x} a1={:#x}",
                    e.seq,
                    e.ticks,
                    e.cpu,
                    crate::trace::kind_name(e.kind),
                    e.pid,
                    e.tid,
                    e.cr3,
                    e.rip,
                    e.vaddr,
                    e.flags,
                    e.arg0,
                    e.arg1
                );
            }
            Ok(())
        }
        _ => {
            shell_println!("Usage: trace mem on|off|dump [n]|clear|serial on|off|mask");
            Err(ShellError::InvalidArguments)
        }
    }
}

/// Launch the userspace PID test binary from initfs.
pub(super) fn cmd_test_pid_impl(_args: &[String]) -> Result<(), ShellError> {
    let path = "/initfs/test_pid";
    shell_println!("Launching {} ...", path);

    let fd = match vfs::open(path, vfs::OpenFlags::READ) {
        Ok(fd) => fd,
        Err(e) => {
            shell_println!("open failed: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };

    let data = match vfs::read_all(fd) {
        Ok(d) => d,
        Err(e) => {
            let _ = vfs::close(fd);
            shell_println!("read failed: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };
    let _ = vfs::close(fd);

    shell_println!("ELF size: {} bytes", data.len());
    match load_and_run_elf(&data, "test_pid") {
        Ok(task_id) => {
            shell_println!("test_pid started (task id={})", task_id);
            Ok(())
        }
        Err(e) => {
            shell_println!("load_and_run_elf failed: {}", e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// Launch the userspace syscall integration test binary from initfs.
pub(super) fn cmd_test_syscalls_impl(_args: &[String]) -> Result<(), ShellError> {
    let path = "/initfs/test_syscalls";
    shell_println!("Launching {} ...", path);

    let fd = match vfs::open(path, vfs::OpenFlags::READ) {
        Ok(fd) => fd,
        Err(e) => {
            shell_println!("open failed: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };

    let data = match vfs::read_all(fd) {
        Ok(d) => d,
        Err(e) => {
            let _ = vfs::close(fd);
            shell_println!("read failed: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };
    let _ = vfs::close(fd);

    shell_println!("ELF size: {} bytes", data.len());
    match load_and_run_elf(&data, "test_syscalls") {
        Ok(task_id) => {
            shell_println!("test_syscalls started (task id={})", task_id);
            Ok(())
        }
        Err(e) => {
            shell_println!("load_and_run_elf failed: {}", e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// Launch the userspace memory test binary from initfs.
pub(super) fn cmd_test_mem_impl(_args: &[String]) -> Result<(), ShellError> {
    let path = "/initfs/test_mem";
    shell_println!("Launching {} ...", path);

    let fd = match vfs::open(path, vfs::OpenFlags::READ) {
        Ok(fd) => fd,
        Err(e) => {
            shell_println!("open failed: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };

    let data = match vfs::read_all(fd) {
        Ok(d) => d,
        Err(e) => {
            let _ = vfs::close(fd);
            shell_println!("read failed: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };
    let _ = vfs::close(fd);

    shell_println!("ELF size: {} bytes", data.len());
    match load_and_run_elf(&data, "test_mem") {
        Ok(task_id) => {
            shell_println!("test_mem started (task id={})", task_id);
            Ok(())
        }
        Err(e) => {
            shell_println!("load_and_run_elf failed: {}", e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// Launch the userspace stressed memory test binary from initfs.
pub(super) fn cmd_test_mem_stressed_impl(_args: &[String]) -> Result<(), ShellError> {
    let path = "/initfs/test_mem_stressed";
    shell_println!("Launching {} ...", path);

    let fd = match vfs::open(path, vfs::OpenFlags::READ) {
        Ok(fd) => fd,
        Err(e) => {
            shell_println!("open failed: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };

    let data = match vfs::read_all(fd) {
        Ok(d) => d,
        Err(e) => {
            let _ = vfs::close(fd);
            shell_println!("read failed: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };
    let _ = vfs::close(fd);

    shell_println!("ELF size: {} bytes", data.len());
    match load_and_run_elf(&data, "test_mem_stressed") {
        Ok(task_id) => {
            shell_println!("test_mem_stressed started (task id={})", task_id);
            Ok(())
        }
        Err(e) => {
            shell_println!("load_and_run_elf failed: {}", e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// Launch the userspace public MemoryRegion test binary from initfs.
pub(super) fn cmd_test_mem_region_impl(_args: &[String]) -> Result<(), ShellError> {
    let path = "/initfs/test_mem_region";
    shell_println!("Launching {} ...", path);

    let fd = match vfs::open(path, vfs::OpenFlags::READ) {
        Ok(fd) => fd,
        Err(e) => {
            shell_println!("open failed: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };

    let data = match vfs::read_all(fd) {
        Ok(d) => d,
        Err(e) => {
            let _ = vfs::close(fd);
            shell_println!("read failed: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };
    let _ = vfs::close(fd);

    shell_println!("ELF size: {} bytes", data.len());
    match load_and_run_elf(&data, "test_mem_region") {
        Ok(task_id) => {
            shell_println!("test_mem_region started (task id={})", task_id);
            Ok(())
        }
        Err(e) => {
            shell_println!("load_and_run_elf failed: {}", e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// Launch the userspace multi-process MemoryRegion test binary from initfs.
pub(super) fn cmd_test_mem_region_proc_impl(_args: &[String]) -> Result<(), ShellError> {
    let path = "/initfs/test_mem_region_proc";
    shell_println!("Launching {} ...", path);

    let fd = match vfs::open(path, vfs::OpenFlags::READ) {
        Ok(fd) => fd,
        Err(e) => {
            shell_println!("open failed: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };

    let data = match vfs::read_all(fd) {
        Ok(d) => d,
        Err(e) => {
            let _ = vfs::close(fd);
            shell_println!("read failed: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };
    let _ = vfs::close(fd);

    shell_println!("ELF size: {} bytes", data.len());
    match load_and_run_elf(&data, "test_mem_region_proc") {
        Ok(task_id) => {
            shell_println!("test_mem_region_proc started (task id={})", task_id);
            Ok(())
        }
        Err(e) => {
            shell_println!("load_and_run_elf failed: {}", e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// Ensure a boot module is visible in /initfs and return its bytes.
fn initfs_or_boot_module(path: &'static str, module: Option<(u64, u64)>) -> Option<&'static [u8]> {
    if let Some(bytes) = vfs::get_initfs_file_bytes(path) {
        return Some(bytes);
    }

    let (base, size) = module?;
    if base == 0 || size == 0 {
        return None;
    }

    let base_virt = memory::phys_to_virt(base) as *const u8;
    if vfs::register_initfs_file(path, base_virt, size as usize).is_err() {
        return None;
    }

    vfs::get_initfs_file_bytes(path)
}

/// Launch the userspace exec regression test binary from initfs.
pub(super) fn cmd_test_exec_impl(_args: &[String]) -> Result<(), ShellError> {
    let path = "/initfs/test_exec";
    shell_println!("Launching {} ...", path);

    let boot_bytes = initfs_or_boot_module(path, crate::boot::limine_shim::test_exec_module());
    let _ = initfs_or_boot_module(
        "/initfs/test_exec_helper",
        crate::boot::limine_shim::test_exec_helper_module(),
    );

    if let Some(data) = boot_bytes {
        shell_println!("ELF size: {} bytes", data.len());
        return match load_and_run_elf(data, "test_exec") {
            Ok(task_id) => {
                shell_println!("test_exec started (task id={})", task_id);
                Ok(())
            }
            Err(e) => {
                shell_println!("load_and_run_elf failed: {}", e);
                Err(ShellError::ExecutionFailed)
            }
        };
    }

    let fd = match vfs::open(path, vfs::OpenFlags::READ) {
        Ok(fd) => fd,
        Err(e) => {
            shell_println!("open failed: {:?}", e);
            if crate::boot::limine_shim::test_exec_module().is_none() {
                shell_println!(
                    "test_exec boot module missing from current image; rebuild the userspace image so /initfs/test_exec is copied"
                );
            }
            return Err(ShellError::ExecutionFailed);
        }
    };

    let data = match vfs::read_all(fd) {
        Ok(d) => d,
        Err(e) => {
            let _ = vfs::close(fd);
            shell_println!("read failed: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };
    let _ = vfs::close(fd);

    shell_println!("ELF size: {} bytes", data.len());
    match load_and_run_elf(&data, "test_exec") {
        Ok(task_id) => {
            shell_println!("test_exec started (task id={})", task_id);
            Ok(())
        }
        Err(e) => {
            shell_println!("load_and_run_elf failed: {}", e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// Builds the config table (one row per `[[silos]]` entry of the boot config).
fn build_config_rows(
    managed: &[ManagedSiloDef],
    managed_runtime_sids: &[(String, u32)],
) -> Vec<ConfigListRow> {
    let mut config_rows = Vec::with_capacity(managed.len());
    for m in managed {
        let mut strates = Vec::new();
        for st in &m.strates {
            if !st.name.is_empty() {
                push_unique(&mut strates, &st.name);
            }
        }
        config_rows.push(ConfigListRow {
            sid: managed_sid_for(managed_runtime_sids, &m.name).unwrap_or(m.sid),
            name: m.name.clone(),
            family: m.family.clone(),
            mode: m.mode.clone(),
            cpu_features: if m.cpu_features.is_empty() {
                String::from("-")
            } else {
                m.cpu_features.clone()
            },
            strates,
        });
    }
    config_rows
}

/// Performs the cmd silo list operation.
fn cmd_silo_list(args: &[String], cmd: Cmd) -> Result<(), ShellError> {
    let mut want_gui = false;
    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "--gui" => want_gui = true,
            _ => {
                shell_println!("Usage: {} list [--gui]", cmd.name());
                return Err(ShellError::InvalidArguments);
            }
        }
    }

    let (managed, managed_source) = load_managed_silos_with_source();
    let managed_runtime_sids = compute_managed_runtime_sids(&managed);

    // The config table is only worth building for a renderer that shows it.
    let config_rows = if want_gui {
        build_config_rows(&managed, &managed_runtime_sids)
    } else {
        Vec::new()
    };

    let mut silos = silo::list_silos_snapshot();
    silos.sort_by_key(|s| s.id);

    let mut rows: Vec<SiloListRow> = Vec::with_capacity(silos.len());
    for s in silos.iter() {
        let display_name = managed_name_for_runtime_sid(&managed_runtime_sids, s.id)
            .unwrap_or_else(|| s.name.clone());
        // Strates come from the boot config entry this runtime silo maps to.
        let strates = config_strates_for_sid(&managed, &managed_runtime_sids, s.id);
        let kernel_only_strate = strates.is_empty() && s.strate_label.is_some();
        rows.push(SiloListRow {
            sid: s.id,
            name: display_name,
            state: s.state,
            tasks: s.task_count,
            mem_used: s.mem_usage_bytes,
            mem_max: s.mem_max_bytes,
            mode: s.mode,
            label: s.strate_label.clone(),
            strates,
            kernel_only_strate,
        });
    }

    if want_gui {
        if render_silo_table_ratatui(&rows, &config_rows, managed_source).unwrap_or(false) {
            return Ok(());
        }
        shell_println!("{} list: GUI unavailable, fallback console", cmd.name());
    }

    // Console presenter. The column widths live in one place so the header and
    // the rows can never disagree.
    const COLS: [usize; 8] = [6, 14, 10, 7, 18, 6, 12, 20];
    shell_println!(
        "{:<6} {:<14} {:<10} {:<7} {:<18} {:<6} {:<12} {}",
        "SID",
        "Name",
        "State",
        "Tasks",
        "Memory",
        "Mode",
        "Label",
        "Strates"
    );
    shell_println!("{}", "-".repeat(COLS.iter().sum::<usize>()));
    for r in &rows {
        shell_println!(
            "{:<6} {:<14} {:<10} {:<7} {:<18} {:<6o} {:<12} {}",
            r.sid,
            r.name,
            silo_state_str(r.state),
            r.tasks,
            memory_cell(r.mem_used, r.mem_max),
            r.mode,
            r.label.as_deref().unwrap_or("-"),
            silo_strates_cell(r)
        );
    }

    // The config table used to be reachable only through the graphical view;
    // print it on every target so the two tables can be compared anywhere.
    if !config_rows.is_empty() {
        shell_println!("");
        shell_println!("Config ({}):", managed_source);
        shell_println!(
            "{:<6} {:<14} {:<6} {:<6} {:<11} {}",
            "SID",
            "Name",
            "Family",
            "Mode",
            "CPU feats",
            "Strates"
        );
        shell_println!("{}", "-".repeat(63));
        for r in &config_rows {
            shell_println!(
                "{:<6} {:<14} {:<6} {:<6} {:<11} {}",
                r.sid,
                r.name,
                r.family,
                r.mode,
                r.cpu_features,
                join_csv(&r.strates)
            );
        }
    }
    Ok(())
}

/// One strate and the silos that run it.
struct StrateEntry {
    name: String,
    belongs_to: Vec<String>,
}

impl StrateEntry {
    fn add_owner(&mut self, silo_name: &str) {
        push_unique(&mut self.belongs_to, silo_name);
    }
}

/// Groups a strate name under `entries`, creating it on first sight.
fn group_strate(entries: &mut Vec<StrateEntry>, name: &str, owner: &str) {
    if let Some(e) = entries.iter_mut().find(|e| e.name == name) {
        e.add_owner(owner);
    } else {
        entries.push(StrateEntry {
            name: String::from(name),
            belongs_to: alloc::vec![String::from(owner)],
        });
    }
}

/// Performs the cmd strate list operation.
fn cmd_strate_list(args: &[String], cmd: Cmd) -> Result<(), ShellError> {
    let mut want_gui = false;
    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "--gui" => want_gui = true,
            _ => {
                shell_println!("Usage: {} list [--gui]", cmd.name());
                return Err(ShellError::InvalidArguments);
            }
        }
    }

    let (managed, managed_source) = load_managed_silos_with_source();
    let managed_runtime_sids = compute_managed_runtime_sids(&managed);

    // Strates declared in the boot config.
    let mut entries: Vec<StrateEntry> = Vec::new();
    for s in &managed {
        for st in &s.strates {
            if !st.name.is_empty() {
                group_strate(&mut entries, &st.name, &s.name);
            }
        }
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    // Strates actually running. A runtime silo is matched to its config entry
    // through the name->sid map, the same rule `silo list` uses; falling back
    // to the kernel label keeps silos that the config does not describe.
    let mut runtime_entries: Vec<StrateEntry> = Vec::new();
    let mut runtime = silo::list_silos_snapshot();
    runtime.sort_by_key(|s| s.id);
    for snapshot in &runtime {
        let names = config_strates_for_sid(&managed, &managed_runtime_sids, snapshot.id);
        if names.is_empty() {
            match snapshot.strate_label.as_deref() {
                Some(label) if !label.is_empty() => {
                    group_strate(&mut runtime_entries, label, &snapshot.name)
                }
                _ => continue,
            }
            continue;
        }
        for name in names {
            group_strate(&mut runtime_entries, &name, &snapshot.name);
        }
    }
    runtime_entries.sort_by(|a, b| a.name.cmp(&b.name));

    let config_rows: Vec<ConfigStrateRow> = entries
        .iter()
        .map(|e| ConfigStrateRow {
            strate: e.name.clone(),
            belongs_to: join_csv(&e.belongs_to),
        })
        .collect();

    let runtime_rows: Vec<RuntimeStrateRow> = runtime_entries
        .iter()
        .map(|e| RuntimeStrateRow {
            strate: e.name.clone(),
            belongs_to: join_csv(&e.belongs_to),
            status: if entries.iter().any(|cfg| cfg.name == e.name) {
                "config+runtime"
            } else {
                "runtime-only"
            },
        })
        .collect();

    if want_gui {
        if render_strate_table_ratatui(&runtime_rows, &config_rows, managed_source).unwrap_or(false)
        {
            return Ok(());
        }
        shell_println!("{} list: GUI unavailable, fallback console", cmd.name());
    }

    shell_println!("Runtime:");
    shell_println!("{:<20} {:<24} {}", "Strate", "BelongsTo", "Status");
    shell_println!("{}", "-".repeat(51));
    for r in &runtime_rows {
        shell_println!("{:<20} {:<24} {}", r.strate, r.belongs_to, r.status);
    }
    shell_println!("");
    shell_println!("Config ({}):", managed_source);
    shell_println!("{:<20} {}", "Strate", "BelongsTo");
    shell_println!("{}", "-".repeat(44));
    for r in &config_rows {
        shell_println!("{:<20} {}", r.strate, r.belongs_to);
    }
    Ok(())
}

/// Resolves a `spawn` target to a binary path.
///
/// The boot config already records where every strate's binary lives, so it is
/// consulted first: the old hardcoded table assumed `/initfs/bin/<name>`, which
/// is wrong for the strates shipped at the root of the initfs
/// (`/initfs/console-admin`, `/initfs/strate-bus`, `/initfs/strate-net`,
/// `/initfs/strate-webrtc`) and made `strate spawn <name>` fail on them.
///
/// Explicit paths and the two filesystem shorthands keep working unchanged.
fn resolve_spawn_path(target: &str) -> String {
    if target.starts_with('/') {
        return String::from(target);
    }
    match target {
        "strate-fs-ext4" => return String::from("/initfs/fs-ext4"),
        "ramfs" | "strate-fs-ramfs" => return String::from("/initfs/strate-fs-ramfs"),
        _ => {}
    }
    // Config lookup: a strate declared under any silo.
    if let Some(found) = config_binary_for_strate(target) {
        return found;
    }
    let mut fallback = String::from("/initfs/bin/");
    fallback.push_str(target);
    fallback
}

/// Binary path the boot config declares for a strate name.
fn config_binary_for_strate(strate_name: &str) -> Option<String> {
    let (managed, _) = load_managed_silos_with_source();
    managed
        .iter()
        .flat_map(|s| s.strates.iter())
        .find(|st| st.name == strate_name)
        .filter(|st| !st.binary.is_empty())
        .map(|st| String::from(st.binary.as_str()))
}

fn cmd_strate_spawn(args: &[String], cmd: Cmd) -> Result<(), ShellError> {
    if args.len() < 2 {
        shell_println!(
            "Usage: {} spawn <path|strate-name> [--label <l>] [--dev <p>] [--type elf|wasm]",
            cmd.name()
        );
        return Err(ShellError::InvalidArguments);
    }
    let target = args[1].as_str();

    let mut label: Option<&str> = None;
    let mut dev: Option<&str> = None;
    let mut spawn_wasm = false;
    let mut i = 2usize;
    while i < args.len() {
        match args[i].as_str() {
            "--label" => {
                if i + 1 >= args.len() {
                    shell_println!("{} spawn: --label needs a value", cmd.name());
                    return Err(ShellError::InvalidArguments);
                }
                label = Some(args[i + 1].as_str());
                i += 2;
            }
            "--dev" => {
                if i + 1 >= args.len() {
                    shell_println!("{} spawn: --dev needs a value", cmd.name());
                    return Err(ShellError::InvalidArguments);
                }
                dev = Some(args[i + 1].as_str());
                i += 2;
            }
            "--type" => {
                if i + 1 >= args.len() {
                    shell_println!("{} spawn: --type needs a value (elf|wasm)", cmd.name());
                    return Err(ShellError::InvalidArguments);
                }
                let value = args[i + 1].as_str();
                // A typo used to be accepted silently and treated as `elf`.
                if value != "elf" && value != "wasm" {
                    shell_println!(
                        "{} spawn: unknown type '{}' (expected elf or wasm)",
                        cmd.name(),
                        value
                    );
                    return Err(ShellError::InvalidArguments);
                }
                spawn_wasm = value == "wasm";
                i += 2;
            }
            _ => {
                shell_println!("{} spawn: unknown option '{}'", cmd.name(), args[i]);
                return Err(ShellError::InvalidArguments);
            }
        }
    }

    if spawn_wasm {
        shell_println!("{} spawn: delegating wasm to wasm-run...", cmd.name());
        return cmd_wasm_run(&[String::from(target)]);
    }

    let module_path = resolve_spawn_path(target);

    let fd = vfs::open(&module_path, vfs::OpenFlags::READ).map_err(|_| {
        shell_println!("{} spawn: cannot open '{}'", cmd.name(), module_path);
        ShellError::ExecutionFailed
    })?;
    let data = match vfs::read_all(fd) {
        Ok(d) => d,
        Err(_) => {
            let _ = vfs::close(fd);
            shell_println!("{} spawn: cannot read '{}'", cmd.name(), module_path);
            return Err(ShellError::ExecutionFailed);
        }
    };
    let _ = vfs::close(fd);

    match silo::kernel_spawn_strate(&data, label, dev) {
        Ok(sid) => {
            shell_println!(
                "{} spawn: started (sid={}, path={}, label={})",
                cmd.name(),
                sid,
                module_path,
                label.unwrap_or("-")
            );
            Ok(())
        }
        Err(e) => {
            shell_println!("{} spawn failed: {:?}", cmd.name(), e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// Prints the config fields the shell models for one silo.
fn print_config_silo(s: &ManagedSiloDef, runtime_sid: Option<u32>) {
    // `sid` in the config is a placeholder (42) for the silos that let userspace
    // allocate the runtime id, so show the mapped value and flag the raw one.
    match runtime_sid {
        Some(sid) if s.sid == CONFIG_SID_PLACEHOLDER => {
            shell_println!("silo '{}' sid={} (auto)", s.name, sid)
        }
        _ => shell_println!("silo '{}' sid={}", s.name, s.sid),
    }
    shell_println!(
        "  family={} mode={} cpu_features={}",
        s.family,
        s.mode,
        if s.cpu_features.is_empty() {
            "-"
        } else {
            s.cpu_features.as_str()
        }
    );
    if s.graphics_enabled {
        shell_println!(
            "  graphics: mode={} ro={} max_sessions={} ttl={}s turn={}",
            if s.graphics_mode.is_empty() {
                "webrtc-native"
            } else {
                s.graphics_mode.as_str()
            },
            s.graphics_read_only,
            s.graphics_max_sessions,
            s.graphics_session_ttl_sec,
            s.graphics_turn_policy
        );
    }
    shell_println!("  strates={}", s.strates.len());
    for st in &s.strates {
        shell_println!(
            "  - {}: binary={} type={} target={}",
            st.name,
            st.binary,
            st.stype,
            st.target
        );
        // Read by strate-bus at boot: worth showing so a config rewrite that
        // would drop it is visible.
        if !st.probe_mode.is_empty() {
            shell_println!("      probe_mode={}", st.probe_mode);
        }
    }
}

/// Performs the cmd strate config show operation.
///
/// `strate config show [silo]`. Uses the effective config, the same source
/// `strate list` and `silo list` report, so the two views cannot disagree.
fn cmd_strate_config_show(args: &[String], cmd: Cmd) -> Result<(), ShellError> {
    let (silos, source) = load_managed_silos_with_source();
    if silos.is_empty() {
        shell_println!("{} config show: no managed silo config", cmd.name());
        return Ok(());
    }
    let managed_runtime_sids = compute_managed_runtime_sids(&silos);

    // args is [cmd, "config", "show", (silo)]. The old `args.len() == 3` test
    // read args[2] -- the literal "show" -- so the single-silo form never ran
    // and a bare `config show` always failed with "silo 'show' not found".
    match args.get(3) {
        Some(name) => {
            let Some(s) = silos.iter().find(|s| s.name == name.as_str()) else {
                shell_println!("{} config show: silo '{}' not found", cmd.name(), name);
                return Err(ShellError::ExecutionFailed);
            };
            print_config_silo(s, managed_sid_for(&managed_runtime_sids, &s.name));
        }
        None => {
            shell_println!("Config ({}):", source);
            for s in &silos {
                let runtime_sid = managed_sid_for(&managed_runtime_sids, &s.name);
                match runtime_sid {
                    Some(sid) if s.sid == CONFIG_SID_PLACEHOLDER => {
                        shell_println!("  '{}' sid={} (auto)", s.name, sid)
                    }
                    _ => shell_println!("  '{}' sid={}", s.name, s.sid),
                }
                shell_println!(
                    "      family={} mode={} strates={}",
                    s.family,
                    s.mode,
                    s.strates.len()
                );
            }
        }
    }
    Ok(())
}

/// Performs the cmd strate config add operation.
fn cmd_strate_config_add(args: &[String], cmd: Cmd) -> Result<(), ShellError> {
    if args.len() < 5 {
        shell_println!(
            "Usage: {} config add <silo> <name> <binary> [--type <t>] [--target <x>] [--family <F>] [--mode <ooo>] [--sid <n>]",
            cmd.name()
        );
        return Err(ShellError::InvalidArguments);
    }
    let silo_name = args[2].as_str();
    let strate_name = args[3].as_str();
    let binary = args[4].as_str();
    if silo_name.is_empty() || strate_name.is_empty() || binary.is_empty() {
        shell_println!("{} config add: invalid empty argument", cmd.name());
        return Err(ShellError::InvalidArguments);
    }

    let mut stype = String::from("elf");
    let mut target = String::from("default");
    let mut family: Option<String> = None;
    let mut mode: Option<String> = None;
    let mut sid: Option<u32> = None;
    let mut i = 5usize;
    while i < args.len() {
        match args[i].as_str() {
            "--type" => {
                if i + 1 >= args.len() {
                    shell_println!("{} config add: missing value for --type", cmd.name());
                    return Err(ShellError::InvalidArguments);
                }
                let value = args[i + 1].as_str();
                if !CONFIG_STRATE_TYPES.contains(&value) {
                    shell_println!(
                        "{} config add: unknown type '{}' (expected one of {})",
                        cmd.name(),
                        value,
                        CONFIG_STRATE_TYPES.join("|")
                    );
                    return Err(ShellError::InvalidArguments);
                }
                stype = String::from(value);
                i += 2;
            }
            "--target" => {
                if i + 1 >= args.len() {
                    shell_println!("{} config add: missing value for --target", cmd.name());
                    return Err(ShellError::InvalidArguments);
                }
                target = args[i + 1].clone();
                i += 2;
            }
            "--family" => {
                if i + 1 >= args.len() {
                    shell_println!("{} config add: missing value for --family", cmd.name());
                    return Err(ShellError::InvalidArguments);
                }
                let value = args[i + 1].as_str();
                if !CONFIG_FAMILIES.contains(&value) {
                    shell_println!(
                        "{} config add: unknown family '{}' (expected one of {})",
                        cmd.name(),
                        value,
                        CONFIG_FAMILIES.join("|")
                    );
                    return Err(ShellError::InvalidArguments);
                }
                family = Some(String::from(value));
                i += 2;
            }
            "--mode" => {
                if i + 1 >= args.len() {
                    shell_println!("{} config add: missing value for --mode", cmd.name());
                    return Err(ShellError::InvalidArguments);
                }
                mode = Some(args[i + 1].clone());
                i += 2;
            }
            "--sid" => {
                if i + 1 >= args.len() {
                    shell_println!("{} config add: missing value for --sid", cmd.name());
                    return Err(ShellError::InvalidArguments);
                }
                sid = args[i + 1].parse::<u32>().ok();
                if sid.is_none() {
                    shell_println!("{} config add: invalid --sid", cmd.name());
                    return Err(ShellError::InvalidArguments);
                }
                i += 2;
            }
            other => {
                shell_println!("{} config add: unknown option '{}'", cmd.name(), other);
                return Err(ShellError::InvalidArguments);
            }
        }
    }

    // Read the *effective* config, not just the raw file: with no
    // /initfs/silo.toml the shell falls back to the embedded defaults, and
    // writing back only the added silo would silently drop those defaults from
    // the next boot.
    let (mut silos, source) = load_managed_silos_with_source();
    let idx = match silos.iter().position(|s| s.name == silo_name) {
        Some(p) => p,
        None => {
            silos.push(ManagedSiloDef {
                name: String::from(silo_name),
                sid: sid.unwrap_or(CONFIG_SID_PLACEHOLDER),
                family: family.clone().unwrap_or_else(|| String::from("USR")),
                mode: mode.clone().unwrap_or_else(|| String::from("000")),
                cpu_features: String::new(),
                graphics_enabled: false,
                graphics_mode: String::new(),
                graphics_read_only: false,
                graphics_max_sessions: 0,
                graphics_session_ttl_sec: 0,
                graphics_turn_policy: String::from("auto"),
                strates: Vec::new(),
            });
            silos.len() - 1
        }
    };

    if let Some(f) = family {
        silos[idx].family = f;
    }
    if let Some(m) = mode {
        silos[idx].mode = m;
    }
    if let Some(s) = sid {
        silos[idx].sid = s;
    }

    if let Some(st) = silos[idx]
        .strates
        .iter_mut()
        .find(|st| st.name == strate_name)
    {
        st.binary = String::from(binary);
        st.stype = stype;
        st.target = target;
    } else {
        silos[idx].strates.push(ManagedStrateDef {
            name: String::from(strate_name),
            binary: String::from(binary),
            stype,
            target,
            probe_mode: String::new(),
        });
    }

    let rendered = render_silo_toml(&silos);
    write_silo_toml_to_initfs(&rendered)?;
    shell_println!(
        "{} config add: wrote {} from {} (silo='{}', strate='{}')",
        cmd.name(),
        CONFIG_PATH,
        source,
        silo_name,
        strate_name
    );
    Ok(())
}

/// Performs the cmd strate config remove operation.
fn cmd_strate_config_remove(args: &[String], cmd: Cmd) -> Result<(), ShellError> {
    if args.len() != 4 {
        shell_println!("Usage: {} config remove <silo> <name>", cmd.name());
        return Err(ShellError::InvalidArguments);
    }
    let silo_name = args[2].as_str();
    let strate_name = args[3].as_str();

    // Removing from the embedded fallback would mean materializing it as a boot
    // config just to delete one entry from it, changing what boots next time.
    let (mut silos, source) = load_managed_silos_with_source();
    if source == CONFIG_SOURCE_EMBEDDED {
        shell_println!(
            "{} config remove: no {} on this device (effective config is {}), nothing to update",
            cmd.name(),
            CONFIG_PATH,
            source
        );
        return Err(ShellError::ExecutionFailed);
    }

    let Some(silo_idx) = silos.iter().position(|s| s.name == silo_name) else {
        shell_println!(
            "{} config remove: silo '{}' not found",
            cmd.name(),
            silo_name
        );
        return Err(ShellError::ExecutionFailed);
    };
    let Some(strate_idx) = silos[silo_idx]
        .strates
        .iter()
        .position(|st| st.name == strate_name)
    else {
        shell_println!(
            "{} config remove: strate '{}' not found in silo '{}'",
            cmd.name(),
            strate_name,
            silo_name
        );
        return Err(ShellError::ExecutionFailed);
    };

    silos[silo_idx].strates.remove(strate_idx);
    if silos[silo_idx].strates.is_empty() {
        silos.remove(silo_idx);
    }

    let rendered = render_silo_toml(&silos);
    write_silo_toml_to_initfs(&rendered)?;
    shell_println!(
        "{} config remove: updated {} (silo='{}', strate='{}')",
        cmd.name(),
        CONFIG_PATH,
        silo_name,
        strate_name
    );
    Ok(())
}

/// Performs the cmd strate config operation.
fn cmd_strate_config(args: &[String], cmd: Cmd) -> Result<(), ShellError> {
    if args.len() < 2 {
        shell_println!("Usage: {} config <show|add|remove> ...", cmd.name());
        return Err(ShellError::InvalidArguments);
    }
    match args[1].as_str() {
        "show" => cmd_strate_config_show(args, cmd),
        "add" => cmd_strate_config_add(args, cmd),
        "remove" => cmd_strate_config_remove(args, cmd),
        _ => {
            shell_println!("Usage: {} config <show|add|remove> ...", cmd.name());
            Err(ShellError::InvalidArguments)
        }
    }
}

/// Performs the cmd strate start operation.
fn cmd_strate_start(args: &[String], cmd: Cmd) -> Result<(), ShellError> {
    if args.len() != 2 {
        shell_println!("Usage: {} start <id|label|name>", cmd.name());
        return Err(ShellError::InvalidArguments);
    }
    let selector = normalize_current_silo_selector(args[1].as_str());
    match silo::kernel_start_silo(selector.as_str()) {
        Ok(sid) => {
            shell_println!("{} start: ok (sid={})", cmd.name(), sid);
            print_strate_state_for_sid(sid);
            Ok(())
        }
        Err(e) => {
            shell_println!("{} start failed: {:?}", cmd.name(), e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// Performs the cmd strate lifecycle operation.
fn cmd_strate_lifecycle(args: &[String], cmd: Cmd) -> Result<(), ShellError> {
    if args.len() != 2 {
        shell_println!(
            "Usage: {} start|stop|kill|destroy <id|label|name>",
            cmd.name()
        );
        return Err(ShellError::InvalidArguments);
    }
    let selector = normalize_current_silo_selector(args[1].as_str());
    let action = args[0].as_str();
    let result = match action {
        "stop" => silo::kernel_stop_silo(selector.as_str(), false),
        "kill" => silo::kernel_stop_silo(selector.as_str(), true),
        "destroy" => silo::kernel_destroy_silo(selector.as_str()),
        // A shell must never panic: report instead.
        _ => {
            shell_println!("Usage: {} stop|kill|destroy <id|label|name>", cmd.name());
            return Err(ShellError::InvalidArguments);
        }
    };
    match result {
        Ok(sid) => {
            shell_println!("{} {}: ok (sid={})", cmd.name(), action, sid);
            if action == "stop" {
                print_strate_state_for_sid(sid);
            }
            Ok(())
        }
        Err(e) => {
            shell_println!("{} {} failed: {:?}", cmd.name(), action, e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// Performs the cmd strate rename operation.
fn cmd_strate_rename(args: &[String], cmd: Cmd) -> Result<(), ShellError> {
    if args.len() != 3 {
        shell_println!("Usage: {} rename <id|label|name> <new_label>", cmd.name());
        return Err(ShellError::InvalidArguments);
    }
    let selector = normalize_current_silo_selector(args[1].as_str());
    let new_label = args[2].as_str();
    match silo::kernel_rename_silo_label(selector.as_str(), new_label) {
        Ok(sid) => {
            shell_println!(
                "{} rename: ok (sid={}, new_label={})",
                cmd.name(),
                sid,
                new_label
            );
            Ok(())
        }
        Err(e) => {
            if matches!(e, crate::syscall::error::SyscallError::InvalidArgument) {
                shell_println!(
                    "{} rename failed: strate is running or not in a renamable state (stop it first)",
                    cmd.name()
                );
            } else {
                shell_println!("{} rename failed: {:?}", cmd.name(), e);
            }
            Err(ShellError::ExecutionFailed)
        }
    }
}

pub(super) fn cmd_strate_impl(args: &[String], cmd: Cmd) -> Result<(), ShellError> {
    if args.is_empty() {
        print_cmd_usage(cmd);
        return Err(ShellError::InvalidArguments);
    }

    match args[0].as_str() {
        "list" => cmd_strate_list(args, cmd),
        "spawn" => cmd_strate_spawn(args, cmd),
        "config" => cmd_strate_config(args, cmd),
        "start" => cmd_strate_start(args, cmd),
        "stop" | "kill" | "destroy" => cmd_strate_lifecycle(args, cmd),
        "rename" => cmd_strate_rename(args, cmd),
        "info" => cmd_silo_info(args, cmd),
        "suspend" => cmd_silo_suspend(args, cmd),
        "resume" => cmd_silo_resume(args, cmd),
        "events" => cmd_silo_events(args, cmd),
        "pledge" => cmd_silo_pledge(args, cmd),
        "unveil" => cmd_silo_unveil(args, cmd),
        "sandbox" => cmd_silo_sandbox(args, cmd),
        "limit" => cmd_silo_limit(args, cmd),
        "attach" => cmd_silo_attach(args, cmd),
        "top" => cmd_silo_top(args, cmd),
        "logs" => cmd_silo_logs(args, cmd),
        _ => {
            print_cmd_usage(cmd);
            Err(ShellError::InvalidArguments)
        }
    }
}

// ============================================================================
// silo info / suspend / resume / events / pledge / unveil / sandbox / top / logs
// ============================================================================
fn cmd_silo_info(args: &[String], cmd: Cmd) -> Result<(), ShellError> {
    if args.len() < 2 {
        shell_println!("Usage: {} info <id|label|name>", cmd.name());
        return Err(ShellError::InvalidArguments);
    }
    let selector = normalize_current_silo_selector(args[1].as_str());
    let detail = silo::silo_detail_snapshot(selector.as_str()).map_err(|e| {
        shell_println!("{} info: {:?}", cmd.name(), e);
        ShellError::ExecutionFailed
    })?;
    let b = &detail.base;

    shell_println!("SID:        {}", b.id);
    shell_println!("Name:       {}", b.name);
    shell_println!("Label:      {}", b.strate_label.as_deref().unwrap_or("-"));
    shell_println!("Tier:       {}", silo_tier_str(b.tier));
    shell_println!("State:      {}", silo_state_str(b.state));
    shell_println!("Family:     {}", strate_family_str(detail.family));
    shell_println!("Mode:       {:03o}", b.mode);
    shell_println!("Sandboxed:  {}", detail.sandboxed);
    shell_println!("Tasks:      {}", b.task_count);
    shell_println!(
        "Memory:     {} / {} / {}",
        crate::shell::output::human_bytes(b.mem_usage_bytes),
        crate::shell::output::human_bytes(b.mem_min_bytes),
        crate::shell::output::human_bytes_or_unlimited(b.mem_max_bytes),
    );
    shell_println!("CPU shares: {}", detail.cpu_shares);
    shell_println!("CPU mask:   {:#x}", detail.cpu_affinity_mask);
    shell_println!("CPU req:    {:#x}", detail.cpu_features_required);
    shell_println!("CPU allow:  {:#x}", detail.cpu_features_allowed);
    shell_println!("XCR0 mask:  {:#x}", detail.xcr0_mask);
    shell_println!("GFX flags:  {:#x}", detail.graphics_flags);
    shell_println!("GFX mode:   {}", graphics_mode_str(detail.graphics_flags));
    shell_println!(
        "GFX ro:     {}",
        flag_str(detail.graphics_flags & silo::SILO_FLAG_GRAPHICS_READ_ONLY != 0)
    );
    shell_println!(
        "GFX turn:   {}",
        flag_str(detail.graphics_flags & silo::SILO_FLAG_WEBRTC_TURN_FORCE != 0)
    );
    shell_println!("GFX sess:   {}", detail.graphics_max_sessions);
    shell_println!("GFX ttl:    {} sec", detail.graphics_session_ttl_sec);
    if detail.max_tasks == 0 {
        shell_println!("Max tasks:  unlimited");
    } else {
        shell_println!("Max tasks:  {}", detail.max_tasks);
    }
    shell_println!("Caps:       {} granted", detail.granted_caps_count);

    if !detail.task_ids.is_empty() {
        shell_println!("Task IDs:   {:?}", detail.task_ids);
    }

    if !detail.unveil_rules.is_empty() {
        shell_println!("Unveil rules:");
        for (path, bits) in &detail.unveil_rules {
            let r = if bits & 4 != 0 { 'r' } else { '-' };
            let w = if bits & 2 != 0 { 'w' } else { '-' };
            let x = if bits & 1 != 0 { 'x' } else { '-' };
            shell_println!("  {}{}{} {}", r, w, x, path);
        }
    }
    Ok(())
}

fn cmd_silo_suspend(args: &[String], cmd: Cmd) -> Result<(), ShellError> {
    if args.len() < 2 {
        shell_println!("Usage: {} suspend <id|label|name>", cmd.name());
        return Err(ShellError::InvalidArguments);
    }
    let selector = normalize_current_silo_selector(args[1].as_str());
    match silo::kernel_suspend_silo(selector.as_str()) {
        Ok(sid) => {
            shell_println!("{} suspend: ok (sid={})", cmd.name(), sid);
            Ok(())
        }
        Err(e) => {
            shell_println!("{} suspend failed: {:?}", cmd.name(), e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

fn cmd_silo_resume(args: &[String], cmd: Cmd) -> Result<(), ShellError> {
    if args.len() < 2 {
        shell_println!("Usage: {} resume <id|label|name>", cmd.name());
        return Err(ShellError::InvalidArguments);
    }
    let selector = normalize_current_silo_selector(args[1].as_str());
    match silo::kernel_resume_silo(selector.as_str()) {
        Ok(sid) => {
            shell_println!("{} resume: ok (sid={})", cmd.name(), sid);
            Ok(())
        }
        Err(e) => {
            shell_println!("{} resume failed: {:?}", cmd.name(), e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

fn event_kind_str(kind: silo::SiloEventKind) -> &'static str {
    match kind {
        silo::SiloEventKind::Started => "Started",
        silo::SiloEventKind::Stopped => "Stopped",
        silo::SiloEventKind::Killed => "Killed",
        silo::SiloEventKind::Crashed => "Crashed",
        silo::SiloEventKind::Paused => "Paused",
        silo::SiloEventKind::Resumed => "Resumed",
    }
}

fn cmd_silo_events(args: &[String], cmd: Cmd) -> Result<(), ShellError> {
    let events = if args.len() >= 2 {
        let selector = normalize_current_silo_selector(args[1].as_str());
        silo::list_events_for_silo(selector.as_str()).map_err(|e| {
            shell_println!("{} events: {:?}", cmd.name(), e);
            ShellError::ExecutionFailed
        })?
    } else {
        silo::list_events_snapshot()
    };

    if events.is_empty() {
        shell_println!("(no events)");
        return Ok(());
    }

    shell_println!(
        "{:<8} {:<10} {:<12} {:<12} {}",
        "SID",
        "Kind",
        "Data0",
        "Data1",
        "Tick"
    );
    shell_println!("{}", "-".repeat(50));
    for ev in &events {
        shell_println!(
            "{:<8} {:<10} {:#010x}   {:#010x}   {}",
            ev.silo_id,
            event_kind_str(ev.kind),
            ev.data0,
            ev.data1,
            ev.tick
        );
    }
    Ok(())
}

fn cmd_silo_pledge(args: &[String], cmd: Cmd) -> Result<(), ShellError> {
    if args.len() < 3 {
        shell_println!("Usage: {} pledge <id|label|name> <octal_mode>", cmd.name());
        return Err(ShellError::InvalidArguments);
    }
    // `strate-init` accepts both `700` and `0o700`; accept both here too.
    let mode_text = args[2].as_str();
    let mode_digits = mode_text
        .strip_prefix("0o")
        .or_else(|| mode_text.strip_prefix("0O"))
        .unwrap_or(mode_text);
    let mode_val = match u16::from_str_radix(mode_digits, 8) {
        Ok(m) if m <= 0o777 => m,
        _ => {
            shell_println!("{} pledge: invalid octal mode '{}'", cmd.name(), mode_text);
            return Err(ShellError::InvalidArguments);
        }
    };
    let selector = normalize_current_silo_selector(args[1].as_str());
    match silo::kernel_pledge_silo(selector.as_str(), mode_val) {
        Ok((old, new)) => {
            shell_println!("{} pledge: {:03o} -> {:03o}", cmd.name(), old, new);
            Ok(())
        }
        Err(e) => {
            shell_println!("{} pledge failed: {:?}", cmd.name(), e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

fn cmd_silo_unveil(args: &[String], cmd: Cmd) -> Result<(), ShellError> {
    if args.len() < 4 {
        shell_println!("Usage: {} unveil <id|label|name> <path> <rwx>", cmd.name());
        return Err(ShellError::InvalidArguments);
    }
    let selector = normalize_current_silo_selector(args[1].as_str());
    let path = args[2].as_str();
    let rights = args[3].as_str();
    match silo::kernel_unveil_silo(selector.as_str(), path, rights) {
        Ok(sid) => {
            shell_println!(
                "{} unveil: ok (sid={}, path={}, rights={})",
                cmd.name(),
                sid,
                path,
                rights
            );
            Ok(())
        }
        Err(e) => {
            shell_println!("{} unveil failed: {:?}", cmd.name(), e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

fn cmd_silo_sandbox(args: &[String], cmd: Cmd) -> Result<(), ShellError> {
    if args.len() < 2 {
        shell_println!("Usage: {} sandbox <id|label|name>", cmd.name());
        return Err(ShellError::InvalidArguments);
    }
    let selector = normalize_current_silo_selector(args[1].as_str());
    match silo::kernel_sandbox_silo(selector.as_str()) {
        Ok(sid) => {
            shell_println!("{} sandbox: ok (sid={})", cmd.name(), sid);
            Ok(())
        }
        Err(e) => {
            shell_println!("{} sandbox failed: {:?}", cmd.name(), e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

fn cmd_silo_top(args: &[String], cmd: Cmd) -> Result<(), ShellError> {
    // `--sort` is optional but its value is validated: a typo used to fall back
    // to the default order with no diagnostic at all.
    let sort_by_mem = match args.get(1) {
        None => false,
        Some(flag) if flag == "--sort" => match args.get(2) {
            Some(value) if value == "mem" => true,
            Some(value) if value == "tasks" => false,
            Some(value) => {
                shell_println!("{} top: unknown sort key '{}'", cmd.name(), value);
                shell_println!("Usage: silo top [--sort mem|tasks]");
                return Err(ShellError::InvalidArguments);
            }
            None => {
                shell_println!("Usage: silo top [--sort mem|tasks]");
                return Err(ShellError::InvalidArguments);
            }
        },
        Some(other) => {
            shell_println!("{} top: unexpected argument '{}'", cmd.name(), other);
            shell_println!("Usage: silo top [--sort mem|tasks]");
            return Err(ShellError::InvalidArguments);
        }
    };
    if let Some(extra) = args.get(3) {
        shell_println!("{} top: unexpected argument '{}'", cmd.name(), extra);
        shell_println!("Usage: silo top [--sort mem|tasks]");
        return Err(ShellError::InvalidArguments);
    }

    let mut silos = silo::list_silos_snapshot();
    if sort_by_mem {
        silos.sort_by_key(|s| core::cmp::Reverse(s.mem_usage_bytes));
    } else {
        silos.sort_by(|a, b| {
            b.task_count
                .cmp(&a.task_count)
                .then(b.mem_usage_bytes.cmp(&a.mem_usage_bytes))
        });
    }

    let total_tasks: usize = silos.iter().map(|s| s.task_count).sum();
    let total_mem: u64 = silos.iter().map(|s| s.mem_usage_bytes).sum();

    shell_println!(
        "Silos: {}   Tasks: {}   Memory: {}",
        silos.len(),
        total_tasks,
        crate::shell::output::human_bytes(total_mem)
    );
    shell_println!("");
    const COLS: [usize; 6] = [6, 14, 10, 7, 16, 6];
    shell_println!(
        "{:<6} {:<14} {:<10} {:<7} {:<16} {:<6}",
        "SID",
        "Name",
        "State",
        "Tasks",
        "Memory",
        "Mode"
    );
    shell_println!("{}", "-".repeat(COLS.iter().sum::<usize>()));
    for s in &silos {
        shell_println!(
            "{:<6} {:<14} {:<10} {:<7} {:<16} {:03o}",
            s.id,
            s.name,
            silo_state_str(s.state),
            s.task_count,
            crate::shell::output::human_bytes(s.mem_usage_bytes),
            s.mode
        );
    }
    Ok(())
}

fn cmd_silo_logs(args: &[String], cmd: Cmd) -> Result<(), ShellError> {
    if args.len() < 2 {
        shell_println!("Usage: {} logs <id|label|name>", cmd.name());
        return Err(ShellError::InvalidArguments);
    }
    let selector = normalize_current_silo_selector(args[1].as_str());
    let events = silo::list_events_for_silo(selector.as_str()).map_err(|e| {
        shell_println!("{} logs: {:?}", cmd.name(), e);
        ShellError::ExecutionFailed
    })?;
    if events.is_empty() {
        shell_println!("(no log entries for this silo)");
        return Ok(());
    }
    let hz = crate::arch::timer::TIMER_HZ;
    for ev in &events {
        let tick_s = ev.tick / hz;
        let tick_cs = (ev.tick % hz) * 100 / hz;
        shell_println!(
            "[{:>6}.{:02}] sid={} {}",
            tick_s,
            tick_cs,
            ev.silo_id,
            event_kind_str(ev.kind)
        );
    }
    Ok(())
}

pub(super) fn cmd_wasm_run_impl(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: wasm-run <path>");
        return Err(ShellError::InvalidArguments);
    }
    let wasm_path = &args[0];

    shell_println!("wasm-run: using running strate-wasm service...");
    let default_service_path = String::from("/srv/strate-wasm/default");
    let bootstrap_service_path = String::from("/srv/strate-wasm/bootstrap");
    shell_println!("wasm-run: waiting for service {} ...", default_service_path);

    let mut selected_service_path: Option<String> = None;
    for _ in 0..100 {
        if crate::shell::is_interrupted() {
            shell_println!("wasm-run: cancelled");
            return Err(ShellError::ExecutionFailed);
        }
        if vfs::stat_path(&default_service_path).is_ok() {
            selected_service_path = Some(default_service_path.clone());
            break;
        }
        if vfs::stat_path(&bootstrap_service_path).is_ok() {
            selected_service_path = Some(bootstrap_service_path.clone());
            break;
        }
        crate::process::yield_task();
    }

    let Some(service_path) = selected_service_path else {
        shell_println!("wasm-run: timed out waiting for /srv/strate-wasm/default");
        return Err(ShellError::ExecutionFailed);
    };

    // Connect and send LOAD then RUN
    let (scheme, rel) = vfs::resolve(&service_path).map_err(|_| ShellError::ExecutionFailed)?;
    let open_res = scheme
        .open(&rel, vfs::OpenFlags::READ)
        .map_err(|_| ShellError::ExecutionFailed)?;
    let port_id = crate::ipc::PortId::from_u64(open_res.file_id);
    let port = crate::ipc::port::get_port(port_id).ok_or(ShellError::ExecutionFailed)?;

    let mut load_msg = crate::ipc::IpcMessage::new(0x100);
    let path_bytes = wasm_path.as_bytes();
    let copy_len = core::cmp::min(path_bytes.len(), 63);
    load_msg.payload[0] = copy_len as u8;
    load_msg.payload[1..1 + copy_len].copy_from_slice(&path_bytes[..copy_len]);

    shell_println!("wasm-run: loading {} ...", wasm_path);
    port.send(load_msg)
        .map_err(|_| ShellError::ExecutionFailed)?;

    let load_ack = port.recv().map_err(|_| ShellError::ExecutionFailed)?;
    let load_status = u32::from_le_bytes([
        load_ack.payload[0],
        load_ack.payload[1],
        load_ack.payload[2],
        load_ack.payload[3],
    ]);
    if load_status != 0 {
        shell_println!("wasm-run: load failed (status={})", load_status);
        return Err(ShellError::ExecutionFailed);
    }

    let run_msg = crate::ipc::IpcMessage::new(0x102);
    shell_println!("wasm-run: starting execution...");
    port.send(run_msg)
        .map_err(|_| ShellError::ExecutionFailed)?;
    let run_ack = port.recv().map_err(|_| ShellError::ExecutionFailed)?;
    let run_status = u32::from_le_bytes([
        run_ack.payload[0],
        run_ack.payload[1],
        run_ack.payload[2],
        run_ack.payload[3],
    ]);
    if run_status != 0 {
        shell_println!("wasm-run: execution failed (status={})", run_status);
        return Err(ShellError::ExecutionFailed);
    }
    shell_println!("wasm-run: done");

    Ok(())
}

/// `health` : system health diagnostic (boot graph, strates, IPC, VFS mounts).
pub(super) fn cmd_health_impl(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("=== Strat9 Health Report ===\n");

    shell_println!("-- VFS Mounts --");
    for m in vfs::list_mounts() {
        shell_println!("  {}", m);
    }

    shell_println!("\n-- IPC Namespace --");
    let bindings = crate::namespace::list_all_bindings();
    if bindings.is_empty() {
        shell_println!("  (none)");
    } else {
        for (name, port_id) in &bindings {
            shell_println!("  {} -> port {}", name, port_id);
        }
    }

    shell_println!("\n-- Active Silos --");
    let silo_list = silo::list_silos_snapshot();
    if silo_list.is_empty() {
        shell_println!("  (none)");
    } else {
        for info in &silo_list {
            shell_println!(
                "  SID={} name={} state={} tasks={}",
                info.id,
                info.name,
                silo_state_str(info.state),
                info.task_count
            );
        }
    }

    shell_println!("\n=== End Health Report ===");
    Ok(())
}
