//! System management commands
use crate::{
    arch::x86_64::vga,
    ipc::PortId,
    process::{
        configure_class_table, elf::load_and_run_elf, log_scheduler_state, reset_scheduler_metrics,
        scheduler_class_table, scheduler_metrics_snapshot, scheduler_verbose_enabled,
        set_scheduler_verbose,
    },
    shell::{
        commands::top::Strat9RatatuiBackend,
        output::{clear_screen, format_bytes},
        ShellError,
    },
    shell_println, silo,
    vfs,
};
use alloc::{string::String, vec::Vec};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Terminal,
};

const STRATE_USAGE: &str = "Usage: strate <list|spawn|start|stop|kill|destroy|rename|config> ...";
const SILO_USAGE: &str = "Usage: silo <list|spawn|start|stop|kill|destroy|rename|config> ...";
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
name = "ssh"
family = "NET"
mode = "076"
sid = 42
[[silos.strates]]
name = "sshd"
binary = "/initfs/bin/sshd"
type = "elf"
"#;

#[derive(Clone)]
struct ManagedStrateDef {
    name: String,
    binary: String,
    stype: String,
    target: String,
}

#[derive(Clone)]
struct ManagedSiloDef {
    name: String,
    sid: u32,
    family: String,
    mode: String,
    strates: Vec<ManagedStrateDef>,
}

fn parse_silo_toml(data: &str) -> Vec<ManagedSiloDef> {
    #[derive(Clone, Copy)]
    enum Section {
        Silo,
        Strate,
    }

    fn push_default_strate(silo: &mut ManagedSiloDef) {
        silo.strates.push(ManagedStrateDef {
            name: String::new(),
            binary: String::new(),
            stype: String::from("elf"),
            target: String::from("default"),
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
                        "sid" => s.sid = val.parse().unwrap_or(42),
                        "family" => s.family = String::from(val),
                        "mode" => s.mode = String::from(val),
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
        for st in &s.strates {
            out.push('\n');
            let _ = writeln!(out, "[[silos.strates]]");
            let _ = writeln!(out, "name = \"{}\"", st.name);
            let _ = writeln!(out, "binary = \"{}\"", st.binary);
            let _ = writeln!(out, "type = \"{}\"", st.stype);
            let _ = writeln!(out, "target_strate = \"{}\"", st.target);
        }
    }
    out
}

fn read_silo_toml_from_initfs() -> Result<String, ShellError> {
    let path = "/initfs/silo.toml";
    match vfs::open(path, vfs::OpenFlags::READ) {
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

fn load_managed_silos_with_source() -> (Vec<ManagedSiloDef>, &'static str) {
    match read_silo_toml_from_initfs() {
        Ok(text) => {
            let parsed = parse_silo_toml(&text);
            if parsed.is_empty() {
                (
                    parse_silo_toml(DEFAULT_MANAGED_SILO_TOML),
                    "embedded-default",
                )
            } else {
                (parsed, "/initfs/silo.toml")
            }
        }
        Err(_) => (
            parse_silo_toml(DEFAULT_MANAGED_SILO_TOML),
            "embedded-default",
        ),
    }
}

fn push_unique(values: &mut Vec<String>, item: &str) {
    if !values.iter().any(|v| v == item) {
        values.push(String::from(item));
    }
}

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

struct SiloListRow {
    sid: u32,
    name: String,
    state: String,
    tasks: usize,
    memory: String,
    mode: u16,
    label: String,
    strates: String,
}

struct RuntimeStrateRow {
    strate: String,
    belongs_to: String,
    status: String,
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
    strates: String,
}

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
            let mut style = Style::default().fg(Color::White);
            if r.strates == "-" {
                style = style.fg(Color::LightRed);
            } else {
                style = style.fg(Color::LightGreen);
            }
            Row::new(alloc::vec![
                Cell::from(alloc::format!("{}", r.sid)),
                Cell::from(r.name.as_str()),
                Cell::from(r.state.as_str()),
                Cell::from(alloc::format!("{}", r.tasks)),
                Cell::from(r.memory.as_str()),
                Cell::from(alloc::format!("{:o}", r.mode)),
                Cell::from(r.label.as_str()),
                Cell::from(r.strates.as_str()),
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
                Cell::from(r.strates.as_str()),
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
                .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
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
                    .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
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
                Constraint::Min(20),
            ];
            let config_table = Table::new(config_table_rows, config_widths)
                .header(
                    Row::new(alloc::vec![
                        Cell::from("SID"),
                        Cell::from("Name"),
                        Cell::from("Family"),
                        Cell::from("Mode"),
                        Cell::from("Strates"),
                    ])
                    .style(Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
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
    }
    Ok(true)
}

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
                Cell::from(r.status.as_str()),
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
                .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
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
                    .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
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
                    Row::new(alloc::vec![Cell::from("Strate"), Cell::from("BelongsTo")])
                        .style(Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
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
    }
    Ok(true)
}

fn write_silo_toml_to_initfs(text: &str) -> Result<(), ShellError> {
    let path = "/initfs/silo.toml";
    let fd = vfs::open(
        path,
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

fn print_strate_state_for_sid(sid: u32) {
    if let Some(s) = silo::list_silos_snapshot().into_iter().find(|s| s.id == sid) {
        shell_println!("state: {:?}", s.state);
    } else {
        shell_println!("state: <unknown>");
    }
}

fn print_strate_usage() {
    shell_println!("{}", STRATE_USAGE);
    shell_println!("  strate list");
    shell_println!("  strate spawn <type> [--label <label>] [--dev <path>]");
    shell_println!("  strate start <id|label>");
    shell_println!("  strate stop <id|label>");
    shell_println!("  strate kill <id|label>");
    shell_println!("  strate destroy <id|label>");
    shell_println!("  strate rename <id|label> <new_label>");
    shell_println!("  strate config show [silo]");
    shell_println!("  strate config add <silo> <name> <binary> [--type <t>] [--target <x>] [--family <F>] [--mode <ooo>] [--sid <n>]");
    shell_println!("  strate config remove <silo> <name>");
}

fn print_silo_usage() {
    shell_println!("{}", SILO_USAGE);
    shell_println!("  silo list");
    shell_println!("  silo spawn <type> [--label <label>] [--dev <path>]");
    shell_println!("  silo start <id|label>");
    shell_println!("  silo stop <id|label>");
    shell_println!("  silo kill <id|label>");
    shell_println!("  silo destroy <id|label>");
    shell_println!("  silo rename <id|label> <new_label>");
    shell_println!("  silo config show [silo]");
    shell_println!("  silo config add <silo> <name> <binary> [--type <t>] [--target <x>] [--family <F>] [--mode <ooo>] [--sid <n>]");
    shell_println!("  silo config remove <silo> <name>");
}

pub fn cmd_silo(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        print_silo_usage();
        return Err(ShellError::InvalidArguments);
    }
    match args[0].as_str() {
        "list" => cmd_silo_list(args),
        "spawn" | "start" | "stop" | "kill" | "destroy" | "rename" | "config" => {
            cmd_strate(args)
        }
        _ => {
            print_silo_usage();
            Err(ShellError::InvalidArguments)
        }
    }
}

pub fn cmd_silos(_args: &[String]) -> Result<(), ShellError> {
    let args = [String::from("list")];
    cmd_silo(&args)
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
    clear_screen();
    Ok(())
}

/// Display CPU information
pub fn cmd_cpuinfo(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("CPU information:");

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
    unsafe {
        crate::arch::x86_64::cli();
        crate::arch::x86_64::io::outb(0x64, 0xFE);
        loop {
            crate::arch::x86_64::hlt();
        }
    }
}

/// scheduler debug on|off|dump | class | metrics [reset]
pub fn cmd_scheduler(args: &[String]) -> Result<(), ShellError> {
    fn parse_class(s: &str) -> Option<crate::process::sched::SchedClassId> {
        crate::process::sched::SchedClassId::parse(s)
    }
    fn parse_kind(s: &str) -> Option<crate::process::sched::SchedPolicyKind> {
        crate::process::sched::SchedPolicyKind::parse(s)
    }
    fn print_table(table: crate::process::sched::SchedClassTable) {
        let pick = table.pick_order();
        let steal = table.steal_order();
        shell_println!(
            "class table: pick=[{},{},{}] steal=[{},{}]",
            pick[0].as_str(),
            pick[1].as_str(),
            pick[2].as_str(),
            steal[0].as_str(),
            steal[1].as_str()
        );
        for entry in table.entries().iter() {
            shell_println!(
                "  class={} name={} rank={}",
                entry.id.as_str(),
                entry.name,
                entry.rank
            );
        }
        let pm = table.policy_map();
        shell_println!(
            "  policy_map: fair->{} rt->{} idle->{}",
            pm[0].as_str(),
            pm[1].as_str(),
            pm[2].as_str()
        );
    }

    if args.is_empty() {
        shell_println!("Usage: scheduler <debug|class|policy|metrics> ...");
        return Err(ShellError::InvalidArguments);
    }

    match args[0].as_str() {
        "debug" => {
            if args.len() != 2 {
                shell_println!("Usage: scheduler debug on|off|dump");
                return Err(ShellError::InvalidArguments);
            }
            match args[1].as_str() {
                "on" => {
                    set_scheduler_verbose(true);
                    shell_println!("scheduler debug: on");
                    Ok(())
                }
                "off" => {
                    set_scheduler_verbose(false);
                    shell_println!("scheduler debug: off");
                    Ok(())
                }
                "dump" => {
                    let table = scheduler_class_table();
                    shell_println!(
                        "scheduler debug: {}",
                        if scheduler_verbose_enabled() {
                            "on"
                        } else {
                            "off"
                        }
                    );
                    print_table(table);
                    log_scheduler_state("shell");
                    Ok(())
                }
                _ => {
                    shell_println!("Usage: scheduler debug on|off|dump");
                    Err(ShellError::InvalidArguments)
                }
            }
        }
        "class" => {
            if args.len() == 1 {
                print_table(scheduler_class_table());
                return Ok(());
            }
            if args.len() >= 3 && args[1].as_str() == "order" && args[2].as_str() == "set" {
                if args.len() != 6 {
                    shell_println!("Usage: scheduler class order set <c1> <c2> <c3>");
                    return Err(ShellError::InvalidArguments);
                }
                let c1 = parse_class(args[3].as_str()).ok_or(ShellError::InvalidArguments)?;
                let c2 = parse_class(args[4].as_str()).ok_or(ShellError::InvalidArguments)?;
                let c3 = parse_class(args[5].as_str()).ok_or(ShellError::InvalidArguments)?;
                let mut table = scheduler_class_table();
                if !table.set_pick_order([c1, c2, c3]) || !configure_class_table(table) {
                    shell_println!("scheduler: rejected class order");
                    return Err(ShellError::InvalidArguments);
                }
                print_table(table);
                return Ok(());
            }
            if args.len() >= 3 && args[1].as_str() == "steal" && args[2].as_str() == "set" {
                if args.len() != 5 {
                    shell_println!("Usage: scheduler class steal set <c1> <c2>");
                    return Err(ShellError::InvalidArguments);
                }
                let c1 = parse_class(args[3].as_str()).ok_or(ShellError::InvalidArguments)?;
                let c2 = parse_class(args[4].as_str()).ok_or(ShellError::InvalidArguments)?;
                let mut table = scheduler_class_table();
                if !table.set_steal_order([c1, c2]) || !configure_class_table(table) {
                    shell_println!("scheduler: rejected steal order");
                    return Err(ShellError::InvalidArguments);
                }
                print_table(table);
                return Ok(());
            }
            shell_println!("Usage: scheduler class [order set <c1> <c2> <c3> | steal set <c1> <c2>]");
            Err(ShellError::InvalidArguments)
        }
        "policy" => {
            if args.len() == 1 || (args.len() == 2 && args[1].as_str() == "map") {
                print_table(scheduler_class_table());
                return Ok(());
            }
            if args.len() >= 3 && args[1].as_str() == "map" && args[2].as_str() == "show" {
                print_table(scheduler_class_table());
                return Ok(());
            }
            if args.len() >= 3 && args[1].as_str() == "map" && args[2].as_str() == "set" {
                if args.len() != 5 {
                    shell_println!("Usage: scheduler policy map set <fair|rt|idle> <rt|fair|idle>");
                    return Err(ShellError::InvalidArguments);
                }
                let kind = parse_kind(args[3].as_str()).ok_or(ShellError::InvalidArguments)?;
                let class = parse_class(args[4].as_str()).ok_or(ShellError::InvalidArguments)?;
                let mut table = scheduler_class_table();
                if !table.set_policy_class(kind, class) || !configure_class_table(table) {
                    shell_println!("scheduler: rejected policy map");
                    return Err(ShellError::InvalidArguments);
                }
                print_table(table);
                return Ok(());
            }
            shell_println!("Usage: scheduler policy map <show|set <fair|rt|idle> <rt|fair|idle>>");
            Err(ShellError::InvalidArguments)
        }
        "metrics" => {
            if args.len() == 2 && args[1].as_str() == "reset" {
                reset_scheduler_metrics();
                shell_println!("scheduler metrics: reset");
                return Ok(());
            }
            if args.len() != 1 {
                shell_println!("Usage: scheduler metrics [reset]");
                return Err(ShellError::InvalidArguments);
            }
            let m = scheduler_metrics_snapshot();
            shell_println!("scheduler metrics: cpu_count={}", m.cpu_count);
            for i in 0..m.cpu_count.min(crate::arch::x86_64::percpu::MAX_CPUS) {
                shell_println!(
                    "  cpu{} rt={} fair={} idle={} sw={} pre={} st+={} st-={}",
                    i,
                    m.rt_runtime_ticks[i],
                    m.fair_runtime_ticks[i],
                    m.idle_runtime_ticks[i],
                    m.switch_count[i],
                    m.preempt_count[i],
                    m.steal_in_count[i],
                    m.steal_out_count[i]
                );
            }
            Ok(())
        }
        _ => {
            shell_println!("Usage: scheduler <debug|class|policy|metrics> ...");
            Err(ShellError::InvalidArguments)
        }
    }
}

/// trace mem on|off|dump [n]|clear|serial on|off|mask
pub fn cmd_trace(args: &[String]) -> Result<(), ShellError> {
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
pub fn cmd_test_pid(_args: &[String]) -> Result<(), ShellError> {
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
    shell_println!("Launching with task name 'init' to inherit bootstrap console/admin caps");
    match load_and_run_elf(&data, "init") {
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
pub fn cmd_test_syscalls(_args: &[String]) -> Result<(), ShellError> {
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
    shell_println!("Launching with task name 'init' to inherit bootstrap console/admin caps");
    match load_and_run_elf(&data, "init") {
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
pub fn cmd_test_mem(_args: &[String]) -> Result<(), ShellError> {
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
    shell_println!("Launching with task name 'init' to inherit bootstrap console/admin caps");
    match load_and_run_elf(&data, "init") {
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
pub fn cmd_test_mem_stressed(_args: &[String]) -> Result<(), ShellError> {
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
    shell_println!("Launching with task name 'init' to inherit bootstrap console/admin caps");
    match load_and_run_elf(&data, "init") {
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

fn cmd_silo_list(_args: &[String]) -> Result<(), ShellError> {
    let (managed, managed_source) = load_managed_silos_with_source();
    let mut silos = silo::list_silos_snapshot();
    silos.sort_by_key(|s| s.id);

    let mut rows: Vec<SiloListRow> = Vec::new();
    let mut config_rows: Vec<ConfigListRow> = Vec::new();

    for m in &managed {
        let mut strates = Vec::new();
        for st in &m.strates {
            if !st.name.is_empty() {
                push_unique(&mut strates, &st.name);
            }
        }
        config_rows.push(ConfigListRow {
            sid: m.sid,
            name: m.name.clone(),
            family: m.family.clone(),
            mode: m.mode.clone(),
            strates: join_csv(&strates),
        });
    }

    for s in silos.iter() {
        let label = s.strate_label.clone().unwrap_or_else(|| String::from("-"));
        let mut strates = Vec::new();
        for m in &managed {
            if m.name == s.name || m.sid == s.id {
                for st in &m.strates {
                    if !st.name.is_empty() {
                        push_unique(&mut strates, &st.name);
                    }
                }
            }
        }
        if strates.is_empty() && label != "-" {
            strates.push(alloc::format!("{} (kernel)", label));
        }
        let strates_cell = join_csv(&strates);
        let (used_val, used_unit) = format_bytes(s.mem_usage_bytes as usize);
        let mem_cell = if s.mem_max_bytes == 0 {
            alloc::format!("{} {} / unlimited", used_val, used_unit)
        } else {
            let (max_val, max_unit) = format_bytes(s.mem_max_bytes as usize);
            alloc::format!("{} {} / {} {}", used_val, used_unit, max_val, max_unit)
        };
        rows.push(SiloListRow {
            sid: s.id,
            name: s.name.clone(),
            state: alloc::format!("{:?}", s.state),
            tasks: s.task_count,
            memory: mem_cell,
            mode: s.mode,
            label,
            strates: strates_cell,
        });
    }
    if render_silo_table_ratatui(&rows, &config_rows, managed_source).unwrap_or(false) {
        return Ok(());
    }

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
    shell_println!("────────────────────────────────────────────────────────────────────────────────────────────────────────────");
    for r in rows {
        shell_println!(
            "{:<6} {:<12} {:<10} {:<7} {:<18} {:<6o} {:<12} {}",
            r.sid,
            r.name,
            r.state,
            r.tasks,
            r.memory,
            r.mode,
            r.label,
            r.strates
        );
    }
    Ok(())
}

fn cmd_strate_list(_args: &[String]) -> Result<(), ShellError> {
    struct StrateEntry {
        name: String,
        belongs_to: Vec<String>,
    }

    let (managed, managed_source) = load_managed_silos_with_source();
    let mut entries: Vec<StrateEntry> = Vec::new();

    for s in &managed {
        for st in &s.strates {
            if st.name.is_empty() {
                continue;
            }
            if let Some(e) = entries.iter_mut().find(|e| e.name == st.name) {
                push_unique(&mut e.belongs_to, &s.name);
            } else {
                entries.push(StrateEntry {
                    name: st.name.clone(),
                    belongs_to: alloc::vec![s.name.clone()],
                });
            }
        }
    }

    let mut runtime_entries: Vec<StrateEntry> = Vec::new();
    for runtime in silo::list_silos_snapshot() {
        let mut names: Vec<String> = Vec::new();
        for m in &managed {
            if m.name == runtime.name || m.sid == runtime.id {
                for st in &m.strates {
                    if !st.name.is_empty() {
                        push_unique(&mut names, &st.name);
                    }
                }
            }
        }
        if names.is_empty() {
            if let Some(label) = runtime.strate_label {
                names.push(label);
            } else {
                continue;
            }
        }

        for name in names {
            if let Some(e) = runtime_entries.iter_mut().find(|e| e.name == name) {
                push_unique(&mut e.belongs_to, &runtime.name);
            } else {
                runtime_entries.push(StrateEntry {
                    name,
                    belongs_to: alloc::vec![runtime.name.clone()],
                });
            }
        }
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));
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
        .map(|e| {
            let in_cfg = entries.iter().any(|cfg| cfg.name == e.name);
            RuntimeStrateRow {
                strate: e.name.clone(),
                belongs_to: join_csv(&e.belongs_to),
                status: if in_cfg {
                    String::from("config+runtime")
                } else {
                    String::from("runtime-only")
                },
            }
        })
        .collect();

    if render_strate_table_ratatui(&runtime_rows, &config_rows, managed_source).unwrap_or(false) {
        return Ok(());
    }

    shell_println!("Runtime:");
    shell_println!("{:<20} {:<24} {}", "Strate", "BelongsTo", "Status");
    shell_println!("────────────────────────────────────────────────────────────");
    for r in runtime_rows {
        shell_println!("{:<20} {:<24} {}", r.strate, r.belongs_to, r.status);
    }
    shell_println!("");
    shell_println!("Config ({}):", managed_source);
    shell_println!("{:<20} {}", "Strate", "BelongsTo");
    shell_println!("────────────────────────────────────────────────────────────");
    for r in config_rows {
        shell_println!("{:<20} {}", r.strate, r.belongs_to);
    }
    Ok(())
}

fn cmd_strate_spawn(args: &[String]) -> Result<(), ShellError> {
    if args.len() < 2 {
        shell_println!("Usage: strate spawn <type> [--label <label>] [--dev <path>]");
        return Err(ShellError::InvalidArguments);
    }
    let strate_type = args[1].as_str();
    let module_path = match strate_type {
        "strate-fs-ext4" => "/initfs/fs-ext4",
        "ramfs" | "strate-fs-ramfs" => "/initfs/strate-fs-ramfs",
        _ => {
            shell_println!("strate spawn: unsupported type '{}'", strate_type);
            return Err(ShellError::InvalidArguments);
        }
    };

    let mut label: Option<&str> = None;
    let mut dev: Option<&str> = None;
    let mut i = 2usize;
    while i < args.len() {
        match args[i].as_str() {
            "--label" => {
                if i + 1 >= args.len() {
                    shell_println!("strate spawn: missing value for --label");
                    return Err(ShellError::InvalidArguments);
                }
                label = Some(args[i + 1].as_str());
                i += 2;
            }
            "--dev" => {
                if i + 1 >= args.len() {
                    shell_println!("strate spawn: missing value for --dev");
                    return Err(ShellError::InvalidArguments);
                }
                dev = Some(args[i + 1].as_str());
                i += 2;
            }
            other => {
                shell_println!("strate spawn: unknown option '{}'", other);
                return Err(ShellError::InvalidArguments);
            }
        }
    }

    let fd = vfs::open(module_path, vfs::OpenFlags::READ).map_err(|_| ShellError::ExecutionFailed)?;
    let data = match vfs::read_all(fd) {
        Ok(d) => d,
        Err(_) => {
            let _ = vfs::close(fd);
            return Err(ShellError::ExecutionFailed);
        }
    };
    let _ = vfs::close(fd);

    match silo::kernel_spawn_strate(&data, label, dev) {
        Ok(sid) => {
            shell_println!(
                "strate spawn: {} started (sid={}, label={}, dev={})",
                strate_type,
                sid,
                label.unwrap_or("default"),
                dev.unwrap_or("auto")
            );
            Ok(())
        }
        Err(e) => {
            shell_println!("strate spawn failed: {:?}", e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

fn cmd_strate_config_show(args: &[String]) -> Result<(), ShellError> {
    let existing = read_silo_toml_from_initfs()?;
    let silos = parse_silo_toml(&existing);
    if silos.is_empty() {
        shell_println!("strate config show: /initfs/silo.toml empty or missing");
        return Ok(());
    }

    if args.len() == 3 {
        let name = args[2].as_str();
        let Some(s) = silos.iter().find(|s| s.name == name) else {
            shell_println!("strate config show: silo '{}' not found", name);
            return Err(ShellError::ExecutionFailed);
        };
        shell_println!(
            "silo '{}' sid={} family={} mode={} strates={}",
            s.name,
            s.sid,
            s.family,
            s.mode,
            s.strates.len()
        );
        for st in &s.strates {
            shell_println!(
                "  - {}: binary={} type={} target={}",
                st.name,
                st.binary,
                st.stype,
                st.target
            );
        }
        return Ok(());
    }

    for s in &silos {
        shell_println!(
            "silo '{}' sid={} family={} mode={} strates={}",
            s.name,
            s.sid,
            s.family,
            s.mode,
            s.strates.len()
        );
    }
    Ok(())
}

fn cmd_strate_config_add(args: &[String]) -> Result<(), ShellError> {
    if args.len() < 5 {
        shell_println!("Usage: strate config add <silo> <name> <binary> [--type <t>] [--target <x>] [--family <F>] [--mode <ooo>] [--sid <n>]");
        return Err(ShellError::InvalidArguments);
    }
    let silo_name = args[2].as_str();
    let strate_name = args[3].as_str();
    let binary = args[4].as_str();
    if silo_name.is_empty() || strate_name.is_empty() || binary.is_empty() {
        shell_println!("strate config add: invalid empty argument");
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
                    shell_println!("strate config add: missing value for --type");
                    return Err(ShellError::InvalidArguments);
                }
                stype = args[i + 1].clone();
                i += 2;
            }
            "--target" => {
                if i + 1 >= args.len() {
                    shell_println!("strate config add: missing value for --target");
                    return Err(ShellError::InvalidArguments);
                }
                target = args[i + 1].clone();
                i += 2;
            }
            "--family" => {
                if i + 1 >= args.len() {
                    shell_println!("strate config add: missing value for --family");
                    return Err(ShellError::InvalidArguments);
                }
                family = Some(args[i + 1].clone());
                i += 2;
            }
            "--mode" => {
                if i + 1 >= args.len() {
                    shell_println!("strate config add: missing value for --mode");
                    return Err(ShellError::InvalidArguments);
                }
                mode = Some(args[i + 1].clone());
                i += 2;
            }
            "--sid" => {
                if i + 1 >= args.len() {
                    shell_println!("strate config add: missing value for --sid");
                    return Err(ShellError::InvalidArguments);
                }
                sid = args[i + 1].parse::<u32>().ok();
                if sid.is_none() {
                    shell_println!("strate config add: invalid --sid");
                    return Err(ShellError::InvalidArguments);
                }
                i += 2;
            }
            other => {
                shell_println!("strate config add: unknown option '{}'", other);
                return Err(ShellError::InvalidArguments);
            }
        }
    }

    let existing = read_silo_toml_from_initfs()?;
    let mut silos = parse_silo_toml(&existing);
    let idx = match silos.iter().position(|s| s.name == silo_name) {
        Some(p) => p,
        None => {
            silos.push(ManagedSiloDef {
                name: String::from(silo_name),
                sid: sid.unwrap_or(42),
                family: family.clone().unwrap_or_else(|| String::from("USR")),
                mode: mode.clone().unwrap_or_else(|| String::from("000")),
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

    if let Some(st) = silos[idx].strates.iter_mut().find(|st| st.name == strate_name) {
        st.binary = String::from(binary);
        st.stype = stype;
        st.target = target;
    } else {
        silos[idx].strates.push(ManagedStrateDef {
            name: String::from(strate_name),
            binary: String::from(binary),
            stype,
            target,
        });
    }

    let rendered = render_silo_toml(&silos);
    write_silo_toml_to_initfs(&rendered)?;
    shell_println!(
        "strate config add: wrote /initfs/silo.toml (silo='{}', strate='{}')",
        silo_name,
        strate_name
    );
    Ok(())
}

fn cmd_strate_config_remove(args: &[String]) -> Result<(), ShellError> {
    if args.len() != 4 {
        shell_println!("Usage: strate config remove <silo> <name>");
        return Err(ShellError::InvalidArguments);
    }
    let silo_name = args[2].as_str();
    let strate_name = args[3].as_str();
    let existing = read_silo_toml_from_initfs()?;
    let mut silos = parse_silo_toml(&existing);

    let Some(silo_idx) = silos.iter().position(|s| s.name == silo_name) else {
        shell_println!("strate config remove: silo '{}' not found", silo_name);
        return Err(ShellError::ExecutionFailed);
    };
    let Some(strate_idx) = silos[silo_idx]
        .strates
        .iter()
        .position(|st| st.name == strate_name) else {
        shell_println!(
            "strate config remove: strate '{}' not found in silo '{}'",
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
        "strate config remove: updated /initfs/silo.toml (silo='{}', strate='{}')",
        silo_name,
        strate_name
    );
    Ok(())
}

fn cmd_strate_config(args: &[String]) -> Result<(), ShellError> {
    if args.len() < 2 {
        shell_println!("Usage: strate config <show|add|remove> ...");
        return Err(ShellError::InvalidArguments);
    }
    match args[1].as_str() {
        "show" => cmd_strate_config_show(args),
        "add" => cmd_strate_config_add(args),
        "remove" => cmd_strate_config_remove(args),
        _ => {
            shell_println!("Usage: strate config <show|add|remove> ...");
            Err(ShellError::InvalidArguments)
        }
    }
}

fn cmd_strate_start(args: &[String]) -> Result<(), ShellError> {
    if args.len() != 2 {
        shell_println!("Usage: strate start <id|label>");
        return Err(ShellError::InvalidArguments);
    }
    let selector = args[1].as_str();
    match silo::kernel_start_silo(selector) {
        Ok(sid) => {
            shell_println!("strate start: ok (sid={})", sid);
            print_strate_state_for_sid(sid);
            Ok(())
        }
        Err(e) => {
            shell_println!("strate start failed: {:?}", e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

fn cmd_strate_lifecycle(args: &[String]) -> Result<(), ShellError> {
    if args.len() != 2 {
        shell_println!("Usage: strate start|stop|kill|destroy <id|label>");
        return Err(ShellError::InvalidArguments);
    }
    let selector = args[1].as_str();
    let action = args[0].as_str();
    let result = match action {
        "stop" => silo::kernel_stop_silo(selector, false),
        "kill" => silo::kernel_stop_silo(selector, true),
        "destroy" => silo::kernel_destroy_silo(selector),
        _ => unreachable!(),
    };
    match result {
        Ok(sid) => {
            shell_println!("strate {}: ok (sid={})", action, sid);
            if action == "stop" {
                print_strate_state_for_sid(sid);
            }
            Ok(())
        }
        Err(e) => {
            shell_println!("strate {} failed: {:?}", action, e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

fn cmd_strate_rename(args: &[String]) -> Result<(), ShellError> {
    if args.len() != 3 {
        shell_println!("Usage: strate rename <id|label> <new_label>");
        return Err(ShellError::InvalidArguments);
    }
    let selector = args[1].as_str();
    let new_label = args[2].as_str();
    match silo::kernel_rename_silo_label(selector, new_label) {
        Ok(sid) => {
            shell_println!("strate rename: ok (sid={}, new_label={})", sid, new_label);
            Ok(())
        }
        Err(e) => {
            if matches!(e, crate::syscall::error::SyscallError::InvalidArgument) {
                shell_println!(
                    "strate rename failed: strate is running or not in a renamable state (stop it first)"
                );
            } else {
                shell_println!("strate rename failed: {:?}", e);
            }
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// strate command suite
pub fn cmd_strate(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        print_strate_usage();
        return Err(ShellError::InvalidArguments);
    }

    match args[0].as_str() {
        "list" => cmd_strate_list(args),
        "spawn" => cmd_strate_spawn(args),
        "config" => cmd_strate_config(args),
        "start" => cmd_strate_start(args),
        "stop" | "kill" | "destroy" => cmd_strate_lifecycle(args),
        "rename" => cmd_strate_rename(args),
        _ => {
            print_strate_usage();
            Err(ShellError::InvalidArguments)
        }
    }
}

/// wasm-run /path/to/app.wasm
pub fn cmd_wasm_run(args: &[String]) -> Result<(), ShellError> {
    if args.len() < 1 {
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
