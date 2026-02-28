//! System management commands
use crate::{
    ipc::PortId,
    process::{
        elf::load_and_run_elf, log_scheduler_state, scheduler_class_table,
        scheduler_verbose_enabled, set_scheduler_verbose,
    },
    shell::{
        output::{clear_screen, format_bytes},
        ShellError,
    },
    shell_println, silo,
    vfs,
};
use alloc::{string::String, vec::Vec};

const STRATE_USAGE: &str = "Usage: strate <list|spawn|start|stop|kill|destroy|rename|config> ...";
const SILO_USAGE: &str = "Usage: silo <list|spawn|start|stop|kill|destroy|rename|config> ...";

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
    shell_println!("  strate list [--all]");
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
    shell_println!("  silo list [--all]");
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
        "list" | "spawn" | "start" | "stop" | "kill" | "destroy" | "rename" | "config" => {
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
    cmd_strate(&args)
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

/// scheduler debug on|off|dump
pub fn cmd_scheduler(args: &[String]) -> Result<(), ShellError> {
    if args.len() != 2 || args[0].as_str() != "debug" {
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
            let pick = table.pick_order();
            let steal = table.steal_order();
            shell_println!(
                "scheduler debug: {}",
                if scheduler_verbose_enabled() {
                    "on"
                } else {
                    "off"
                }
            );
            shell_println!(
                "class table: pick=[{},{},{}] steal=[{},{}]",
                pick[0].as_str(),
                pick[1].as_str(),
                pick[2].as_str(),
                steal[0].as_str(),
                steal[1].as_str()
            );
            log_scheduler_state("shell");
            Ok(())
        }
        _ => {
            shell_println!("Usage: scheduler debug on|off|dump");
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

/// strate command suite
pub fn cmd_strate(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        print_strate_usage();
        return Err(ShellError::InvalidArguments);
    }

    match args[0].as_str() {
        "list" => {
            let mut silos = silo::list_silos_snapshot();
            if args.get(1).map(|s| s.as_str()) != Some("--all") {
                silos.retain(|s| s.strate_label.is_some());
            }
            silos.sort_by_key(|s| s.id);

            shell_println!(
                "{:<6} {:<12} {:<10} {:<7} {:<18} {:<6} {}",
                "SID",
                "Name",
                "State",
                "Tasks",
                "Memory",
                "Mode",
                "Label"
            );
            shell_println!(
                "────────────────────────────────────────────────────────────────────────────────────────"
            );
            for s in silos {
                let label = s.strate_label.unwrap_or_else(|| String::from("-"));
                let (used_val, used_unit) = format_bytes(s.mem_usage_bytes as usize);
                let mem_cell = if s.mem_max_bytes == 0 {
                    alloc::format!("{} {} / unlimited", used_val, used_unit)
                } else {
                    let (max_val, max_unit) = format_bytes(s.mem_max_bytes as usize);
                    alloc::format!("{} {} / {} {}", used_val, used_unit, max_val, max_unit)
                };
                shell_println!(
                    "{:<6} {:<12} {:<10?} {:<7} {:<18} {:<6o} {}",
                    s.id,
                    s.name,
                    s.state,
                    s.task_count,
                    mem_cell,
                    s.mode,
                    label
                );
            }
            Ok(())
        }
        "spawn" => {
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

            let fd = vfs::open(module_path, vfs::OpenFlags::READ)
                .map_err(|_| ShellError::ExecutionFailed)?;
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
        "config" => {
            if args.len() < 2 {
                shell_println!("Usage: strate config <show|add|remove> ...");
                return Err(ShellError::InvalidArguments);
            }
            match args[1].as_str() {
                "show" => {
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
                "add" => {
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

                    if let Some(st) = silos[idx].strates.iter_mut().find(|st| st.name == strate_name)
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
                "remove" => {
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
                _ => {
                    shell_println!("Usage: strate config <show|add|remove> ...");
                    Err(ShellError::InvalidArguments)
                }
            }
        }
        "start" => {
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
        "stop" | "kill" | "destroy" => {
            if args.len() != 2 {
                shell_println!("Usage: strate start|stop|kill|destroy <id|label>");
                return Err(ShellError::InvalidArguments);
            }
            let selector = args[1].as_str();
            let result = match args[0].as_str() {
                "stop" => silo::kernel_stop_silo(selector, false),
                "kill" => silo::kernel_stop_silo(selector, true),
                "destroy" => silo::kernel_destroy_silo(selector),
                _ => unreachable!(),
            };
            match result {
                Ok(sid) => {
                    shell_println!("strate {}: ok (sid={})", args[0], sid);
                    if args[0].as_str() == "stop" {
                        print_strate_state_for_sid(sid);
                    }
                    Ok(())
                }
                Err(e) => {
                    shell_println!("strate {} failed: {:?}", args[0], e);
                    Err(ShellError::ExecutionFailed)
                }
            }
        }
        "rename" => {
            if args.len() != 3 {
                shell_println!("Usage: strate rename <id|label> <new_label>");
                return Err(ShellError::InvalidArguments);
            }
            let selector = args[1].as_str();
            let new_label = args[2].as_str();
            match silo::kernel_rename_silo_label(selector, new_label) {
                Ok(sid) => {
                    shell_println!(
                        "strate rename: ok (sid={}, new_label={})",
                        sid,
                        new_label
                    );
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

    // 1. Spawn the wasm interpreter strate
    shell_println!("wasm-run: spawning interpreter silo...");
    let interpreter_path = "/initfs/strate-wasm";
    let fd = vfs::open(interpreter_path, vfs::OpenFlags::READ)
        .map_err(|_| ShellError::ExecutionFailed)?;
    let elf_data = match vfs::read_all(fd) {
        Ok(d) => d,
        Err(_) => {
            let _ = vfs::close(fd);
            return Err(ShellError::ExecutionFailed);
        }
    };
    let _ = vfs::close(fd);

    // Spawn with a unique label to avoid conflicts
    let sid = match silo::kernel_spawn_strate(&elf_data, None, None) {
        Ok(id) => id,
        Err(e) => {
            shell_println!("wasm-run: failed to spawn interpreter: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };
    let label = alloc::format!("inst-{}", sid);

    // 2. Wait for the service to appear in /srv (poll)
    let service_path = alloc::format!("/srv/strate-wasm/{}", label);
    shell_println!("wasm-run: waiting for service {} ...", service_path);

    let mut found = false;
    for _ in 0..100 {
        if vfs::stat_path(&service_path).is_ok() {
            found = true;
            break;
        }
        crate::process::yield_task();
    }

    if !found {
        shell_println!("wasm-run: timed out waiting for strate-wasm");
        return Err(ShellError::ExecutionFailed);
    }

    // 3. Connect and send LOAD then RUN
    let (scheme, rel) = vfs::resolve(&service_path).map_err(|_| ShellError::ExecutionFailed)?;
    let open_res = scheme
        .open(&rel, vfs::OpenFlags::READ)
        .map_err(|_| ShellError::ExecutionFailed)?;
    let port_id = crate::ipc::PortId::from_u64(open_res.file_id);
    let port = crate::ipc::port::get_port(port_id).ok_or(ShellError::ExecutionFailed)?;

    // OP_WASM_LOAD_PATH = 0x100
    let mut load_msg = crate::ipc::IpcMessage::new(0x100);
    let path_bytes = wasm_path.as_bytes();
    let copy_len = core::cmp::min(path_bytes.len(), 62);
    load_msg.payload[1] = copy_len as u8;
    load_msg.payload[2..2 + copy_len].copy_from_slice(&path_bytes[..copy_len]);

    shell_println!("wasm-run: loading {} ...", wasm_path);
    port.send(load_msg)
        .map_err(|_| ShellError::ExecutionFailed)?;

    // Wait for ACK (simplistic)
    let _ = port.recv().map_err(|_| ShellError::ExecutionFailed)?;

    // OP_WASM_RUN_MAIN = 0x102
    let mut run_msg = crate::ipc::IpcMessage::new(0x102);
    shell_println!("wasm-run: starting execution...");
    port.send(run_msg)
        .map_err(|_| ShellError::ExecutionFailed)?;

    Ok(())
}
