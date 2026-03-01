use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;
use strat9_syscall::{call, flag, Dirent};

use crate::net;

// ---------------------------------------------------------------------------
// Structured process info
// ---------------------------------------------------------------------------

pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub state: String,
    pub silo_id: String,
    pub mem_used: String,
}

fn parse_proc_status(raw: &str) -> ProcInfo {
    let mut info = ProcInfo {
        pid: 0,
        ppid: 0,
        name: String::new(),
        state: String::new(),
        silo_id: String::new(),
        mem_used: String::new(),
    };
    for line in raw.lines() {
        let (key, val) = match line.split_once(':') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => continue,
        };
        match key {
            "Pid" => info.pid = val.parse().unwrap_or(0),
            "PPid" => info.ppid = val.parse().unwrap_or(0),
            "Name" => info.name = val.into(),
            "State" => info.state = val.into(),
            "SiloId" => info.silo_id = val.into(),
            "SiloMemUsed" => info.mem_used = val.into(),
            _ => {}
        }
    }
    info
}

// ---------------------------------------------------------------------------
// /proc readers
// ---------------------------------------------------------------------------

pub fn kernel_version() -> String {
    net::read_file_text("/proc/version")
}

pub fn cpu_info() -> String {
    net::read_file_text("/proc/cpuinfo")
}

pub fn mem_info() -> String {
    net::read_file_text("/proc/meminfo")
}

pub fn silo_info() -> String {
    net::read_file_text("/proc/silos")
}

pub fn net_routes() -> String {
    net::read_file_text("/net/routes")
}

// ---------------------------------------------------------------------------
// /net scheme readers
// ---------------------------------------------------------------------------

pub fn net_address() -> String {
    net::read_file_text("/net/address").trim().into()
}

pub fn net_gateway() -> String {
    net::read_file_text("/net/gateway").trim().into()
}

pub fn net_dns() -> String {
    net::read_file_text("/net/dns").trim().into()
}

pub fn net_ip() -> String {
    net::read_file_text("/net/ip").trim().into()
}

pub fn net_netmask() -> String {
    net::read_file_text("/net/netmask").trim().into()
}

// ---------------------------------------------------------------------------
// Process list via /proc + getdents (loops until all entries read)
// ---------------------------------------------------------------------------

pub fn process_list() -> Vec<ProcInfo> {
    let fd = match call::openat(
        0,
        "/proc",
        (flag::OpenFlags::RDONLY | flag::OpenFlags::DIRECTORY).bits() as usize,
        0,
    ) {
        Ok(fd) => fd as usize,
        Err(_) => return Vec::new(),
    };

    let mut pids = Vec::new();
    let mut raw = [0u8; 4096];
    let dirent_size = core::mem::size_of::<Dirent>();

    loop {
        let n = match call::getdents(fd, &mut raw) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };

        let mut offset = 0usize;
        while offset + dirent_size <= n {
            // SAFETY: Dirent is repr(C), kernel packs entries correctly.
            let entry = unsafe { &*(raw.as_ptr().add(offset) as *const Dirent) };
            if let Ok(name_str) = core::str::from_utf8(entry.name()) {
                if let Ok(pid) = name_str.parse::<u32>() {
                    pids.push(pid);
                }
            }
            let advance = if entry.next > 0 {
                entry.next
            } else {
                dirent_size
            };
            offset += advance;
        }
    }
    let _ = call::close(fd);

    let mut result = Vec::with_capacity(pids.len());
    for pid in pids {
        let status_raw = net::read_file_text(&format!("/proc/{}/status", pid));
        if !status_raw.is_empty() {
            result.push(parse_proc_status(&status_raw));
        }
    }
    result
}

pub fn uptime_secs() -> u64 {
    net::clock_gettime_ns() / 1_000_000_000
}

// ---------------------------------------------------------------------------
// Kill a process by PID
// ---------------------------------------------------------------------------

pub fn kill_process(pid: u32) -> bool {
    call::kill(pid as isize, 9).is_ok()
}

// ---------------------------------------------------------------------------
// JSON builders
// ---------------------------------------------------------------------------

pub fn json_health() -> String {
    let pid = call::getpid().unwrap_or(0);
    let up = uptime_secs();
    format!(r#"{{"status":"ok","pid":{},"uptime_secs":{}}}"#, pid, up)
}

pub fn json_uptime() -> String {
    let ns = net::clock_gettime_ns();
    let secs = ns / 1_000_000_000;
    let mins = secs / 60;
    let hours = mins / 60;
    let days = hours / 24;
    format!(
        r#"{{"uptime_ns":{},"secs":{},"human":"{}d {}h {}m {}s"}}"#,
        ns, secs, days, hours % 24, mins % 60, secs % 60
    )
}

pub fn json_version() -> String {
    format!(r#"{{"version":"{}"}}"#, json_escape(&kernel_version()))
}

pub fn json_cpuinfo() -> String {
    format!(r#"{{"cpuinfo":"{}"}}"#, json_escape(&cpu_info()))
}

pub fn json_meminfo() -> String {
    format!(r#"{{"meminfo":"{}"}}"#, json_escape(&mem_info()))
}

pub fn json_silos() -> String {
    format!(r#"{{"silos":"{}"}}"#, json_escape(&silo_info()))
}

pub fn json_network() -> String {
    format!(
        r#"{{"address":"{}","gateway":"{}","dns":"{}","ip":"{}","netmask":"{}"}}"#,
        json_escape(&net_address()),
        json_escape(&net_gateway()),
        json_escape(&net_dns()),
        json_escape(&net_ip()),
        json_escape(&net_netmask()),
    )
}

pub fn json_routes() -> String {
    format!(r#"{{"routes":"{}"}}"#, json_escape(&net_routes()))
}

pub fn json_processes() -> String {
    let procs = process_list();
    let mut out = String::with_capacity(procs.len() * 120 + 32);
    let _ = write!(out, r#"{{"count":{},"processes":["#, procs.len());
    for (i, p) in procs.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            r#"{{"pid":{},"ppid":{},"name":"{}","state":"{}","silo":"{}","mem":"{}"}}"#,
            p.pid,
            p.ppid,
            json_escape(&p.name),
            json_escape(&p.state),
            json_escape(&p.silo_id),
            json_escape(&p.mem_used),
        );
    }
    out.push_str("]}");
    out
}

pub fn json_kill_result(pid: u32) -> String {
    let ok = kill_process(pid);
    format!(
        r#"{{"pid":{},"killed":{},"error":{}}}"#,
        pid,
        ok,
        if ok { "null" } else { "\"EPERM or ESRCH\"" }
    )
}

pub fn json_all() -> String {
    let mut out = String::with_capacity(4096);
    out.push_str(r#"{"health":"#);
    out.push_str(&json_health());
    out.push_str(r#","uptime":"#);
    out.push_str(&json_uptime());
    out.push_str(r#","version":"#);
    out.push_str(&json_version());
    out.push_str(r#","cpuinfo":"#);
    out.push_str(&json_cpuinfo());
    out.push_str(r#","meminfo":"#);
    out.push_str(&json_meminfo());
    out.push_str(r#","silos":"#);
    out.push_str(&json_silos());
    out.push_str(r#","network":"#);
    out.push_str(&json_network());
    out.push_str(r#","routes":"#);
    out.push_str(&json_routes());
    out.push_str(r#","processes":"#);
    out.push_str(&json_processes());
    out.push('}');
    out
}

// ---------------------------------------------------------------------------
// JSON string escaping
// ---------------------------------------------------------------------------

pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}
