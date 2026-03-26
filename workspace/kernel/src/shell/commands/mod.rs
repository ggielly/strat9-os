//! Shell command registry and entry points
//!

pub mod gfx;
pub mod help;
pub mod hw;
pub mod mem;
pub mod net;
pub mod proc;
pub mod ps;
pub mod sys;
pub mod timer;
pub mod top;
pub mod util;
pub mod vfs;

use super::ShellError;
use alloc::{collections::BTreeMap, string::String};

pub struct CommandRegistry {
    commands: BTreeMap<String, fn(&[String]) -> Result<(), ShellError>>,
}

impl CommandRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            commands: BTreeMap::new(),
        };

        // General
        registry.register("help", help::cmd_help);
        registry.register("version", sys::cmd_version);
        registry.register("clear", sys::cmd_clear);
        registry.register("reboot", sys::cmd_reboot);
        registry.register("shutdown", sys::cmd_shutdown);
        registry.register("uptime", util::cmd_uptime);
        registry.register("echo", util::cmd_echo);
        registry.register("watch", util::cmd_watch);
        registry.register("date", util::cmd_date);
        registry.register("ntpdate", util::cmd_ntpdate);

        // Process
        registry.register("ps", ps::cmd_ps);
        registry.register("kill", proc::cmd_kill);
        registry.register("whoami", util::cmd_whoami);

        // Filesystem
        registry.register("scheme", vfs::cmd_scheme);
        registry.register("mount", vfs::cmd_mount);
        registry.register("umount", vfs::cmd_umount);
        registry.register("cd", vfs::cmd_cd);
        registry.register("ls", vfs::cmd_ls);
        registry.register("cat", vfs::cmd_cat);
        registry.register("stat", vfs::cmd_stat);
        registry.register("mkdir", vfs::cmd_mkdir);
        registry.register("touch", vfs::cmd_touch);
        registry.register("rm", vfs::cmd_rm);
        registry.register("write", vfs::cmd_write);
        registry.register("cp", vfs::cmd_cp);
        registry.register("mv", vfs::cmd_mv);
        registry.register("df", vfs::cmd_df);
        registry.register("grep", util::cmd_grep);

        // Memory
        registry.register("mem", mem::cmd_mem);

        // Hardware / IPC / Diagnostics
        registry.register("lspci", hw::cmd_lspci);
        registry.register("lsns", hw::cmd_lsns);
        registry.register("cpuinfo", sys::cmd_cpuinfo);
        registry.register("dmesg", util::cmd_dmesg);
        registry.register("audit", util::cmd_audit);
        registry.register("env", util::cmd_env);
        registry.register("setenv", util::cmd_setenv);
        registry.register("unsetenv", util::cmd_unsetenv);
        registry.register("health", sys::cmd_health);

        // Silo / Strate
        registry.register("strate", sys::cmd_strate);
        registry.register("silo", sys::cmd_silo);
        registry.register("silos", sys::cmd_silos);

        // Network
        registry.register("ping", net::cmd_ping);
        registry.register("ifconfig", net::cmd_ifconfig);
        registry.register("net", net::cmd_net);
        registry.register("nslookup", net::cmd_nslookup);
        registry.register("telnet", net::cmd_telnet);

        // Scheduler
        registry.register("scheduler", sys::cmd_scheduler);
        registry.register("trace", sys::cmd_trace);

        // Graphics
        registry.register("gfx", gfx::cmd_gfx);
        registry.register("gfx-demo", gfx::cmd_gfx_demo);
        registry.register("top", top::cmd_top);
        registry.register("timer", timer::cmd_timer);

        // Testing
        registry.register("test_pid", sys::cmd_test_pid);
        registry.register("test_syscalls", sys::cmd_test_syscalls);
        registry.register("test_mem", sys::cmd_test_mem);
        registry.register("test_mem_stressed", sys::cmd_test_mem_stressed);
        registry.register("test_mem_region", sys::cmd_test_mem_region);
        registry.register("test_mem_region_proc", sys::cmd_test_mem_region_proc);
        registry.register("test_exec", sys::cmd_test_exec);
        registry.register("wasm-run", sys::cmd_wasm_run);

        registry
    }

    pub fn register(&mut self, name: &str, func: fn(&[String]) -> Result<(), ShellError>) {
        self.commands.insert(String::from(name), func);
    }

    pub fn execute(&self, cmd: &super::parser::Command) -> Result<(), ShellError> {
        if let Some(func) = self.commands.get(&cmd.name) {
            func(&cmd.args)
        } else {
            Err(ShellError::UnknownCommand)
        }
    }

    /// Return all registered command names (sorted).
    pub fn command_names(&self) -> alloc::vec::Vec<&str> {
        self.commands.keys().map(|k| k.as_str()).collect()
    }
}
