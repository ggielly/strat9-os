//! Shell command registry and entry points
//!
//! Organizes shell commands into separate modules for better maintenance.

pub mod gfx;
pub mod help;
pub mod mem;
pub mod net;
pub mod ps;
pub mod sys;
pub mod timer;
pub mod top;
pub mod vfs;

use super::ShellError;
use alloc::{collections::BTreeMap, string::String};

/// Registry for all shell commands
pub struct CommandRegistry {
    commands: BTreeMap<String, fn(&[String]) -> Result<(), ShellError>>,
}

impl CommandRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            commands: BTreeMap::new(),
        };

        // Register commands
        registry.register("help", help::cmd_help);
        registry.register("version", sys::cmd_version);
        registry.register("clear", sys::cmd_clear);
        registry.register("mem", mem::cmd_mem);
        registry.register("ps", ps::cmd_ps);
        registry.register("scheme", vfs::cmd_scheme);
        registry.register("mount", vfs::cmd_mount);
        registry.register("umount", vfs::cmd_umount);
        registry.register("cd", vfs::cmd_cd);
        registry.register("ls", vfs::cmd_ls);
        registry.register("cat", vfs::cmd_cat);
        registry.register("mkdir", vfs::cmd_mkdir);
        registry.register("touch", vfs::cmd_touch);
        registry.register("rm", vfs::cmd_rm);
        registry.register("write", vfs::cmd_write);
        registry.register("cpuinfo", sys::cmd_cpuinfo);
        registry.register("test_pid", sys::cmd_test_pid);
        registry.register("test_syscalls", sys::cmd_test_syscalls);
        registry.register("test_mem", sys::cmd_test_mem);
        registry.register("test_mem_stressed", sys::cmd_test_mem_stressed);
        registry.register("reboot", sys::cmd_reboot);
        registry.register("gfx", gfx::cmd_gfx);
        registry.register("gfx-demo", gfx::cmd_gfx_demo);
        registry.register("top", top::cmd_top);
        registry.register("timer", timer::cmd_timer);
        registry.register("scheduler", sys::cmd_scheduler);
        registry.register("trace", sys::cmd_trace);
        registry.register("ping", net::cmd_ping);
        registry.register("ifconfig", net::cmd_ifconfig);
        registry.register("strate", sys::cmd_strate);
        registry.register("silo", sys::cmd_silo);
        registry.register("silos", sys::cmd_silos);
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
}
