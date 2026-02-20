//! Shell command registry and entry points
//!
//! Organizes shell commands into separate modules for better maintenance.

pub mod help;
pub mod mem;
pub mod ps;
pub mod sys;
pub mod gfx;
pub mod top;

use alloc::{string::String, vec::Vec, collections::BTreeMap};
use super::ShellError;

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
        registry.register("scheme", sys::cmd_scheme);
        registry.register("cpuinfo", sys::cmd_cpuinfo);
        registry.register("reboot", sys::cmd_reboot);
        registry.register("gfx", gfx::cmd_gfx);
        registry.register("gfx-demo", gfx::cmd_gfx_demo);
        registry.register("top", top::cmd_top);
        
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
