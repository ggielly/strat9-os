//! Command registry and dispatcher
//!
//! Maintains a registry of available commands and dispatches them.

use super::{builtins::*, parser::Command, ShellError};
use alloc::{collections::BTreeMap, string::String};

/// Function pointer type for command handlers
type CommandHandler = fn(&[String]) -> Result<(), ShellError>;

/// Command registry
pub struct CommandRegistry {
    commands: BTreeMap<&'static str, CommandHandler>,
}

impl CommandRegistry {
    /// Create a new command registry with all built-in commands
    pub fn new() -> Self {
        let mut reg = Self {
            commands: BTreeMap::new(),
        };

        // Register all built-in commands
        reg.register("help", cmd_help);
        reg.register("version", cmd_version);
        reg.register("clear", cmd_clear);
        reg.register("mem", cmd_mem);
        reg.register("ps", cmd_ps);
        reg.register("silo", cmd_silo);
        reg.register("scheme", cmd_scheme);
        reg.register("cpuinfo", cmd_cpuinfo);
        reg.register("reboot", cmd_reboot);
        reg.register("gfx", cmd_gfx);
        reg.register("gfx-demo", cmd_gfx_demo);

        reg
    }

    /// Register a new command
    pub fn register(&mut self, name: &'static str, handler: CommandHandler) {
        self.commands.insert(name, handler);
    }

    /// Execute a command
    pub fn execute(&self, cmd: &Command) -> Result<(), ShellError> {
        let handler = self
            .commands
            .get(cmd.name.as_str())
            .ok_or(ShellError::UnknownCommand)?;

        handler(&cmd.args)
    }

    /// Check if a command exists
    pub fn has_command(&self, name: &str) -> bool {
        self.commands.contains_key(name)
    }
}
