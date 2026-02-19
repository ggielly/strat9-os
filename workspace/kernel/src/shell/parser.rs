//! Command Parser
//!
//! Minimal parser for shell commands.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

/// Parsed command structure
#[derive(Debug)]
pub struct Command {
    /// Command name (e.g., "mem", "silo", "ps")
    pub name: String,
    /// Arguments (e.g., ["ls"] for "silo ls")
    pub args: Vec<String>,
}

/// Parse a command line into a Command structure
///
/// Returns None if the line is empty or contains only whitespace.
pub fn parse(line: &str) -> Option<Command> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut parts = trimmed.split_whitespace();
    let name = parts.next()?.to_string();
    let args: Vec<String> = parts.map(|s| s.to_string()).collect();

    Some(Command { name, args })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple() {
        let cmd = parse("help").unwrap();
        assert_eq!(cmd.name, "help");
        assert_eq!(cmd.args.len(), 0);
    }

    #[test]
    fn test_parse_with_args() {
        let cmd = parse("silo ls").unwrap();
        assert_eq!(cmd.name, "silo");
        assert_eq!(cmd.args.len(), 1);
        assert_eq!(cmd.args[0], "ls");
    }

    #[test]
    fn test_parse_empty() {
        assert!(parse("").is_none());
        assert!(parse("   ").is_none());
    }
}
