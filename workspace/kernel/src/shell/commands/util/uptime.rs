use super::*;

/// Show uptime and basic runtime counters.
pub fn cmd_uptime(args: &[String]) -> Result<(), ShellError> {
    super::cmd_uptime_impl(args)
}
