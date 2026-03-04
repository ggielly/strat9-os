use super::*;

/// Ping command entrypoint.
pub fn cmd_ping(args: &[String]) -> Result<(), ShellError> {
    super::cmd_ping_impl(args)
}
