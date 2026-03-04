use super::*;

/// Display system health information.
pub fn cmd_health(args: &[String]) -> Result<(), ShellError> {
    super::cmd_health_impl(args)
}
