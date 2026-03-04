use super::*;

/// Silo management command entrypoint.
pub fn cmd_silo(args: &[String]) -> Result<(), ShellError> {
    super::cmd_silo_impl(args)
}
