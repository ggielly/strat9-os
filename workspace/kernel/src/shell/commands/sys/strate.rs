use super::*;

/// Strate management command entrypoint.
pub fn cmd_strate(args: &[String]) -> Result<(), ShellError> {
    super::cmd_strate_impl(args)
}
