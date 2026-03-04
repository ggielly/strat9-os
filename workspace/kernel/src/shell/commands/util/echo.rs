use super::*;

/// Echo arguments to shell output.
pub fn cmd_echo(args: &[String]) -> Result<(), ShellError> {
    super::cmd_echo_impl(args)
}
