use super::*;

/// Clear display.
pub fn cmd_clear(args: &[String]) -> Result<(), ShellError> {
    super::cmd_clear_impl(args)
}
