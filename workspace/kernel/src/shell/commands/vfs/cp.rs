use super::*;

/// Copy file contents.
pub fn cmd_cp(args: &[String]) -> Result<(), ShellError> {
    super::cmd_cp_impl(args)
}
