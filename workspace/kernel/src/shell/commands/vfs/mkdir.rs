use super::*;

/// Create directory.
pub fn cmd_mkdir(args: &[String]) -> Result<(), ShellError> {
    super::cmd_mkdir_impl(args)
}
