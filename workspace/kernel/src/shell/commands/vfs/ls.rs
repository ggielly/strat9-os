use super::*;

/// List directory entries.
pub fn cmd_ls(args: &[String]) -> Result<(), ShellError> {
    super::cmd_ls_impl(args)
}
