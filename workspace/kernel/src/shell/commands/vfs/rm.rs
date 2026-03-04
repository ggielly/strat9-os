use super::*;

/// Remove file entry.
pub fn cmd_rm(args: &[String]) -> Result<(), ShellError> {
    super::cmd_rm_impl(args)
}
