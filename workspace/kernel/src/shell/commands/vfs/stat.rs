use super::*;

/// Show file metadata.
pub fn cmd_stat(args: &[String]) -> Result<(), ShellError> {
    super::cmd_stat_impl(args)
}
