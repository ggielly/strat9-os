use super::*;

/// Move or rename entry.
pub fn cmd_mv(args: &[String]) -> Result<(), ShellError> {
    super::cmd_mv_impl(args)
}
