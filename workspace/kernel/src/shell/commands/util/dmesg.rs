use super::*;

/// Show recent kernel log entries.
pub fn cmd_dmesg(args: &[String]) -> Result<(), ShellError> {
    super::cmd_dmesg_impl(args)
}
