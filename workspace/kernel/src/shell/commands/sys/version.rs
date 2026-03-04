use super::*;

/// Print kernel version.
pub fn cmd_version(args: &[String]) -> Result<(), ShellError> {
    super::cmd_version_impl(args)
}
