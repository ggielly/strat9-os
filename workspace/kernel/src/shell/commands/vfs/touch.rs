use super::*;

/// Create empty file.
pub fn cmd_touch(args: &[String]) -> Result<(), ShellError> {
    super::cmd_touch_impl(args)
}
