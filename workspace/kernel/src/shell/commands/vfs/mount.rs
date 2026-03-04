use super::*;

/// Mount filesystems and schemes.
pub fn cmd_mount(args: &[String]) -> Result<(), ShellError> {
    super::cmd_mount_impl(args)
}
