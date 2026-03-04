use super::*;

/// Unmount filesystems.
pub fn cmd_umount(args: &[String]) -> Result<(), ShellError> {
    super::cmd_umount_impl(args)
}
