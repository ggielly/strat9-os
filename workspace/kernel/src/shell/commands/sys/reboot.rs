use super::*;

/// Reboot machine.
pub fn cmd_reboot(args: &[String]) -> Result<(), ShellError> {
    super::cmd_reboot_impl(args)
}
