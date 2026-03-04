use super::*;

/// Ifconfig command entrypoint.
pub fn cmd_ifconfig(args: &[String]) -> Result<(), ShellError> {
    super::cmd_ifconfig_impl(args)
}
