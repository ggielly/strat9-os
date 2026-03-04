use super::*;

/// Net command entrypoint.
pub fn cmd_net(args: &[String]) -> Result<(), ShellError> {
    super::cmd_net_impl(args)
}
