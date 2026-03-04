use super::*;

/// Display current silo and task identity.
pub fn cmd_whoami(args: &[String]) -> Result<(), ShellError> {
    super::cmd_whoami_impl(args)
}
