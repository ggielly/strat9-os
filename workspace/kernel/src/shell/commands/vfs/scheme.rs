use super::*;

/// Manage VFS schemes.
pub fn cmd_scheme(args: &[String]) -> Result<(), ShellError> {
    super::cmd_scheme_impl(args)
}
