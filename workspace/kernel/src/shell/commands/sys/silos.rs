use super::*;

/// Display all silos.
pub fn cmd_silos(args: &[String]) -> Result<(), ShellError> {
    super::cmd_silos_impl(args)
}
