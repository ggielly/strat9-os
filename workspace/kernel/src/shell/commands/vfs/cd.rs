use super::*;

/// Change working directory.
pub fn cmd_cd(args: &[String]) -> Result<(), ShellError> {
    super::cmd_cd_impl(args)
}
