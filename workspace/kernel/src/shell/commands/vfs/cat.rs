use super::*;

/// Print file contents.
pub fn cmd_cat(args: &[String]) -> Result<(), ShellError> {
    super::cmd_cat_impl(args)
}
