use super::*;

/// Search for matching lines in file or piped input.
pub fn cmd_grep(args: &[String]) -> Result<(), ShellError> {
    super::cmd_grep_impl(args)
}
