use super::*;

/// Write string data into file.
pub fn cmd_write(args: &[String]) -> Result<(), ShellError> {
    super::cmd_write_impl(args)
}
