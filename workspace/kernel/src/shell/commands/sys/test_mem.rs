use super::*;

/// Run memory test routine.
pub fn cmd_test_mem(args: &[String]) -> Result<(), ShellError> {
    super::cmd_test_mem_impl(args)
}
