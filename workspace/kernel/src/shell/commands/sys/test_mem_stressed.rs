use super::*;

/// Run stressed memory test routine.
pub fn cmd_test_mem_stressed(args: &[String]) -> Result<(), ShellError> {
    super::cmd_test_mem_stressed_impl(args)
}
