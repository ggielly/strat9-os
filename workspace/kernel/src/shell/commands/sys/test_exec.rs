use super::*;

/// Run exec-related regression test routine.
pub fn cmd_test_exec(args: &[String]) -> Result<(), ShellError> {
    super::cmd_test_exec_impl(args)
}
