use super::*;

/// Run PID namespace test routine.
pub fn cmd_test_pid(args: &[String]) -> Result<(), ShellError> {
    super::cmd_test_pid_impl(args)
}
