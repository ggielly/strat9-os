use super::*;

/// Run syscall test routine.
pub fn cmd_test_syscalls(args: &[String]) -> Result<(), ShellError> {
    super::cmd_test_syscalls_impl(args)
}
