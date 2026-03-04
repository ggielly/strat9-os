use super::*;

/// Configure runtime tracing.
pub fn cmd_trace(args: &[String]) -> Result<(), ShellError> {
    super::cmd_trace_impl(args)
}
