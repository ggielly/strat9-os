use super::*;

/// Show CPU information.
pub fn cmd_cpuinfo(args: &[String]) -> Result<(), ShellError> {
    super::cmd_cpuinfo_impl(args)
}
