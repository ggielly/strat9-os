use super::*;

/// Userspace ping entrypoint: launches /initfs/ping (legacy /initfs/bin/ping accepted) with the given args.
pub fn cmd_ping(args: &[String]) -> Result<(), ShellError> {
    super::cmd_ping_spawn_impl(args)
}
