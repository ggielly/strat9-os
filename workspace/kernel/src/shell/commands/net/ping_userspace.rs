use super::*;

/// Userspace ping entrypoint: launches /initfs/bin/ping with the given args.
pub fn cmd_ping(args: &[String]) -> Result<(), ShellError> {
    super::cmd_ping_spawn_impl(args)
}
