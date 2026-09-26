use super::*;

/// Dynamically adjust silo resource limits.
///
/// Usage: `silo limit <id|label|name> <key> <value>`
///
/// Keys: `mem_max`, `mem_min`, `max_tasks`, `cpu_shares`.
pub(super) fn cmd_silo_limit(args: &[String], cmd: Cmd) -> Result<(), ShellError> {
    if args.len() < 4 {
        shell_println!("Usage: {} limit <id|label|name> <key> <value>", cmd.name());
        shell_println!("  Keys: mem_max, mem_min, max_tasks, cpu_shares");
        return Err(ShellError::InvalidArguments);
    }
    let selector = normalize_current_silo_selector(args[1].as_str());
    let key = args[2].as_str();
    let value: u64 = args[3].parse().map_err(|_| {
        shell_println!("{} limit: invalid value '{}'", cmd.name(), args[3]);
        ShellError::InvalidArguments
    })?;

    match silo::kernel_limit_silo(selector.as_str(), key, value) {
        Ok(sid) => {
            shell_println!("{} limit: {}={} for sid={}", cmd.name(), key, value, sid);
            Ok(())
        }
        Err(e) => {
            shell_println!("{} limit failed: {:?}", cmd.name(), e);
            Err(ShellError::ExecutionFailed)
        }
    }
}
