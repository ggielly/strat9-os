use super::*;

/// Dynamically adjust silo resource limits.
///
/// Usage: `silo limit <id|label|name> <key> <value>`
///
/// Keys: `mem_max`, `mem_min`, `max_tasks`, `cpu_shares`.
pub(super) fn cmd_silo_limit(args: &[String]) -> Result<(), ShellError> {
    if args.len() < 4 {
        shell_println!("Usage: silo limit <id|label|name> <key> <value>");
        shell_println!("  Keys: mem_max, mem_min, max_tasks, cpu_shares");
        return Err(ShellError::InvalidArguments);
    }
    let selector = normalize_current_silo_selector(args[1].as_str());
    let key = args[2].as_str();
    let value: u64 = args[3].parse().map_err(|_| {
        shell_println!("silo limit: invalid value '{}'", args[3]);
        ShellError::InvalidArguments
    })?;

    match silo::kernel_limit_silo(selector.as_str(), key, value) {
        Ok(sid) => {
            shell_println!("silo limit: {}={} for sid={}", key, value, sid);
            Ok(())
        }
        Err(e) => {
            shell_println!("silo limit failed: {:?}", e);
            Err(ShellError::ExecutionFailed)
        }
    }
}
