use super::*;
use alloc::{collections::BTreeMap, string::String};

static SHELL_ENV: crate::sync::SpinLock<Option<BTreeMap<String, String>>> =
    crate::sync::SpinLock::new(None);

/// Initialize kernel shell environment with default values.
pub fn init_shell_env() {
    let mut map = BTreeMap::new();
    map.insert(String::from("KERNEL"), String::from("strat9"));
    map.insert(String::from("ARCH"), String::from("x86_64"));
    map.insert(String::from("SHELL"), String::from("chevron"));
    map.insert(String::from("HOME"), String::from("/"));
    map.insert(String::from("PATH"), String::from("/initfs/bin"));
    *SHELL_ENV.lock() = Some(map);
}

/// Get a shell environment variable by key.
pub fn shell_getenv(key: &str) -> Option<String> {
    SHELL_ENV.lock().as_ref().and_then(|m| m.get(key).cloned())
}

/// Set a shell environment variable.
pub fn shell_setenv(key: &str, val: &str) {
    let mut guard = SHELL_ENV.lock();
    let map = guard.get_or_insert_with(BTreeMap::new);
    map.insert(String::from(key), String::from(val));
}

/// Remove a shell environment variable.
pub fn shell_unsetenv(key: &str) {
    if let Some(map) = SHELL_ENV.lock().as_mut() {
        map.remove(key);
    }
}

/// Display all shell environment variables.
pub fn cmd_env(_args: &[String]) -> Result<(), ShellError> {
    if let Some(map) = SHELL_ENV.lock().as_ref() {
        for (k, v) in map.iter() {
            shell_println!("{}={}", k, v);
        }
    }

    let ticks = crate::process::scheduler::ticks();
    let hz = crate::arch::x86_64::timer::TIMER_HZ;
    shell_println!("UPTIME_SECS={}", ticks / hz);
    shell_println!("SILO_COUNT={}", crate::silo::list_silos_snapshot().len());
    shell_println!("MOUNT_COUNT={}", vfs::list_mounts().len());
    Ok(())
}

/// Set a shell environment variable: `setenv KEY=VALUE`.
pub fn cmd_setenv(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: setenv KEY=VALUE");
        return Err(ShellError::InvalidArguments);
    }
    let arg = &args[0];
    if let Some(eq_pos) = arg.find('=') {
        let key = &arg[..eq_pos];
        let val = &arg[eq_pos + 1..];
        shell_setenv(key, val);
    } else {
        shell_setenv(arg, "");
    }
    Ok(())
}

/// Remove a shell environment variable: `unsetenv KEY`.
pub fn cmd_unsetenv(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: unsetenv KEY");
        return Err(ShellError::InvalidArguments);
    }
    shell_unsetenv(&args[0]);
    Ok(())
}
