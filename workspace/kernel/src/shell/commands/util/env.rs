use super::*;
use alloc::{collections::BTreeMap, string::String, vec::Vec};

/// The shell environment: exactly what `setenv` stores and `unsetenv` removes.
///
/// A plain map rather than an `Option<BTreeMap<..>>`: [`init_shell_env`]
/// populates it during shell start up and nothing ever clears it, so the
/// `Option` only forced an `as_ref()` / `get_or_insert_with` / `and_then`
/// dance at every single use and bought no state that the map cannot express.
static SHELL_ENV: crate::sync::SpinLock<BTreeMap<String, String>> =
    crate::sync::SpinLock::new(BTreeMap::new());

/// Names `env` reports from live kernel state.
///
/// These are never stored in the environment map, and `setenv`/`unsetenv`
/// refuse them, so a name can never show up both as a settable variable and as
/// a computed value: `env` output is unambiguous about which is which.
pub(crate) const COMPUTED_KEYS: [&str; 3] = ["UPTIME_SECS", "SILO_COUNT", "MOUNT_COUNT"];

/// Header introducing the read-only section of `env` output.
const COMPUTED_HEADER: &str = "-- computed (read-only, not settable) --";

/// The operation a `setenv` argument denotes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnvOp<'a> {
    /// `NAME=VALUE`: store `VALUE` under `NAME`. An empty `VALUE` is legal.
    Set {
        /// Variable name.
        key: &'a str,
        /// Value to store, possibly empty.
        value: &'a str,
    },
    /// `NAME` with no `=`: POSIX `setenv NAME` unsets, so this is `unsetenv`.
    Unset {
        /// Variable name to remove.
        key: &'a str,
    },
    /// The argument was refused.
    Invalid(SetenvError),
}

/// Why `setenv` refused its argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SetenvError {
    /// `` (empty argument) or `=value`: there is no variable name at all.
    EmptyName,
    /// A computed name from [`COMPUTED_KEYS`], which reflects kernel state.
    ComputedName,
}

/// Decides what a `setenv` argument does, without touching the environment.
///
/// - `FOO=bar` -> `Set { key: "FOO", value: "bar" }`
/// - `FOO=` -> `Set { key: "FOO", value: "" }` (an empty value, *not* an unset)
/// - `FOO` -> `Unset { key: "FOO" }`, matching `unsetenv FOO`
/// - `` or `=bar` -> `Invalid(EmptyName)`
/// - `UPTIME_SECS=1` -> `Invalid(ComputedName)`
pub(crate) fn setenv_action(arg: &str) -> EnvOp<'_> {
    // `split_once` splits on the *first* `=`, so a value may contain `=`
    // (`setenv URL=http://h/?a=b` keeps the whole tail) while the name, which
    // may not be empty, can never contain one.
    let (key, value) = match arg.split_once('=') {
        Some((key, value)) => (key, Some(value)),
        None => (arg, None),
    };

    if key.is_empty() {
        return EnvOp::Invalid(SetenvError::EmptyName);
    }
    if is_computed_key(key) {
        return EnvOp::Invalid(SetenvError::ComputedName);
    }

    match value {
        Some(value) => EnvOp::Set { key, value },
        None => EnvOp::Unset { key },
    }
}

/// Whether `key` names a computed, read-only value rather than a stored
/// variable.
pub(crate) fn is_computed_key(key: &str) -> bool {
    COMPUTED_KEYS.contains(&key)
}

/// Message printed when `setenv` refuses `arg`.
fn rejection_message(err: SetenvError, key: &str) -> String {
    match err {
        SetenvError::EmptyName => String::from("setenv: empty variable name"),
        SetenvError::ComputedName => {
            alloc::format!(
                "setenv: '{}' is read-only (computed from kernel state)",
                key
            )
        }
    }
}

/// The environment installed by [`init_shell_env`].
///
/// `ARCH` reports the architecture the kernel was actually built for, so the
/// value follows the target instead of claiming `x86_64` on every build.
fn default_env() -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    map.insert(String::from("KERNEL"), String::from("strat9"));
    map.insert(String::from("ARCH"), String::from(crate::arch::ARCH_NAME));
    map.insert(String::from("SHELL"), String::from("chevron"));
    map.insert(String::from("HOME"), String::from("/"));
    map.insert(String::from("PATH"), String::from("/initfs/bin"));
    map
}

/// Initialize the shell environment with default values.
///
/// Resets any variable set before the shell started, so the environment is
/// exactly [`default_env`] afterwards regardless of call order.
pub fn init_shell_env() {
    *SHELL_ENV.lock() = default_env();
}

/// Get a shell environment variable by key.
///
/// Used by the `$VAR` expansion in [`crate::shell::scripting`].
pub fn shell_getenv(key: &str) -> Option<String> {
    SHELL_ENV.lock().get(key).cloned()
}

/// Set a shell environment variable.
pub fn shell_setenv(key: &str, val: &str) {
    SHELL_ENV
        .lock()
        .insert(String::from(key), String::from(val));
}

/// Remove a shell environment variable, returning whether it was set.
pub fn shell_unsetenv(key: &str) -> bool {
    SHELL_ENV.lock().remove(key).is_some()
}

/// Display the environment, then the read-only values derived from kernel state.
pub fn cmd_env(_args: &[String]) -> Result<(), ShellError> {
    // Snapshot first: printing holds the VGA and serial locks, and holding the
    // environment lock across console writes would serialise every other shell
    // task behind a slow framebuffer flush.
    let entries: Vec<(String, String)> = SHELL_ENV
        .lock()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    for (k, v) in &entries {
        shell_println!("{}={}", k, v);
    }

    // The computed values are deliberately in their own section: they are not
    // stored, `setenv` cannot change them and `unsetenv` cannot remove them,
    // which used to make them indistinguishable from real entries.
    shell_println!("{}", COMPUTED_HEADER);
    let ticks = crate::process::scheduler::ticks();
    shell_println!("UPTIME_SECS={}", ticks / crate::arch::timer::TIMER_HZ);
    shell_println!("SILO_COUNT={}", crate::silo::silo_count());
    shell_println!("MOUNT_COUNT={}", vfs::mount_count());
    Ok(())
}

/// Set or clear a shell environment variable: `setenv KEY=VALUE` or `setenv KEY`.
pub fn cmd_setenv(args: &[String]) -> Result<(), ShellError> {
    if args.len() != 1 {
        shell_println!("Usage: setenv KEY=VALUE   (or `setenv KEY` to unset)");
        return Err(ShellError::InvalidArguments);
    }

    match setenv_action(&args[0]) {
        EnvOp::Set { key, value } => shell_setenv(key, value),
        EnvOp::Unset { key } => unset_variable(key),
        EnvOp::Invalid(err) => {
            // Report the name, not the whole `NAME=VALUE` argument.
            let key = match args[0].split_once('=') {
                Some((key, _)) => key,
                None => args[0].as_str(),
            };
            shell_println!("{}", rejection_message(err, key));
            return Err(ShellError::InvalidArguments);
        }
    }
    Ok(())
}

/// Remove a shell environment variable: `unsetenv KEY`.
pub fn cmd_unsetenv(args: &[String]) -> Result<(), ShellError> {
    if args.len() != 1 {
        shell_println!("Usage: unsetenv KEY");
        return Err(ShellError::InvalidArguments);
    }
    unset_variable(&args[0]);
    Ok(())
}

/// Shared by `unsetenv KEY` and `setenv KEY`: both refuse an empty or computed
/// name, and both say so when there was nothing to remove, so a silent no-op is
/// never mistaken for a successful change.
fn unset_variable(key: &str) {
    if key.is_empty() {
        shell_println!("unsetenv: empty variable name");
        return;
    }
    if is_computed_key(key) {
        shell_println!(
            "unsetenv: '{}' is read-only (computed from kernel state)",
            key
        );
        return;
    }
    if !shell_unsetenv(key) {
        shell_println!("unsetenv: '{}' was not set", key);
    }
}
