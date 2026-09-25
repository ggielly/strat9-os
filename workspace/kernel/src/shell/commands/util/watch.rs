use super::*;
use crate::shell::commands::CommandRegistry;

/// Control-C as delivered by the keyboard driver.
const QUIT_CTRL_C: u8 = 0x03;
/// Convenience quit key, matching `top`.
const QUIT_KEY: u8 = b'q';

/// A validated `watch` invocation.
pub(super) struct WatchPlan<'a> {
    /// Delay between two runs, in seconds.
    pub(super) interval_secs: u64,
    /// The watched command, still split into one token per argument.
    pub(super) command: &'a [String],
}

/// Why a `watch` argument vector was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WatchError {
    /// No interval, or no command to watch.
    Usage,
    /// The interval is not a non-negative integer.
    NotANumber,
    /// The interval parsed but is zero, which would busy-loop.
    ZeroInterval,
}

/// Validates the `watch` argument vector: an interval plus at least one token
/// of command. Pure, so the boundary cases (no args, garbage interval, zero)
/// can be exercised without a shell.
pub(super) fn parse_watch_args<'a>(args: &'a [String]) -> Result<WatchPlan<'a>, WatchError> {
    if args.len() < 2 {
        return Err(WatchError::Usage);
    }
    let interval_secs: u64 = args[0].parse().map_err(|_| WatchError::NotANumber)?;
    if interval_secs == 0 {
        return Err(WatchError::ZeroInterval);
    }
    Ok(WatchPlan {
        interval_secs,
        command: &args[1..],
    })
}

/// Message printed for a rejected `watch` invocation.
fn watch_error_message(err: WatchError, arg: &str) -> String {
    match err {
        WatchError::Usage => String::from("Usage: watch <seconds> <command...>"),
        WatchError::NotANumber => alloc::format!("watch: invalid interval '{}'", arg),
        WatchError::ZeroInterval => String::from("watch: interval must be >= 1 second"),
    }
}

/// Ticks between two runs for a given interval in seconds.
///
/// Saturating on purpose: `watch 18446744073709551615 ps` parses as a `u64`, and
/// a plain multiply wrapped around into a very short interval instead of an
/// effectively endless wait.
pub(super) fn interval_ticks(interval_secs: u64) -> u64 {
    let ticks = interval_secs.saturating_mul(crate::arch::timer::TIMER_HZ);
    // TIMER_HZ is a positive constant today; the floor keeps a hypothetical 0 Hz
    // timer from turning the wait loop into a spin.
    if ticks == 0 {
        1
    } else {
        ticks
    }
}

/// The watched command as a single line, for the header only.
///
/// Never fed back to the parser: the tokens are re-joined for display, while
/// execution always uses the original split tokens.
pub(super) fn watched_label(command: &[String]) -> String {
    command.join(" ")
}

/// Returns `true` when the user asked `watch` to stop.
///
/// Honours the shell cancellation contract ([`crate::shell::is_interrupted`])
/// and additionally accepts Ctrl+C or `q` straight from the keyboard, for the
/// case where the keypress never reaches the shell flag.
fn should_stop() -> bool {
    if crate::shell::is_interrupted() {
        return true;
    }
    matches!(
        crate::arch::keyboard::read_char(),
        Some(QUIT_CTRL_C) | Some(QUIT_KEY)
    )
}

/// Runs `command` once, expanding `$VAR` in every token first.
///
/// Dispatches through [`CommandRegistry::execute`] instead of
/// [`crate::shell::run_line`]: `run_line` parses a *string*, so handing it the
/// re-joined argv re-splits it and corrupts any argument containing a space
/// (`watch 1 echo "a b"` ran `echo` with the arguments `"a` and `b"`), and the
/// parser has no quoting to fall back on. Pipelines and redirections stay
/// available: the outer shell parses those before `watch` ever sees the
/// tokens, so they never reach the command vector.
fn run_watched(command: &[String], registry: &CommandRegistry) {
    let mut parsed = crate::shell::parser::Command {
        name: crate::shell::scripting::expand_vars(&command[0]),
        args: alloc::vec::Vec::with_capacity(command.len().saturating_sub(1)),
    };
    for arg in &command[1..] {
        parsed.args.push(crate::shell::scripting::expand_vars(arg));
    }

    // `run_line` cleared the pipe before every dispatch; keep that guarantee so
    // a watched command can never read a previous stage's leftover input.
    crate::shell::output::clear_pipe_input();

    let name = parsed.name.clone();
    match registry.execute(&parsed) {
        Ok(()) => crate::shell::scripting::set_last_exit(0),
        Err(err) => report_command_error(err, &name),
    }
}

/// Mirrors the reporting `run_line` performs for a failed command.
fn report_command_error(err: ShellError, name: &str) {
    use crate::shell::scripting;
    match err {
        ShellError::UnknownCommand => {
            scripting::set_last_exit(127);
            shell_println!("Error: unknown command '{}'", name);
        }
        ShellError::InvalidArguments => {
            scripting::set_last_exit(2);
            shell_println!("Error: invalid arguments for '{}'", name);
        }
        ShellError::ExecutionFailed => {
            scripting::set_last_exit(1);
            shell_println!("Error: '{}' execution failed", name);
        }
    }
}

/// Clears the screen between runs.
///
/// Guarded on VGA: a serial-only target has no screen, and clearing one would
/// erase the log the operator is watching.
fn clear_between_runs() {
    if crate::arch::vga::is_available() {
        crate::shell::output::clear_screen();
    }
}

/// Yields for `period` ticks. Returns `false` when the user asked to stop.
fn wait_period(period: u64) -> bool {
    let start = crate::process::scheduler::ticks();
    loop {
        if should_stop() {
            return false;
        }
        // `saturating_sub`, like `top`: the tick counter is a free running `u64`
        // that wraps, and a plain `-` would overflow on the wrap (a panic in
        // debug builds) instead of simply waiting the wrap out.
        if crate::process::scheduler::ticks().saturating_sub(start) >= period {
            return true;
        }
        crate::process::yield_task();
    }
}

/// Repeat `command` every `period` ticks until interrupted. Returns the number
/// of runs that completed.
fn run_watch(command: &[String], registry: &CommandRegistry, period: u64) -> u64 {
    let mut runs: u64 = 0;
    loop {
        if should_stop() {
            return runs;
        }

        // Cleared before every run but the first, so the "Press Ctrl+C to stop"
        // banner stays readable instead of being wiped on entry.
        if runs > 0 {
            clear_between_runs();
        }
        runs = runs.saturating_add(1);
        shell_println!("[watch run #{}]", runs);

        run_watched(command, registry);

        if !wait_period(period) {
            return runs;
        }
    }
}

/// Execute a command repeatedly at a given interval.
///
/// Usage: `watch <seconds> <command...>`
///
/// Runs the specified command every N seconds until Ctrl+C or `q`, then
/// reports how many runs completed.
pub fn cmd_watch(args: &[String]) -> Result<(), ShellError> {
    let plan = match parse_watch_args(args) {
        Ok(plan) => plan,
        Err(err) => {
            shell_println!(
                "{}",
                watch_error_message(err, args.first().map_or("", |s| s.as_str()))
            );
            return Err(ShellError::InvalidArguments);
        }
    };

    let period = interval_ticks(plan.interval_secs);
    // Built once: the registry is a full command table, and it used to be
    // rebuilt from scratch on every single iteration through `run_line`.
    let registry = CommandRegistry::new();

    shell_println!(
        "Every {}s: {}",
        plan.interval_secs,
        watched_label(plan.command)
    );
    shell_println!("Press Ctrl+C to stop.\n");

    let runs = run_watch(plan.command, &registry, period);
    shell_println!("\nwatch: stopped after {} run(s)", runs);
    Ok(())
}
