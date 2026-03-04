use super::*;

/// Execute a wasm module command.
pub fn cmd_wasm_run(args: &[String]) -> Result<(), ShellError> {
    super::cmd_wasm_run_impl(args)
}
