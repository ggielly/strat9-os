use crate::{alloc::string::String, shell::ShellError, shell_println};

/// `heap` — dump heap and buddy allocator diagnostics.
pub fn cmd_heap(_args: &[String]) -> Result<(), ShellError> {
    crate::memory::heap::dump_diagnostics();
    Ok(())
}
