//! Help command implementation
use crate::shell_println;
use crate::shell::ShellError;
use alloc::string::String;

/// Display help information
pub fn cmd_help(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("Strat9-OS shell (Chevron) - available commands:");
    shell_println!("");
    shell_println!("  help              - Display this help message");
    shell_println!("  version           - Display kernel version");
    shell_println!("  clear             - Clear the screen");
    shell_println!("  mem               - Display memory status");
    shell_println!("  mem zones         - Display detailed zone information");
    shell_println!("  ps                - List all tasks");
    shell_println!("  top               - Graphical task manager (interactive)");
    shell_println!("  ls [path]         - List mount points or directory contents");
    shell_println!("  cat <path>        - Display file contents");
    shell_println!("  scheme ls         - List registered schemes");
    shell_println!("  cpuinfo           - Display CPU information");
    shell_println!("  reboot            - Reboot the system");
    shell_println!("  gfx help          - Show gfx command help");
    shell_println!("  gfx info          - Display framebuffer/console info");
    shell_println!("  gfx mode on|off   - Enable/disable double-buffer mode");
    shell_println!("  gfx ui <scale>    - Set UI scale: compact|normal|large");
    shell_println!("  gfx test          - Draw graphics validation screen");
    shell_println!("  gfx-demo          - Draw a graphics console UI demo");
    shell_println!("");
    Ok(())
}
