//! Help command implementation
use crate::{shell::ShellError, shell_println};
use alloc::string::String;

/// Display help information
pub fn cmd_help(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("Strat9-OS shell (Chevron) - available commands :");
    shell_println!("");
    shell_println!("  help              - Display this help message");
    shell_println!("  version           - Display kernel version");
    shell_println!("  clear             - Clear the screen");
    shell_println!("  mem               - Display memory status");
    shell_println!("  mem zones         - Display detailed zone information");
    shell_println!("  ps                - List all tasks");
    shell_println!("  top               - Graphical task manager (interactive)");
    shell_println!("  cd [path]         - Change current shell directory");
    shell_println!("  ls [path]         - List mount points or directory contents");
    shell_println!("  cat <path>        - Display file contents");
    shell_println!("  mkdir <path>      - Create a new directory");
    shell_println!("  touch <path>      - Create a new empty file");
    shell_println!("  rm <path>         - Remove a file or directory");
    shell_println!("  write <path> <t>  - Write text to a file");
    shell_println!("  scheme ls         - List registered schemes");
    shell_println!("  mount ls          - List current mount points");
    shell_println!("  mount <src> <dst> - Mount an existing source mount onto dst");
    shell_println!("  umount <path>     - Unmount a mount point");
    shell_println!("  strate list [--all] - List strates (or all silos)");
    shell_println!("  strate spawn ...  - Spawn a strate (type, --label, --dev)");
    shell_println!("  strate config ... - Manage /initfs/silo.toml (show/add/remove)");
    shell_println!("  strate start <x>  - Start a strate by id/label");
    shell_println!("  strate stop <x>   - Stop a strate by id/label");
    shell_println!("  strate kill <x>   - Kill a strate by id/label");
    shell_println!("  strate destroy <x>- Destroy metadata + module by id/label");
    shell_println!("  strate rename ... - Rename a strate label (stopped/ready)");
    shell_println!("  silo list [--all] - List silos/strates");
    shell_println!("  silo spawn ...    - Spawn a silo strate (--label, --dev)");
    shell_println!("  silo config ...   - Manage /initfs/silo.toml (show/add/remove)");
    shell_println!("  silo start|stop|kill|destroy|rename ... - Silo lifecycle");
    shell_println!("  silos             - Shortcut for 'strate list'");
    shell_println!("  cpuinfo           - Display CPU information");
    shell_println!("  test_pid          - Launch /initfs/test_pid userspace binary");
    shell_println!("  test_syscalls     - Launch /initfs/test_syscalls verbose syscall suite");
    shell_println!("  test_mem          - Launch /initfs/test_mem verbose memory test");
    shell_println!("  test_mem_stressed - Launch /initfs/test_mem_stressed stress test");
    shell_println!("  reboot            - Reboot the system");
    shell_println!("  scheduler debug   - Scheduler debug on|off|dump");
    shell_println!("  trace mem ...     - Memory trace on|off|dump|clear|serial|mask");
    shell_println!("  gfx help          - Show gfx command help");
    shell_println!("  gfx info          - Display framebuffer/console info");
    shell_println!("  gfx mode on|off   - Enable/disable double-buffer mode");
    shell_println!("  gfx ui <scale>    - Set UI scale: compact|normal|large");
    shell_println!("  gfx test          - Draw graphics validation screen");
    shell_println!("  gfx-demo          - Draw a graphics console UI demo");
    shell_println!("  ping [ip] [count] - ICMP echo request (default: gateway, 4)");
    shell_println!("  ifconfig          - Display network configuration");
    shell_println!("  ifconfig inet <ip/prefix> - Set static IPv4 address");
    shell_println!("  ifconfig gateway <ip|clear> - Set/clear default gateway");
    shell_println!("  ifconfig dns <ip> [ip] [ip] - Set DNS servers");
    shell_println!("  ifconfig dns clear - Clear DNS servers");
    shell_println!("  ifconfig dhcp <on|off> - Enable/disable DHCP client state");
    shell_println!("  net route show    - Show IPv4 routes from /net/routes");
    shell_println!("  net route add <cidr> <gw> - Add/replace an IPv4 route");
    shell_println!("  net route del <cidr> - Remove an IPv4 route");
    shell_println!("  net route default set <gw> - Set default gateway route");
    shell_println!("  net route default clear - Clear default gateway route");
    shell_println!("");
    Ok(())
}
