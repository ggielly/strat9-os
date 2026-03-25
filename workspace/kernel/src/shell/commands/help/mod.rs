//! Help command implementation
use crate::{shell::ShellError, shell_println};
use alloc::string::String;

pub fn cmd_help(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("Strat9-OS shell (Chevron) - available commands:");
    shell_println!("");

    shell_println!("-- General --");
    shell_println!("  help              - Display this help message");
    shell_println!("  version           - Display kernel version");
    shell_println!("  clear             - Clear the screen");
    shell_println!("  uptime            - System uptime since boot");
    shell_println!("  echo <text ...>   - Print text to console");
    shell_println!("  reboot            - Reboot the system");

    shell_println!("");
    shell_println!("-- Process --");
    shell_println!("  ps                - List all tasks");
    shell_println!("  top               - Graphical task manager (interactive)");
    shell_println!("  kill <pid>        - Terminate a task by PID");
    shell_println!("  whoami            - Show current silo identity");

    shell_println!("");
    shell_println!("-- Filesystem --");
    shell_println!("  cd [path]         - Change current directory");
    shell_println!("  ls [path]         - List directory contents");
    shell_println!("  cat <path>        - Display file contents");
    shell_println!("  stat <path>       - Display file metadata");
    shell_println!("  mkdir <path>      - Create a directory");
    shell_println!("  touch <path>      - Create an empty file");
    shell_println!("  rm <path>         - Remove a file or directory");
    shell_println!("  cp <src> <dst>    - Copy a file");
    shell_println!("  mv <src> <dst>    - Move/rename a file");
    shell_println!("  write <path> <t>  - Write text to a file");
    shell_println!("  grep <pat> <path> - Search text in a file");
    shell_println!("  df                - Show mounted filesystems usage");
    shell_println!("  scheme ls         - List registered schemes");
    shell_println!("  mount [src] [dst] - List or create mount points");
    shell_println!("  umount <path>     - Unmount a mount point");

    shell_println!("");
    shell_println!("-- Silo / Strate --");
    shell_println!("  silo list         - List all silos");
    shell_println!("  silo info <x>     - Detailed silo information");
    shell_println!("  silo spawn <p>    - Spawn strate (path/type, --label, --dev, --type)");
    shell_println!("  silo start|stop|kill|destroy <x> - Lifecycle");
    shell_println!("  silo suspend|resume <x> - Pause/resume a running silo");
    shell_println!("  silo rename <x> <new> - Rename silo label");
    shell_println!("  silo config show|add|remove ... - TOML configuration");
    shell_println!("  silo events [x]   - Show silo event history");
    shell_println!("  silo pledge <x> <mode> - Reduce silo permissions (octal)");
    shell_println!("  silo unveil <x> <path> <rwx> - Restrict path access");
    shell_println!("  silo sandbox <x>  - Enter sandbox mode");
    shell_println!("  silo top [--sort mem|tasks] - Silo resource overview");
    shell_println!("  silo logs <x>     - Show silo event log");
    shell_println!("  silos             - Shortcut for 'silo list'");

    shell_println!("");
    shell_println!("-- Memory --");
    shell_println!("  mem               - Display memory status");
    shell_println!("  mem zones         - Display detailed zone information");

    shell_println!("");
    shell_println!("-- Hardware / IPC --");
    shell_println!("  lspci             - List PCI devices");
    shell_println!("  lsns              - List IPC namespace bindings");
    shell_println!("  cpuinfo           - Display CPU information");
    shell_println!("  dmesg             - Show kernel log buffer");
    shell_println!("  env               - Show system environment info");
    shell_println!("  health            - System health diagnostic");

    shell_println!("");
    shell_println!("-- Network --");
    shell_println!("  ping [ip] [count] - ICMP echo request");
    shell_println!("  ifconfig          - Network configuration");
    shell_println!("  net route ...     - IPv4 routing table");

    shell_println!("");
    shell_println!("-- Scheduler --");
    shell_println!("  scheduler debug|class|metrics|dump|policy ... ");

    shell_println!("");
    shell_println!("-- Graphics --");
    shell_println!("  gfx help|info|mode|ui|test - Framebuffer commands");
    shell_println!("  gfx-demo          - Graphics demo");

    shell_println!("");
    shell_println!("-- Testing --");
    shell_println!("  test_pid | test_syscalls | test_mem | test_mem_stressed | test_mem_region | test_mem_region_proc");
    shell_println!("  wasm-run <path>   - Run a WASM application");
    shell_println!("  trace mem ...     - Memory trace control");
    shell_println!("");
    Ok(())
}
