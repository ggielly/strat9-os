//! VFS management commands
use crate::shell_println;
use crate::shell::ShellError;
use crate::vfs::{self, OpenFlags};
use alloc::string::String;

/// List mounted schemes or directory contents
pub fn cmd_ls(args: &[String]) -> Result<(), ShellError> {
    let path = if args.is_empty() {
        "/"
    } else {
        &args[0]
    };

    if path == "/" {
        shell_println!("Mount points:");
        let mounts = vfs::list_mounts();
        for mount in mounts {
            shell_println!("  {}", mount);
        }
        return Ok(());
    }

    // Try to open as directory
    match vfs::open(path, OpenFlags::READ | OpenFlags::DIRECTORY) {
        Ok(fd) => {
            let mut buf = [0u8; 4096];
            match vfs::read(fd, &mut buf) {
                Ok(n) => {
                    if n > 0 {
                        let content = core::str::from_utf8(&buf[..n]).unwrap_or("<binary data>");
                        shell_println!("{}", content);
                    } else {
                        shell_println!("(empty directory or not supported)");
                    }
                }
                Err(e) => {
                    shell_println!("Error reading directory: {:?}", e);
                }
            }
            let _ = vfs::close(fd);
        }
        Err(e) => {
            shell_println!("Error opening {}: {:?}", path, e);
        }
    }

    Ok(())
}

/// Display file contents
pub fn cmd_cat(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: cat <path>");
        return Ok(());
    }

    let path = &args[0];
    match vfs::open(path, OpenFlags::READ) {
        Ok(fd) => {
            let mut buf = [0u8; 1024];
            loop {
                match vfs::read(fd, &mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let s = core::str::from_utf8(&buf[..n]).unwrap_or_else(|_| {
                            // If not valid UTF-8, just show hex or something?
                            // For now, just print what we can
                            "(non-UTF8 data)"
                        });
                        crate::shell_print!("{}", s);
                    }
                    Err(e) => {
                        shell_println!("
Error reading file: {:?}", e);
                        break;
                    }
                }
            }
            shell_println!("");
            let _ = vfs::close(fd);
        }
        Err(e) => {
            shell_println!("Error opening {}: {:?}", path, e);
        }
    }

    Ok(())
}

/// List registered schemes
pub fn cmd_scheme(args: &[String]) -> Result<(), ShellError> {
    if args.len() == 0 || args[0] != "ls" {
        shell_println!("Usage: scheme ls");
        return Ok(());
    }

    shell_println!("Registered Schemes:");
    shell_println!("Name         Type");
    shell_println!("────────────────────────────────────");

    let schemes = vfs::list_schemes();
    for scheme in schemes {
        shell_println!("  {:<12} {}", scheme, "Kernel/IPC");
    }

    shell_println!("");
    Ok(())
}

/// Create a new directory
pub fn cmd_mkdir(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: mkdir <path>");
        return Ok(());
    }

    let path = &args[0];
    match vfs::mkdir(path, 0o755) {
        Ok(()) => shell_println!("Directory created: {}", path),
        Err(e) => shell_println!("Error creating directory {}: {:?}", path, e),
    }
    Ok(())
}

/// Create a new empty file
pub fn cmd_touch(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: touch <path>");
        return Ok(());
    }

    let path = &args[0];
    match vfs::create_file(path, 0o644) {
        Ok(()) => shell_println!("File created: {}", path),
        Err(e) => shell_println!("Error creating file {}: {:?}", path, e),
    }
    Ok(())
}

/// Remove a file or directory
pub fn cmd_rm(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: rm <path>");
        return Ok(());
    }

    let path = &args[0];
    match vfs::unlink(path) {
        Ok(()) => shell_println!("Removed: {}", path),
        Err(e) => shell_println!("Error removing {}: {:?}", path, e),
    }
    Ok(())
}

/// Write text to a file
pub fn cmd_write(args: &[String]) -> Result<(), ShellError> {
    if args.len() < 2 {
        shell_println!("Usage: write <path> <text>");
        return Ok(());
    }

    let path = &args[0];
    let text = &args[1];

    match vfs::open(path, vfs::OpenFlags::WRITE) {
        Ok(fd) => {
            match vfs::write(fd, text.as_bytes()) {
                Ok(n) => shell_println!("Wrote {} bytes to {}", n, path),
                Err(e) => shell_println!("Error writing to {}: {:?}", path, e),
            }
            let _ = vfs::close(fd);
        }
        Err(e) => {
            shell_println!("Error opening {}: {:?}", path, e);
        }
    }
    Ok(())
}
