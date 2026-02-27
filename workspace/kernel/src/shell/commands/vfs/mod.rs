//! VFS management commands
use crate::{
    shell::ShellError,
    shell_println,
    vfs::{self, scheme::DT_DIR, DirEntry, OpenFlags},
};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use spin::Lazy;

// ─── Shell CWD ───────────────────────────────────────────────────────────────

/// Current working directory for the chevron shell.
///
/// Stored as a global because `CommandRegistry` uses plain function pointers
/// (no `&mut self`) so state cannot be threaded through call arguments.
static SHELL_CWD: Lazy<crate::sync::SpinLock<String>> =
    Lazy::new(|| crate::sync::SpinLock::new(String::from("/")));

/// Read the current working directory.
pub fn get_cwd() -> String {
    SHELL_CWD.lock().clone()
}

fn set_cwd(path: String) {
    *SHELL_CWD.lock() = path;
}

/// Collapse `..`, `.` and redundant `/` in an absolute path.
fn normalize_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                let _ = parts.pop();
            }
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        return String::from("/");
    }
    let mut result = String::from("/");
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            result.push('/');
        }
        result.push_str(part);
    }
    result
}

/// Resolve `path` relative to the shell CWD.
///
/// - Empty or `""` → current directory.
/// - Starts with `/` → treated as absolute (normalized).
/// - Otherwise → joined with CWD and normalized.
pub fn resolve_shell_path(path: &str) -> String {
    if path.is_empty() {
        return get_cwd();
    }
    if path.starts_with('/') {
        return normalize_path(path);
    }
    let cwd = get_cwd();
    let combined = if cwd.ends_with('/') {
        alloc::format!("{}{}", cwd, path)
    } else {
        alloc::format!("{}/{}", cwd, path)
    };
    normalize_path(&combined)
}

// ─── cd ──────────────────────────────────────────────────────────────────────

/// Change the shell working directory.
pub fn cmd_cd(args: &[String]) -> Result<(), ShellError> {
    let target = if args.is_empty() {
        String::from("/")
    } else {
        resolve_shell_path(&args[0])
    };

    // Verify the path exists and is a directory.
    match vfs::open(&target, OpenFlags::READ | OpenFlags::DIRECTORY) {
        Ok(fd) => {
            let _ = vfs::close(fd);
            set_cwd(target);
        }
        Err(e) => {
            let arg = args.first().map(|s| s.as_str()).unwrap_or("/");
            shell_println!("cd: {}: {:?}", arg, e);
        }
    }
    Ok(())
}

// ─── ls ──────────────────────────────────────────────────────────────────────

/// List directory contents or mount points.
pub fn cmd_ls(args: &[String]) -> Result<(), ShellError> {
    let path = if args.is_empty() {
        resolve_shell_path("")
    } else {
        resolve_shell_path(&args[0])
    };

    // Root special-case: show mount points (until overlays are implemented).
    if path == "/" {
        shell_println!("Mount points:");
        for m in vfs::list_mounts() {
            shell_println!("  {}", m);
        }
        return Ok(());
    }

    match vfs::open(&path, OpenFlags::READ | OpenFlags::DIRECTORY) {
        Ok(fd) => {
            // Prefer getdents (scheme-neutral, works with ramfs, devfs, procfs…)
            match vfs::getdents(fd) {
                Ok(entries) => {
                    if entries.is_empty() {
                        shell_println!("(empty)");
                    } else {
                        for e in &entries {
                            let type_char = if e.file_type == DT_DIR { 'd' } else { '-' };
                            shell_println!("  {}{}", type_char, e.name);
                        }
                    }
                }
                Err(_) => {
                    // Fallback for schemes that implement read-as-listing.
                    let mut buf = [0u8; 4096];
                    match vfs::read(fd, &mut buf) {
                        Ok(n) if n > 0 => {
                            let s = core::str::from_utf8(&buf[..n]).unwrap_or("(binary)");
                            shell_println!("{}", s.trim_end());
                        }
                        _ => shell_println!("(empty)"),
                    }
                }
            }
            let _ = vfs::close(fd);
        }
        Err(e) => shell_println!("ls: {}: {:?}", path, e),
    }

    Ok(())
}

// ─── cat ─────────────────────────────────────────────────────────────────────

/// Display file contents.
pub fn cmd_cat(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: cat <path>");
        return Ok(());
    }

    let path = resolve_shell_path(&args[0]);
    match vfs::open(&path, OpenFlags::READ) {
        Ok(fd) => {
            let mut buf = [0u8; 1024];
            loop {
                match vfs::read(fd, &mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let s = core::str::from_utf8(&buf[..n])
                            .unwrap_or("(non-UTF8 data)");
                        crate::shell_print!("{}", s);
                    }
                    Err(e) => {
                        shell_println!("\nError reading file: {:?}", e);
                        break;
                    }
                }
            }
            shell_println!("");
            let _ = vfs::close(fd);
        }
        Err(e) => shell_println!("cat: {}: {:?}", path, e),
    }
    Ok(())
}

// ─── scheme ──────────────────────────────────────────────────────────────────

/// List registered schemes.
pub fn cmd_scheme(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() || args[0] != "ls" {
        shell_println!("Usage: scheme ls");
        return Ok(());
    }

    shell_println!("Registered schemes:");
    shell_println!("{:<14} {}", "Name", "Type");
    shell_println!("────────────────────────────────────");
    for scheme in vfs::list_schemes() {
        shell_println!("  {:<12} Kernel/IPC", scheme);
    }
    shell_println!("");
    Ok(())
}

pub fn cmd_mount(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() || args[0] == "ls" {
        shell_println!("Mount points:");
        for m in vfs::list_mounts() {
            shell_println!("  {}", m);
        }
        shell_println!("");
        shell_println!("Usage: mount <source> <target>");
        return Ok(());
    }
    if args.len() != 2 {
        shell_println!("Usage: mount <source> <target>");
        return Ok(());
    }

    let source = resolve_shell_path(&args[0]);
    let target = resolve_shell_path(&args[1]);

    let (scheme, rel) = match vfs::resolve(&source) {
        Ok(v) => v,
        Err(e) => {
            shell_println!("mount: source {} unavailable: {:?}", source, e);
            return Ok(());
        }
    };
    if !rel.is_empty() {
        shell_println!("mount: source must be a mount root: {}", source);
        return Ok(());
    }

    match vfs::mount(&target, scheme) {
        Ok(()) => shell_println!("mount: {} mounted on {}", source, target),
        Err(e) => shell_println!("mount: {} -> {} failed: {:?}", source, target, e),
    }
    Ok(())
}

pub fn cmd_umount(args: &[String]) -> Result<(), ShellError> {
    if args.len() != 1 {
        shell_println!("Usage: umount <target>");
        return Ok(());
    }

    let target = resolve_shell_path(&args[0]);
    match vfs::unmount(&target) {
        Ok(()) => shell_println!("umount: {}", target),
        Err(e) => shell_println!("umount: {}: {:?}", target, e),
    }
    Ok(())
}

// ─── mkdir ───────────────────────────────────────────────────────────────────

/// Create a new directory.
pub fn cmd_mkdir(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: mkdir <path>");
        return Ok(());
    }
    let path = resolve_shell_path(&args[0]);
    match vfs::mkdir(&path, 0o755) {
        Ok(()) => shell_println!("mkdir: {}", path),
        Err(e) => shell_println!("mkdir: {}: {:?}", path, e),
    }
    Ok(())
}

// ─── touch ───────────────────────────────────────────────────────────────────

/// Create a new empty file.
pub fn cmd_touch(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: touch <path>");
        return Ok(());
    }
    let path = resolve_shell_path(&args[0]);
    match vfs::create_file(&path, 0o644) {
        Ok(()) => shell_println!("touch: {}", path),
        Err(e) => shell_println!("touch: {}: {:?}", path, e),
    }
    Ok(())
}

// ─── rm ──────────────────────────────────────────────────────────────────────

/// Remove a file or directory.
pub fn cmd_rm(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: rm <path>");
        return Ok(());
    }
    let path = resolve_shell_path(&args[0]);
    match vfs::unlink(&path) {
        Ok(()) => shell_println!("rm: {}", path),
        Err(e) => shell_println!("rm: {}: {:?}", path, e),
    }
    Ok(())
}

// ─── write ───────────────────────────────────────────────────────────────────

/// Write text to a file.
pub fn cmd_write(args: &[String]) -> Result<(), ShellError> {
    if args.len() < 2 {
        shell_println!("Usage: write <path> <text>");
        return Ok(());
    }
    let path = resolve_shell_path(&args[0]);
    let text = &args[1];

    match vfs::open(&path, OpenFlags::WRITE | OpenFlags::CREATE) {
        Ok(fd) => {
            match vfs::write(fd, text.as_bytes()) {
                Ok(n) => shell_println!("write: {} bytes → {}", n, path),
                Err(e) => shell_println!("write: {}: {:?}", path, e),
            }
            let _ = vfs::close(fd);
        }
        Err(e) => shell_println!("write: {}: {:?}", path, e),
    }
    Ok(())
}
