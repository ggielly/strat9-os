//! VFS management commands
mod cat;
mod cd;
mod cp;
mod df;
mod ls;
mod mkdir;
mod mount;
mod mv;
mod rm;
mod scheme;
mod stat;
mod touch;
mod umount;
mod write;

use crate::{
    shell::ShellError,
    shell_println,
    vfs::{self, scheme::DT_DIR, OpenFlags},
};
use alloc::{string::String, vec::Vec};
use spin::Lazy;

pub use cat::cmd_cat;
pub use cd::cmd_cd;
pub use cp::cmd_cp;
pub use df::cmd_df;
pub use ls::cmd_ls;
pub use mkdir::cmd_mkdir;
pub use mount::cmd_mount;
pub use mv::cmd_mv;
pub use rm::cmd_rm;
pub use scheme::cmd_scheme;
pub use stat::cmd_stat;
pub use touch::cmd_touch;
pub use umount::cmd_umount;
pub use write::cmd_write;

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

/// Sets cwd.
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
pub(super) fn cmd_cd_impl(args: &[String]) -> Result<(), ShellError> {
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
pub(super) fn cmd_ls_impl(args: &[String]) -> Result<(), ShellError> {
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
/// Display file contents or piped input.
///
/// When invoked without arguments and pipe input is available,
/// prints the piped data. Otherwise reads from the specified path.
pub(super) fn cmd_cat_impl(args: &[String]) -> Result<(), ShellError> {
    if let Some(piped) = crate::shell::output::take_pipe_input() {
        if args.is_empty() {
            let s = core::str::from_utf8(&piped).unwrap_or("(non-UTF8 data)");
            crate::shell_print!("{}", s);
            if !s.ends_with('\n') {
                shell_println!();
            }
            return Ok(());
        }
    }

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
                        let s = core::str::from_utf8(&buf[..n]).unwrap_or("(non-UTF8 data)");
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
pub(super) fn cmd_scheme_impl(args: &[String]) -> Result<(), ShellError> {
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

/// Performs the cmd mount operation.
pub(super) fn cmd_mount_impl(args: &[String]) -> Result<(), ShellError> {
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

/// Performs the cmd umount operation.
pub(super) fn cmd_umount_impl(args: &[String]) -> Result<(), ShellError> {
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
pub(super) fn cmd_mkdir_impl(args: &[String]) -> Result<(), ShellError> {
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
pub(super) fn cmd_touch_impl(args: &[String]) -> Result<(), ShellError> {
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
pub(super) fn cmd_rm_impl(args: &[String]) -> Result<(), ShellError> {
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

pub(super) fn cmd_write_impl(args: &[String]) -> Result<(), ShellError> {
    if args.len() < 2 {
        shell_println!("Usage: write <path> <text>");
        return Ok(());
    }
    let path = resolve_shell_path(&args[0]);
    let text = &args[1];

    match vfs::open(&path, OpenFlags::WRITE | OpenFlags::CREATE) {
        Ok(fd) => {
            match vfs::write(fd, text.as_bytes()) {
                Ok(n) => shell_println!("write: {} bytes -> {}", n, path),
                Err(e) => shell_println!("write: {}: {:?}", path, e),
            }
            let _ = vfs::close(fd);
        }
        Err(e) => shell_println!("write: {}: {:?}", path, e),
    }
    Ok(())
}

// ─── stat ───────────────────────────────────────────────────────────────────

pub(super) fn cmd_stat_impl(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: stat <path>");
        return Err(ShellError::InvalidArguments);
    }
    let path = resolve_shell_path(&args[0]);
    match vfs::stat_path(&path) {
        Ok(st) => {
            let ftype = match st.st_mode & 0xF000 {
                0x4000 => "directory",
                0x8000 => "regular file",
                0xA000 => "symbolic link",
                0x1000 => "FIFO",
                0x6000 => "block device",
                0x2000 => "character device",
                _ => "unknown",
            };
            shell_println!("  File: {}", path);
            shell_println!("  Type: {}", ftype);
            shell_println!("  Size: {} bytes", st.st_size);
            shell_println!("  Mode: {:04o}", st.st_mode & 0o7777);
            shell_println!("  Links: {}", st.st_nlink);
            shell_println!("  Inode: {}", st.st_ino);
        }
        Err(e) => shell_println!("stat: {}: {:?}", path, e),
    }
    Ok(())
}

// ─── cp ─────────────────────────────────────────────────────────────────────

pub(super) fn cmd_cp_impl(args: &[String]) -> Result<(), ShellError> {
    if args.len() < 2 {
        shell_println!("Usage: cp <src> <dst>");
        return Err(ShellError::InvalidArguments);
    }
    let src = resolve_shell_path(&args[0]);
    let dst = resolve_shell_path(&args[1]);

    let fd_src = vfs::open(&src, OpenFlags::READ).map_err(|e| {
        shell_println!("cp: cannot open '{}': {:?}", src, e);
        ShellError::ExecutionFailed
    })?;
    let data = match vfs::read_all(fd_src) {
        Ok(d) => d,
        Err(e) => {
            let _ = vfs::close(fd_src);
            shell_println!("cp: cannot read '{}': {:?}", src, e);
            return Err(ShellError::ExecutionFailed);
        }
    };
    let _ = vfs::close(fd_src);

    let fd_dst = vfs::open(
        &dst,
        OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
    )
    .map_err(|e| {
        shell_println!("cp: cannot create '{}': {:?}", dst, e);
        ShellError::ExecutionFailed
    })?;
    match vfs::write(fd_dst, &data) {
        Ok(n) => shell_println!("cp: {} -> {} ({} bytes)", src, dst, n),
        Err(e) => shell_println!("cp: write to '{}': {:?}", dst, e),
    }
    let _ = vfs::close(fd_dst);
    Ok(())
}

// ─── mv ─────────────────────────────────────────────────────────────────────

pub(super) fn cmd_mv_impl(args: &[String]) -> Result<(), ShellError> {
    if args.len() < 2 {
        shell_println!("Usage: mv <src> <dst>");
        return Err(ShellError::InvalidArguments);
    }
    let src = resolve_shell_path(&args[0]);
    let dst = resolve_shell_path(&args[1]);

    match vfs::rename(&src, &dst) {
        Ok(()) => {
            shell_println!("mv: {} -> {}", src, dst);
            return Ok(());
        }
        Err(crate::syscall::error::SyscallError::NotSupported) => {
            // Cross-mount: fallback to cp + rm
        }
        Err(e) => {
            shell_println!("mv: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    }

    cmd_cp(args)?;
    match vfs::unlink(&src) {
        Ok(()) => shell_println!("mv: removed {}", src),
        Err(e) => shell_println!("mv: could not remove source '{}': {:?}", src, e),
    }
    Ok(())
}

// ─── df ─────────────────────────────────────────────────────────────────────

pub(super) fn cmd_df_impl(_args: &[String]) -> Result<(), ShellError> {
    let mounts = vfs::list_mounts();
    shell_println!("{:<20} {}", "Mount", "Status");
    shell_println!("────────────────────────────────────────");
    for m in &mounts {
        let status = if vfs::open(m, OpenFlags::READ | OpenFlags::DIRECTORY)
            .map(|fd| {
                let _ = vfs::close(fd);
            })
            .is_ok()
        {
            "accessible"
        } else {
            "unavailable"
        };
        shell_println!("{:<20} {}", m, status);
    }
    shell_println!("{} mount(s)", mounts.len());
    Ok(())
}
