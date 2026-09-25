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

// ========== Path resolution ==============================

/// Resolves `args[index]` against the working directory, reporting failures.
///
/// Path resolution is the kernel's job: the shell used to keep its own
/// `SHELL_CWD` plus a private copy of the `..` / `.` collapsing rules, next to
/// the kernel's `process.cwd` and `resolve_path`. Two working directories and
/// two path normalisers had to be kept in sync by hand, and the shell's copy
/// resolved paths without the silo path policy the syscalls apply.
fn resolve_arg(args: &[String], index: usize, cmd: &str) -> Result<String, ShellError> {
    match args.get(index) {
        Some(raw) => resolve_path(raw, cmd),
        None => Err(ShellError::InvalidArguments),
    }
}

/// Resolves a literal path, reporting the failure against `cmd`.
fn resolve_path(raw: &str, cmd: &str) -> Result<String, ShellError> {
    vfs::resolve_path_for_current_task(raw).map_err(|e| {
        shell_println!("{}: {}: {:?}", cmd, raw, e);
        ShellError::ExecutionFailed
    })
}

/// The working directory itself, for commands invoked without a path.
fn resolve_cwd(cmd: &str) -> Result<String, ShellError> {
    resolve_path(".", cmd)
}

// ========== cd ============================================================

/// Change the working directory.
pub(super) fn cmd_cd_impl(args: &[String]) -> Result<(), ShellError> {
    let target = args.first().map(|s| s.as_str()).unwrap_or("/");
    match vfs::set_current_dir(target) {
        Ok(()) => {
            let cwd = vfs::current_dir().unwrap_or_else(|_| String::from("/"));
            shell_println!("cd: {}", cwd);
            Ok(())
        }
        Err(e) => {
            shell_println!("cd: {}: {:?}", target, e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

// ========== ls ============================================================

/// File-type character of a `st_mode`, shared by `ls -l` and `stat`.
///
/// The two used to decode the same `S_IFMT` constants independently, once in
/// octal and once in hex, so a new file type only had to be added twice.
fn file_type_char(mode: u32) -> char {
    match mode & 0o170000 {
        0o040000 => 'd',
        0o120000 => 'l',
        0o060000 => 'b',
        0o020000 => 'c',
        0o010000 => 'p',
        0o140000 => 's',
        0o100000 => '-',
        _ => '?',
    }
}

/// Human name of a `st_mode` file type, for `stat`.
fn file_type_name(mode: u32) -> &'static str {
    match mode & 0o170000 {
        0o040000 => "directory",
        0o100000 => "regular file",
        0o120000 => "symbolic link",
        0o010000 => "FIFO",
        0o060000 => "block device",
        0o020000 => "character device",
        0o140000 => "socket",
        _ => "unknown",
    }
}

/// Format `st_mode` into a 10-char permission string like `drwxr-xr-x`.
fn format_mode(mode: u32) -> String {
    let perms = mode & 0o7777;
    let mut out = String::with_capacity(10);
    out.push(file_type_char(mode));

    // Per class: (r, w, x, special bit, char when x+special, char when only
    // special). setuid/setgid render as s/S, the sticky bit as t/T.
    const CLASSES: [(u32, u32, u32, u32, char, char); 3] = [
        (0o400, 0o200, 0o100, 0o4000, 's', 'S'),
        (0o40, 0o20, 0o10, 0o2000, 's', 'S'),
        (0o4, 0o2, 0o1, 0o1000, 't', 'T'),
    ];
    for (r, w, x, special_bit, with_exec, without_exec) in CLASSES {
        out.push(if perms & r != 0 { 'r' } else { '-' });
        out.push(if perms & w != 0 { 'w' } else { '-' });
        out.push(match (perms & x != 0, perms & special_bit != 0) {
            (true, true) => with_exec,
            (true, false) => 'x',
            (false, true) => without_exec,
            (false, false) => '-',
        });
    }
    out
}

/// Format mtime (seconds since epoch) into `Mon DD HH:MM`.
///
/// The civil-date arithmetic lives in the kernel's RTC module; the shell used
/// to redo it here with a 365-day year and a fixed 28-day February, which put
/// every timestamp from March onwards one day off and drifted further each year.
fn format_mtime(mtime: strat9_abi::data::TimeSpec) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let dt = crate::hardware::timer::rtc::RtcDateTime::from_timestamp(mtime.tv_sec as u64);
    let month = MONTHS
        .get((dt.month as usize).saturating_sub(1))
        .copied()
        .unwrap_or("???");
    alloc::format!("{} {:>2} {:02}:{:02}", month, dt.day, dt.hour, dt.minute)
}

/// List directory contents or mount points.
pub(super) fn cmd_ls_impl(args: &[String]) -> Result<(), ShellError> {
    let long = args.iter().any(|a| a == "-l");
    // The first non-flag argument is the directory, wherever it sits.
    let path = match args.iter().position(|a| !a.starts_with('-')) {
        Some(index) => resolve_arg(args, index, "ls")?,
        None => resolve_cwd("ls")?,
    };

    let fd = match vfs::open(&path, OpenFlags::READ | OpenFlags::DIRECTORY) {
        Ok(fd) => fd,
        Err(e) => {
            shell_println!("ls: {}: {:?}", path, e);
            return Err(ShellError::ExecutionFailed);
        }
    };

    // `ls /` used to short-circuit to the mount list and never show the root
    // directory itself. The root listing is real content, so print both.
    let is_root = path == "/";
    if is_root {
        shell_println!("Mount points:");
        for m in vfs::list_mounts() {
            shell_println!("  {}", m);
        }
        shell_println!("");
    }

    match vfs::getdents(fd) {
        Ok(entries) => {
            if entries.is_empty() {
                shell_println!("(empty)");
            } else if long {
                for e in &entries {
                    // `fstat_at` resolves the name against the directory fd we
                    // already hold, instead of re-walking `path/name` from the
                    // root for every entry.
                    match vfs::fstat_at(fd as u64, &e.name) {
                        Ok(st) => shell_println!(
                            "{} {:>3} {:>4} {:>4} {:>8} {} {}{}",
                            format_mode(st.st_mode),
                            st.st_nlink,
                            st.st_uid,
                            st.st_gid,
                            st.st_size,
                            format_mtime(st.st_mtime),
                            e.name,
                            if e.file_type == DT_DIR { "/" } else { "" }
                        ),
                        Err(_) => shell_println!(
                            "{} {}{}",
                            file_type_char_from_dirent(e.file_type),
                            e.name,
                            if e.file_type == DT_DIR { "/" } else { "" }
                        ),
                    }
                }
            } else {
                for e in &entries {
                    shell_println!(
                        "{} {}{}",
                        file_type_char_from_dirent(e.file_type),
                        e.name,
                        if e.file_type == DT_DIR { "/" } else { "" }
                    );
                }
            }
        }
        Err(_) => {
            // Not a real directory: show the file's contents, like `cat`.
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
    Ok(())
}

/// Type character for a `getdents` entry, which reports a raw DT_* value.
fn file_type_char_from_dirent(file_type: u8) -> char {
    if file_type == DT_DIR {
        'd'
    } else {
        '-'
    }
}

// ========== cat ==================================================

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
        return Err(ShellError::InvalidArguments);
    }

    let path = resolve_arg(args, 0, "cat")?;
    let fd = match vfs::open(&path, OpenFlags::READ) {
        Ok(fd) => fd,
        Err(e) => {
            shell_println!("cat: {}: {:?}", path, e);
            return Err(ShellError::ExecutionFailed);
        }
    };
    let mut buf = [0u8; 1024];
    let mut failed = false;
    loop {
        match vfs::read(fd, &mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let s = core::str::from_utf8(&buf[..n]).unwrap_or("(non-UTF8 data)");
                crate::shell_print!("{}", s);
            }
            Err(e) => {
                shell_println!("\ncat: {}: {:?}", path, e);
                failed = true;
                break;
            }
        }
    }
    shell_println!("");
    let _ = vfs::close(fd);
    if failed {
        Err(ShellError::ExecutionFailed)
    } else {
        Ok(())
    }
}

// ========== scheme ========================================

/// List registered schemes.
pub(super) fn cmd_scheme_impl(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() || args[0] != "ls" {
        shell_println!("Usage: scheme ls");
        return Ok(());
    }

    let schemes = vfs::list_schemes();
    shell_println!("Registered schemes ({}):", schemes.len());
    // The old table had a "Type" column hardcoded to "Kernel/IPC" for every
    // row, which told the user nothing. The router does not record which kind a
    // scheme is, so the column is gone rather than faked.
    for scheme in &schemes {
        shell_println!("  {}", scheme);
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
        return Err(ShellError::InvalidArguments);
    }

    let source = resolve_arg(args, 0, "mount")?;
    let target = resolve_arg(args, 1, "mount")?;

    let (scheme, rel) = match vfs::resolve(&source) {
        Ok(v) => v,
        Err(e) => {
            shell_println!("mount: source {} unavailable: {:?}", source, e);
            return Err(ShellError::ExecutionFailed);
        }
    };
    if !rel.is_empty() {
        shell_println!("mount: source must be a mount root: {}", source);
        return Err(ShellError::InvalidArguments);
    }

    match vfs::mount(&target, scheme) {
        Ok(()) => {
            shell_println!("mount: {} mounted on {}", source, target);
            Ok(())
        }
        Err(e) => {
            shell_println!("mount: {} -> {} failed: {:?}", source, target, e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// Performs the cmd umount operation.
pub(super) fn cmd_umount_impl(args: &[String]) -> Result<(), ShellError> {
    if args.len() != 1 {
        shell_println!("Usage: umount <target>");
        return Err(ShellError::InvalidArguments);
    }

    let target = resolve_arg(args, 0, "umount")?;
    match vfs::unmount(&target) {
        Ok(()) => {
            shell_println!("umount: {}", target);
            Ok(())
        }
        Err(e) => {
            shell_println!("umount: {}: {:?}", target, e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

// ========== mkdir ==================================================

/// Create a new directory.
pub(super) fn cmd_mkdir_impl(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: mkdir <path>");
        return Err(ShellError::InvalidArguments);
    }
    let path = resolve_arg(args, 0, "mkdir")?;
    match vfs::mkdir(&path, 0o755) {
        Ok(()) => {
            shell_println!("mkdir: {}", path);
            Ok(())
        }
        Err(e) => {
            shell_println!("mkdir: {}: {:?}", path, e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

// ========== touch ==================================================

/// Create a new empty file.
pub(super) fn cmd_touch_impl(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: touch <path>");
        return Err(ShellError::InvalidArguments);
    }
    let path = resolve_arg(args, 0, "touch")?;
    match vfs::create_file(&path, 0o644) {
        Ok(()) => {
            shell_println!("touch: {}", path);
            Ok(())
        }
        Err(e) => {
            shell_println!("touch: {}: {:?}", path, e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

// ========== rm ============================================================

/// Remove a file or an empty directory.
///
/// Usage: `rm [-r] [-f] <path>`. The flags used to be ignored: `rm -rf /x`
/// silently tried to unlink the first positional argument's neighbour, and
/// `rm` on a directory failed with a bare `unlink` error.
pub(super) fn cmd_rm_impl(args: &[String]) -> Result<(), ShellError> {
    let mut recursive = false;
    let mut force = false;
    let mut paths: Vec<&String> = Vec::new();

    for arg in args {
        match arg.as_str() {
            "-r" | "-rf" | "-fr" | "-R" => recursive = true,
            "-f" => force = true,
            other if other.starts_with('-') => {
                shell_println!("rm: unknown option '{}'", other);
                shell_println!("Usage: rm [-r] [-f] <path>");
                return Err(ShellError::InvalidArguments);
            }
            _ => paths.push(arg),
        }
    }

    if paths.is_empty() {
        shell_println!("Usage: rm [-r] [-f] <path>");
        return Err(ShellError::InvalidArguments);
    }
    if paths.len() > 1 {
        shell_println!("rm: expected a single path, got {}", paths.len());
        shell_println!("Usage: rm [-r] [-f] <path>");
        return Err(ShellError::InvalidArguments);
    }

    let path = match vfs::resolve_path_for_current_task(paths[0]) {
        Ok(p) => p,
        Err(e) => {
            if force {
                return Ok(());
            }
            shell_println!("rm: {}: {:?}", paths[0], e);
            return Err(ShellError::ExecutionFailed);
        }
    };

    // Unlinking the root would take the whole namespace down.
    if path == "/" {
        shell_println!("rm: refusing to remove /");
        return Err(ShellError::InvalidArguments);
    }

    let is_dir = is_directory(&path);
    if is_dir && !recursive {
        shell_println!("rm: {}: is a directory (use -r)", path);
        return Err(ShellError::ExecutionFailed);
    }

    let result = if is_dir {
        remove_tree(&path)
    } else {
        vfs::unlink(&path)
    };

    match result {
        Ok(()) => {
            shell_println!("rm: {}", path);
            Ok(())
        }
        Err(e) => {
            if force {
                return Ok(());
            }
            shell_println!("rm: {}: {:?}", path, e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// True when `path` is a directory. Symlinks are followed, like `stat`.
fn is_directory(path: &str) -> bool {
    vfs::stat_path(path)
        .map(|st| file_type_char(st.st_mode) == 'd')
        .unwrap_or(false)
}

/// Joins a directory and an entry name into a child path.
fn child_path(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        alloc::format!("{}{}", dir, name)
    } else {
        alloc::format!("{}/{}", dir, name)
    }
}

/// Removes a directory and everything below it.
///
/// The kernel's `unlink` refuses a non-empty directory (`NotEmpty`) and does not
/// recurse, so the walk lives here, on top of `getdents`. Symlinks are unlinked
/// rather than followed, so a link pointing at a directory cannot make `rm -r`
/// delete the target's contents.
fn remove_tree(path: &str) -> Result<(), crate::syscall::error::SyscallError> {
    // A symlink is removed, never descended into.
    if vfs::readlink(path).is_ok() {
        return vfs::unlink(path);
    }

    let fd = vfs::open(path, OpenFlags::READ | OpenFlags::DIRECTORY)?;
    let entries = vfs::getdents(fd);
    let _ = vfs::close(fd);

    if let Ok(entries) = entries {
        for entry in entries {
            let child = child_path(path, &entry.name);
            if entry.file_type == DT_DIR {
                remove_tree(&child)?;
            } else {
                vfs::unlink(&child)?;
            }
        }
    }
    vfs::unlink(path)
}

// ========== write ==================================================

/// Write every byte of `data`, looping over short writes.
///
/// `vfs::write` is allowed to accept fewer bytes than offered, so a single call
/// silently truncates the file. `write` and `cp` both used to do that.
fn write_all(fd: u32, data: &[u8]) -> Result<usize, crate::syscall::error::SyscallError> {
    let mut written = 0usize;
    while written < data.len() {
        match vfs::write(fd, &data[written..]) {
            Ok(0) => break,
            Ok(n) => written += n,
            Err(e) => return Err(e),
        }
    }
    Ok(written)
}

pub(super) fn cmd_write_impl(args: &[String]) -> Result<(), ShellError> {
    if args.len() < 2 {
        shell_println!("Usage: write <path> <text>");
        return Err(ShellError::InvalidArguments);
    }
    let path = resolve_arg(args, 0, "write")?;
    let text = &args[1];

    let fd = vfs::open(&path, OpenFlags::WRITE | OpenFlags::CREATE).map_err(|e| {
        shell_println!("write: {}: {:?}", path, e);
        ShellError::ExecutionFailed
    })?;
    let result = write_all(fd, text.as_bytes());
    let _ = vfs::close(fd);

    match result {
        Ok(n) => {
            shell_println!("write: {} bytes -> {}", n, path);
            Ok(())
        }
        Err(e) => {
            shell_println!("write: {}: {:?}", path, e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

// ========== stat ==================================================

pub(super) fn cmd_stat_impl(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: stat <path>");
        return Err(ShellError::InvalidArguments);
    }
    let path = resolve_arg(args, 0, "stat")?;
    match vfs::stat_path(&path) {
        Ok(st) => {
            shell_println!("  File:  {}", path);
            shell_println!("  Type:  {}", file_type_name(st.st_mode));
            shell_println!("  Mode:  {}", format_mode(st.st_mode));
            shell_println!("  Size:  {} bytes", st.st_size);
            shell_println!("  Links: {}", st.st_nlink);
            shell_println!("  Inode: {}", st.st_ino);
            shell_println!("  Uid:   {}", st.st_uid);
            shell_println!("  Gid:   {}", st.st_gid);
            shell_println!("  Mtime: {}", format_mtime(st.st_mtime));
            Ok(())
        }
        Err(e) => {
            shell_println!("stat: {}: {:?}", path, e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

// ========== cp ==================================================

/// Copies a file, reporting whether every byte landed.
///
/// Shared by `cp` and by the cross-mount fallback of `mv`, which must not
/// delete its source when the copy failed: `cp` used to print the write error
/// and still return `Ok(())`, so `mv` went on to unlink the source and lost it.
fn copy_file(src: &str, dst: &str) -> Result<usize, ShellError> {
    let fd_src = vfs::open(src, OpenFlags::READ).map_err(|e| {
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
        dst,
        OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
    )
    .map_err(|e| {
        shell_println!("cp: cannot create '{}': {:?}", dst, e);
        ShellError::ExecutionFailed
    })?;
    let written = write_all(fd_dst, &data);
    let _ = vfs::close(fd_dst);

    match written {
        Ok(n) if n == data.len() => Ok(n),
        Ok(n) => {
            shell_println!(
                "cp: short write to '{}': {} of {} bytes",
                dst,
                n,
                data.len()
            );
            Err(ShellError::ExecutionFailed)
        }
        Err(e) => {
            shell_println!("cp: write to '{}': {:?}", dst, e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

pub(super) fn cmd_cp_impl(args: &[String]) -> Result<(), ShellError> {
    if args.len() < 2 {
        shell_println!("Usage: cp <src> <dst>");
        return Err(ShellError::InvalidArguments);
    }
    let src = resolve_arg(args, 0, "cp")?;
    let dst = resolve_arg(args, 1, "cp")?;
    let n = copy_file(&src, &dst)?;
    shell_println!("cp: {} -> {} ({} bytes)", src, dst, n);
    Ok(())
}

// ========== mv ==================================================

pub(super) fn cmd_mv_impl(args: &[String]) -> Result<(), ShellError> {
    if args.len() < 2 {
        shell_println!("Usage: mv <src> <dst>");
        return Err(ShellError::InvalidArguments);
    }
    let src = resolve_arg(args, 0, "mv")?;
    let dst = resolve_arg(args, 1, "mv")?;

    match vfs::rename(&src, &dst) {
        Ok(()) => {
            shell_println!("mv: {} -> {}", src, dst);
            return Ok(());
        }
        Err(crate::syscall::error::SyscallError::NotSupported) => {
            // Cross-mount: copy, then remove the source -- but only if the copy
            // really landed every byte.
        }
        Err(e) => {
            shell_println!("mv: {} -> {}: {:?}", src, dst, e);
            return Err(ShellError::ExecutionFailed);
        }
    }

    let n = copy_file(&src, &dst)?;
    match vfs::unlink(&src) {
        Ok(()) => {
            shell_println!("mv: {} -> {} ({} bytes copied)", src, dst, n);
            Ok(())
        }
        Err(e) => {
            shell_println!(
                "mv: copied {} -> {} but could not remove source '{}': {:?}",
                src,
                dst,
                src,
                e
            );
            Err(ShellError::ExecutionFailed)
        }
    }
}

// ========== df ==================================================

pub(super) fn cmd_df_impl(_args: &[String]) -> Result<(), ShellError> {
    let mounts = vfs::list_mounts();
    shell_println!("{:<20} {}", "Mount", "Status");
    shell_println!("=======================================================================================================");
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
