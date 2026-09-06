use alloc::{string::String, sync::Arc};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::{sync::SpinLock, syscall::error::SyscallError};

use super::{
    fd::FileDescriptorTable,
    file::OpenFile,
    scheme::{
        finalize_pseudo_stat, DynScheme, FileFlags, FileStat, OpenFlags, OpenResult, Scheme,
        DEV_CONSOLE,
    },
};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static CONSOLE: SpinLock<Option<Arc<ConsoleScheme>>> = SpinLock::new(None);

/// Kernel console scheme : thin redirect to serial/VGA.
///
/// Architecture:
/// - Writes always go to serial (for debug / early boot).
/// - Before the display server starts, writes also go to VGA (boot mode).
/// - Once the display server is active, VGA writes are skipped because
///   the display server owns the framebuffer. Full redirect-to-display-server
///   logic will be added when the console silo is integrated.
///
/// `VgaWriter` remains boot-only; the display server takes over the
/// framebuffer at userspace startup.
pub struct ConsoleScheme;

impl ConsoleScheme {
    /// Creates a new instance.
    pub fn new() -> Self {
        ConsoleScheme
    }
}

impl Scheme for ConsoleScheme {
    /// Performs the open operation.
    fn open(&self, _path: &str, _flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        Ok(OpenResult {
            file_id: id,
            size: None,
            flags: FileFlags::DEVICE,
        })
    }

    /// Performs the read operation.
    ///
    /// The console scheme is write-only (output to serial/VGA).
    /// Keyboard input must come from `/dev/input/kbd` via `InputScheme`.
    /// Reading from the keyboard buffer here would compete with the userspace
    /// console (strate-console) and silently steal keystrokes.
    fn read(&self, _file_id: u64, _offset: u64, _buf: &mut [u8]) -> Result<usize, SyscallError> {
        Err(SyscallError::Again)
    }

    /// Performs the write operation.
    ///
    /// Boot mode: serial + VGA (when VGA hardware is present).
    /// Runtime mode: serial only : the display server owns the framebuffer.
    /// TODO: skip VGA writes once the display server signals readiness.
    fn write(&self, _file_id: u64, _offset: u64, buf: &[u8]) -> Result<usize, SyscallError> {
        if let Ok(s) = core::str::from_utf8(buf) {
            // Always write to serial (debug / crash output).
            crate::serial_print!("{}", s);
            // Boot-mode VGA output: write to the VGA buffer while the display
            // server is not yet active. Once the display server starts, this
            // branch should be gated on a readiness flag (e.g. DISPLAY_SERVER_ACTIVE).
            if crate::arch::vga::is_available() {
                crate::vga_print!("{}", s);
            }
        } else {
            for &b in buf {
                crate::serial_print!("{}", b as char);
            }
        }
        Ok(buf.len())
    }

    /// Performs the close operation.
    fn close(&self, _file_id: u64) -> Result<(), SyscallError> {
        Ok(())
    }

    /// Performs the stat operation.
    fn stat(&self, _file_id: u64) -> Result<FileStat, SyscallError> {
        Ok(finalize_pseudo_stat(
            FileStat {
                st_ino: 0,
                st_mode: 0o020666,
                st_nlink: 1,
                st_size: 0,
                st_blksize: 1,
                st_blocks: 0,
                ..FileStat::zeroed()
            },
            DEV_CONSOLE,
            1,
        ))
    }
}

/// Initializes console scheme.
pub fn init_console_scheme() -> Arc<ConsoleScheme> {
    let scheme = Arc::new(ConsoleScheme::new());
    *CONSOLE.lock() = Some(scheme.clone());
    scheme
}

/// Performs the setup stdio operation.
pub fn setup_stdio(fd_table: &mut FileDescriptorTable) {
    let scheme = match CONSOLE.lock().clone() {
        Some(s) => s as DynScheme,
        None => return,
    };

    // fd 0 : stdin (read)
    let r0 = match scheme.open("console", OpenFlags::READ) {
        Ok(r) => r,
        Err(_) => return,
    };
    let stdin = Arc::new(OpenFile::new(
        scheme.clone(),
        r0.file_id,
        String::from("/dev/console"),
        OpenFlags::READ,
        FileFlags::DEVICE,
        None,
    ));
    fd_table.insert_at(0, stdin);

    // fd 1 : stdout (write)
    let r1 = match scheme.open("console", OpenFlags::WRITE) {
        Ok(r) => r,
        Err(_) => return,
    };
    let stdout = Arc::new(OpenFile::new(
        scheme.clone(),
        r1.file_id,
        String::from("/dev/console"),
        OpenFlags::WRITE,
        FileFlags::DEVICE,
        None,
    ));
    fd_table.insert_at(1, stdout);

    // fd 2 : stderr (write)
    let r2 = match scheme.open("console", OpenFlags::WRITE) {
        Ok(r) => r,
        Err(_) => return,
    };
    let stderr = Arc::new(OpenFile::new(
        scheme,
        r2.file_id,
        String::from("/dev/console"),
        OpenFlags::WRITE,
        FileFlags::DEVICE,
        None,
    ));
    fd_table.insert_at(2, stderr);
}
