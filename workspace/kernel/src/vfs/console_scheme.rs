use alloc::{string::String, sync::Arc};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::{display_state, sync::SpinLock, syscall::error::SyscallError};

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

/// One kernel console output backend.
///
/// Backends are intentionally tiny: they are the *mechanism* used before a
/// userspace display server exists (boot, early logs, emergencies). Terminal
/// emulation, line discipline and composition belong to the `strate-console`
/// and `strate-graphical` strates, not here.
trait ConsoleBackend: Send + Sync {
    /// Short name, useful for diagnostics.
    fn name(&self) -> &'static str;

    /// Whether this backend can currently accept output.
    fn available(&self) -> bool;

    /// Write raw bytes (already UTF-8 or Latin-1 fallback).
    fn write(&self, buf: &[u8]);
}

/// Serial backend: always available, never gated. It is the panic/debug path.
struct SerialBackend;

impl ConsoleBackend for SerialBackend {
    fn name(&self) -> &'static str {
        "serial"
    }

    fn available(&self) -> bool {
        true
    }

    fn write(&self, buf: &[u8]) {
        if let Ok(s) = core::str::from_utf8(buf) {
            crate::serial_print!("{}", s);
        } else {
            for &b in buf {
                crate::serial_print!("{}", b as char);
            }
        }
    }
}

/// VGA text/framebuffer backend, boot-only.
///
/// Gated by [`display_state::kernel_fb_allowed`]: as soon as a display
/// server owns the screen, the kernel stops drawing and keeps serial only.
/// This replaces the old unconditional `vga_print!` call and its TODO.
struct VgaBackend;

impl ConsoleBackend for VgaBackend {
    fn name(&self) -> &'static str {
        "vga"
    }

    fn available(&self) -> bool {
        crate::arch::vga::is_available() && display_state::kernel_fb_allowed()
    }

    fn write(&self, buf: &[u8]) {
        if let Ok(s) = core::str::from_utf8(buf) {
            crate::vga_print!("{}", s);
        } else {
            for &b in buf {
                crate::vga_print!("{}", b as char);
            }
        }
    }
}

static SERIAL_BACKEND: SerialBackend = SerialBackend;
static VGA_BACKEND: VgaBackend = VgaBackend;

/// Ordered kernel console backends.
///
/// Serial first: it must always receive output even when the framebuffer is
/// owned by a strate or absent.
fn backends() -> [&'static dyn ConsoleBackend; 2] {
    [&SERIAL_BACKEND, &VGA_BACKEND]
}

/// Kernel console scheme: thin redirect to serial/VGA.
///
/// Architecture:
/// - Writes always go to serial (debug / panic / early boot).
/// - Before a userspace display server takes ownership, writes also go to
///   the kernel framebuffer (VGA/GOP) through the boot console.
/// - Once `/dev/display/<id>.<screen>` is opened for writing, the display
///   strate owns the framebuffer (`display_state::strate_owned()`); kernel
///   output becomes serial-only until that handle is closed.
///
/// `read()` never returns keyboard bytes: input is owned by
/// `/dev/input/kbd` and the `strate-input` strate, so a kernel console read
/// cannot steal keystrokes from the userspace console.
pub struct ConsoleScheme;

impl ConsoleScheme {
    /// Creates a new instance.
    pub fn new() -> Self {
        ConsoleScheme
    }
}

impl Default for ConsoleScheme {
    fn default() -> Self {
        Self::new()
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
    /// The kernel console is write-only (output to serial/VGA).
    /// Keyboard input must come from `/dev/input/kbd` via `InputScheme`.
    /// Reading from the keyboard buffer here would compete with the
    /// userspace console (strate-console) and silently steal keystrokes.
    fn read(&self, _file_id: u64, _offset: u64, _buf: &mut [u8]) -> Result<usize, SyscallError> {
        Err(SyscallError::Again)
    }

    /// Performs the write operation.
    ///
    /// Serial always receives the bytes. The framebuffer backend is only
    /// used while the kernel owns the display (boot / no display server).
    fn write(&self, _file_id: u64, _offset: u64, buf: &[u8]) -> Result<usize, SyscallError> {
        for backend in backends() {
            if backend.available() {
                backend.write(buf);
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
