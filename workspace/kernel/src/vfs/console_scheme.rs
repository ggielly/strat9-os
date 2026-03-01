use alloc::{string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::sync::SpinLock;
use crate::syscall::error::SyscallError;

use super::fd::FileDescriptorTable;
use super::file::OpenFile;
use super::scheme::{DirEntry, FileStat, FileFlags, OpenFlags, OpenResult, Scheme, DynScheme};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static CONSOLE: SpinLock<Option<Arc<ConsoleScheme>>> = SpinLock::new(None);

pub struct ConsoleScheme;

impl ConsoleScheme {
    pub fn new() -> Self {
        ConsoleScheme
    }
}

impl Scheme for ConsoleScheme {
    fn open(&self, _path: &str, _flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        Ok(OpenResult {
            file_id: id,
            size: None,
            flags: FileFlags::DEVICE,
        })
    }

    fn read(&self, _file_id: u64, _offset: u64, buf: &mut [u8]) -> Result<usize, SyscallError> {
        let mut count = 0;
        for slot in buf.iter_mut() {
            match crate::arch::x86_64::keyboard::read_char() {
                Some(ch) => {
                    *slot = ch;
                    count += 1;
                }
                None => break,
            }
        }
        Ok(count)
    }

    fn write(&self, _file_id: u64, _offset: u64, buf: &[u8]) -> Result<usize, SyscallError> {
        if let Ok(s) = core::str::from_utf8(buf) {
            crate::serial_print!("{}", s);
            if crate::arch::x86_64::vga::is_available() {
                crate::vga_print!("{}", s);
            }
        } else {
            for &b in buf {
                crate::serial_print!("{}", b as char);
            }
        }
        Ok(buf.len())
    }

    fn close(&self, _file_id: u64) -> Result<(), SyscallError> {
        Ok(())
    }

    fn stat(&self, _file_id: u64) -> Result<FileStat, SyscallError> {
        Ok(FileStat {
            st_ino: 0,
            st_mode: 0o020666,
            st_nlink: 1,
            st_size: 0,
            st_blksize: 1,
            st_blocks: 0,
        })
    }
}

pub fn init_console_scheme() -> Arc<ConsoleScheme> {
    let scheme = Arc::new(ConsoleScheme::new());
    *CONSOLE.lock() = Some(scheme.clone());
    scheme
}

pub fn setup_stdio(fd_table: &mut FileDescriptorTable) {
    let scheme = match CONSOLE.lock().clone() {
        Some(s) => s as DynScheme,
        None => return,
    };

    // fd 0 — stdin (read)
    let r0 = scheme.open("console", OpenFlags::READ).unwrap();
    let stdin = Arc::new(OpenFile::new(
        scheme.clone(),
        r0.file_id,
        String::from("/dev/console"),
        OpenFlags::READ,
        FileFlags::DEVICE,
        None,
    ));
    fd_table.insert_at(0, stdin);

    // fd 1 — stdout (write)
    let r1 = scheme.open("console", OpenFlags::WRITE).unwrap();
    let stdout = Arc::new(OpenFile::new(
        scheme.clone(),
        r1.file_id,
        String::from("/dev/console"),
        OpenFlags::WRITE,
        FileFlags::DEVICE,
        None,
    ));
    fd_table.insert_at(1, stdout);

    // fd 2 — stderr (write)
    let r2 = scheme.open("console", OpenFlags::WRITE).unwrap();
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
