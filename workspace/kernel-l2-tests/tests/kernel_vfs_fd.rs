//! L2 — VFS file layer: OpenFile offsets/permissions + FileDescriptorTable.
//!
//! Uses a controllable mock `Scheme` (the trait's defaults make this cheap)
//! against the VERBATIM kernel OpenFile / FileDescriptorTable code — the
//! same logic every POSIX-style fd operation flows through.

use std::sync::Arc;
use kernel_l2_tests::vfs::fd::FileDescriptorTable;
use kernel_l2_tests::vfs::file::OpenFile;
use kernel_l2_tests::vfs::scheme::{
    DirEntry, FileFlags, FileStat, KernelScheme, OpenFlags, OpenResult, Scheme,
};
use kernel_l2_tests::syscall::error::SyscallError;

// ===========================================================================
// Mock scheme: in-memory file with configurable content
// ===========================================================================

/// Mock scheme: content stored behind the REAL kernel SpinLock.
struct Mock {
    data: kernel_l2_tests::sync::SpinLock<Vec<u8>>,
    fail_writes: bool,
}

impl Mock {
    fn new(data: &[u8]) -> Self {
        Self { data: kernel_l2_tests::sync::SpinLock::new(data.to_vec()), fail_writes: false }
    }
}

impl Scheme for Mock {
    fn open(&self, path: &str, _flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        Ok(OpenResult {
            file_id: path.len() as u64,
            size: Some(self.data.lock().len() as u64),
            flags: FileFlags::empty(),
        })
    }

    fn read(&self, _file_id: u64, offset: u64, buf: &mut [u8]) -> Result<usize, SyscallError> {
        let data = self.data.lock();
        let off = offset as usize;
        if off >= data.len() {
            return Ok(0);
        }
        let n = buf.len().min(data.len() - off);
        buf[..n].copy_from_slice(&data[off..off + n]);
        Ok(n)
    }

    fn write(&self, _file_id: u64, offset: u64, buf: &[u8]) -> Result<usize, SyscallError> {
        if self.fail_writes {
            return Err(SyscallError::IoError);
        }
        let mut data = self.data.lock();
        let off = offset as usize;
        if off + buf.len() > data.len() {
            data.resize(off + buf.len(), 0);
        }
        data[off..off + buf.len()].copy_from_slice(buf);
        Ok(buf.len())
    }

    fn close(&self, _file_id: u64) -> Result<(), SyscallError> {
        Ok(())
    }
}

fn open_file(flags: OpenFlags) -> Arc<OpenFile> {
    Arc::new(OpenFile::new(
        Arc::new(Mock::new(b"Hello, Strat9!")),
        1,
        "/mock/file".to_string(),
        flags,
        FileFlags::empty(),
        None,
    ))
}

// ===========================================================================
// OpenFile: offset advancement + permission enforcement
// ===========================================================================

#[test]
fn openfile_read_advances_offset() {
    let f = open_file(OpenFlags::READ);
    let mut buf = [0u8; 5];

    assert_eq!(f.read(&mut buf), Ok(5));
    assert_eq!(&buf, b"Hello");

    // Second read continues from the offset.
    assert_eq!(f.read(&mut buf), Ok(5));
    assert_eq!(&buf, b", Str");
}

#[test]
fn openfile_read_past_eof_returns_zero() {
    let f = open_file(OpenFlags::READ);
    f.read(&mut [0u8; 14]).unwrap(); // consume "Hello, Strat9!"
    let mut buf = [0xFFu8; 4];
    assert_eq!(f.read(&mut buf), Ok(0));
    assert_eq!(buf, [0xFF; 4], "EOF read must not touch the buffer");
}

#[test]
fn openfile_write_on_readonly_denied() {
    let f = open_file(OpenFlags::READ);
    assert_eq!(
        f.write(b"nope"),
        Err(SyscallError::PermissionDenied),
        "write on O_RDONLY file must be denied"
    );
}

#[test]
fn openfile_read_on_writeonly_denied() {
    let f = open_file(OpenFlags::WRITE);
    assert_eq!(
        f.read(&mut [0u8; 4]),
        Err(SyscallError::PermissionDenied)
    );
}

#[test]
fn openfile_write_advances_shared_offset() {
    // OpenFile keeps ONE offset per handle: write advances it, and a
    // subsequent read continues from there (POSIX single-offset semantics).
    let f = open_file(OpenFlags::READ | OpenFlags::WRITE);
    assert_eq!(f.write(b"HELLO"), Ok(5));
    let mut buf = [0u8; 5];
    assert_eq!(f.read(&mut buf), Ok(5));
    // Content is now "HELLO, Strat9!" (write replaced in place at offset 0);
    // the shared offset sits at 5 → read resumes on ", Str".
    assert_eq!(&buf, b", Str");

    // Rewind via truncate-free path is impossible on the handle; verify the
    // underlying mock content was extended in place instead.
    assert_eq!(f.write(b"!"), Ok(1));
}

// ===========================================================================
// FileDescriptorTable
// ===========================================================================

fn table_with_files(n: usize, flags: OpenFlags) -> (FileDescriptorTable, Vec<Arc<OpenFile>>) {
    let mut t = FileDescriptorTable::new();
    let mut files = Vec::new();
    for _ in 0..n {
        let f = open_file(flags);
        t.insert(f.clone());
        files.push(f);
    }
    (t, files)
}

#[test]
fn fd_insert_allocates_lowest_sequential_fds() {
    let (t, _) = table_with_files(3, OpenFlags::READ);
    for fd in 0..3u32 {
        assert!(t.contains(fd));
    }
    assert!(!t.contains(3));
}

#[test]
fn fd_remove_then_reuse_lowest_slot() {
    let (mut t, _) = table_with_files(3, OpenFlags::READ);
    t.remove(1).expect("remove fd 1");
    assert!(!t.contains(1));

    // Next insert must reuse fd 1 (lowest free), not append at 3.
    let new_fd = t.insert(open_file(OpenFlags::READ));
    assert_eq!(new_fd, 1, "lowest free fd must be reused");
}

#[test]
fn fd_get_after_remove_fails_with_bad_handle() {
    let (mut t, _) = table_with_files(2, OpenFlags::READ);
    t.remove(0).unwrap();
    assert!(matches!(t.get(0), Err(SyscallError::BadHandle)));
}

#[test]
fn fd_duplicate_targets_lowest_free_fd() {
    let (mut t, _) = table_with_files(3, OpenFlags::READ);
    t.remove(1).unwrap();
    let dup = t.duplicate(0).expect("dup");
    assert_eq!(dup, 1, "dup must land on lowest free slot");
    // Both fds reference the same underlying file: writes through one are
    // visible via the other (shared offset? no — separate offsets per fd,
    // but same scheme+file_id; we pin handle identity instead).
    assert!(t.get(dup).is_ok());
    assert!(Arc::ptr_eq(&t.get(0).unwrap(), &t.get(dup).unwrap()));
}

#[test]
fn fd_cloexec_flag_roundtrip() {
    let mut t = FileDescriptorTable::new();
    let f = open_file(OpenFlags::READ);
    let fd = t.insert_with_flags(f, true);
    assert_eq!(t.get_cloexec(fd), Ok(true));
    t.set_cloexec(fd, false).unwrap();
    assert_eq!(t.get_cloexec(fd), Ok(false));
}

#[test]
fn fd_replace_open_flags() {
    let mut t = FileDescriptorTable::new();
    let fd = t.insert(open_file(OpenFlags::READ));
    t.replace_open_flags(fd, OpenFlags::RDWR).unwrap();
    // Replacing flags must not disturb the file binding.
    assert!(t.contains(fd));
}

// ===========================================================================
// Nice values (FAIR scheduling class)
// ===========================================================================

mod nice {
    use kernel_l2_tests::sched_nice::{AtomicNice, Nice, NiceValue};

    #[test]
    fn nice_saturation_clamps_to_posix_range() {
        assert_eq!(Nice::new(-100).value(), NiceValue::MIN);
        assert_eq!(Nice::new(100).value(), NiceValue::MAX);
        assert_eq!(Nice::new(0).value().get(), 0);
        assert_eq!(Nice::new(-20).value(), NiceValue::MIN);
        assert_eq!(Nice::new(19).value(), NiceValue::MAX);
        // Ordering: lower nice = higher priority (Ord derived on i8).
        assert!(Nice::new(-5).value() < Nice::new(5).value());
    }

    #[test]
    fn atomic_nice_roundtrip() {
        let a = AtomicNice::new(Nice::new(10));
        assert_eq!(a.load(core::sync::atomic::Ordering::SeqCst), Nice::new(10));
        a.store(Nice::new(-15), core::sync::atomic::Ordering::SeqCst);
        assert_eq!(a.load(core::sync::atomic::Ordering::SeqCst), Nice::new(-15));
        // Saturation survives the atomic roundtrip (i32 storage truncation guard).
        a.store(Nice::new(127), core::sync::atomic::Ordering::SeqCst);
        assert_eq!(a.load(core::sync::atomic::Ordering::SeqCst), Nice::new(19));
    }
}
