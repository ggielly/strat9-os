//! Level 1: one function per `/thread` control file.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use strat9_syscall::{call, error::{Error, Result}, flag};

const THREAD_DIR: &str = "/thread";

/// Cached yield fd: opened once per process, shared by every thread.
///
/// Sharing is safe: a read on the fd executes `sched_yield` in the context of
/// the calling thread, so no per-thread state lives behind it.
static YIELD_FD: AtomicU32 = AtomicU32::new(0);

/// Decimal formatter (no_std, allocation-free).
pub(crate) fn utoa(mut v: u32, buf: &mut [u8; 10]) -> &[u8] {
    if v == 0 {
        buf[9] = b'0';
        return &buf[9..];
    }
    let mut i = buf.len();
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    &buf[i..]
}

fn open_thread(name: &str, posix_flags: u32) -> Result<usize> {
    let mut path = String::from(THREAD_DIR);
    path.push('/');
    path.push_str(name);
    call::open(path.as_str(), posix_flags)
}

/// Create a thread with an explicit entry point.
///
/// - `entry`: user function address executed with `arg` in RDI.
/// - `stack_size`: requested stack size; the kernel allocates, maps and
///   owns the stack (bounds 4 KiB..16 MiB, page rounded; 0 = 64 KiB default).
/// - `arg`: first argument passed to `entry`.
/// - `tls`: FS.base for TLS (0 = none).
///
/// Returns the new thread's TID. The kernel reclaims the stack when the
/// thread exits — joining is optional (`detach` costs nothing).
pub fn thread_create(entry: usize, stack_size: usize, arg: usize, tls: usize) -> Result<u32> {
    #[repr(C)]
    struct Request {
        entry: u64,
        stack_size: u64,
        arg0: u64,
        tls_base: u64,
    }
    let req = Request {
        entry: entry as u64,
        stack_size: stack_size as u64,
        arg0: arg as u64,
        tls_base: tls as u64,
    };
    // SAFETY: `req` is a 32-byte repr(C) POD, read back entirely by the kernel.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            core::ptr::addr_of!(req) as *const u8,
            core::mem::size_of::<Request>(),
        )
    };

    let fd = open_thread("create", flag::O_RDWR)?;
    let write_res = call::write(fd, bytes);
    let read_res = match write_res {
        Ok(_) => {
            let mut tid_buf = [0u8; 4];
            match call::read(fd, &mut tid_buf) {
                Ok(n) if n == 4 => Ok(u32::from_le_bytes(tid_buf)),
                Ok(_) => Err(Error::IoError),
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    };
    let _ = call::close(fd);
    read_res
}

/// Join a thread created by the current task.
///
/// Blocks until `tid` exits and returns its exit code. Errors mirror the raw
/// syscall semantics: `EINVAL` self-join, `ENOENT` unknown or already-joined
/// thread, `EPERM` not a child of the caller.
pub fn thread_join(tid: u32) -> Result<i32> {
    let mut name = String::from("join/");
    let mut buf = [0u8; 10];
    // SAFETY: digits are valid UTF-8.
    name.push_str(unsafe { core::str::from_utf8_unchecked(utoa(tid, &mut buf)) });

    let fd = open_thread(&name, flag::O_RDONLY)?;
    let res = loop {
        let mut code_buf = [0u8; 4];
        break match call::read(fd, &mut code_buf) {
            Ok(n) if n == 4 => Ok(i32::from_le_bytes(code_buf)),
            Ok(_) => Err(Error::IoError),
            Err(e) => Err(e),
        };
    };
    let _ = call::close(fd);
    res
}

/// Exit the current thread with `code`. Never returns.
pub fn thread_exit(code: i32) -> ! {
    if let Ok(fd) = open_thread("exit", flag::O_WRONLY) {
        let _ = call::write(fd, &code.to_le_bytes());
    }
    #[allow(clippy::empty_loop)]
    loop {
        core::hint::spin_loop();
    }
}

/// TID of the calling thread (resolved at read time by the scheme).
pub fn thread_current() -> u32 {
    let Ok(fd) = open_thread("current", flag::O_RDONLY) else {
        return 0;
    };
    let mut buf = [0u8; 4];
    let tid = match call::read(fd, &mut buf) {
        Ok(n) if n == 4 => u32::from_le_bytes(buf),
        _ => 0,
    };
    let _ = call::close(fd);
    tid
}

/// Yield the CPU. The control fd is cached process-wide after the first call,
/// so steady-state cost is a single read syscall.
pub fn thread_yield() {
    let mut fd = YIELD_FD.load(Ordering::Acquire);
    if fd == 0 {
        match open_thread("yield", flag::O_RDONLY) {
            Ok(opened) => {
                fd = opened as u32;
                match YIELD_FD.compare_exchange(0, fd, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => {}
                    Err(winner) => {
                        // Another thread cached its fd first; drop ours.
                        let _ = call::close(opened);
                        fd = winner;
                    }
                }
            }
            Err(_) => return,
        }
    }
    let mut scratch = [0u8; 1];
    let _ = call::read(fd as usize, &mut scratch);
}

/// Kill a thread of the current process. The kill is performed by opening
/// `kill/<tid>` (Plan 9 style), so errors surface directly:
/// `ESRCH` unknown thread, `EPERM` other process.
pub fn thread_kill(tid: u32) -> Result<()> {
    let mut name = String::from("kill/");
    let mut buf = [0u8; 10];
    // SAFETY: digits are valid UTF-8.
    name.push_str(unsafe { core::str::from_utf8_unchecked(utoa(tid, &mut buf)) });

    let fd = call::open(format_path(&name).as_str(), flag::O_RDONLY)?;
    let _ = call::close(fd);
    Ok(())
}

fn format_path(suffix: &str) -> String {
    let mut p = String::from(THREAD_DIR);
    p.push('/');
    p.push_str(suffix);
    p
}

/// One live thread of the calling process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadInfo {
    pub tid: u32,
}

// ============================================================================
// Level 2: ergonomic closure-based threads
// ============================================================================

/// Default stack size for spawned closures (64 KiB).
pub const DEFAULT_STACK_SIZE: usize = 64 * 1024;

/// Builder for [`Thread::spawn_with`].
#[derive(Debug, Clone)]
pub struct Builder {
    stack_size: usize,
}

impl Builder {
    /// Builder with the default 64 KiB kernel-owned stack.
    pub fn new() -> Self {
        Builder {
            stack_size: DEFAULT_STACK_SIZE,
        }
    }

    /// Requested user stack size for the new thread
    /// (kernel clamps to 4 KiB..16 MiB and rounds up to a page).
    pub fn stack_size(mut self, size: usize) -> Self {
        self.stack_size = size;
        self
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

/// A handle to a spawned thread.
///
/// Dropping the handle **detaches** the thread: because stacks are
/// kernel-owned, detachment requires no cleanup at all — the kernel reclaims
/// the stack at exit. Call [`Thread::join`] to obtain the exit code instead.
#[derive(Debug)]
pub struct Thread {
    tid: u32,
    joined: bool,
}

impl Thread {
    /// Spawn a closure on a fresh kernel-owned stack.
    pub fn spawn<F: FnOnce() + Send + 'static>(f: F) -> Result<Thread> {
        Thread::spawn_with(Builder::new(), f)
    }

    /// Spawn with a custom [`Builder`].
    pub fn spawn_with<F: FnOnce() + Send + 'static>(b: Builder, f: F) -> Result<Thread> {
        let boxed: Box<dyn FnOnce() + Send> = Box::new(f);
        let arg = Box::into_raw(Box::new(boxed)) as usize;
        match thread_create(trampoline as *const () as usize, b.stack_size, arg, 0) {
            Ok(tid) => Ok(Thread { tid, joined: false }),
            Err(e) => {
                // Roll back the closure allocation on failure.
                unsafe { drop(Box::from_raw(arg as *mut Box<dyn FnOnce() + Send>)) };
                Err(e)
            }
        }
    }

    /// TID of this thread.
    pub fn tid(&self) -> u32 {
        self.tid
    }

    /// Block until the thread exits and return its exit code.
    ///
    /// Panics if the handle was already joined or detached.
    pub fn join(mut self) -> Result<i32> {
        assert!(!self.joined, "thread handle already consumed");
        self.joined = true; // neutralize Drop
        let tid = self.tid;
        drop(self);
        thread_join(tid)
    }

    /// Detach the thread: let it run to completion without joining.
    ///
    /// Free by design — the kernel owns the stack and reclaims it at exit.
    pub fn detach(mut self) {
        self.joined = true;
    }

    /// Handle for the calling thread.
    ///
    /// Note: v1 resolves the TID through `/thread/current` on every call
    /// (3 syscalls); no TLS slot is reserved yet.
    pub fn current() -> Thread {
        Thread {
            tid: thread_current(),
            joined: true, // joining yourself is invalid anyway
        }
    }

    /// Yield the calling thread's time slice.
    pub fn yield_now() {
        thread_yield();
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        if !self.joined {
            // Implicit detach: nothing to do, kernel-owned stacks are reclaimed
            // by the kernel itself when the thread exits.
            self.joined = true;
        }
    }
}

/// Closure trampoline executed as the thread entry point.
extern "C" fn trampoline(arg0: usize) -> ! {
    // SAFETY: `arg0` was produced by `Box::into_raw` in `spawn_with` for this
    // thread only.
    let boxed = unsafe { Box::from_raw(arg0 as *mut Box<dyn FnOnce() + Send>) };
    boxed();
    thread_exit(0)
}

/// List the threads of the current process (directory listing of `/thread`).
pub fn thread_list() -> Result<Vec<ThreadInfo>> {
    let fd = call::open(THREAD_DIR, flag::O_RDONLY)?;
    let mut content = Vec::new();
    let mut chunk = [0u8; 128];
    loop {
        match call::read(fd, &mut chunk) {
            Ok(0) => break,
            Ok(n) => content.extend_from_slice(&chunk[..n]),
            Err(e) => {
                let _ = call::close(fd);
                return Err(e);
            }
        }
    }
    let _ = call::close(fd);

    let mut out = Vec::new();
    let mut cur: Option<u32> = None;
    for &b in &content {
        match b {
            b'0'..=b'9' => {
                let v = cur.unwrap_or(0);
                cur = Some(v.checked_mul(10).and_then(|x| x.checked_add((b - b'0') as u32)).unwrap_or(u32::MAX));
            }
            b'\n' | b' ' | b'\r' | b'\t' => {
                if let Some(v) = cur.take() {
                    out.push(ThreadInfo { tid: v });
                }
            }
            _ => {
                // Non-numeric line (control files are listed too): skip token.
                cur = None;
            }
        }
    }
    if let Some(v) = cur.take() {
        out.push(ThreadInfo { tid: v });
    }
    Ok(out)
}
