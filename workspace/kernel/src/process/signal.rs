//! Signal handling for Strat9-OS.
//!
//! Provides basic signal infrastructure for POSIX compatibility.
//! Implements signal delivery, masking, and handling.

use core::sync::atomic::{AtomicU64, Ordering};

/// Signal numbers (POSIX-compatible).
///
/// Standard POSIX signal numbers for compatibility with userspace libc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Signal {
    /// Hangup detected on controlling terminal
    SIGHUP = 1,
    /// Interrupt from keyboard (Ctrl+C)
    SIGINT = 2,
    /// Quit from keyboard (Ctrl+\)
    SIGQUIT = 3,
    /// Illegal instruction
    SIGILL = 4,
    /// Trace/breakpoint trap
    SIGTRAP = 5,
    /// Abort signal
    SIGABRT = 6,
    /// Bus error (bad memory access)
    SIGBUS = 7,
    /// Floating-point exception
    SIGFPE = 8,
    /// Kill signal (cannot be caught or ignored)
    SIGKILL = 9,
    /// User-defined signal 1
    SIGUSR1 = 10,
    /// Segmentation fault
    SIGSEGV = 11,
    /// User-defined signal 2
    SIGUSR2 = 12,
    /// Broken pipe
    SIGPIPE = 13,
    /// Timer signal
    SIGALRM = 14,
    /// Termination signal
    SIGTERM = 15,
    /// Child stopped or terminated
    SIGCHLD = 17,
    /// Continue if stopped
    SIGCONT = 18,
    /// Stop process (cannot be caught or ignored)
    SIGSTOP = 19,
    /// Stop typed at terminal
    SIGTSTP = 20,
    /// Background read attempt
    SIGTTIN = 21,
    /// Background write attempt
    SIGTTOU = 22,
    /// Urgent data on socket
    SIGURG = 23,
    /// CPU time limit exceeded
    SIGXCPU = 24,
    /// File size limit exceeded
    SIGXFSZ = 25,
    /// Virtual timer expired
    SIGVTALRM = 26,
    /// Profiling timer expired
    SIGPROF = 27,
    /// Window size changed
    SIGWINCH = 28,
    /// I/O possible on socket
    SIGIO = 29,
    /// Power failure
    SIGPWR = 30,
    /// Bad system call
    SIGSYS = 31,
}

impl Signal {
    /// Convert a signal number to a Signal enum.
    pub fn from_u32(num: u32) -> Option<Self> {
        match num {
            1 => Some(Signal::SIGHUP),
            2 => Some(Signal::SIGINT),
            3 => Some(Signal::SIGQUIT),
            4 => Some(Signal::SIGILL),
            5 => Some(Signal::SIGTRAP),
            6 => Some(Signal::SIGABRT),
            7 => Some(Signal::SIGBUS),
            8 => Some(Signal::SIGFPE),
            9 => Some(Signal::SIGKILL),
            10 => Some(Signal::SIGUSR1),
            11 => Some(Signal::SIGSEGV),
            12 => Some(Signal::SIGUSR2),
            13 => Some(Signal::SIGPIPE),
            14 => Some(Signal::SIGALRM),
            15 => Some(Signal::SIGTERM),
            17 => Some(Signal::SIGCHLD),
            18 => Some(Signal::SIGCONT),
            19 => Some(Signal::SIGSTOP),
            20 => Some(Signal::SIGTSTP),
            21 => Some(Signal::SIGTTIN),
            22 => Some(Signal::SIGTTOU),
            23 => Some(Signal::SIGURG),
            24 => Some(Signal::SIGXCPU),
            25 => Some(Signal::SIGXFSZ),
            26 => Some(Signal::SIGVTALRM),
            27 => Some(Signal::SIGPROF),
            28 => Some(Signal::SIGWINCH),
            29 => Some(Signal::SIGIO),
            30 => Some(Signal::SIGPWR),
            31 => Some(Signal::SIGSYS),
            _ => None,
        }
    }

    /// Convert Signal to its numeric value.
    pub fn as_u32(self) -> u32 {
        self as u32
    }

    /// Check if this signal cannot be caught or blocked.
    pub fn is_uncatchable(self) -> bool {
        matches!(self, Signal::SIGKILL | Signal::SIGSTOP)
    }

    /// Get the bit position for this signal in a signal mask.
    pub fn bit(self) -> u64 {
        1u64 << (self.as_u32() - 1)
    }
}

/// Signal mask constants
pub const SIGNAL_MASK_SIZE: usize = 8; // u64 = 64 bits, enough for signals 1-64
pub const SIGNAL_MAX: u32 = 64;

/// How to modify the signal mask
pub const SIG_BLOCK: i32 = 0;
pub const SIG_UNBLOCK: i32 = 1;
pub const SIG_SETMASK: i32 = 2;

/// A set of signals represented as a bitmask.
///
/// Uses atomic operations for lock-free signal delivery.
#[derive(Debug)]
pub struct SignalSet {
    mask: AtomicU64,
}

impl Clone for SignalSet {
    fn clone(&self) -> Self {
        Self::from_mask(self.get_mask())
    }
}

impl SignalSet {
    /// Create an empty signal set.
    pub const fn new() -> Self {
        Self {
            mask: AtomicU64::new(0),
        }
    }

    /// Create a signal set from a raw mask value.
    pub const fn from_mask(mask: u64) -> Self {
        Self {
            mask: AtomicU64::new(mask),
        }
    }

    /// Add a signal to the set.
    pub fn add(&self, signal: Signal) {
        let bit = signal.bit();
        self.mask.fetch_or(bit, Ordering::SeqCst);
    }

    /// Remove a signal from the set.
    pub fn remove(&self, signal: Signal) {
        let bit = !signal.bit();
        self.mask.fetch_and(bit, Ordering::SeqCst);
    }

    /// Check if a signal is in the set.
    pub fn contains(&self, signal: Signal) -> bool {
        let bit = signal.bit();
        (self.mask.load(Ordering::SeqCst) & bit) != 0
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.mask.load(Ordering::SeqCst) == 0
    }

    /// Get the raw mask value.
    pub fn get_mask(&self) -> u64 {
        self.mask.load(Ordering::SeqCst)
    }

    /// Set the raw mask value.
    pub fn set_mask(&self, mask: u64) {
        self.mask.store(mask, Ordering::SeqCst);
    }

    /// Clear all signals.
    pub fn clear(&self) {
        self.mask.store(0, Ordering::SeqCst);
    }

    /// Get the next pending signal (lowest numbered).
    pub fn next_pending(&self) -> Option<Signal> {
        let pending = self.mask.load(Ordering::SeqCst);
        if pending == 0 {
            return None;
        }
        // Find the lowest set bit (lowest signal number).
        let signal_num = pending.trailing_zeros() + 1;
        Signal::from_u32(signal_num)
    }

    /// Get signals that are in self but not in blocked.
    pub fn unblocked(&self, blocked: &SignalSet) -> u64 {
        let pending = self.mask.load(Ordering::SeqCst);
        let blocked_mask = blocked.mask.load(Ordering::SeqCst);
        pending & !blocked_mask
    }
}

/// Signal action flags
pub const SA_NOCLDSTOP: u32 = 1 << 0;
pub const SA_NOCLDWAIT: u32 = 1 << 1;
pub const SA_SIGINFO: u32 = 1 << 2;
pub const SA_RESTORER: u32 = 1 << 3;
pub const SA_ONSTACK: u32 = 1 << 4;
pub const SA_RESTART: u32 = 1 << 5;
pub const SA_NODEFER: u32 = 1 << 6;
pub const SA_RESETHAND: u32 = 1 << 7;

/// Signal handler type
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum SigAction {
    /// Use default handler
    Default,
    /// Ignore the signal
    Ignore,
    /// Call handler at this address
    Handler(u64),
}

impl Default for SigAction {
    fn default() -> Self {
        SigAction::Default
    }
}

/// Signal alternate stack
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct SigStack {
    /// Stack base address
    pub ss_sp: u64,
    /// Stack flags
    pub ss_flags: i32,
    /// Stack size
    pub ss_size: usize,
}

/// Send a signal to a task.
///
/// # Arguments
///
/// - `target`: Task ID to send the signal to
/// - `signal`: Signal to send
///
/// # Returns
///
/// - `Ok(())` if the signal was delivered
/// - `Err(InvalidArgument)` if the task doesn't exist or signal is invalid
pub fn send_signal(
    target: crate::process::TaskId,
    signal: Signal,
) -> Result<(), crate::syscall::error::SyscallError> {
    use crate::{process::get_task_by_id, syscall::error::SyscallError};

    // SIGKILL and SIGSTOP cannot be ignored
    if signal.is_uncatchable() {
        // Still deliver them
    }

    let task = get_task_by_id(target).ok_or(SyscallError::InvalidArgument)?;

    // Add signal to the task's pending set.
    // We have a reference to the task, so it's safe to access its fields.
    let pending = &task.pending_signals;
    pending.add(signal);

    // If the task is blocked and the signal is not blocked, wake it.
    unsafe {
        let state = &*task.state.get();
        if *state == crate::process::TaskState::Blocked {
            let blocked = &task.blocked_signals;
            if !blocked.contains(signal) {
                // Wake the task so it can handle the signal.
                crate::process::wake_task(target);
            }
        }
    }

    Ok(())
}

/// Check if the current task has any pending signals.
///
/// Used by blocking syscalls to determine if they should return EINTR.
pub fn has_pending_signals() -> bool {
    use crate::process::current_task_clone;

    if let Some(task) = current_task_clone() {
        let pending = &task.pending_signals;
        let blocked = &task.blocked_signals;
        pending.unblocked(blocked) != 0
    } else {
        false
    }
}

/// Consume the next pending signal.
///
/// Removes the signal from the pending set and returns it.
pub fn consume_next_signal() -> Option<Signal> {
    use crate::process::current_task_clone;

    if let Some(task) = current_task_clone() {
        let pending = &task.pending_signals;
        let blocked = &task.blocked_signals;
        let unblocked = pending.unblocked(blocked);
        if unblocked != 0 {
            let signal_num = unblocked.trailing_zeros() + 1;
            if let Some(signal) = Signal::from_u32(signal_num) {
                pending.remove(signal);
                return Some(signal);
            }
        }
    }
    None
}
