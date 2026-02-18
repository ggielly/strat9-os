//! Interval timer support (ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF)
//!
//! POSIX interval timers allow processes to receive periodic signals.
//! Three types are supported:
//! - ITIMER_REAL: Real (wall clock) time, sends SIGALRM
//! - ITIMER_VIRTUAL: Process CPU time, sends SIGVTALRM (not yet impl)
//! - ITIMER_PROF: Process + system CPU time, sends SIGPROF (not yet impl)

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Interval timer types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ITimerWhich {
    Real = 0,
    Virtual = 1,
    Prof = 2,
}

impl ITimerWhich {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(ITimerWhich::Real),
            1 => Some(ITimerWhich::Virtual),
            2 => Some(ITimerWhich::Prof),
            _ => None,
        }
    }

    /// Returns the signal number to send when this timer expires
    pub fn signal(self) -> u32 {
        match self {
            ITimerWhich::Real => 14,    // SIGALRM
            ITimerWhich::Virtual => 26, // SIGVTALRM
            ITimerWhich::Prof => 27,    // SIGPROF
        }
    }
}

/// Interval timer specification (matches POSIX itimerval)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ITimerVal {
    /// Interval for periodic timer (0 = one-shot)
    pub it_interval: TimeVal,
    /// Current value (time until next expiration)
    pub it_value: TimeVal,
}

impl ITimerVal {
    pub const fn zero() -> Self {
        Self {
            it_interval: TimeVal::zero(),
            it_value: TimeVal::zero(),
        }
    }

    /// Convert to nanoseconds
    pub fn to_nanos(&self) -> (u64, u64) {
        (self.it_interval.to_nanos(), self.it_value.to_nanos())
    }
}

/// Time value (seconds + microseconds)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TimeVal {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

impl TimeVal {
    pub const fn zero() -> Self {
        Self {
            tv_sec: 0,
            tv_usec: 0,
        }
    }

    /// Convert to nanoseconds
    pub fn to_nanos(&self) -> u64 {
        (self.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add((self.tv_usec as u64).saturating_mul(1_000))
    }

    /// Create from nanoseconds
    pub fn from_nanos(nanos: u64) -> Self {
        let tv_sec = (nanos / 1_000_000_000) as i64;
        let tv_usec = ((nanos % 1_000_000_000) / 1_000) as i64;
        Self { tv_sec, tv_usec }
    }
}

/// Per-task interval timer state
pub struct ITimerState {
    /// Next expiration time in nanoseconds (0 = disarmed)
    next_expiration: AtomicU64,
    /// Interval in nanoseconds (0 = one-shot)
    interval_ns: AtomicU64,
    /// Whether this timer is armed
    armed: AtomicBool,
}

impl ITimerState {
    pub const fn new() -> Self {
        Self {
            next_expiration: AtomicU64::new(0),
            interval_ns: AtomicU64::new(0),
            armed: AtomicBool::new(false),
        }
    }

    /// Get current timer value (time until next expiration)
    pub fn get(&self, current_time_ns: u64) -> ITimerVal {
        let next = self.next_expiration.load(Ordering::Relaxed);
        let interval = self.interval_ns.load(Ordering::Relaxed);

        let value_ns = if next > current_time_ns {
            next - current_time_ns
        } else {
            0
        };

        ITimerVal {
            it_interval: TimeVal::from_nanos(interval),
            it_value: TimeVal::from_nanos(value_ns),
        }
    }

    /// Set timer value
    pub fn set(&self, value: &ITimerVal, current_time_ns: u64) {
        let (interval_ns, value_ns) = value.to_nanos();

        self.interval_ns.store(interval_ns, Ordering::Relaxed);

        if value_ns == 0 {
            // Disarm timer
            self.armed.store(false, Ordering::Relaxed);
            self.next_expiration.store(0, Ordering::Relaxed);
        } else {
            // Arm timer
            let next = current_time_ns.saturating_add(value_ns);
            self.next_expiration.store(next, Ordering::Relaxed);
            self.armed.store(true, Ordering::Relaxed);
        }
    }

    /// Check if timer has expired and needs to fire
    pub fn check_expired(&self, current_time_ns: u64) -> bool {
        if !self.armed.load(Ordering::Relaxed) {
            return false;
        }

        let next = self.next_expiration.load(Ordering::Relaxed);
        if current_time_ns >= next && next != 0 {
            // Timer expired
            let interval = self.interval_ns.load(Ordering::Relaxed);
            if interval == 0 {
                // One-shot timer: disarm
                self.armed.store(false, Ordering::Relaxed);
                self.next_expiration.store(0, Ordering::Relaxed);
            } else {
                // Periodic timer: reset to next interval
                let new_next = current_time_ns.saturating_add(interval);
                self.next_expiration.store(new_next, Ordering::Relaxed);
            }
            true
        } else {
            false
        }
    }

    /// Disarm the timer
    pub fn disarm(&self) {
        self.armed.store(false, Ordering::Relaxed);
        self.next_expiration.store(0, Ordering::Relaxed);
        self.interval_ns.store(0, Ordering::Relaxed);
    }
}

/// Container for all three interval timers
pub struct ITimers {
    pub real: ITimerState,
    pub virtual_timer: ITimerState,
    pub prof: ITimerState,
}

impl ITimers {
    pub const fn new() -> Self {
        Self {
            real: ITimerState::new(),
            virtual_timer: ITimerState::new(),
            prof: ITimerState::new(),
        }
    }

    pub fn get(&self, which: ITimerWhich) -> &ITimerState {
        match which {
            ITimerWhich::Real => &self.real,
            ITimerWhich::Virtual => &self.virtual_timer,
            ITimerWhich::Prof => &self.prof,
        }
    }

    /// Check all timers for expiration and send signals if necessary
    /// Returns a list of (ITimerWhich, signal_number) pairs for expired timers
    pub fn check_all(&self, current_time_ns: u64) -> alloc::vec::Vec<(ITimerWhich, u32)> {
        use alloc::vec::Vec;
        let mut expired = Vec::new();

        if self.real.check_expired(current_time_ns) {
            expired.push((ITimerWhich::Real, ITimerWhich::Real.signal()));
        }
        if self.virtual_timer.check_expired(current_time_ns) {
            expired.push((ITimerWhich::Virtual, ITimerWhich::Virtual.signal()));
        }
        if self.prof.check_expired(current_time_ns) {
            expired.push((ITimerWhich::Prof, ITimerWhich::Prof.signal()));
        }

        expired
    }
}

/// Global timer tick function to be called from timer interrupt handler.
/// Checks all tasks for expired interval timers and sends appropriate signals.
///
/// # Safety
/// Should only be called from the timer interrupt handler with interrupts disabled.
pub fn tick_all_timers(current_time_ns: u64) {
    use crate::process::{get_all_tasks, send_signal, signal::Signal};

    // Get all tasks and check their timers
    if let Some(tasks) = get_all_tasks() {
        for task in tasks {
            let expired = task.itimers.check_all(current_time_ns);
            for (_which, signal_num) in expired {
                if let Some(signal) = Signal::from_u32(signal_num) {
                    let _ = send_signal(task.id, signal);
                }
            }
        }
    }
}
