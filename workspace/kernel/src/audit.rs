//! Kernel audit log for security-sensitive operations.
//!
//! Records events like silo creation/destruction, privilege changes,
//! capability violations, and syscall denials into a fixed-size ring
//! buffer queryable via the `audit` shell command.

use crate::sync::SpinLock;
use alloc::{string::String, vec::Vec};

const AUDIT_CAPACITY: usize = 512;

/// Categories of auditable events.
#[derive(Debug, Clone, Copy)]
pub enum AuditCategory {
    /// Silo lifecycle (create, destroy, suspend, resume).
    Silo,
    /// Capability grant, revoke, or violation.
    Capability,
    /// Syscall denied or restricted.
    Syscall,
    /// Process lifecycle (exec, fork, exit).
    Process,
    /// Security policy change (pledge, unveil, sandbox).
    Security,
}

/// A single audit log entry.
#[derive(Clone)]
pub struct AuditEntry {
    /// Monotonic sequence number.
    pub seq: u64,
    /// Kernel tick at which the event was recorded.
    pub tick: u64,
    /// PID of the task that triggered the event.
    pub pid: u32,
    /// Silo ID (0 if none).
    pub silo_id: u32,
    /// Event category.
    pub category: AuditCategory,
    /// Short human-readable description.
    pub message: String,
}

struct AuditLog {
    entries: [Option<AuditEntry>; AUDIT_CAPACITY],
    head: usize,
    count: usize,
    next_seq: u64,
}

impl AuditLog {
    const fn new() -> Self {
        const NONE: Option<AuditEntry> = None;
        Self {
            entries: [NONE; AUDIT_CAPACITY],
            head: 0,
            count: 0,
            next_seq: 1,
        }
    }

    fn push(&mut self, category: AuditCategory, pid: u32, silo_id: u32, message: String) {
        let tick = crate::process::scheduler::ticks();
        let seq = self.next_seq;
        self.next_seq += 1;

        let entry = AuditEntry {
            seq,
            tick,
            pid,
            silo_id,
            category,
            message,
        };
        let idx = (self.head + self.count) % AUDIT_CAPACITY;
        self.entries[idx] = Some(entry);
        if self.count < AUDIT_CAPACITY {
            self.count += 1;
        } else {
            self.head = (self.head + 1) % AUDIT_CAPACITY;
        }
    }

    fn entries_newest(&self, n: usize) -> Vec<AuditEntry> {
        let take = n.min(self.count);
        let mut out = Vec::with_capacity(take);
        let start = if self.count > take {
            (self.head + self.count - take) % AUDIT_CAPACITY
        } else {
            self.head
        };
        for i in 0..take {
            let idx = (start + i) % AUDIT_CAPACITY;
            if let Some(e) = &self.entries[idx] {
                out.push(e.clone());
            }
        }
        out
    }
}

static AUDIT: SpinLock<AuditLog> = SpinLock::new(AuditLog::new());

/// Record an audit event.
///
/// Called from various kernel subsystems when security-relevant
/// operations occur (silo creation, capability changes, etc.).
pub fn log(category: AuditCategory, pid: u32, silo_id: u32, message: String) {
    AUDIT.lock().push(category, pid, silo_id, message);
}

/// Retrieve the most recent `n` audit entries.
pub fn recent(n: usize) -> Vec<AuditEntry> {
    AUDIT.lock().entries_newest(n)
}

/// Return total number of audit events recorded since boot.
pub fn total_count() -> u64 {
    AUDIT.lock().next_seq - 1
}
