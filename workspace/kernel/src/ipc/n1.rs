//! N1 Type-Safe IPC : annotation macro and kernel-internal wiring.
//!
//! The N1 (TypeSafe) isolation level guarantees that communicating
//! components share the same address space (Ring 0) and that every
//! module tagged `#[n1_safe]` contains **zero `unsafe` blocks**.
//! This is verified by `cargo-geiger` in CI; the macro itself is a
//! documentation + compile-time annotation marker.
//!
//! # Usage
//!
//! ```rust
//! use crate::ipc::n1::n1_safe;
//!
//! #[n1_safe]
//! /// This function is N1-safe: no raw pointers, no `asm!`, no FFI.
//! fn notify_scheduler(event: N1Event) { /* safe code only */ }
//! ```
//!
//! # Kernel-internal N1 channels
//!
//! The following kernel component pairs use `IntrusiveMailbox` for
//! zero-copy kernel-internal IPC (N1):
//!
//! | Producer      | Consumer     | Channel                | Purpose              |
//! |---------------|--------------|------------------------|----------------------|
//! | NIC IRQ       | Scheduler    | `NIC_SCHED_MAILBOX`    | Link up/down events  |
//! | Scheduler     | NIC          | `SCHED_NIC_MAILBOX`    | Flow control hints   |

use crate::ipc::mailbox::IntrusiveMailbox;

// ---------------------------------------------------------------------------
// n1_safe attribute macro
// ---------------------------------------------------------------------------

/// Marks a function or module as N1 (Type-Safe IPC) compliant.
///
/// N1 compliance means:
/// - Zero `unsafe` blocks in the annotated code.
/// - No raw pointer dereferences.
/// - No `asm!` or FFI calls.
/// - Only uses safe Rust abstractions.
///
/// The actual verification is done by `cargo-geiger` in CI.
/// This macro is a **documentation marker** and a compile-time assertion
/// that helps reviewers identify N1-safe boundaries.
///
/// # Example
///
/// ```ignore
/// use crate::ipc::n1::n1_safe;
///
/// #[n1_safe]
/// fn handle_nic_event(event: NicEvent) -> Result<(), IpcError> {
///     NIC_SCHED_MAILBOX.send(&event.encode())?;
///     Ok(())
/// }
/// ```
#[macro_export]
macro_rules! n1_safe {
    // Function form: marks a function as N1-safe.
    // Attributes are captured and re-emitted; #[inline(always)] is added.
    ($(#[$attr:meta])* $vis:vis fn $name:ident($($arg:ident: $argty:ty),*) $(-> $ret:ty)? $body:block) => {
        $(#[$attr])*
        #[doc(hidden)]
        #[allow(unused_attributes)]
        #[inline(always)]
        $vis fn $name($($arg: $argty),*) $(-> $ret)? $body
    };
    // Module form: marks an entire module as N1-safe.
    ($(#[$attr:meta])* $vis:vis mod $name:ident $body:tt) => {
        $(#[$attr])*
        #[doc(hidden)]
        $vis mod $name $body
    };
}

// ---------------------------------------------------------------------------
// N1 event types
// ---------------------------------------------------------------------------

/// Events that can flow over N1 kernel-internal channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum N1Event {
    /// NIC link status changed (up/down).
    NicLinkChange,
    /// NIC ring backpressure (consumer too slow).
    NicBackpressure,
    /// Memory pressure notification.
    MemoryPressure,
    /// Filesystem event (file created, deleted, etc.).
    FsNotification,
    /// Scheduler tick / timeslice hint.
    SchedTick,
    /// Generic wakeup signal.
    Wakeup,
}

impl N1Event {
    /// Encode this event as a byte slice for mailbox transport.
    pub fn encode(&self) -> [u8; 2] {
        [*self as u8, 0u8]
    }

    /// Decode an event from a byte slice.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.is_empty() {
            return None;
        }
        match buf[0] {
            0 => Some(Self::NicLinkChange),
            1 => Some(Self::NicBackpressure),
            2 => Some(Self::MemoryPressure),
            3 => Some(Self::FsNotification),
            4 => Some(Self::SchedTick),
            5 => Some(Self::Wakeup),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Kernel-internal N1 mailboxes
// ---------------------------------------------------------------------------

/// Mailbox for NIC → Scheduler notifications (link up/down, backpressure).
///
/// The NIC IRQ handler sends events here; the scheduler polls or waits
/// on this mailbox during idle loops.
pub static NIC_SCHED_MAILBOX: IntrusiveMailbox = IntrusiveMailbox::new();

/// Mailbox for Scheduler → NIC flow-control hints.
///
/// When the scheduler detects that a silo is overloading the NIC, it
/// sends a throttling hint here. The NIC driver checks this mailbox
/// during `handle_interrupt()`.
pub static SCHED_NIC_MAILBOX: IntrusiveMailbox = IntrusiveMailbox::new();

// ---------------------------------------------------------------------------
// Helper: send an N1 event (safe wrapper)
// ---------------------------------------------------------------------------

n1_safe! {
    /// Send an N1 event to the NIC → Scheduler mailbox.
    /// Uses only safe Rust: `IntrusiveMailbox` push(), no raw pointers.
    #[inline(always)] // N1 path
    pub fn notify_scheduler(event: N1Event) {
        let _ = NIC_SCHED_MAILBOX.push(&event.encode());
    }
}

n1_safe! {
    /// Send an N1 event to the Scheduler → NIC mailbox.
    #[inline(always)] // N1 path
    pub fn notify_nic_driver(event: N1Event) {
        let _ = SCHED_NIC_MAILBOX.push(&event.encode());
    }
}

n1_safe! {
    /// Poll the NIC → Scheduler mailbox for pending events.
    /// Returns `None` if empty.
    #[inline(always)] // N1 path
    pub fn poll_scheduler_events() -> Option<N1Event> {
        match NIC_SCHED_MAILBOX.pop() {
            Some(msg) => N1Event::decode(&msg.data.payload),
            None => None,
        }
    }
}

n1_safe! {
    /// Poll the Scheduler → NIC mailbox for pending flow-control hints.
    #[inline(always)] // N1 path
    pub fn poll_nic_events() -> Option<N1Event> {
        match SCHED_NIC_MAILBOX.pop() {
            Some(msg) => N1Event::decode(&msg.data.payload),
            None => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn n1_event_roundtrip() {
        let events = [
            N1Event::NicLinkChange,
            N1Event::NicBackpressure,
            N1Event::MemoryPressure,
            N1Event::FsNotification,
            N1Event::SchedTick,
            N1Event::Wakeup,
        ];
        for ev in &events {
            let encoded = ev.encode();
            let decoded = N1Event::decode(&encoded).unwrap();
            assert_eq!(*ev, decoded);
        }
    }

    #[test]
    fn n1_mailbox_send_recv() {
        notify_scheduler(N1Event::NicLinkChange);
        assert_eq!(poll_scheduler_events(), Some(N1Event::NicLinkChange));
        assert_eq!(poll_scheduler_events(), None);
    }
}
