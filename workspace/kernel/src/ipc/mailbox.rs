//! N1 IntrusiveMailbox : lock-free LIFO mailbox for kernel-internal IPC.
//!
//! This is a **stack (LIFO)** structure, not a FIFO queue.  Messages are
//! inserted at the head and popped from the head.  This is acceptable for
//! notification-style IPC between trusted kernel components (scheduler <==>
//! VFS, scheduler <==> memory manager) where message ordering is not critical.
//!
//! For FIFO-guaranteed IPC, use the [`LockFreeRing`] (N2) instead.
//!
//! # Safety
//!
//! The mailbox uses tagged pointers (x86-64 canonical addresses) for ABA-safe
//! lock-free push/pop.  See [`tag_ptr`] and [`untag_ptr`].

use alloc::boxed::Box;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::transport::{
    IpcConsumer, IpcError, IpcProducer, IpcTransport, TransportCapabilities, TransportLevel,
};
use crate::ipc::message::IpcMessage;

// ---------------------------------------------------------------------------
// Tagged-pointer constants (x86-64 4-level paging only)
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
const TAG_SHIFT: usize = 48;
#[cfg(target_arch = "x86_64")]
const TAG_MASK: usize = 0xFFFF_0000_0000_0000;
#[cfg(target_arch = "x86_64")]
const PTR_MASK: usize = !TAG_MASK;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("IntrusiveMailbox tagged-pointer requires x86-64 4-level paging. "
    "See PML5 (TAG_SHIFT=57) or node-index allocator for other architectures.");

static TAG_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Encode a wrapped tag into the upper bits of a pointer value.
fn tag_ptr(ptr: usize) -> usize {
    let tag = TAG_COUNTER.fetch_add(1, Ordering::Relaxed) & 0xFFFF;
    (ptr & PTR_MASK) | (tag << TAG_SHIFT)
}

/// Strip the tag and recover the real pointer.
fn untag_ptr(tagged: usize) -> *mut MailboxMessage {
    (tagged & PTR_MASK) as *mut MailboxMessage
}

// ---------------------------------------------------------------------------
// MailboxError
// ---------------------------------------------------------------------------

/// Errors from mailbox operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxError {
    /// Allocation of a new message node failed.
    AllocFailed,
}

// ---------------------------------------------------------------------------
// MailboxMessage : intrusive node
// ---------------------------------------------------------------------------

/// A single message node in the intrusive linked list.
#[repr(C)]
pub struct MailboxMessage {
    /// Intrusive link to the next node (null = end of list).
    next: AtomicUsize,
    /// Message payload.
    pub data: IpcMessage,
}

// ---------------------------------------------------------------------------
// IntrusiveMailbox
// ---------------------------------------------------------------------------

/// A lock-free LIFO mailbox (stack) for kernel-internal IPC.
///
/// Messages are pushed atomically to the head of an intrusive linked list
/// and popped from the head.  This is **not** a FIFO queue : message order
/// is reversed on reception.
///
/// # Use case
///
/// Use for notification-style IPC between trusted kernel components where
/// low latency (~10 cycles) matters more than message ordering.  For
/// FIFO-guaranteed IPC, use [`LockFreeRing`](super::lockfree_ring::LockFreeRing).
#[derive(Debug)]
pub struct IntrusiveMailbox {
    head: AtomicUsize,
}

impl IntrusiveMailbox {
    /// Create a new empty mailbox.
    pub const fn new() -> Self {
        IntrusiveMailbox {
            head: AtomicUsize::new(0),
        }
    }

    /// Push a message onto the mailbox (LIFO : inserted at head).
    ///
    /// Allocates a new `MailboxMessage` from the kernel heap.
    /// This allocation is the primary cost; for a deterministic fast path
    /// consider a pre-allocated freelist (see design doc §12.15).
    pub fn push(&self, msg: &[u8]) -> Result<(), MailboxError> {
        let node = MailboxMessage::try_from_slice(msg).ok_or(MailboxError::AllocFailed)?;
        let node_ptr = Box::into_raw(alloc::boxed::Box::new(node)) as usize;

        loop {
            let current = self.head.load(Ordering::Acquire);
            unsafe {
                (*(node_ptr as *mut MailboxMessage))
                    .next
                    .store(current & PTR_MASK, Ordering::Relaxed);
            }
            let new_tagged = tag_ptr(node_ptr);
            if self
                .head
                .compare_exchange_weak(current, new_tagged, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    /// Pop a message from the mailbox (LIFO : from head).
    pub fn pop(&self) -> Option<alloc::boxed::Box<MailboxMessage>> {
        loop {
            let current = self.head.load(Ordering::Acquire);
            if current & PTR_MASK == 0 {
                return None;
            }
            let current_ptr = untag_ptr(current);
            let next = unsafe { (*current_ptr).next.load(Ordering::Relaxed) };
            let new_tagged = tag_ptr(next);
            if self
                .head
                .compare_exchange_weak(current, new_tagged, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return Some(unsafe { alloc::boxed::Box::from_raw(current_ptr) });
            }
        }
    }

    /// Whether the mailbox is empty.
    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Relaxed) & PTR_MASK == 0
    }
}

impl MailboxMessage {
    /// Allocate a new `MailboxMessage` from a byte slice.
    fn try_from_slice(data: &[u8]) -> Option<MailboxMessage> {
        let len = data.len().min(256);
        let mut msg = MailboxMessage {
            next: AtomicUsize::new(0),
            data: IpcMessage::new(0),
        };
        msg.data.payload[..len].copy_from_slice(&data[..len]);
        Some(msg)
    }
}

// ---------------------------------------------------------------------------
// IpcTransport impl for IntrusiveMailbox
// ---------------------------------------------------------------------------

impl IpcTransport for IntrusiveMailbox {
    fn level(&self) -> TransportLevel {
        TransportLevel::TypeSafe
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            max_message_size: 256,
            blocking: false,
            zero_copy: false,
            vectored: false,
            directions: 1,
            estimated_cost_cycles: 10,
        }
    }

    fn name(&self) -> &'static str {
        "mailbox"
    }
}

impl IpcProducer for IntrusiveMailbox {
    fn send(&self, msg: &[u8]) -> Result<(), IpcError> {
        self.push(msg).map_err(|_| IpcError::TransportFailed)
    }

    fn try_send(&self, msg: &[u8]) -> Result<(), IpcError> {
        self.send(msg)
    }
}

impl IpcConsumer for IntrusiveMailbox {
    fn recv(&self, buf: &mut [u8]) -> Result<usize, IpcError> {
        match self.pop() {
            Some(node) => {
                let len = node.data.payload.len().min(buf.len());
                buf[..len].copy_from_slice(&node.data.payload[..len]);
                Ok(len)
            }
            None => Err(IpcError::WouldBlock),
        }
    }

    fn try_recv(&self, buf: &mut [u8]) -> Result<Option<usize>, IpcError> {
        match self.recv(buf) {
            Ok(n) => Ok(Some(n)),
            Err(IpcError::WouldBlock) => Ok(None),
            Err(e) => Err(e),
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
    fn push_pop_single() {
        let mb = IntrusiveMailbox::new();
        mb.push(b"hello").unwrap();
        let node = mb.pop().unwrap();
        assert_eq!(&node.data.payload[..5], b"hello");
    }

    #[test]
    fn push_pop_lifo_order() {
        let mb = IntrusiveMailbox::new();
        mb.push(b"first").unwrap();
        mb.push(b"second").unwrap();
        // LIFO: second popped first
        let node2 = mb.pop().unwrap();
        assert_eq!(&node2.data.payload[..6], b"second");
        let node1 = mb.pop().unwrap();
        assert_eq!(&node1.data.payload[..5], b"first");
    }

    #[test]
    fn pop_empty() {
        let mb = IntrusiveMailbox::new();
        assert!(mb.pop().is_none());
    }
}
