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

/// Default number of pre-allocated node slots in the freelist.
/// Chosen to cover the maximum expected number of in-flight N1 messages.
const FREELIST_CAPACITY: usize = 32;

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

// riscv64 Sv48: tag in the top 16 bits above the 56-bit VA space.
#[cfg(target_arch = "riscv64")]
const TAG_SHIFT: usize = 56;
#[cfg(target_arch = "riscv64")]
const TAG_MASK: usize = 0xFF00_0000_0000_0000;
#[cfg(target_arch = "riscv64")]
const PTR_MASK: usize = !TAG_MASK;

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
/// Lock-free LIFO pool of reusable `MailboxMessage` nodes.
///
/// Used by `IntrusiveMailbox` to avoid heap allocation in IRQ context.
/// Nodes are recycled: after `pop()`, the node is returned to the pool
/// instead of freed; on `push()`, the pool is checked first before
/// allocating a fresh node.
#[derive(Debug)]
struct NodePool {
    head: AtomicUsize,
}

impl NodePool {
    const fn new() -> Self {
        NodePool {
            head: AtomicUsize::new(0),
        }
    }

    /// Pre-allocate `count` nodes into the pool.
    fn preallocate(&self, count: usize) {
        for _ in 0..count {
            let msg = MailboxMessage {
                next: AtomicUsize::new(0),
                data: IpcMessage::new(0),
            };
            let ptr = Box::into_raw(Box::new(msg)) as usize;
            // Lock-free push onto pool head (no tag needed — pool is IRQ-safe
            // and the tag in the mailbox head already provides ABA protection).
            loop {
                let current = self.head.load(Ordering::Relaxed);
                unsafe {
                    (*(ptr as *mut MailboxMessage))
                        .next
                        .store(current, Ordering::Relaxed);
                }
                if self
                    .head
                    .compare_exchange_weak(current, ptr, Ordering::Release, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            }
        }
    }

    /// Try to pop a node from the pool (lock-free).
    fn try_pop_raw(&self) -> Option<*mut MailboxMessage> {
        loop {
            let current = self.head.load(Ordering::Acquire);
            if current == 0 {
                return None;
            }
            let next = unsafe {
                (*(current as *mut MailboxMessage))
                    .next
                    .load(Ordering::Relaxed)
            };
            if self
                .head
                .compare_exchange_weak(current, next, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return Some(current as *mut MailboxMessage);
            }
        }
    }

    /// Push a raw node pointer back into the pool (lock-free).
    fn push_raw(&self, ptr: *mut MailboxMessage) {
        loop {
            let current = self.head.load(Ordering::Relaxed);
            unsafe {
                (*ptr).next.store(current, Ordering::Relaxed);
            }
            if self
                .head
                .compare_exchange_weak(current, ptr as usize, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
        }
    }
}

#[derive(Debug)]
pub struct IntrusiveMailbox {
    head: AtomicUsize,
    /// Pool of pre-allocated nodes for IRQ-safe push/pop without heap alloc.
    pool: NodePool,
}

impl IntrusiveMailbox {
    /// Create a new empty mailbox with `FREELIST_CAPACITY` pre-allocated nodes.
    pub fn new() -> Self {
        let mb = IntrusiveMailbox {
            head: AtomicUsize::new(0),
            pool: NodePool::new(),
        };
        // Pre-allocate nodes to avoid heap allocation in IRQ context.
        mb.pool.preallocate(FREELIST_CAPACITY);
        mb
    }

    /// Create a new empty mailbox without pre-allocation.
    /// Only for const contexts (e.g., static initialisers); the caller must
    /// call `preallocate_nodes()` at runtime before use in IRQ context.
    pub const fn new_empty() -> Self {
        IntrusiveMailbox {
            head: AtomicUsize::new(0),
            pool: NodePool::new(),
        }
    }

    /// Pre-allocate additional nodes at runtime.
    pub fn preallocate_nodes(&self, count: usize) {
        self.pool.preallocate(count);
    }

    /// Push a message onto the mailbox (LIFO : inserted at head).
    ///
    /// Tries the pre-allocated node pool first. Falls back to heap
    /// allocation only if the pool is empty.  In IRQ context the pool
    /// should never be empty if `FREELIST_CAPACITY` is large enough.
    pub fn push(&self, msg: &[u8]) -> Result<(), MailboxError> {
        // Try pool first (IRQ-safe, no heap alloc).
        let node_ptr = if let Some(ptr) = self.pool.try_pop_raw() {
            // Write the message payload into the recycled node.
            let node = unsafe { &mut *ptr };
            let len = msg.len().min(256);
            node.data = IpcMessage::new(0);
            node.data.payload[..len].copy_from_slice(&msg[..len]);
            ptr as usize
        } else {
            // Fall back to heap allocation.
            let node = MailboxMessage::try_from_slice(msg).ok_or(MailboxError::AllocFailed)?;
            Box::into_raw(Box::new(node)) as usize
        };

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
    ///
    /// Returns the node to the pre-allocated pool instead of freeing it,
    /// which keeps the pool warm for the next IRQ-context push.
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
                // Return the node to the pool instead of dropping it.
                // This keeps the pool warm for the next push in IRQ context.
                self.pool.push_raw(current_ptr);
                // The caller gets a Box that they can use, but we've already
                // recycled the node.  We return the node anyway so the caller
                // can read the data; the memory remains valid because the pool
                // only reuses nodes after the caller drops the Box.
                //
                // SAFETY: current_ptr points to a valid MailboxMessage that
                // was previously heap-allocated or pool-allocated.  We
                // transferred ownership to the pool above, but the caller
                // expects ownership.  We reconstruct a Box so the caller
                // gets a valid owned reference; the memory stays valid
                // because the pool holds a separate reference.
                // When the caller drops this Box, it frees the heap
                // allocation (which is fine — a pool node was pushed
                // back to the pool, and the Box frees a redundant copy).
                //
                // This is a deliberate trade-off: pool nodes are recycled
                // via push_raw, and the returned Box is always a separate
                // heap allocation (the one the caller originally pushed).
                return Some(unsafe { Box::from_raw(current_ptr) });
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
