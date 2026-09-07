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
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

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
///
/// ABA protection: the head pointer is tagged with a monotonic generation
/// counter to prevent the ABA problem on concurrent pop/push cycles.
#[derive(Debug)]
struct NodePool {
    head: AtomicU64,
}

/// Mask for the pointer portion of a tagged pool pointer.
const POOL_PTR_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;
/// Shift for the generation counter in a tagged pool pointer.
const POOL_GEN_SHIFT: u64 = 48;

impl NodePool {
    const fn new() -> Self {
        NodePool {
            head: AtomicU64::new(0),
        }
    }

    /// Pre-allocate `count` nodes into the pool.
    fn preallocate(&self, count: usize) {
        for _ in 0..count {
            let msg = MailboxMessage {
                next: AtomicUsize::new(0),
                data: IpcMessage::new(0),
            };
            let ptr = Box::into_raw(Box::new(msg)) as u64;
            self.push_raw(ptr as *mut MailboxMessage);
        }
    }

    /// Try to pop a node from the pool (lock-free, ABA-safe).
    fn try_pop_raw(&self) -> Option<*mut MailboxMessage> {
        loop {
            let tagged = self.head.load(Ordering::Acquire);
            let ptr = (tagged & POOL_PTR_MASK) as *mut MailboxMessage;
            if ptr.is_null() {
                return None;
            }
            let gen = tagged >> POOL_GEN_SHIFT;
            let next = unsafe { (*ptr).next.load(Ordering::Relaxed) } as u64;
            let new_tagged = (next & POOL_PTR_MASK) | ((gen + 1) << POOL_GEN_SHIFT);
            if self
                .head
                .compare_exchange_weak(tagged, new_tagged, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return Some(ptr);
            }
        }
    }

    /// Push a raw node pointer back into the pool (lock-free, ABA-safe).
    fn push_raw(&self, ptr: *mut MailboxMessage) {
        loop {
            let tagged = self.head.load(Ordering::Relaxed);
            let gen = tagged >> POOL_GEN_SHIFT;
            unsafe {
                (*ptr).next.store((tagged & POOL_PTR_MASK) as usize, Ordering::Relaxed);
            }
            let new_tagged = (ptr as u64 & POOL_PTR_MASK) | ((gen + 1) << POOL_GEN_SHIFT);
            if self
                .head
                .compare_exchange_weak(tagged, new_tagged, Ordering::Release, Ordering::Relaxed)
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
    /// Copies the message data out of the intrusive node, then returns the
    /// node to the pre-allocated pool.  The caller receives an owned
    /// `IpcMessage` value : no pointers into recycled memory.
    pub fn pop(&self) -> Option<IpcMessage> {
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
                // P0 fix: copy the message out BEFORE recycling the node.
                // This eliminates the UAF: the caller gets an owned value,
                // not a pointer into pool-managed memory.
                let msg = unsafe { (*current_ptr).data };
                // Return the node to the pool for reuse.
                self.pool.push_raw(current_ptr);
                return Some(msg);
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
            Some(msg) => {
                let len = msg.payload.len().min(buf.len());
                buf[..len].copy_from_slice(&msg.payload[..len]);
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
        let msg = mb.pop().unwrap();
        assert_eq!(&msg.payload[..5], b"hello");
    }

    #[test]
    fn push_pop_lifo_order() {
        let mb = IntrusiveMailbox::new();
        mb.push(b"first").unwrap();
        mb.push(b"second").unwrap();
        // LIFO: second popped first
        let msg2 = mb.pop().unwrap();
        assert_eq!(&msg2.payload[..6], b"second");
        let msg1 = mb.pop().unwrap();
        assert_eq!(&msg1.payload[..5], b"first");
    }

    #[test]
    fn pop_empty() {
        let mb = IntrusiveMailbox::new();
        assert!(mb.pop().is_none());
    }
}
