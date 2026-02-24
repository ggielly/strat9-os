//! IPC Port — a kernel-managed message queue with blocking send/recv.
//!
//! Each port has a bounded FIFO queue of `IpcMessage`s. Senders block if
//! the queue is full; receivers block if it's empty. The scheduler's
//! block/wake API (via `WaitQueue`) provides the blocking mechanism.

use super::message::IpcMessage;
use crate::{
    process::TaskId,
    sync::{SpinLock, WaitQueue},
};
use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};
use core::sync::atomic::{AtomicU64, Ordering};

/// Maximum number of messages buffered in a single port.
const PORT_QUEUE_CAPACITY: usize = 16;

/// Unique identifier for an IPC port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortId(pub u64);

impl PortId {
    /// Get the raw u64 value.
    pub fn as_u64(self) -> u64 {
        self.0
    }

    /// Create a PortId from a raw u64.
    pub fn from_u64(raw: u64) -> Self {
        PortId(raw)
    }
}

impl core::fmt::Display for PortId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IpcError {
    #[error("port not found")]
    PortNotFound,
    #[error("not owner of port")]
    NotOwner,
    #[error("port destroyed")]
    PortDestroyed,
}

/// An IPC port: a bounded message queue with blocking semantics.
pub struct Port {
    /// Unique port identifier.
    pub id: PortId,
    /// TaskId of the port's creator/owner.
    pub owner: TaskId,
    /// The message queue (bounded to `PORT_QUEUE_CAPACITY`).
    queue: SpinLock<PortQueue>,
    /// Tasks blocked because the queue is full (waiting to send).
    send_waitq: WaitQueue,
    /// Tasks blocked because the queue is empty (waiting to receive).
    recv_waitq: WaitQueue,
}

/// Internal queue state, protected by a spinlock.
struct PortQueue {
    messages: VecDeque<IpcMessage>,
    /// Set to true when the port is destroyed; blocked tasks wake with error.
    destroyed: bool,
}

impl Port {
    /// Create a new port owned by the given task.
    fn new(id: PortId, owner: TaskId) -> Self {
        Port {
            id,
            owner,
            queue: SpinLock::new(PortQueue {
                messages: VecDeque::with_capacity(PORT_QUEUE_CAPACITY),
                destroyed: false,
            }),
            send_waitq: WaitQueue::new(),
            recv_waitq: WaitQueue::new(),
        }
    }

    /// Send a message to this port.
    ///
    /// If the queue is full, the calling task blocks until space is available.
    /// Returns `Err(IpcError::PortDestroyed)` if the port is destroyed while
    /// the sender is blocked.
    pub fn send(&self, msg: IpcMessage) -> Result<(), IpcError> {
        loop {
            {
                let mut q = self.queue.lock();
                if q.destroyed {
                    return Err(IpcError::PortDestroyed);
                }
                if q.messages.len() < PORT_QUEUE_CAPACITY {
                    q.messages.push_back(msg);
                    drop(q);
                    // Wake one receiver that may be waiting for a message.
                    self.recv_waitq.wake_one();
                    return Ok(());
                }
            }
            // Queue is full — block until a receiver drains a message.
            self.send_waitq.wait();
            // After waking, loop back and re-check (might have been destroyed).
        }
    }

    /// Receive a message from this port.
    ///
    /// If the queue is empty, the calling task blocks until a message arrives.
    /// Returns `Err(IpcError::PortDestroyed)` if the port is destroyed while
    /// the receiver is blocked.
    pub fn recv(&self) -> Result<IpcMessage, IpcError> {
        loop {
            {
                let mut q = self.queue.lock();
                if let Some(msg) = q.messages.pop_front() {
                    drop(q);
                    // Wake one sender that may be waiting for space.
                    self.send_waitq.wake_one();
                    return Ok(msg);
                }
                if q.destroyed {
                    return Err(IpcError::PortDestroyed);
                }
            }
            // Queue is empty — block until a sender posts a message.
            self.recv_waitq.wait();
        }
    }

    /// Try to receive a message from this port without blocking.
    ///
    /// Returns `Ok(Some(msg))` if a message was available, `Ok(None)` if empty,
    /// or `Err(IpcError::PortDestroyed)` if the port is destroyed.
    pub fn try_recv(&self) -> Result<Option<IpcMessage>, IpcError> {
        let mut q = self.queue.lock();
        if let Some(msg) = q.messages.pop_front() {
            drop(q);
            // Wake one sender that may be waiting for space.
            self.send_waitq.wake_one();
            return Ok(Some(msg));
        }
        if q.destroyed {
            return Err(IpcError::PortDestroyed);
        }
        Ok(None)
    }

    /// Mark the port as destroyed and wake all blocked tasks.
    fn destroy(&self) {
        {
            let mut q = self.queue.lock();
            q.destroyed = true;
        }
        self.send_waitq.wake_all();
        self.recv_waitq.wake_all();
    }
}

// ===========================================================================
// Global port registry
// ===========================================================================

/// Next port ID to assign.
static NEXT_PORT_ID: AtomicU64 = AtomicU64::new(1);

/// Global registry of all live ports.
static PORTS: SpinLock<Option<BTreeMap<PortId, Arc<Port>>>> = SpinLock::new(None);

/// Ensure the registry is initialized (called lazily).
fn ensure_registry(guard: &mut Option<BTreeMap<PortId, Arc<Port>>>) {
    if guard.is_none() {
        *guard = Some(BTreeMap::new());
    }
}

/// Create a new port owned by `owner`. Returns the new port's ID.
pub fn create_port(owner: TaskId) -> PortId {
    let id = PortId(NEXT_PORT_ID.fetch_add(1, Ordering::Relaxed));
    let port = Arc::new(Port::new(id, owner));

    let mut registry = PORTS.lock();
    ensure_registry(&mut *registry);
    registry.as_mut().unwrap().insert(id, port);

    log::debug!("IPC: created port {} (owner={})", id, owner);
    id
}

/// Look up a port by ID. Returns a cloned `Arc<Port>` if found.
pub fn get_port(id: PortId) -> Option<Arc<Port>> {
    let registry = PORTS.lock();
    registry.as_ref().and_then(|map| map.get(&id).cloned())
}

/// Destroy a port, removing it from the registry and waking all waiters.
///
/// Returns `Ok(())` if destroyed, `Err` if not found or not owned by caller.
pub fn destroy_port(id: PortId, caller: TaskId) -> Result<(), IpcError> {
    let port = {
        let mut registry = PORTS.lock();
        let map = registry.as_mut().ok_or(IpcError::PortNotFound)?;
        let port = map.get(&id).ok_or(IpcError::PortNotFound)?;
        if port.owner != caller {
            return Err(IpcError::NotOwner);
        }
        let port = port.clone();
        map.remove(&id);
        port
    };

    port.destroy();
    log::debug!("IPC: destroyed port {} (by task {})", id, caller);
    Ok(())
}
