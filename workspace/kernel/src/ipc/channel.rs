//! Typed MPMC blocking channel for IPC between kernel tasks and silos.
//!
//! ## Two levels of abstraction
//!
//! ### 1. Typed MPMC channel — kernel-internal
//!
//! [`channel`]`<T>(capacity)` returns a `(`[`Sender`]`<T>, `[`Receiver`]`<T>)` pair.
//! Both endpoints are cloneable (Multi-Producer / Multi-Consumer).
//! When the last `Sender` is dropped, all waiting `Receiver`s see
//! `Err(`[`ChannelError::Disconnected`]`)`, and vice-versa.
//!
//! ```text
//! let (tx, rx) = channel::<u64>(8);
//! let tx2 = tx.clone();           // second producer
//! let rx2 = rx.clone();           // second consumer
//! ```
//!
//! ### 2. Symmetric channel — userspace IPC (silo-to-silo)
//!
//! [`SyncChan`] is a symmetric [`IpcMessage`] channel: any holder can send
//! *or* receive.  It is stored by [`ChanId`] in a global registry and
//! accessed from userspace via `SYS_CHAN_*` syscalls.  Destroyed explicitly
//! via [`SyncChan::destroy`] when all userspace handles are closed.
//!
//! ## Blocking guarantee
//!
//! Both levels use [`WaitQueue::wait_until`] — the condition closure is
//! evaluated atomically under the waiter lock, eliminating the classic
//! lost-wakeup race without a polling loop.
//!
//! ## Lock ordering
//!
//! To avoid deadlock:
//! - The `queue` (buffer) lock is **always** acquired *inside* the
//!   `wait_until` closure, and released *before* `wake_one()` is called.
//! - `send_waitq.wake_one()` is called **outside** any recv closure.
//! - `recv_waitq.wake_one()` is called **outside** any send closure.

use super::message::IpcMessage;
use crate::sync::{SpinLock, WaitQueue};
use alloc::{collections::BTreeMap, sync::Arc};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use crossbeam_queue::ArrayQueue;

const STATUS_CONNECTED: u8 = 0;
const STATUS_SENDER_GONE: u8 = 1;
const STATUS_RECEIVER_GONE: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChannelError {
    #[error("would block")]
    WouldBlock,
    #[error("channel disconnected")]
    Disconnected,
}

// ─────────────────────────────────────────────────────────────────────────────
// Typed MPMC channel — kernel-internal
// ─────────────────────────────────────────────────────────────────────────────

/// Shared inner state for the typed MPMC channel.
struct ChannelInner<T: Send> {
    /// Bounded message queue.
    buffer: ArrayQueue<T>,
    /// Tasks blocked because the buffer is full (waiting to send).
    send_waitq: WaitQueue,
    /// Tasks blocked because the buffer is empty (waiting to receive).
    recv_waitq: WaitQueue,
    /// Channel status: CONNECTED / SENDER_GONE / RECEIVER_GONE.
    status: AtomicU8,
    /// Number of live [`Sender`] endpoints.
    sender_count: AtomicUsize,
    /// Number of live [`Receiver`] endpoints.
    receiver_count: AtomicUsize,
}

impl<T: Send> ChannelInner<T> {
    fn new(capacity: usize) -> Self {
        ChannelInner {
            buffer: ArrayQueue::new(capacity.max(1)),
            send_waitq: WaitQueue::new(),
            recv_waitq: WaitQueue::new(),
            status: AtomicU8::new(STATUS_CONNECTED),
            sender_count: AtomicUsize::new(1),
            receiver_count: AtomicUsize::new(1),
        }
    }

    #[inline]
    fn is_sender_gone(&self) -> bool {
        self.status.load(Ordering::Acquire) == STATUS_SENDER_GONE
    }

    #[inline]
    fn is_receiver_gone(&self) -> bool {
        self.status.load(Ordering::Acquire) == STATUS_RECEIVER_GONE
    }
}

/// The send end of a [`channel`].
///
/// Cloneable (MPMC): each clone shares the same internal channel.
/// When the last `Sender` is dropped, waiting receivers are woken with
/// [`ChannelError::Disconnected`].
pub struct Sender<T: Send> {
    inner: Arc<ChannelInner<T>>,
}

impl<T: Send> Clone for Sender<T> {
    fn clone(&self) -> Self {
        self.inner.sender_count.fetch_add(1, Ordering::AcqRel);
        Sender {
            inner: self.inner.clone(),
        }
    }
}

impl<T: Send> Drop for Sender<T> {
    fn drop(&mut self) {
        if self.inner.sender_count.fetch_sub(1, Ordering::AcqRel) == 1 {
            // Last sender gone — mark and wake blocked receivers.
            self.inner
                .status
                .store(STATUS_SENDER_GONE, Ordering::Release);
            self.inner.recv_waitq.wake_all();
        }
    }
}

impl<T: Send> Sender<T> {
    /// Send a message, blocking until buffer space is available.
    ///
    /// Returns `Ok(())` on success, or `Err(`[`ChannelError::Disconnected`]`)`
    /// if all receivers have been dropped before or during the send.
    pub fn send(&self, msg: T) -> Result<(), ChannelError> {
        let mut pending = Some(msg);

        let result = self.inner.send_waitq.wait_until(|| {
            // Receiver gone: discard message and report disconnect.
            if self.inner.is_receiver_gone() {
                pending.take();
                return Some(Err(ChannelError::Disconnected));
            }

            // SAFETY: `pending` is always `Some` on every invocation of this
            // closure.  It is `take`-n here and either pushed (success) or
            // replaced (full queue → retry next wakeup).
            let m = pending.take().unwrap();
            match self.inner.buffer.push(m) {
                Ok(()) => Some(Ok(())),
                Err(m) => {
                    pending = Some(m);
                    None
                }
            }
            // `buf` (queue lock) is released here, before returning from the
            // closure — never held while wake_one() is called below.
        });

        // Wake exactly one receiver AFTER releasing the waiters lock.
        if result.is_ok() {
            self.inner.recv_waitq.wake_one();
        }
        result
    }

    /// Try to send without blocking.
    ///
    /// Returns `Err((msg, WouldBlock))` if the buffer is full, or
    /// `Err((msg, Disconnected))` if all receivers are gone.
    pub fn try_send(&self, msg: T) -> Result<(), (T, ChannelError)> {
        if self.inner.is_receiver_gone() {
            return Err((msg, ChannelError::Disconnected));
        }
        match self.inner.buffer.push(msg) {
            Ok(()) => {
                self.inner.recv_waitq.wake_one();
                Ok(())
            }
            Err(m) => {
                let err = if self.inner.is_receiver_gone() {
                    ChannelError::Disconnected
                } else {
                    ChannelError::WouldBlock
                };
                Err((m, err))
            }
        }
    }

    /// Returns `true` if all receivers have been dropped.
    pub fn is_disconnected(&self) -> bool {
        self.inner.is_receiver_gone()
    }

    /// Create a new [`Receiver`] endpoint connected to the same channel.
    pub fn receiver(&self) -> Receiver<T> {
        self.inner.receiver_count.fetch_add(1, Ordering::AcqRel);
        let _ = self.inner.status.compare_exchange(
            STATUS_RECEIVER_GONE,
            STATUS_CONNECTED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        Receiver {
            inner: self.inner.clone(),
        }
    }
}

/// The receive end of a [`channel`].
///
/// Cloneable (MPMC): each clone shares the same internal channel.
/// When the last `Receiver` is dropped, waiting senders are woken with
/// [`ChannelError::Disconnected`].
pub struct Receiver<T: Send> {
    inner: Arc<ChannelInner<T>>,
}

impl<T: Send> Clone for Receiver<T> {
    fn clone(&self) -> Self {
        self.inner.receiver_count.fetch_add(1, Ordering::AcqRel);
        Receiver {
            inner: self.inner.clone(),
        }
    }
}

impl<T: Send> Drop for Receiver<T> {
    fn drop(&mut self) {
        if self.inner.receiver_count.fetch_sub(1, Ordering::AcqRel) == 1 {
            // Last receiver gone — mark and wake blocked senders.
            self.inner
                .status
                .store(STATUS_RECEIVER_GONE, Ordering::Release);
            self.inner.send_waitq.wake_all();
        }
    }
}

impl<T: Send> Receiver<T> {
    /// Receive a message, blocking until one is available.
    ///
    /// Returns `Ok(msg)` on success.  Returns `Err(`[`ChannelError::Disconnected`]`)`
    /// if all senders have been dropped *and* the buffer is empty.
    pub fn recv(&self) -> Result<T, ChannelError> {
        let result = self.inner.recv_waitq.wait_until(|| {
            // Try to pop under the waiters lock so we don't race with senders.
            let msg_opt = self.inner.buffer.pop();
            if let Some(msg) = msg_opt {
                return Some(Ok(msg));
            }
            // Buffer empty: check for disconnect.
            if self.inner.is_sender_gone() {
                return Some(Err(ChannelError::Disconnected));
            }
            None // keep waiting
        });

        // Wake exactly one sender AFTER releasing the waiters lock.
        if result.is_ok() {
            self.inner.send_waitq.wake_one();
        }
        result
    }

    /// Try to receive without blocking.
    ///
    /// Returns `Err(WouldBlock)` if the buffer is empty, or
    /// `Err(Disconnected)` if all senders are gone and the buffer is empty.
    pub fn try_recv(&self) -> Result<T, ChannelError> {
        let msg_opt = self.inner.buffer.pop();
        if let Some(msg) = msg_opt {
            self.inner.send_waitq.wake_one();
            return Ok(msg);
        }
        if self.inner.is_sender_gone() {
            return Err(ChannelError::Disconnected);
        }
        Err(ChannelError::WouldBlock)
    }

    /// Returns `true` if all senders have been dropped.
    pub fn is_disconnected(&self) -> bool {
        self.inner.is_sender_gone()
    }

    /// Create a new [`Sender`] endpoint connected to the same channel.
    pub fn sender(&self) -> Sender<T> {
        self.inner.sender_count.fetch_add(1, Ordering::AcqRel);
        let _ = self.inner.status.compare_exchange(
            STATUS_SENDER_GONE,
            STATUS_CONNECTED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        Sender {
            inner: self.inner.clone(),
        }
    }
}

/// Create a new bounded MPMC channel with the given `capacity`.
///
/// Returns `(Sender<T>, Receiver<T>)`.  Both endpoints are cloneable to add
/// more producers or consumers.  The capacity is rounded up to at least 1.
///
/// # Example (kernel-internal)
///
/// ```rust,ignore
/// let (tx, rx) = channel::<u64>(8);
/// tx.send(42).unwrap();
/// assert_eq!(rx.recv().unwrap(), 42);
/// ```
pub fn channel<T: Send>(capacity: usize) -> (Sender<T>, Receiver<T>) {
    let inner = Arc::new(ChannelInner::new(capacity));
    (
        Sender {
            inner: inner.clone(),
        },
        Receiver { inner },
    )
}

// Symmetric channel (SyncChan) — userspace / silo-to-silo IPC
/// A symmetric bounded channel over [`IpcMessage`], used by the global
/// channel registry for silo-to-silo syscall-level IPC.
///
/// Unlike [`Sender`]/[`Receiver`], `SyncChan` has no directional
/// specialisation: any caller with an `Arc<SyncChan>` can both send and
/// receive.  Destruction is explicit (via [`SyncChan::destroy`]), triggered
/// when the last userspace handle is closed.
pub struct SyncChan {
    /// Bounded message queue.
    queue: ArrayQueue<IpcMessage>,
    /// Tasks blocked because the queue is full.
    send_waitq: WaitQueue,
    /// Tasks blocked because the queue is empty.
    recv_waitq: WaitQueue,
    /// Set to `true` by [`SyncChan::destroy`]; wakes all blocked tasks.
    destroyed: AtomicBool,
}

impl SyncChan {
    fn new(capacity: usize) -> Self {
        SyncChan {
            queue: ArrayQueue::new(capacity.max(1)),
            send_waitq: WaitQueue::new(),
            recv_waitq: WaitQueue::new(),
            destroyed: AtomicBool::new(false),
        }
    }

    /// Send a message, blocking until space is available.
    ///
    /// Returns `Err(`[`ChannelError::Disconnected`]`)` if the channel has
    /// been destroyed while the sender was blocked.
    pub fn send(&self, msg: IpcMessage) -> Result<(), ChannelError> {
        let mut pending = Some(msg);

        let result = self.send_waitq.wait_until(|| {
            if self.destroyed.load(Ordering::Acquire) {
                pending.take();
                return Some(Err(ChannelError::Disconnected));
            }
            // SAFETY: `pending` is always `Some` on every closure invocation.
            let m = pending.take().unwrap();
            match self.queue.push(m) {
                Ok(()) => Some(Ok(())),
                Err(m) => {
                    pending = Some(m);
                    None
                }
            }
            // queue lock released here
        });

        if result.is_ok() {
            self.recv_waitq.wake_one();
        }
        result
    }

    /// Try to send without blocking.
    ///
    /// Returns `Err(WouldBlock)` if the queue is full, or
    /// `Err(Disconnected)` if the channel is destroyed.
    pub fn try_send(&self, msg: IpcMessage) -> Result<(), ChannelError> {
        if self.destroyed.load(Ordering::Acquire) {
            return Err(ChannelError::Disconnected);
        }
        match self.queue.push(msg) {
            Ok(()) => {
                self.recv_waitq.wake_one();
                Ok(())
            }
            Err(_) => Err(ChannelError::WouldBlock),
        }
    }

    /// Receive a message, blocking until one arrives.
    ///
    /// Returns `Err(`[`ChannelError::Disconnected`]`)` if the channel was
    /// destroyed while the receiver was blocked.
    pub fn recv(&self) -> Result<IpcMessage, ChannelError> {
        let result = self.recv_waitq.wait_until(|| {
            let msg_opt = self.queue.pop();
            if let Some(msg) = msg_opt {
                return Some(Ok(msg));
            }
            if self.destroyed.load(Ordering::Acquire) {
                return Some(Err(ChannelError::Disconnected));
            }
            None
        });

        if result.is_ok() {
            self.send_waitq.wake_one();
        }
        result
    }

    /// Try to receive without blocking.
    ///
    /// Returns `Err(WouldBlock)` if the queue is empty, or
    /// `Err(Disconnected)` if the channel is destroyed and empty.
    pub fn try_recv(&self) -> Result<IpcMessage, ChannelError> {
        let msg_opt = self.queue.pop();
        if let Some(msg) = msg_opt {
            self.send_waitq.wake_one();
            return Ok(msg);
        }
        if self.destroyed.load(Ordering::Acquire) {
            return Err(ChannelError::Disconnected);
        }
        Err(ChannelError::WouldBlock)
    }

    /// Mark the channel as destroyed and wake all blocked tasks.
    ///
    /// Called when the last userspace handle is closed.  Subsequent send/recv
    /// operations on any still-held reference return `Disconnected`.
    pub fn destroy(&self) {
        self.destroyed.store(true, Ordering::Release);
        self.send_waitq.wake_all();
        self.recv_waitq.wake_all();
    }

    /// Returns `true` if the channel has been destroyed.
    pub fn is_destroyed(&self) -> bool {
        self.destroyed.load(Ordering::Acquire)
    }

    /// Returns the current number of messages buffered.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Returns `true` if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_full(&self) -> bool {
        self.queue.is_full()
    }

    pub fn can_send(&self) -> bool {
        !self.destroyed.load(Ordering::Acquire) && !self.queue.is_full()
    }
}

// Global channel registry — userspace syscall surface
/// Unique identifier for a [`SyncChan`] in the global registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChanId(pub u64);

impl ChanId {
    pub fn as_u64(self) -> u64 {
        self.0
    }
    pub fn from_u64(raw: u64) -> Self {
        ChanId(raw)
    }
}

impl core::fmt::Display for ChanId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Next channel ID to allocate.
static NEXT_CHAN_ID: AtomicU64 = AtomicU64::new(1);

/// Global registry: `ChanId → Arc<SyncChan>`.
static CHANNELS: SpinLock<Option<BTreeMap<ChanId, Arc<SyncChan>>>> = SpinLock::new(None);

fn ensure_registry(guard: &mut Option<BTreeMap<ChanId, Arc<SyncChan>>>) {
    if guard.is_none() {
        *guard = Some(BTreeMap::new());
    }
}

/// Create a new [`SyncChan`] with the given capacity and register it.
///
/// Returns the [`ChanId`] to be returned to the creating task as a handle.
pub fn create_channel(capacity: usize) -> ChanId {
    let id = ChanId(NEXT_CHAN_ID.fetch_add(1, Ordering::Relaxed));
    let chan = Arc::new(SyncChan::new(capacity));
    let mut reg = CHANNELS.lock();
    ensure_registry(&mut *reg);
    reg.as_mut().unwrap().insert(id, chan);
    log::debug!("IPC: created sync-channel {} (cap={})", id, capacity);
    id
}

/// Look up a channel by ID. Returns a cloned `Arc<SyncChan>` if found.
pub fn get_channel(id: ChanId) -> Option<Arc<SyncChan>> {
    let reg = CHANNELS.lock();
    reg.as_ref().and_then(|map| map.get(&id).cloned())
}

/// Destroy a channel: remove it from the registry and wake all waiters.
///
/// After this call, any thread still holding an `Arc<SyncChan>` to the
/// same channel will see `Err(Disconnected)` on the next send/recv.
pub fn destroy_channel(id: ChanId) -> Result<(), ChannelError> {
    let chan = {
        let mut reg = CHANNELS.lock();
        let map = reg.as_mut().ok_or(ChannelError::Disconnected)?;
        map.remove(&id).ok_or(ChannelError::Disconnected)?
    };
    chan.destroy();
    log::debug!("IPC: destroyed sync-channel {}", id);
    Ok(())
}
