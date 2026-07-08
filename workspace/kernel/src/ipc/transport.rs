//! IPC transport layer: traits, dispatch enum, and manager.
//!
//! This module defines the three-level transport hierarchy:
//! - **N1 (TypeSafe)**: kernel-internal mailbox, same address space, ~3-10 cycles.
//! - **N2 (LockFree)**: shared-memory SPSC ring with futex notification, ~400-4000 cycles.
//! - **N3 (Mmu)**: thread migration with PCID-preserving CR3 switch (research track).
//!
//! The [`TransportManager`] selects the appropriate level per silo-pair at
//! connection creation time using a configurable decision matrix.
use super::{
    lockfree_ring::{LockFreeRing, RingError, RingSlot},
    mailbox::IntrusiveMailbox,
    n3::{MigrationState, N3Transport},
};
use crate::{process, silo::SiloId, sync::SpinLock};
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
// ---------------------------------------------------------------------------
// Transport level enumeration
// ---------------------------------------------------------------------------

/// Isolation level of an IPC transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum TransportLevel {
    /// Rust type-based isolation : kernel-internal, same address space.
    TypeSafe = 1,
    /// Shared-memory lock-free SPSC ring with futex notification.
    LockFree = 2,
    /// MMU-based thread migration with PCID preservation (research).
    Mmu = 3,
}

// ---------------------------------------------------------------------------
// IpcTransport trait hierarchy
// ---------------------------------------------------------------------------

/// Describes the capabilities of an IPC transport.
#[derive(Debug, Clone, Copy)]
pub struct TransportCapabilities {
    /// Maximum message size in bytes.
    pub max_message_size: usize,
    /// Whether the transport supports blocking send/recv.
    pub blocking: bool,
    /// Whether the transport supports zero-copy (DMA into buffers).
    pub zero_copy: bool,
    /// Whether the transport supports vectored I/O (scatter-gather).
    pub vectored: bool,
    /// Number of directions (1 = simplex, 2 = duplex).
    pub directions: u8,
    /// Approximate round-trip cost in CPU cycles (for scheduler hints).
    pub estimated_cost_cycles: u32,
}

/// Core trait for all IPC transports.
pub trait IpcTransport: Send + Sync {
    /// The isolation level of this transport.
    fn level(&self) -> TransportLevel;
    /// Static capabilities of this transport.
    fn capabilities(&self) -> TransportCapabilities;
    /// Human-readable name for debugging / profiling.
    fn name(&self) -> &'static str;
}

/// Producer side : sends messages into the transport.
pub trait IpcProducer: IpcTransport {
    /// Send a message, blocking if the buffer is full.
    fn send(&self, msg: &[u8]) -> Result<(), IpcError>;
    /// Send without blocking.
    fn try_send(&self, msg: &[u8]) -> Result<(), IpcError>;
    /// Send using vectored I/O (scatter-gather).
    ///
    /// Default implementation concatenates buffers and calls `send()`.
    /// Subtypes may override for zero-copy scatter-gather.
    fn send_vectored(&self, bufs: &[&[u8]]) -> Result<(), IpcError> {
        let total: usize = bufs.iter().map(|b| b.len()).sum();
        if total > self.capabilities().max_message_size {
            return Err(IpcError::MessageTooLarge);
        }
        let mut buf = alloc::vec![0u8; total];
        let mut offset = 0;
        for b in bufs {
            buf[offset..offset + b.len()].copy_from_slice(b);
            offset += b.len();
        }
        self.send(&buf)
    }
}

/// Consumer side : receives messages from the transport.
pub trait IpcConsumer: IpcTransport {
    /// Receive a message, blocking if the buffer is empty.
    fn recv(&self, buf: &mut [u8]) -> Result<usize, IpcError>;
    /// Receive without blocking.
    fn try_recv(&self, buf: &mut [u8]) -> Result<Option<usize>, IpcError>;
}

/// Notification side : futex-based wakeup for blocking transports.
pub trait IpcNotification: IpcTransport {
    /// Notify the consumer that data is available.
    fn notify_consumer(&self);
    /// Notify the producer that space is available.
    fn notify_producer(&self);
    /// Block until a notification arrives.
    fn wait_notification(&self) -> Result<(), IpcError>;
}

// ---------------------------------------------------------------------------
// IpcError
// ---------------------------------------------------------------------------

/// Errors from IPC transport operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    /// Transport buffer is full.
    WouldBlock,
    /// Transport has been closed or disconnected.
    Disconnected,
    /// Message exceeds transport capacity.
    MessageTooLarge,
    /// Provided buffer is too small for pending message.
    BufferTooSmall,
    /// No transport exists for the given pair.
    TransportNotFound,
    /// Insufficient permissions.
    PermissionDenied,
    /// Generic transport failure.
    TransportFailed,
    /// `validate_rip()` failed : invalid or non-executable instruction pointer.
    InvalidRip,
    /// Watchdog timeout : migration was not completed in time.
    TimedOut,
}

// ---------------------------------------------------------------------------
// TransportEndpoint : sum-type dispatch (no vtable)
// ---------------------------------------------------------------------------

/// A concrete IPC transport endpoint, dispatched via enum (no `dyn` vtable).
#[derive(Debug, Clone)]
pub enum TransportEndpoint {
    /// N1 kernel-internal mailbox.
    Mailbox(Arc<IntrusiveMailbox>),
    /// N2 lock-free SPSC ring.
    LockFree(Arc<LockFreeRing>),
    /// N3 MMU thread migration.
    Mmu(Arc<super::n3::N3Transport>),
}

impl IpcTransport for TransportEndpoint {
    fn level(&self) -> TransportLevel {
        match self {
            Self::Mailbox(_) => TransportLevel::TypeSafe,
            Self::LockFree(_) => TransportLevel::LockFree,
            Self::Mmu(_) => TransportLevel::Mmu,
        }
    }

    fn capabilities(&self) -> TransportCapabilities {
        match self {
            Self::Mailbox(m) => m.capabilities(),
            Self::LockFree(r) => r.capabilities(),
            Self::Mmu(n) => n.capabilities(),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Mailbox(_) => "mailbox",
            Self::LockFree(_) => "lockfree",
            Self::Mmu(n) => n.name(),
        }
    }
}

impl IpcProducer for TransportEndpoint {
    fn send(&self, msg: &[u8]) -> Result<(), IpcError> {
        match self {
            Self::Mailbox(m) => m.send(msg),
            Self::LockFree(r) => r.send(msg),
            Self::Mmu(n) => n.send(msg),
        }
    }

    fn try_send(&self, msg: &[u8]) -> Result<(), IpcError> {
        match self {
            Self::Mailbox(m) => m.try_send(msg),
            Self::LockFree(r) => r.try_send(msg),
            Self::Mmu(n) => n.try_send(msg),
        }
    }
}

impl IpcConsumer for TransportEndpoint {
    fn recv(&self, buf: &mut [u8]) -> Result<usize, IpcError> {
        match self {
            Self::Mailbox(m) => m.recv(buf),
            Self::LockFree(r) => r.recv(buf),
            Self::Mmu(n) => n.recv(buf),
        }
    }

    fn try_recv(&self, buf: &mut [u8]) -> Result<Option<usize>, IpcError> {
        match self {
            Self::Mailbox(m) => m.try_recv(buf),
            Self::LockFree(r) => r.try_recv(buf),
            Self::Mmu(n) => n.try_recv(buf),
        }
    }
}

// LockFreeRing implements IpcTransport, IpcProducer, IpcConsumer
impl IpcTransport for LockFreeRing {
    fn level(&self) -> TransportLevel {
        TransportLevel::LockFree
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            max_message_size: RingSlot::SLOT_SIZE,
            blocking: true,
            zero_copy: true,
            vectored: true,
            directions: 2,
            estimated_cost_cycles: 400,
        }
    }

    fn name(&self) -> &'static str {
        "lockfree"
    }
}

impl IpcProducer for LockFreeRing {
    fn send(&self, msg: &[u8]) -> Result<(), IpcError> {
        self.write(msg).map_err(ring_to_ipc_error)?;
        self.notify_consumer_raw();
        Ok(())
    }

    fn try_send(&self, msg: &[u8]) -> Result<(), IpcError> {
        self.write(msg).map_err(ring_to_ipc_error)?;
        self.notify_consumer_raw();
        Ok(())
    }
}

impl IpcConsumer for LockFreeRing {
    fn recv(&self, buf: &mut [u8]) -> Result<usize, IpcError> {
        self.read(buf).map_err(ring_to_ipc_error)
    }

    fn try_recv(&self, buf: &mut [u8]) -> Result<Option<usize>, IpcError> {
        self.try_read(buf).map_err(ring_to_ipc_error)
    }
}

fn ring_to_ipc_error(e: RingError) -> IpcError {
    match e {
        RingError::Full => IpcError::WouldBlock,
        RingError::Empty => IpcError::WouldBlock,
        RingError::MessageTooLarge => IpcError::MessageTooLarge,
        RingError::BufferTooSmall => IpcError::BufferTooSmall,
        _ => IpcError::TransportFailed,
    }
}

// ---------------------------------------------------------------------------
// TransportId / TransportCreateResult
// ---------------------------------------------------------------------------

/// Unique identifier for a transport connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransportId(u64);

impl TransportId {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        TransportId(NEXT.fetch_add(1, Ordering::Relaxed))
    }

    /// Create a TransportId from a raw u64.
    pub fn from_u64(raw: u64) -> Self {
        TransportId(raw)
    }

    /// Get the raw u64 value.
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// Result of a successful transport creation.
#[derive(Debug, Clone)]
pub struct TransportCreateResult {
    pub id: TransportId,
    pub local: TransportEndpoint,
    pub remote: TransportEndpoint,
    pub level: TransportLevel,
    /// (src_silo, dst_silo) pair used for cache invalidation on close.
    pub(crate) pair: (u32, u32),
}

// ---------------------------------------------------------------------------
// TransportConfig
// ---------------------------------------------------------------------------

/// User-supplied configuration for transport creation.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Minimum acceptable isolation level.
    pub min_level: TransportLevel,
    /// Requested ring capacity in slots (N2 only).
    pub ring_capacity: Option<u32>,
    /// Requested slot size in bytes (N2 only).
    pub slot_size: Option<usize>,
}

// ---------------------------------------------------------------------------
// Decision matrix
// ---------------------------------------------------------------------------

/// Policy entry for a single cell in the decision matrix.
#[derive(Debug, Clone)]
struct TransportPolicyEntry {
    level: TransportLevel,
    ring_capacity: u32,
}

/// Default decision matrix for Tier × Tier transport selection.
const DECISION_MATRIX: [[TransportPolicyEntry; 3]; 3] = [
    // src = Critical
    [
        TransportPolicyEntry {
            level: TransportLevel::TypeSafe,
            ring_capacity: 0,
        },
        TransportPolicyEntry {
            level: TransportLevel::TypeSafe,
            ring_capacity: 0,
        },
        TransportPolicyEntry {
            level: TransportLevel::LockFree,
            ring_capacity: 256,
        },
    ],
    // src = System
    [
        TransportPolicyEntry {
            level: TransportLevel::TypeSafe,
            ring_capacity: 0,
        },
        TransportPolicyEntry {
            level: TransportLevel::LockFree,
            ring_capacity: 256,
        },
        TransportPolicyEntry {
            level: TransportLevel::LockFree,
            ring_capacity: 256,
        },
    ],
    // src = User
    [
        TransportPolicyEntry {
            level: TransportLevel::LockFree,
            ring_capacity: 256,
        },
        TransportPolicyEntry {
            level: TransportLevel::LockFree,
            ring_capacity: 256,
        },
        TransportPolicyEntry {
            // User→User: maximum isolation via MMU thread migration.
            // N3 provides hermetic Ring 3 isolation without shared memory.
            level: TransportLevel::Mmu,
            ring_capacity: 0,
        },
    ],
];

/// Per-transport performance counters.
#[derive(Debug, Clone)]
pub struct TransportStats {
    /// Total transports created.
    pub created: u64,
    /// Total messages sent (incremented by syscall handler).
    pub sent: u64,
    /// Total messages received.
    pub received: u64,
    /// Total errors.
    pub errors: u64,
    /// Current transport level.
    pub level: TransportLevel,
}

impl TransportStats {
    const fn new(level: TransportLevel) -> Self {
        TransportStats {
            created: 0,
            sent: 0,
            received: 0,
            errors: 0,
            level,
        }
    }
}

// ---------------------------------------------------------------------------
// TransportEndpoint helpers for polling
// ---------------------------------------------------------------------------

impl TransportEndpoint {
    /// Whether the transport has data to read.
    pub fn has_data(&self) -> bool {
        match self {
            Self::Mailbox(m) => !m.is_empty(),
            Self::LockFree(r) => r.has_data(),
            Self::Mmu(n) => {
                let frame = n.frame();
                frame.msg_len > 0 && frame.generation.load(Ordering::Acquire) > 0
            }
        }
    }

    /// Whether the transport has space to write.
    pub fn has_space(&self) -> bool {
        match self {
            Self::Mailbox(_) => true,
            Self::LockFree(r) => r.has_space(),
            Self::Mmu(n) => {
                let frame = n.frame();
                frame.state.load(Ordering::Acquire) == MigrationState::Ready as u8
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TransportManager
// ---------------------------------------------------------------------------

/// Central transport manager : selects and creates IPC transports per silo pair.
///
/// Uses a static decision matrix (tier × tier) with optional dynamic
/// overrides.  A small FIFO cache avoids redundant creation for frequently
/// used pairs.
pub struct TransportManager {
    /// Static decision matrix: [src_tier][dst_tier] -> policy.
    decision_matrix: [[TransportPolicyEntry; 3]; 3],
    /// Dynamic overrides (set by silo admin).
    policy_overrides: SpinLock<BTreeMap<(u32, u32), TransportPolicyEntry>>,
    /// Active transport registry.
    active: SpinLock<BTreeMap<TransportId, TransportCreateResult>>,
    /// Simple FIFO transport cache (no_std, no allocation).
    cache: SpinLock<TransportCache>,
    /// Per-transport performance statistics.
    pub stats: SpinLock<TransportStats>,
}

impl TransportManager {
    /// Create a new manager with the default decision matrix.
    pub const fn new() -> Self {
        TransportManager {
            decision_matrix: DECISION_MATRIX,
            policy_overrides: SpinLock::new(BTreeMap::new()),
            active: SpinLock::new(BTreeMap::new()),
            cache: SpinLock::new(TransportCache::new()),
            stats: SpinLock::new(TransportStats::new(TransportLevel::LockFree)),
        }
    }

    /// Establish a transport between `src` and `dst`.
    ///
    /// Selection order:
    /// 1. Cache hit (fast path for repeated pairs).
    /// 2. Dynamic override (admin-configured policy).
    /// 3. Static decision matrix (safe default).
    pub fn establish(
        &self,
        src: SiloId,
        dst: SiloId,
        config: TransportConfig,
    ) -> Result<TransportCreateResult, IpcError> {
        let pair = (src.sid, dst.sid);

        // 1. Cache lookup
        {
            let mut cache = self.cache.lock();
            if let Some(cached) = cache.get(pair) {
                if cached.level as u8 >= config.min_level as u8 {
                    return Ok(cached.clone());
                }
            }
        }

        // 2. Dynamic overrides
        {
            let overrides = self.policy_overrides.lock();
            if let Some(entry) = overrides.get(&pair) {
                return self.create(pair, entry.level, entry.ring_capacity);
            }
        }

        // 3. Static matrix
        let entry = &self.decision_matrix[src.tier as usize][dst.tier as usize];
        let level = if entry.level < config.min_level {
            config.min_level
        } else {
            entry.level
        };
        self.create(
            pair,
            level,
            config.ring_capacity.unwrap_or(entry.ring_capacity),
        )
    }

    /// Create a transport at the given level.
    fn create(
        &self,
        _pair: (u32, u32),
        level: TransportLevel,
        capacity: u32,
    ) -> Result<TransportCreateResult, IpcError> {
        let id = TransportId::new();

        let (local, remote) = match level {
            TransportLevel::TypeSafe => {
                let mb = IntrusiveMailbox::new();
                let arc = Arc::new(mb);
                (
                    TransportEndpoint::Mailbox(arc.clone()),
                    TransportEndpoint::Mailbox(arc),
                )
            }
            TransportLevel::LockFree => {
                let ring = LockFreeRing::new(capacity.max(4), 2048)
                    .map_err(|_| IpcError::TransportFailed)?;
                (
                    TransportEndpoint::LockFree(ring.clone()),
                    TransportEndpoint::LockFree(ring),
                )
            }
            TransportLevel::Mmu => {
                // N3 MMU thread migration.
                //
                // Creates a unidirectional N3Transport: sender = current task,
                // receiver = first task found in the destination silo.
                // For full-duplex N3, two transports must be created
                // (one in each direction).
                let sender = process::current_task_clone().ok_or(IpcError::TransportFailed)?;
                let sender_id = sender.id;

                // Find a task in the destination silo.
                let all_tasks = process::get_all_tasks().ok_or(IpcError::TransportFailed)?;
                let receiver_task = all_tasks
                    .iter()
                    .find(|t| {
                        crate::silo::try_silo_id_for_task(t.id).map_or(false, |sid| sid == _pair.1)
                    })
                    .cloned()
                    .ok_or(IpcError::Disconnected)?;

                let transport = N3Transport::new(sender_id, receiver_task.id)?;
                let arc = Arc::new(transport);
                (
                    TransportEndpoint::Mmu(arc.clone()),
                    TransportEndpoint::Mmu(arc),
                )
            }
        };

        let result = TransportCreateResult {
            id,
            local,
            remote: remote.clone(),
            level,
            pair: _pair,
        };

        // Increment global transport creation counter
        self.stats.lock().created += 1;

        {
            let mut cache = self.cache.lock();
            cache.put(_pair, result.clone());
        }
        {
            let mut active = self.active.lock();
            active.insert(id, result.clone());
        }

        Ok(result)
    }

    /// Look up a transport endpoint by ID.
    pub fn get_endpoint(&self, id: TransportId) -> Option<TransportEndpoint> {
        let active = self.active.lock();
        active.get(&id).map(|r| r.local.clone())
    }

    /// Remove a transport from the registry (called when all handles close).
    /// Also invalidates the cache entry for the pair to prevent stale reuse.
    pub fn close(&self, id: TransportId) -> Result<(), IpcError> {
        let mut active = self.active.lock();
        let removed = active.remove(&id).ok_or(IpcError::TransportNotFound)?;
        // Invalidate cache entry to prevent stale reuse.
        let mut cache = self.cache.lock();
        cache.invalidate(removed.pair);
        Ok(())
    }

    /// Override the transport policy for a specific silo pair.
    pub fn set_policy(&self, src: u32, dst: u32, level: TransportLevel, capacity: u32) {
        let mut overrides = self.policy_overrides.lock();
        overrides.insert(
            (src, dst),
            TransportPolicyEntry {
                level,
                ring_capacity: capacity,
            },
        );
    }
}

// ---------------------------------------------------------------------------
// TransportCache : no_std FIFO cache
// ---------------------------------------------------------------------------

const CACHE_SIZE: usize = 128;

struct TransportCache {
    entries: [((u32, u32), Option<TransportCreateResult>); CACHE_SIZE],
    next: usize,
}

impl TransportCache {
    const fn new() -> Self {
        const NONE: ((u32, u32), Option<TransportCreateResult>) = ((0, 0), None);
        TransportCache {
            entries: [NONE; CACHE_SIZE],
            next: 0,
        }
    }

    fn get(&mut self, key: (u32, u32)) -> Option<&TransportCreateResult> {
        self.entries
            .iter()
            .find_map(|(k, v)| if *k == key { v.as_ref() } else { None })
    }

    fn put(&mut self, key: (u32, u32), value: TransportCreateResult) {
        let idx = self.next;
        self.entries[idx] = (key, Some(value));
        self.next = (self.next + 1) % CACHE_SIZE;
    }

    /// Invalidate any cached entry for the given key.
    fn invalidate(&mut self, key: (u32, u32)) {
        if let Some(entry) = self.entries.iter_mut().find(|(k, _)| *k == key) {
            entry.1 = None;
        }
    }
}

// ---------------------------------------------------------------------------
// TypedLockFreeRing : typestate pattern for SPSC role safety
// ---------------------------------------------------------------------------

use core::marker::PhantomData;

/// Producer role marker: only this side can call `write()`.
pub struct Producer;

/// Consumer role marker: can only call `read()`.
pub struct Consumer;

/// SPSC ring with compile-time role enforcement.
///
/// `TypedLockFreeRing<Producer>` has both `write()` and `read()`.
/// `TypedLockFreeRing<Consumer>` has only `read()`.
/// The compiler rejects any misuse at compile time.
pub struct TypedLockFreeRing<Role> {
    inner: Arc<LockFreeRing>,
    _role: PhantomData<Role>,
}

impl TypedLockFreeRing<Producer> {
    /// Write into the ring (producer only).
    pub fn write(&self, data: &[u8]) -> Result<(), RingError> {
        self.inner.write(data)
    }
}

impl<T> TypedLockFreeRing<T> {
    /// Read from the ring (both roles).
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, RingError> {
        self.inner.read(buf)
    }
}

/// Create a typed SPSC pair returning separate producer and consumer ends.
pub fn create_spsc_pair(
    cap: u32,
    slot_size: usize,
) -> Result<(TypedLockFreeRing<Producer>, TypedLockFreeRing<Consumer>), RingError> {
    let ring = LockFreeRing::new(cap, slot_size)?;
    Ok((
        TypedLockFreeRing {
            inner: ring.clone(),
            _role: PhantomData,
        },
        TypedLockFreeRing {
            inner: ring,
            _role: PhantomData,
        },
    ))
}

// NicDataPlane : multi-queue NIC data-path
// ---------------------------------------------------------------------------

/// Shared NIC ←→ scheduler routing table.
///
/// Updated by the scheduler on each context switch; read **only** by the NIC
/// driver via a read-only (PTE_RO) mapping in Ring 3.  The NIC must never
/// write this table : doing so would corrupt scheduler state.
#[repr(C)]
pub struct NicRoutingTable {
    /// Number of valid entries.
    pub count: AtomicU32,
    _pad: [u8; 60],
    /// Routing entries, one per silo.
    pub entries: [RoutingEntry; MAX_ROUTES],
}

/// A single entry in the NIC routing table.
#[repr(C, align(64))]
pub struct RoutingEntry {
    pub silo_id: u64,
    pub core_id: u32,
    pub state: AtomicU32,
    pub rpc_count: AtomicU64,
    pub generation: AtomicU64,
}

/// Maximum number of routing entries.
pub const MAX_ROUTES: usize = 64;

impl Default for NicRoutingTable {
    fn default() -> Self {
        NicRoutingTable {
            count: AtomicU32::new(0),
            _pad: [0u8; 60],
            entries: unsafe { core::mem::zeroed() },
        }
    }
}

/// Per-queue ring pair for multi-queue NIC RSS.
pub struct RingPair {
    pub rx: Arc<LockFreeRing>,
    pub tx: Arc<LockFreeRing>,
}

/// Multi-queue NIC data plane using independent SPSC rings.
///
/// Each RSS queue gets its own `RingPair`; the NIC driver writes into the
/// RX ring of the current queue, and the networking silo (strate-net) polls
/// all RX rings in round-robin.
pub struct NicDataPlane {
    /// One ring pair per RSS queue.
    pub queues: Vec<RingPair>,
    /// Shared routing table (read-only for Ring 3).
    pub routing: NicRoutingTable,
}
