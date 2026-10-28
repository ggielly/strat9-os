//! Shared-memory network queue.
//!
//! A `NetQueue` owns one `NET_QUEUE_SIZE` region allocated from the shared
//! ring allocator.  The region is mapped into the networking strate with
//! `SYS_NET_QUEUE_MAP`, so both sides address the same descriptor rings and
//! frame pools.  The kernel keeps a page table (`vas`/`phys`) because the
//! pages are not guaranteed to be physically contiguous.
//!
//! The queue is the data plane primitive: once mapped, RX and TX are driven
//! by the descriptor rings and the `kick`/IRQ notifications, without a
//! syscall per packet.

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use strat9_abi::net::{
    features, link_flags, NetFrameDesc, NetQueueHeader, NET_FRAME_SIZE, NET_QUEUE_SIZE,
};
use crate::ipc::shared_ring::{self, RingId, SharedRing};
use crate::sync::waitqueue::WaitQueue;
use crate::sync::SpinLock;

/// Per-queue event counter and wait queue.
///
/// The counter is monotonic and lives outside the shared region: the device
/// only needs to call `notify()` (from IRQ or poll context), and the consumer
/// waits on it.  A consumer remembers the last sequence it observed so a
/// wakeup that races with the check is never lost.
pub struct QueueEvent {
    seq: AtomicU64,
    waiters: WaitQueue,
}

impl QueueEvent {
    pub const fn new() -> Self {
        Self {
            seq: AtomicU64::new(0),
            waiters: WaitQueue::new(),
        }
    }

    #[inline]
    pub fn notify(&self) {
        self.seq.fetch_add(1, Ordering::Release);
        self.waiters.wake_all();
    }

    #[inline]
    pub fn sequence(&self) -> u64 {
        self.seq.load(Ordering::Acquire)
    }

    /// Block until the sequence differs from `seen`, then update `seen`.
    #[inline]
    pub fn wait(&self, seen: &mut u64) {
        self.waiters.wait_until(|| {
            let current = self.seq.load(Ordering::Acquire);
            if current != *seen {
                *seen = current;
                Some(())
            } else {
                None
            }
        });
    }

    /// Non-blocking variant.
    #[inline]
    pub fn poll(&self, seen: &mut u64) -> bool {
        let current = self.seq.load(Ordering::Acquire);
        if current != *seen {
            *seen = current;
            true
        } else {
            false
        }
    }
}

impl Default for QueueEvent {
    fn default() -> Self {
        Self::new()
    }
}

/// One shared RX/TX queue pair for a network device.
pub struct NetQueue {
    pub qid: u16,
    pub dev_id: u64,
    pub ring_id: RingId,
    ring: Arc<SharedRing>,
    /// Kernel virtual address of each page, in mapping order.
    vas: Vec<u64>,
    /// Physical address of each page, in mapping order.
    phys: Vec<u64>,
    header: *mut NetQueueHeader,
    pub event: Arc<QueueEvent>,
    /// IRQ vector bound to this queue (0xFF = polling).
    pub irq: AtomicU8,
    /// IPC port bound to this queue (0 = none).
    pub port: AtomicU64,
    /// Feature mask negotiated with the device.
    pub features: AtomicU64,
    /// Serialises queue teardown against the IRQ handler.
    pub alive: AtomicU8,
    /// Descriptor popped by a consumer whose buffer was too small.  It must
    /// be returned before the next descriptor to preserve ordering.
    pending_rx: SpinLock<Option<NetFrameDesc>>,
}

// SAFETY: all shared accesses go through atomics in the header, or through
// the single-producer/single-consumer descriptor rings.  `vas`/`phys` are
// immutable after construction.  `header` points into a shared region whose
// lifetime is tied to `ring` (held by this struct).
unsafe impl Send for NetQueue {}
unsafe impl Sync for NetQueue {}

impl NetQueue {
    /// Allocate and initialise a queue region.
    pub fn new(dev_id: u64, qid: u16, feature_mask: u64, mtu: u32, epoch: u32) -> Result<Arc<Self>, &'static str> {
        let ring_id = shared_ring::create_ring(NET_QUEUE_SIZE)
            .map_err(|_| "failed to allocate network queue region")?;
        let ring = shared_ring::get_ring(ring_id).ok_or("network queue region disappeared")?;

        let phys = ring.frame_phys_addrs();
        if phys.is_empty() {
            let _ = shared_ring::destroy_ring(ring_id);
            return Err("empty network queue region");
        }
        let vas = phys
            .iter()
            .map(|pa| crate::memory::phys_to_virt(*pa) as u64)
            .collect::<Vec<_>>();

        let header = vas[0] as *mut NetQueueHeader;
        // SAFETY: `vas[0]` points to the first page of a region of
        // `NET_QUEUE_SIZE` bytes, which is at least `size_of::<NetQueueHeader>()`
        // and 8-byte aligned (page aligned).
        unsafe {
            NetQueueHeader::init(header, qid, feature_mask, mtu, epoch);
        }

        Ok(Arc::new(Self {
            qid,
            dev_id,
            ring_id,
            ring,
            vas,
            phys,
            header,
            event: Arc::new(QueueEvent::new()),
            irq: AtomicU8::new(0xFF),
            port: AtomicU64::new(0),
            features: AtomicU64::new(feature_mask),
            alive: AtomicU8::new(1),
            pending_rx: SpinLock::new(None),
        }))
    }

    #[inline]
    pub fn header(&self) -> &NetQueueHeader {
        // SAFETY: `header` is valid for the lifetime of `self` (backed by
        // `ring`, which is held by `self`).
        unsafe { &*self.header }
    }

    #[inline]
    pub fn header_mut_ptr(&self) -> *mut NetQueueHeader {
        self.header
    }

    #[inline]
    pub fn region(&self) -> &Arc<SharedRing> {
        &self.ring
    }

    #[inline]
    pub fn phys_pages(&self) -> &[u64] {
        &self.phys
    }

    #[inline]
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire) != 0
    }

    /// Mark the queue dead and wake any waiter.  The region is released when
    /// the last `Arc<NetQueue>` is dropped.
    pub fn shutdown(&self) {
        self.alive.store(0, Ordering::Release);
        self.event.notify();
    }

    /// Translate a byte offset in the region to its kernel VA.
    #[inline]
    fn ptr_at(&self, offset: usize) -> Option<*mut u8> {
        if offset >= NET_QUEUE_SIZE {
            return None;
        }
        let page = offset / 4096;
        let delta = offset % 4096;
        self.vas.get(page).map(|base| (*base as *mut u8).add(delta))
    }

    /// Physical address of a byte offset in the region.
    #[inline]
    pub fn phys_at(&self, offset: usize) -> Option<u64> {
        if offset >= NET_QUEUE_SIZE {
            return None;
        }
        let page = offset / 4096;
        let delta = offset % 4096;
        self.phys.get(page).map(|base| *base + delta as u64)
    }

    /// Physical address of an RX slot (for programming DMA).
    #[inline]
    pub fn rx_slot_phys(&self, slot: u32) -> Option<u64> {
        if slot as usize >= strat9_abi::net::NET_POOL_SLOTS {
            return None;
        }
        let off = strat9_abi::net::NET_RX_POOL_OFF + slot as usize * NET_FRAME_SIZE;
        self.phys_at(off)
    }

    /// Physical address of a TX slot.
    #[inline]
    pub fn tx_slot_phys(&self, slot: u32) -> Option<u64> {
        if slot as usize >= strat9_abi::net::NET_POOL_SLOTS {
            return None;
        }
        let off = strat9_abi::net::NET_TX_POOL_OFF + slot as usize * NET_FRAME_SIZE;
        self.phys_at(off)
    }

    /// Kernel VA of an RX slot.
    #[inline]
    pub fn rx_slot_ptr(&self, slot: u32) -> Option<*mut u8> {
        if slot as usize >= strat9_abi::net::NET_POOL_SLOTS {
            return None;
        }
        let off = strat9_abi::net::NET_RX_POOL_OFF + slot as usize * NET_FRAME_SIZE;
        self.ptr_at(off)
    }

    /// Kernel VA of a TX slot.
    #[inline]
    pub fn tx_slot_ptr(&self, slot: u32) -> Option<*mut u8> {
        if slot as usize >= strat9_abi::net::NET_POOL_SLOTS {
            return None;
        }
        let off = strat9_abi::net::NET_TX_POOL_OFF + slot as usize * NET_FRAME_SIZE;
        self.ptr_at(off)
    }

    /// Copy a frame into an RX slot and publish it.
    ///
    /// Called from the IRQ/poll path.  Returns `false` if the ring or the
    /// slot pool is full.
    pub fn push_rx(&self, frame: &[u8]) -> bool {
        if frame.len() > NET_FRAME_SIZE {
            self.header().rx_dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let Some(slot) = self.header().alloc_rx_slot() else {
            self.header().rx_dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        let Some(dst) = self.rx_slot_ptr(slot) else {
            self.header().free_rx_slot(slot);
            return false;
        };
        // SAFETY: `dst` points to a `NET_FRAME_SIZE` slot owned by us.
        unsafe {
            core::ptr::copy_nonoverlapping(frame.as_ptr(), dst, frame.len());
        }
        let desc = NetFrameDesc {
            slot,
            len: frame.len() as u16,
            flags: strat9_abi::net::fd_flags::SOP | strat9_abi::net::fd_flags::EOP,
            vlan: 0,
            rss: 0,
        };
        // SAFETY: single RX producer (IRQ/poll path serialised by the caller).
        if unsafe { self.header().rx_push(desc) } {
            true
        } else {
            self.header().free_rx_slot(slot);
            self.header().rx_dropped.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    /// Pop one RX descriptor (stack side).  A descriptor previously returned
    /// with `putback_rx` is served first to preserve ordering.
    pub fn pop_rx(&self) -> Option<NetFrameDesc> {
        if let Some(desc) = self.pending_rx.lock().take() {
            return Some(desc);
        }
        // SAFETY: single RX consumer.
        unsafe { self.header().rx_pop() }
    }

    /// Put back an RX descriptor whose consumer buffer was too small.
    pub fn putback_rx(&self, desc: NetFrameDesc) {
        *self.pending_rx.lock() = Some(desc);
    }

    /// Release an RX slot after the stack copied its payload.
    pub fn release_rx(&self, slot: u32) {
        self.header().free_rx_slot(slot);
    }

    /// Allocate a TX slot and return its kernel VA.
    pub fn alloc_tx(&self) -> Option<(u32, *mut u8)> {
        let slot = self.header().alloc_tx_slot()?;
        match self.tx_slot_ptr(slot) {
            Some(ptr) => Some((slot, ptr)),
            None => {
                self.header().free_tx_slot(slot);
                None
            }
        }
    }

    /// Publish a TX descriptor after the stack filled the slot.
    pub fn push_tx(&self, desc: NetFrameDesc) -> bool {
        if desc.slot as usize >= strat9_abi::net::NET_POOL_SLOTS {
            return false;
        }
        // SAFETY: single TX producer.
        if unsafe { self.header().tx_push(desc) } {
            true
        } else {
            self.header().free_tx_slot(desc.slot);
            self.header().tx_dropped.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    /// Pop one TX descriptor (kernel/device side).
    pub fn pop_tx(&self) -> Option<NetFrameDesc> {
        // SAFETY: single TX consumer.
        unsafe { self.header().tx_pop() }
    }

    /// Release a transmitted TX slot.
    pub fn release_tx(&self, slot: u32) {
        self.header().free_tx_slot(slot);
    }

    /// Update the shared link state.
    pub fn set_link(&self, up: bool, speed_mbps: u32) {
        let mut flags = 0;
        if up {
            flags |= link_flags::UP | link_flags::CARRIER | link_flags::FULL_DUPLEX;
        }
        self.header().link.store(flags, Ordering::Release);
        self.header().speed_mbps.store(speed_mbps, Ordering::Relaxed);
    }

    /// Current feature mask.
    #[inline]
    pub fn feature_mask(&self) -> u64 {
        self.features.load(Ordering::Acquire)
    }

    /// Enable features after negotiation.
    #[inline]
    pub fn set_features(&self, mask: u64) {
        self.features.store(mask & features::ALL, Ordering::Release);
        self.header()
            .features
            .store(mask & features::ALL, Ordering::Release);
    }
}

impl Drop for NetQueue {
    fn drop(&mut self) {
        self.alive.store(0, Ordering::Release);
        // Wake waiters before revoking mappings, then release the pages.
        self.event.notify();
        let _ = shared_ring::destroy_ring(self.ring_id);
    }
}

/// A set of queues for one device.
pub struct NetQueues {
    pub queues: Vec<Arc<NetQueue>>,
}

impl NetQueues {
    pub fn new() -> Self {
        Self { queues: Vec::new() }
    }

    pub fn push(&mut self, queue: Arc<NetQueue>) {
        self.queues.push(queue);
    }

    pub fn get(&self, qid: u16) -> Option<&Arc<NetQueue>> {
        self.queues.iter().find(|q| q.qid == qid)
    }

    pub fn len(&self) -> usize {
        self.queues.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queues.is_empty()
    }
}

impl Default for NetQueues {
    fn default() -> Self {
        Self::new()
    }
}

/// Global serialisation for queue creation/teardown.
pub static QUEUE_LOCK: SpinLock<()> = SpinLock::new(());
