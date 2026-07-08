//! NIC data-plane using lock-free SPSC rings (N2).
//!
//! Each RSS queue gets a dedicated RX/TX `LockFreeRing` pair.  The NIC
//! driver writes received packets into the RX ring during interrupt
//! handling; the networking silo (strate-net) reads from the RX ring and
//! writes to the TX ring without kernel syscalls.
//!
//! # Usage
//!
//! ```ignore
//! let dp = NicDataPlane::new(queue_count, slot_size)?;
//! // In IRQ handler:
//! while let Some(pkt) = read_packet_from_hw() {
//!     dp.push_rx(queue_id, &pkt);
//! }
//! dp.notify_consumer(queue_id);
//!
//! // In strate-net:
//! let pkt = dp.pop_rx(0, &mut buf)?;
//! dp.push_tx(0, &response)?;
//! ```

use alloc::{sync::Arc, vec::Vec};

use crate::ipc::lockfree_ring::{LockFreeRing, RingError};

/// A pair of RX/TX rings for one RSS queue.
pub struct RingPair {
    /// Inbound packets (NIC → strate-net).
    pub rx: Arc<LockFreeRing>,
    /// Outbound packets (strate-net → NIC).
    pub tx: Arc<LockFreeRing>,
}

/// Multi-queue NIC data plane.
///
/// Initialised during NIC driver setup.  Each hardware queue gets one
/// `RingPair`; the consumer (strate-net) polls all RX rings in round-robin.
pub struct NicDataPlane {
    /// One ring pair per RSS queue.
    pub queues: Vec<RingPair>,
}

impl NicDataPlane {
    /// Create a new data plane with `queue_count` ring pairs.
    ///
    /// Each ring has `slot_count` slots of `slot_size` bytes.
    /// Returns an error if ring allocation fails.
    pub fn new(
        queue_count: usize,
        slot_count: u32,
        slot_size: usize,
    ) -> Result<Self, &'static str> {
        let mut queues = Vec::with_capacity(queue_count);
        for _ in 0..queue_count {
            let rx = LockFreeRing::new(slot_count, slot_size)
                .map_err(|_| "failed to allocate RX ring")?;
            let tx = LockFreeRing::new(slot_count, slot_size)
                .map_err(|_| "failed to allocate TX ring")?;
            queues.push(RingPair { rx, tx });
        }
        Ok(NicDataPlane { queues })
    }

    /// Push a received packet into the RX ring for `queue_index`.
    ///
    /// Called from the NIC IRQ handler.  Returns `Err(RingError::Full)` if
    /// the ring is full (backpressure : drop the packet), or
    /// `Err(RingError::InvalidParameters)` if the queue index is out of range.
    pub fn push_rx(&self, queue_index: usize, data: &[u8]) -> Result<(), RingError> {
        let pair = self.queues.get(queue_index).ok_or(RingError::InvalidParameters)?;
        pair.rx.write(data)
    }

    /// Pop a received packet from the RX ring for `queue_index`.
    ///
    /// Called by strate-net.  Returns `Ok(None)` if the ring is empty.
    pub fn pop_rx(&self, queue_index: usize, buf: &mut [u8]) -> Result<Option<usize>, RingError> {
        let pair = self.queues.get(queue_index).ok_or(RingError::InvalidParameters)?;
        pair.rx.try_read(buf)
    }

    /// Push an outbound packet into the TX ring for `queue_index`.
    ///
    /// Called by strate-net.  The NIC driver will read from the TX ring
    /// and transmit onto the wire.
    pub fn push_tx(&self, queue_index: usize, data: &[u8]) -> Result<(), RingError> {
        let pair = self.queues.get(queue_index).ok_or(RingError::InvalidParameters)?;
        pair.tx.write(data)
    }

    /// Pop an outbound packet from the TX ring for `queue_index`.
    ///
    /// Called by the NIC driver.  Returns `Ok(None)` if the ring is empty.
    pub fn pop_tx(&self, queue_index: usize, buf: &mut [u8]) -> Result<Option<usize>, RingError> {
        let pair = self.queues.get(queue_index).ok_or(RingError::InvalidParameters)?;
        pair.tx.try_read(buf)
    }

    /// Notify the consumer (strate-net) that new RX data is available.
    pub fn notify_rx_consumer(&self, queue_index: usize) {
        if let Some(pair) = self.queues.get(queue_index) {
            pair.rx.notify_consumer_raw();
        }
    }

    /// Notify the NIC driver that new TX data is available.
    pub fn notify_tx_producer(&self, queue_index: usize) {
        if let Some(pair) = self.queues.get(queue_index) {
            pair.tx.notify_producer_raw();
        }
    }

    /// Number of queues (ring pairs).
    pub fn queue_count(&self) -> usize {
        self.queues.len()
    }
}
