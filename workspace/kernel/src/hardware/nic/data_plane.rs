//! Network data plane built on shared-memory `NetQueue` regions.
//!
//! Each queue owns a `NET_QUEUE_SIZE` region (descriptor rings + frame
//! pools).  The region can be mapped into the networking strate with
//! `SYS_NET_QUEUE_MAP`, at which point RX/TX become syscall-free.  The legacy
//! `SYS_NET_RECV` / `SYS_NET_SEND` paths are kept as compatibility wrappers:
//! they operate on the same queues and therefore share the same buffers.
//!
//! There is no allocation on the packet path: slots are preallocated in the
//! region and recycled through the header bitmaps.

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::Ordering;

use strat9_abi::net::{NetFrameDesc, NET_FRAME_SIZE};

use super::net_queue::NetQueue;

/// One device's queue range in the flat `queues` vector.
#[derive(Debug, Clone, Copy)]
pub struct DeviceQueues {
    pub resource: u64,
    pub first: usize,
    pub count: usize,
}

/// A set of queues for the registered NICs.
///
/// Each device owns `queue_count` queues (software RSS queues today, hardware
/// queues when the driver exposes them).  `queues` stays a flat vector so the
/// legacy syscalls can keep using a small integer index, while `devices` maps
/// a `Nic` capability resource to its queue range.
pub struct NicDataPlane {
    pub queues: Vec<Arc<NetQueue>>,
    pub devices: Vec<DeviceQueues>,
}

impl NicDataPlane {
    /// Create `count` queues for each `(device_resource, count)` entry.
    pub fn new(devices: &[(u64, u16)]) -> Result<Self, &'static str> {
        if devices.is_empty() {
            return Err("no network queue requested");
        }
        let mut queues = Vec::new();
        let mut ranges = Vec::with_capacity(devices.len());
        for (resource, count) in devices {
            let first = queues.len();
            let count = (*count).max(1);
            for qid in 0..count {
                queues.push(NetQueue::new(*resource, qid, 0, 1500, 1)?);
            }
            ranges.push(DeviceQueues {
                resource: *resource,
                first,
                count: count as usize,
            });
        }
        Ok(Self {
            queues,
            devices: ranges,
        })
    }

    #[inline]
    pub fn queue(&self, index: usize) -> Option<&Arc<NetQueue>> {
        self.queues.get(index)
    }

    #[inline]
    pub fn clone_queue(&self, index: usize) -> Option<Arc<NetQueue>> {
        self.queues.get(index).cloned()
    }

    /// Resolve `(device resource, queue id)` to a queue.
    pub fn queue_for(&self, resource: u64, qid: u16) -> Option<Arc<NetQueue>> {
        let range = self.devices.iter().find(|d| d.resource == resource)?;
        if (qid as usize) >= range.count {
            return None;
        }
        self.queues.get(range.first + qid as usize).cloned()
    }

    /// Number of queues exposed by a device.
    pub fn queue_count_for(&self, resource: u64) -> u16 {
        self.devices
            .iter()
            .find(|d| d.resource == resource)
            .map(|d| d.count as u16)
            .unwrap_or(0)
    }

    #[inline]
    pub fn queue_count(&self) -> usize {
        self.queues.len()
    }

    /// Apply a driver's negotiated features and MTU to one queue.
    pub fn configure(&self, index: usize, feature_mask: u64, mtu: u32) {
        if let Some(queue) = self.queue(index) {
            queue.configure(feature_mask, mtu);
        }
    }

    /// Apply features/MTU to every queue of a device.
    pub fn configure_device(&self, resource: u64, feature_mask: u64, mtu: u32) {
        if let Some(range) = self.devices.iter().find(|d| d.resource == resource) {
            for index in range.first..range.first + range.count {
                if let Some(queue) = self.queue(index) {
                    queue.configure(feature_mask, mtu);
                }
            }
        }
    }

    pub fn push_rx_for(&self, resource: u64, qid: u16, data: &[u8]) -> bool {
        self.queue_for(resource, qid)
            .map(|queue| queue.push_rx(data))
            .unwrap_or(false)
    }

    pub fn pop_rx_for(
        &self,
        resource: u64,
        qid: u16,
        buf: &mut [u8],
    ) -> Result<Option<usize>, RxError> {
        let queue = self.queue_for(resource, qid).ok_or(RxError::InvalidQueue)?;
        self.pop_rx_queue(&queue, buf)
    }

    pub fn push_tx_for(&self, resource: u64, qid: u16, data: &[u8]) -> Result<(), TxError> {
        let queue = self.queue_for(resource, qid).ok_or(TxError::InvalidQueue)?;
        self.push_tx_queue(&queue, data)
    }

    pub fn pop_tx_for(
        &self,
        resource: u64,
        qid: u16,
        buf: &mut [u8],
    ) -> Result<Option<usize>, TxError> {
        let queue = self.queue_for(resource, qid).ok_or(TxError::InvalidQueue)?;
        self.pop_tx_queue(&queue, buf)
    }

    pub fn set_link_for(&self, resource: u64, qid: u16, up: bool, speed_mbps: u32) {
        if let Some(queue) = self.queue_for(resource, qid) {
            queue.set_link(up, speed_mbps);
        }
    }

    /// Push a received frame into the queue's RX ring.
    ///
    /// Called from the NIC IRQ/poll path.  No allocation, no lock.
    pub fn push_rx(&self, index: usize, data: &[u8]) -> bool {
        match self.queue(index) {
            Some(queue) => queue.push_rx(data),
            None => false,
        }
    }

    /// Copy one RX frame into `buf` and release its slot.
    ///
    /// Returns `Ok(None)` when the ring is empty.  If `buf` is smaller than
    /// the frame, the slot is **not** consumed and `BufferTooSmall` is
    /// returned; this is the non-destructive read contract.
    pub fn pop_rx(&self, index: usize, buf: &mut [u8]) -> Result<Option<usize>, RxError> {
        let queue = self.queue(index).ok_or(RxError::InvalidQueue)?;
        self.pop_rx_queue(&queue, buf)
    }

    fn pop_rx_queue(&self, queue: &Arc<NetQueue>, buf: &mut [u8]) -> Result<Option<usize>, RxError> {
        let Some(desc) = queue.pop_rx() else {
            return Ok(None);
        };
        let len = desc.len as usize;
        if len > buf.len() {
            // Preserve the descriptor for the next read instead of consuming
            // it: the RX ring is SPSC, so pushing it back would violate the
            // producer contract.
            queue.putback_rx(desc);
            return Err(RxError::BufferTooSmall);
        }
        let Some(src) = queue.rx_slot_ptr(desc.slot) else {
            queue.release_rx(desc.slot);
            return Err(RxError::InvalidSlot);
        };
        // SAFETY: the slot is owned by the consumer until `release_rx`, and
        // `src` points to `NET_FRAME_SIZE` bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), len);
        }
        queue.release_rx(desc.slot);
        Ok(Some(len))
    }

    /// Queue one TX frame.  Copies into a slot; `kick()` must be called to
    /// notify the device (the legacy syscall does it inline).
    pub fn push_tx(&self, index: usize, data: &[u8]) -> Result<(), TxError> {
        let queue = self.queue(index).ok_or(TxError::InvalidQueue)?;
        self.push_tx_queue(&queue, data)
    }

    fn push_tx_queue(&self, queue: &Arc<NetQueue>, data: &[u8]) -> Result<(), TxError> {
        if data.len() > NET_FRAME_SIZE {
            return Err(TxError::TooLarge);
        }
        let (slot, dst) = queue.alloc_tx().ok_or(TxError::QueueFull)?;
        // SAFETY: the slot is owned by us until published.
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
        }
        let desc = NetFrameDesc {
            slot,
            len: data.len() as u16,
            flags: strat9_abi::net::fd_flags::SOP
                | strat9_abi::net::fd_flags::EOP
                | strat9_abi::net::fd_flags::NEED_COMP,
            vlan: 0,
            rss: 0,
            reserved: 0,
        };
        if !queue.push_tx(desc) {
            return Err(TxError::QueueFull);
        }
        Ok(())
    }

    /// Pop one TX frame into `buf` for transmission.  The slot is released
    /// immediately: the current drivers copy into their DMA ring, so the slot
    /// can be reused as soon as the copy completes.
    pub fn pop_tx(&self, index: usize, buf: &mut [u8]) -> Result<Option<usize>, TxError> {
        let queue = self.queue(index).ok_or(TxError::InvalidQueue)?;
        self.pop_tx_queue(&queue, buf)
    }

    fn pop_tx_queue(&self, queue: &Arc<NetQueue>, buf: &mut [u8]) -> Result<Option<usize>, TxError> {
        let Some(desc) = queue.pop_tx() else {
            return Ok(None);
        };
        let len = desc.len as usize;
        if len > buf.len() {
            queue.release_tx(desc.slot);
            return Err(TxError::BufferTooSmall);
        }
        let Some(src) = queue.tx_slot_ptr(desc.slot) else {
            queue.release_tx(desc.slot);
            return Err(TxError::InvalidSlot);
        };
        // SAFETY: the slot is owned by the consumer until `release_tx`.
        unsafe {
            core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), len);
        }
        queue.release_tx(desc.slot);
        Ok(Some(len))
    }

    /// Notify the consumer that RX data is available.
    pub fn notify_rx_consumer(&self, index: usize) {
        if let Some(queue) = self.queue(index) {
            queue.event.notify();
        }
    }

    /// Notify the device that TX descriptors are pending.
    pub fn notify_tx_producer(&self, index: usize) {
        if let Some(queue) = self.queue(index) {
            queue.event.notify();
        }
    }

    /// Count RX packets without consuming them.
    pub fn rx_pending(&self, index: usize) -> u32 {
        self.queue(index)
            .map(|q| q.header().rx.len())
            .unwrap_or(0)
    }

    /// Count TX packets without consuming them.
    pub fn tx_pending(&self, index: usize) -> u32 {
        self.queue(index)
            .map(|q| q.header().tx.len())
            .unwrap_or(0)
    }

    /// Update the link state exported in every queue header.
    pub fn set_link(&self, index: usize, up: bool, speed_mbps: u32) {
        if let Some(queue) = self.queue(index) {
            queue.set_link(up, speed_mbps);
        }
    }
}

/// Errors from the compatibility RX path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxError {
    InvalidQueue,
    InvalidSlot,
    BufferTooSmall,
}

/// Errors from the compatibility TX path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxError {
    InvalidQueue,
    InvalidSlot,
    BufferTooSmall,
    QueueFull,
    TooLarge,
}

impl From<RxError> for crate::syscall::error::SyscallError {
    fn from(error: RxError) -> Self {
        use crate::syscall::error::SyscallError;
        match error {
            RxError::InvalidQueue => SyscallError::BadHandle,
            RxError::InvalidSlot => SyscallError::IoError,
            RxError::BufferTooSmall => SyscallError::MessageSize,
        }
    }
}

impl From<TxError> for crate::syscall::error::SyscallError {
    fn from(error: TxError) -> Self {
        use crate::syscall::error::SyscallError;
        match error {
            TxError::InvalidQueue => SyscallError::BadHandle,
            TxError::InvalidSlot => SyscallError::IoError,
            TxError::BufferTooSmall => SyscallError::MessageSize,
            TxError::QueueFull => SyscallError::Again,
            TxError::TooLarge => SyscallError::MessageSize,
        }
    }
}

/// Keep the descriptor flags import used (documentation / future batching).
const _: u16 = strat9_abi::net::fd_flags::NEED_COMP;

/// Link flag helper kept for symmetry with the ABI.
#[inline]
pub fn link_is_up(queue: &NetQueue) -> bool {
    queue.header().link.load(Ordering::Acquire) & strat9_abi::net::link_flags::UP != 0
}
