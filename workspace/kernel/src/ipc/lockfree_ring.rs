//! Lock-free bounded message queue backed by [`crossbeam_queue::ArrayQueue`].
//!
//! Replaces the previous manual atomic-ring implementation with a safe,
//! well-tested SPSC/MPSC queue.  Keeps the same external API
//! (`write`/`read`/`try_write`/`try_read`/`has_data`/`has_space`) for
//! backward compatibility.
//!
//! Physical frames are still allocated for `frame_phys_addrs()` (IPC ring
//! syscall compat).  DMA is not supported : the NIC data plane uses
//! dedicated hardware ring buffers.

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use crossbeam_queue::ArrayQueue;

use crate::{
    memory::{allocate_frame, free_frame, PhysFrame},
    sync::with_irqs_disabled,
};

// ---------------------------------------------------------------------------
// RingError
// ---------------------------------------------------------------------------

/// Errors returned by ring operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingError {
    /// Ring has no free slots.
    Full,
    /// Ring contains no messages.
    Empty,
    /// Message exceeds slot capacity.
    MessageTooLarge,
    /// Provided buffer is too small for the pending message.
    BufferTooSmall,
    /// Memory allocation failed during ring creation.
    AllocFailed,
    /// Invalid ring parameters (size, capacity, etc.).
    InvalidParameters,
}

// ---------------------------------------------------------------------------
// LockFreeRing
// ---------------------------------------------------------------------------

/// A bounded lock-free message queue.
///
/// Internally uses [`crossbeam_queue::ArrayQueue<Box<[u8]>>`] for safe,
/// tested message passing.  Also allocates minimal physical frames for
/// `frame_phys_addrs()` used by the shared-ring IPC syscall.
#[derive(Debug)]
pub struct LockFreeRing {
    queue: ArrayQueue<Box<[u8]>>,
    slot_limit: usize,
    frames: Vec<PhysFrame>,
}

unsafe impl Send for LockFreeRing {}
unsafe impl Sync for LockFreeRing {}

impl LockFreeRing {
    /// Default slot count.
    const DEFAULT_CAPACITY: u32 = 256;

    /// Create a new ring with `slot_count` slots for messages up to
    /// `slot_size` bytes.
    pub fn new(slot_count: u32, slot_size: usize) -> Result<Arc<Self>, RingError> {
        if slot_count == 0 || slot_size == 0 {
            return Err(RingError::InvalidParameters);
        }
        let cap = slot_count.next_power_of_two() as usize;
        let queue = ArrayQueue::new(cap);

        // Allocate a minimal set of physical frames for IPC ring compat.
        let mut frames = Vec::new();
        if let Ok(frame) = with_irqs_disabled(|token| allocate_frame(token)) {
            frames.push(frame);
        }

        Ok(Arc::new(LockFreeRing {
            queue,
            slot_limit: slot_size,
            frames,
        }))
    }

    /// The number of slots in this ring.
    #[inline]
    pub fn capacity(&self) -> u32 {
        self.queue.capacity() as u32
    }

    /// The maximum message size in bytes.
    #[inline]
    pub fn slot_size(&self) -> u32 {
        self.slot_limit as u32
    }

    /// Physical addresses of the backing frames (for IPC ring compat).
    pub fn frame_phys_addrs(&self) -> Vec<u64> {
        self.frames
            .iter()
            .map(|f| f.start_address.as_u64())
            .collect()
    }

    /// Write `data` into the ring.  Returns `Full` if no slot is available,
    /// or `MessageTooLarge` if the data exceeds the slot capacity.
    #[inline]
    pub fn write(&self, data: &[u8]) -> Result<(), RingError> {
        if data.len() > self.slot_limit {
            return Err(RingError::MessageTooLarge);
        }
        let buf: Box<[u8]> = data.into();
        self.queue.push(buf).map_err(|_| RingError::Full)
    }

    /// Read one message from the ring into `buf`.
    #[inline]
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, RingError> {
        let msg = self.queue.pop().ok_or(RingError::Empty)?;
        if msg.len() > buf.len() {
            return Err(RingError::BufferTooSmall);
        }
        buf[..msg.len()].copy_from_slice(&msg);
        Ok(msg.len())
    }

    /// Non-blocking write.
    #[inline]
    pub fn try_write(&self, data: &[u8]) -> Result<(), RingError> {
        self.write(data)
    }

    /// Write multiple buffers in a single slot (scatter-gather).
    pub fn write_vectored(&self, bufs: &[&[u8]]) -> Result<(), RingError> {
        let total: usize = bufs.iter().map(|b| b.len()).sum();
        if total > self.slot_limit {
            return Err(RingError::MessageTooLarge);
        }
        let mut buf = alloc::vec![0u8; total];
        let mut offset = 0;
        for b in bufs {
            buf[offset..offset + b.len()].copy_from_slice(b);
            offset += b.len();
        }
        let boxed: Box<[u8]> = buf.into_boxed_slice();
        self.queue.push(boxed).map_err(|_| RingError::Full)
    }

    /// Non-blocking read.  Returns `Ok(None)` when the ring is empty.
    #[inline]
    pub fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, RingError> {
        match self.queue.pop() {
            Some(msg) => {
                if msg.len() > buf.len() {
                    return Err(RingError::BufferTooSmall);
                }
                buf[..msg.len()].copy_from_slice(&msg);
                Ok(Some(msg.len()))
            }
            None => Ok(None),
        }
    }

    /// Notify the consumer that new data is available.
    /// No-op under ArrayQueue (notification is handled by the caller).
    pub fn notify_consumer_raw(&self) {}

    /// Notify the producer that space has been freed.
    /// No-op under ArrayQueue.
    pub fn notify_producer_raw(&self) {}

    /// Returns true if the ring contains at least one message.
    pub fn has_data(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Returns true if at least one slot is free.
    pub fn has_space(&self) -> bool {
        self.queue.len() < self.queue.capacity()
    }

    /// DMA buffer descriptor.
    ///
    /// ArrayQueue does not expose physical addresses; this method returns
    /// `None`.  The NIC data plane uses dedicated hardware ring buffers.
    pub fn dma_buffer(&self, _slot_index: u32) -> Option<DmaBuffer> {
        None
    }
}

impl Drop for LockFreeRing {
    fn drop(&mut self) {
        for frame in self.frames.drain(..) {
            with_irqs_disabled(|token| free_frame(token, frame));
        }
    }
}

// ---------------------------------------------------------------------------
// DmaBuffer
// ---------------------------------------------------------------------------

/// Descriptor for a DMA-accessible buffer region.
///
/// Note: the ArrayQueue-backed ring does not support DMA; this type is
/// kept for backward compatibility only.
#[derive(Debug, Clone, Copy)]
pub struct DmaBuffer {
    pub phys_addr: u64,
    pub virt_addr: *const u8,
}

unsafe impl Send for DmaBuffer {}
unsafe impl Sync for DmaBuffer {}

// ---------------------------------------------------------------------------
// IpcNotification impl
// ---------------------------------------------------------------------------

use super::transport::{IpcError, IpcNotification};

impl IpcNotification for LockFreeRing {
    fn notify_consumer(&self) {
        self.notify_consumer_raw();
    }

    fn notify_producer(&self) {
        self.notify_producer_raw();
    }

    fn wait_notification(&self) -> Result<(), IpcError> {
        for _ in 0..64 {
            if self.has_data() {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        loop {
            if self.has_data() {
                return Ok(());
            }
            crate::process::block_current_task();
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
    fn ping_pong_64b() {
        let ring = LockFreeRing::new(64, 256).unwrap();
        let msg = [0xABu8; 64];
        ring.write(&msg).unwrap();
        let mut buf = [0u8; 64];
        let n = ring.read(&mut buf).unwrap();
        assert_eq!(n, 64);
        assert_eq!(buf, [0xAB; 64]);
    }

    #[test]
    fn full_ring() {
        let ring = LockFreeRing::new(4, 64).unwrap();
        for _ in 0..3 {
            ring.write(b"hello").unwrap();
        }
        assert_eq!(ring.write(b"world"), Err(RingError::Full));
        let mut buf = [0u8; 64];
        ring.read(&mut buf).unwrap();
        ring.write(b"world").unwrap();
    }

    #[test]
    fn message_too_large() {
        let ring = LockFreeRing::new(8, 64).unwrap();
        let oversized = [0u8; 128];
        assert_eq!(ring.write(&oversized), Err(RingError::MessageTooLarge));
    }

    #[test]
    fn buffer_too_small() {
        let ring = LockFreeRing::new(8, 256).unwrap();
        ring.write(b"hello world").unwrap();
        let mut tiny = [0u8; 4];
        assert_eq!(ring.read(&mut tiny), Err(RingError::BufferTooSmall));
    }

    #[test]
    fn empty_ring() {
        let ring = LockFreeRing::new(8, 64).unwrap();
        let mut buf = [0u8; 64];
        assert_eq!(ring.read(&mut buf), Err(RingError::Empty));
    }

    #[test]
    fn try_read_empty() {
        let ring = LockFreeRing::new(8, 64).unwrap();
        let mut buf = [0u8; 64];
        assert_eq!(ring.try_read(&mut buf), Ok(None));
    }

    #[test]
    fn write_vectored() {
        let ring = LockFreeRing::new(8, 256).unwrap();
        ring.write_vectored(&[b"hello", b" ", b"world"]).unwrap();
        let mut buf = [0u8; 256];
        let n = ring.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello world");
    }
}
