//! Shared-memory network queue ABI.
//!
//! This module is the single source of truth for the layout that the kernel
//! and a userspace networking strate share.  It is deliberately independent
//! of the device model: any NIC (e1000, virtio-net, vmxnet3, …) can expose a
//! `NetQueueHeader` region and let the stack drive its rings directly.
//!
//! Design rules:
//! - one producer and one consumer per direction (RX and TX);
//! - free-running `head`/`tail` counters, power-of-two ring size;
//! - frame slots live in a pool inside the same mapped region;
//! - slot ownership is tracked by a bitmap, not by a free list, so the
//!   consumer can release a slot without another ring;
//! - no allocation, no lock, no syscall once the region is mapped.
//!
//! Layout (all offsets stable, region is page-aligned):
//!
//! ```text
//! 0x0000  NetQueueHeader
//! 0x0100  RX descriptors  (NET_RING_SLOTS × 16 bytes)
//! 0x1100  TX descriptors  (NET_RING_SLOTS × 16 bytes)
//! 0x2100  statistics / reserved
//! 0x3000  RX frame pool   (NET_POOL_SLOTS × 2048 bytes)
//! 0x83000 TX frame pool   (NET_POOL_SLOTS × 2048 bytes)
//! 0x103000 end
//! ```

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// `"STNQ"` little-endian.
pub const NET_QUEUE_MAGIC: u32 = 0x514E_5453;
/// Current ABI revision.
pub const NET_QUEUE_ABI: u16 = 1;

/// A frame slot is a fixed 2 KiB cell (enough for a 1514-byte frame plus
/// headroom and a future 1500-byte jumbo-lite path).
pub const NET_FRAME_SIZE: usize = 2048;
/// Number of descriptors in each direction (must be a power of two).
pub const NET_RING_SLOTS: usize = 256;
/// Number of frame slots in each pool (must be a multiple of 64).
pub const NET_POOL_SLOTS: usize = 256;

pub const NET_QUEUE_HDR_SIZE: usize = 0x100;
pub const NET_RX_DESC_OFF: usize = 0x100;
pub const NET_TX_DESC_OFF: usize = 0x1100;
pub const NET_STATS_OFF: usize = 0x2100;
pub const NET_RX_POOL_OFF: usize = 0x3000;
pub const NET_TX_POOL_OFF: usize = NET_RX_POOL_OFF + NET_POOL_SLOTS * NET_FRAME_SIZE;
pub const NET_QUEUE_SIZE: usize = NET_TX_POOL_OFF + NET_POOL_SLOTS * NET_FRAME_SIZE;

const _: () = assert!(NET_RING_SLOTS.is_power_of_two());
const _: () = assert!(NET_POOL_SLOTS % 64 == 0);
const _: () = assert!(NET_QUEUE_SIZE % 4096 == 0);
const _: () = assert!(NET_QUEUE_SIZE / 4096 == 0x103);

/// Frame descriptor flags.
pub mod fd_flags {
    /// Last descriptor of a packet.
    pub const EOP: u16 = 1 << 0;
    /// First descriptor of a packet.
    pub const SOP: u16 = 1 << 1;
    /// Device computed a valid L4 checksum.
    pub const CSUM_OK: u16 = 1 << 2;
    /// Request a completion for this packet.
    pub const NEED_COMP: u16 = 1 << 3;
    /// VLAN tag present in `vlan`.
    pub const VLAN: u16 = 1 << 4;
    /// Frame was truncated by the device.
    pub const TRUNCATED: u16 = 1 << 5;
}

/// Negotiated device features.  Kept as plain `u64` bits so the ABI does not
/// depend on `bitflags`.
pub mod features {
    pub const CSUM_TX: u64 = 1 << 0;
    pub const CSUM_RX: u64 = 1 << 1;
    pub const TSO_TX: u64 = 1 << 2;
    pub const LRO_RX: u64 = 1 << 3;
    pub const VLAN_TX: u64 = 1 << 4;
    pub const VLAN_RX: u64 = 1 << 5;
    pub const RSS: u64 = 1 << 6;
    pub const DATA_RING: u64 = 1 << 7;
    pub const ZC_TX: u64 = 1 << 8;
    pub const ZC_RX: u64 = 1 << 9;
    pub const MULTI_QUEUE: u64 = 1 << 10;
    pub const POLLING: u64 = 1 << 11;

    pub const ALL: u64 = CSUM_TX
        | CSUM_RX
        | TSO_TX
        | LRO_RX
        | VLAN_TX
        | VLAN_RX
        | RSS
        | DATA_RING
        | ZC_TX
        | ZC_RX
        | MULTI_QUEUE
        | POLLING;
}

/// Link flags returned by `SYS_NET_LINK`.
pub mod link_flags {
    pub const UP: u32 = 1 << 0;
    pub const FULL_DUPLEX: u32 = 1 << 1;
    pub const CARRIER: u32 = 1 << 2;
}

/// Event kinds delivered to a bound IPC port.
pub mod event {
    pub const RX_READY: u32 = 1;
    pub const TX_DONE: u32 = 2;
    pub const LINK_UP: u32 = 3;
    pub const LINK_DOWN: u32 = 4;
    pub const QUEUE_ERROR: u32 = 5;
    pub const RESET: u32 = 6;
    pub const DEVICE_ADD: u32 = 7;
    pub const DEVICE_REMOVE: u32 = 8;
    pub const QUIESCE: u32 = 9;
    pub const RESUME: u32 = 10;
}

/// One frame descriptor, 16 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetFrameDesc {
    /// Index in the RX or TX pool.
    pub slot: u32,
    /// Payload length in bytes.
    pub len: u16,
    /// `fd_flags`.
    pub flags: u16,
    /// VLAN tag when `fd_flags::VLAN` is set, zero otherwise.
    pub vlan: u16,
    /// Reserved for RSS/queue steering.
    pub rss: u16,
    /// Reserved, must be zero.
    pub reserved: u32,
}

const _: () = assert!(core::mem::size_of::<NetFrameDesc>() == 16);

/// A single-producer / single-consumer descriptor ring.
///
/// `head` is the consumer index, `tail` the producer index.  Both are
/// free-running; the array index is `counter & (size - 1)`.  The size must be
/// a power of two.
#[repr(C)]
pub struct NetRing {
    pub head: AtomicU32,
    pub tail: AtomicU32,
    pub size: u32,
    pub flags: u32,
}

impl NetRing {
    pub const fn new(size: u32) -> Self {
        Self {
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            size,
            flags: 0,
        }
    }

    #[inline]
    pub fn len(&self) -> u32 {
        self.tail
            .load(Ordering::Acquire)
            .wrapping_sub(self.head.load(Ordering::Acquire))
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Publish one descriptor.  Single producer only.
    ///
    /// # Safety
    /// `descs` must point to `self.size` valid `NetFrameDesc` entries.
    #[inline]
    pub unsafe fn push(&self, descs: *mut NetFrameDesc, desc: NetFrameDesc) -> bool {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        if tail.wrapping_sub(head) >= self.size {
            return false;
        }
        let mask = (self.size - 1) as usize;
        core::ptr::write(descs.add((tail as usize) & mask), desc);
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        true
    }

    /// Consume one descriptor.  Single consumer only.
    ///
    /// # Safety
    /// `descs` must point to `self.size` valid `NetFrameDesc` entries.
    #[inline]
    pub unsafe fn pop(&self, descs: *const NetFrameDesc) -> Option<NetFrameDesc> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let mask = (self.size - 1) as usize;
        let desc = core::ptr::read(descs.add((head as usize) & mask));
        self.head.store(head.wrapping_add(1), Ordering::Release);
        Some(desc)
    }
}

const _: () = assert!(core::mem::size_of::<NetRing>() == 16);

/// Header of a shared network queue.
///
/// The structure is placed at offset 0 of the mapped region.  It contains
/// only atomics and plain integers so it has the same layout in kernel and
/// userspace.
#[repr(C)]
pub struct NetQueueHeader {
    pub magic: u32,
    pub abi: u16,
    pub flags: u16,
    pub qid: u16,
    pub frame_size: u16,
    pub slots: u16,
    pub reserved0: u16,
    /// Negotiated `features::*` bits.
    pub features: AtomicU64,
    pub rx: NetRing,
    pub tx: NetRing,
    /// Slot allocation bitmaps (bit set = slot owned).
    pub rx_bitmap: [AtomicU64; 4],
    pub tx_bitmap: [AtomicU64; 4],
    pub rx_dropped: AtomicU64,
    pub tx_dropped: AtomicU64,
    pub irq_count: AtomicU64,
    pub poll_count: AtomicU64,
    /// Device generation; bumped on hotplug/reset.
    pub epoch: AtomicU32,
    /// `link_flags::*`.
    pub link: AtomicU32,
    /// Last observed link speed in Mbps (0 = unknown).
    pub speed_mbps: AtomicU32,
    /// Maximum transmission unit (IP payload).
    pub mtu: AtomicU32,
    pub reserved: [u8; 64],
}

const _: () = assert!(core::mem::size_of::<NetQueueHeader>() <= NET_QUEUE_HDR_SIZE);

impl NetQueueHeader {
    /// Initialise a raw header in place.
    ///
    /// # Safety
    /// `ptr` must point to at least `NET_QUEUE_SIZE` writable bytes aligned
    /// to 8 bytes.
    pub unsafe fn init(ptr: *mut Self, qid: u16, features: u64, mtu: u32, epoch: u32) {
        core::ptr::write(
            ptr,
            Self {
                magic: NET_QUEUE_MAGIC,
                abi: NET_QUEUE_ABI,
                flags: 0,
                qid,
                frame_size: NET_FRAME_SIZE as u16,
                slots: NET_RING_SLOTS as u16,
                reserved0: 0,
                features: AtomicU64::new(features),
                rx: NetRing::new(NET_RING_SLOTS as u32),
                tx: NetRing::new(NET_RING_SLOTS as u32),
                rx_bitmap: [
                    AtomicU64::new(0),
                    AtomicU64::new(0),
                    AtomicU64::new(0),
                    AtomicU64::new(0),
                ],
                tx_bitmap: [
                    AtomicU64::new(0),
                    AtomicU64::new(0),
                    AtomicU64::new(0),
                    AtomicU64::new(0),
                ],
                rx_dropped: AtomicU64::new(0),
                tx_dropped: AtomicU64::new(0),
                irq_count: AtomicU64::new(0),
                poll_count: AtomicU64::new(0),
                epoch: AtomicU32::new(epoch),
                link: AtomicU32::new(0),
                speed_mbps: AtomicU32::new(0),
                mtu: AtomicU32::new(mtu),
                reserved: [0u8; 64],
            },
        );
    }

    #[inline]
    pub fn is_valid(&self) -> bool {
        self.magic == NET_QUEUE_MAGIC
            && self.abi == NET_QUEUE_ABI
            && self.frame_size as usize == NET_FRAME_SIZE
            && self.slots as usize == NET_RING_SLOTS
    }

    #[inline]
    pub fn as_ptr(&self) -> *mut u8 {
        self as *const Self as *mut u8
    }

    /// # Safety
    /// `self` must be the header of a valid `NET_QUEUE_SIZE` region.
    #[inline]
    pub unsafe fn rx_descs(&self) -> *mut NetFrameDesc {
        self.as_ptr().add(NET_RX_DESC_OFF) as *mut NetFrameDesc
    }

    /// # Safety
    /// `self` must be the header of a valid `NET_QUEUE_SIZE` region.
    #[inline]
    pub unsafe fn tx_descs(&self) -> *mut NetFrameDesc {
        self.as_ptr().add(NET_TX_DESC_OFF) as *mut NetFrameDesc
    }

    /// # Safety
    /// `self` must be the header of a valid `NET_QUEUE_SIZE` region.
    #[inline]
    pub unsafe fn rx_slot(&self, slot: u32) -> *mut u8 {
        debug_assert!((slot as usize) < NET_POOL_SLOTS);
        self.as_ptr()
            .add(NET_RX_POOL_OFF + slot as usize * self.frame_size as usize)
    }

    /// # Safety
    /// `self` must be the header of a valid `NET_QUEUE_SIZE` region.
    #[inline]
    pub unsafe fn tx_slot(&self, slot: u32) -> *mut u8 {
        debug_assert!((slot as usize) < NET_POOL_SLOTS);
        self.as_ptr()
            .add(NET_TX_POOL_OFF + slot as usize * self.frame_size as usize)
    }

    /// Allocate a free RX slot.
    #[inline]
    pub fn alloc_rx_slot(&self) -> Option<u32> {
        bitmap_alloc(&self.rx_bitmap)
    }

    /// Release an RX slot previously returned by `alloc_rx_slot`.
    #[inline]
    pub fn free_rx_slot(&self, slot: u32) {
        bitmap_free(&self.rx_bitmap, slot);
    }

    /// Allocate a free TX slot.
    #[inline]
    pub fn alloc_tx_slot(&self) -> Option<u32> {
        bitmap_alloc(&self.tx_bitmap)
    }

    /// Release a TX slot previously returned by `alloc_tx_slot`.
    #[inline]
    pub fn free_tx_slot(&self, slot: u32) {
        bitmap_free(&self.tx_bitmap, slot);
    }

    /// Publish an RX descriptor (kernel/device side).
    ///
    /// # Safety
    /// `self` must be a valid header and the caller must be the single RX
    /// producer.
    #[inline]
    pub unsafe fn rx_push(&self, desc: NetFrameDesc) -> bool {
        self.rx.push(self.rx_descs(), desc)
    }

    /// Consume an RX descriptor (stack side).
    ///
    /// # Safety
    /// `self` must be a valid header and the caller must be the single RX
    /// consumer.
    #[inline]
    pub unsafe fn rx_pop(&self) -> Option<NetFrameDesc> {
        self.rx.pop(self.rx_descs())
    }

    /// Publish a TX descriptor (stack side).
    ///
    /// # Safety
    /// `self` must be a valid header and the caller must be the single TX
    /// producer.
    #[inline]
    pub unsafe fn tx_push(&self, desc: NetFrameDesc) -> bool {
        self.tx.push(self.tx_descs(), desc)
    }

    /// Consume a TX descriptor (kernel/device side).
    ///
    /// # Safety
    /// `self` must be a valid header and the caller must be the single TX
    /// consumer.
    #[inline]
    pub unsafe fn tx_pop(&self) -> Option<NetFrameDesc> {
        self.tx.pop(self.tx_descs())
    }
}

/// Allocate the first zero bit of a 256-bit bitmap.
#[inline]
pub fn bitmap_alloc(words: &[AtomicU64; 4]) -> Option<u32> {
    for (index, word) in words.iter().enumerate() {
        loop {
            let current = word.load(Ordering::Relaxed);
            if current == u64::MAX {
                break;
            }
            let bit = (!current).trailing_zeros();
            let mask = 1u64 << bit;
            if word
                .compare_exchange_weak(
                    current,
                    current | mask,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return Some(index as u32 * 64 + bit);
            }
        }
    }
    None
}

/// Clear a bit in a 256-bit bitmap.
#[inline]
pub fn bitmap_free(words: &[AtomicU64; 4], slot: u32) {
    let index = (slot as usize) / 64;
    if index >= words.len() {
        return;
    }
    let mask = 1u64 << (slot % 64);
    words[index].fetch_and(!mask, Ordering::Release);
}

/// Result of `SYS_NET_QUEUE_MAP`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NetQueueMap {
    pub base: u64,
    pub len: u64,
    pub qid: u16,
    pub frame_size: u16,
    pub slots: u16,
    pub flags: u16,
}

/// Result of `SYS_NET_LINK`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NetLinkInfo {
    pub mac: [u8; 6],
    pub _pad: u16,
    pub mtu: u32,
    pub flags: u32,
    pub speed_mbps: u32,
    pub epoch: u32,
}

/// Queue statistics.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NetStats {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub rx_dropped: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub tx_dropped: u64,
    pub irqs: u64,
    pub polls: u64,
}

/// Result of `SYS_NET_QUEUE_INFO`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NetQueueInfo {
    pub features: u64,
    pub qid: u16,
    pub slots: u16,
    pub frame_size: u16,
    pub _pad0: u16,
    pub epoch: u32,
    pub mtu: u32,
    pub stats: NetStats,
}

/// Event delivered to a port bound with `SYS_NET_IRQ_BIND`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NetEvent {
    pub kind: u32,
    pub qid: u16,
    pub flags: u16,
    pub epoch: u32,
    pub _pad: u32,
    pub data: u64,
}

/// One entry of a batched RX/TX request.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NetFrame {
    /// User buffer address (RX: destination, TX: source).
    pub addr: u64,
    /// Buffer length.
    pub len: u32,
    /// Descriptor flags (see `fd_flags`).
    pub flags: u32,
}
