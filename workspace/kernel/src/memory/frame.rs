// Physical frame allocator abstraction

use crate::{memory::boot_alloc::BootAllocator, sync::IrqDisabledToken};
use core::{
    mem, ptr,
    sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering},
};
use x86_64::PhysAddr;

pub const PAGE_SIZE: u64 = 4096;
pub const FRAME_META_ALIGN: usize = 64;
pub const FRAME_META_SIZE: usize = 64;
pub const FRAME_META_LINK_NONE: u64 = u64::MAX;

/// Persistent flags stored in [`FrameMeta`].
pub mod frame_flags {
    /// La frame est allouée.
    pub const ALLOCATED: u32 = 1 << 8;
    /// La frame est libre.
    pub const FREE: u32 = 1 << 9;
    /// La frame est réservée au noyau.
    pub const KERNEL: u32 = 1 << 10;
    /// La frame appartient à l'espace utilisateur.
    pub const USER: u32 = 1 << 11;
    /// La frame est empoisonnée et ne doit plus être recyclée telle quelle.
    pub const POISONED: u32 = 1 << 12;
    /// Frame éligible au copy-on-write.
    pub const COW: u32 = 1 << 0;
    /// Frame partagée de type DLL, jamais COW.
    pub const DLL: u32 = 1 << 1;
    /// Frame anonyme.
    pub const ANONYMOUS: u32 = 1 << 2;
}

/// Bytes used by the named fields of [`FrameMeta`] before the padding.
const FRAME_META_FIELDS_SIZE: usize = 8 + 8 + 4 + 1 + 3 + 4; // next+prev+flags+order+_reserved0+refcount


/// Intriside metadata for a physical frame.
/// - 64 bytes (one cache line) for efficient atomic access and to avoid false sharing.

#[repr(C, align(64))]
pub struct FrameMeta {
    pub(crate) next: AtomicU64,
    pub(crate) prev: AtomicU64,
    pub(crate) flags: AtomicU32,
    pub(crate) order: AtomicU8,
    _reserved0: [u8; 3],
    pub(crate) refcount: AtomicU32,
    _cacheline_pad: [u8; FRAME_META_SIZE - FRAME_META_FIELDS_SIZE],
}

impl FrameMeta {
    
    /// Create emplty metadata ready to be initialized by the boot allocator.
    pub const fn new() -> Self {
        Self {
            next: AtomicU64::new(FRAME_META_LINK_NONE),
            prev: AtomicU64::new(FRAME_META_LINK_NONE),
            flags: AtomicU32::new(0),
            order: AtomicU8::new(0),    /// 
            _reserved0: [0; 3],
            refcount: AtomicU32::new(0),
            _cacheline_pad: [0; FRAME_META_SIZE - FRAME_META_FIELDS_SIZE],
        }
    }

    #[inline]
    pub fn next(&self) -> u64 {
        self.next.load(Ordering::Acquire)
    }

    #[inline]
    pub fn set_next(&self, next: u64) {
        self.next.store(next, Ordering::Release);
    }

    #[inline]
    pub fn prev(&self) -> u64 {
        self.prev.load(Ordering::Acquire)
    }

    #[inline]
    pub fn set_prev(&self, prev: u64) {
        self.prev.store(prev, Ordering::Release);
    }

    #[inline]
    pub fn inc_ref(&self) {
        self.refcount.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn dec_ref(&self) -> u32 {
        self.refcount.fetch_sub(1, Ordering::Release)
    }

    #[inline]
    pub fn get_refcount(&self) -> u32 {
        self.refcount.load(Ordering::Acquire)
    }

    #[inline]
    pub fn set_flags(&self, flags: u32) {
        self.flags.store(flags, Ordering::Release);
    }

    #[inline]
    pub fn get_flags(&self) -> u32 {
        self.flags.load(Ordering::Acquire)
    }

    #[inline]
    pub fn get_order(&self) -> u8 {
        self.order.load(Ordering::Acquire)
    }

    #[inline]
    pub fn set_order(&self, order: u8) {
        self.order.store(order, Ordering::Release);
    }

    #[inline]
    pub fn reset_refcount(&self) {
        self.refcount.store(0, Ordering::Release);
    }

    #[inline]
    pub fn is_cow(&self) -> bool {
        self.get_flags() & frame_flags::COW != 0
    }

    #[inline]
    pub fn is_dll(&self) -> bool {
        self.get_flags() & frame_flags::DLL != 0
    }
}

const _: () = {
    assert!(mem::align_of::<FrameMeta>() == FRAME_META_ALIGN);
    assert!(mem::size_of::<FrameMeta>() == FRAME_META_SIZE);
};


/// The metadata array size for `ram_size` bytes, rounded up to the nearest page since each frame 
/// has a dedicated metadata entry.

/// @param ram_size Total RAM size to be covered by the metadata (in bytes).
/// 
pub const fn metadata_size_for(ram_size: u64) -> u64 {
    let frames = (ram_size / PAGE_SIZE) + if ram_size % PAGE_SIZE == 0 { 0 } else { 1 };
    frames * FRAME_META_SIZE as u64
}

static METADATA_BASE_VIRT: AtomicU64 = AtomicU64::new(0);
static METADATA_FRAME_COUNT: AtomicU64 = AtomicU64::new(0);

/// Initialize the global metadata array for all physical frames.
pub fn init_metadata_array(total_ram: u64, boot_alloc: &mut BootAllocator) {
    let frame_count = (total_ram / PAGE_SIZE) + if total_ram % PAGE_SIZE == 0 { 0 } else { 1 };
    if frame_count == 0 {
        METADATA_BASE_VIRT.store(0, Ordering::Release);
        METADATA_FRAME_COUNT.store(0, Ordering::Release);
        return;
    }

    let bytes = metadata_size_for(total_ram) as usize;
    let phys = boot_alloc.alloc(bytes, FRAME_META_ALIGN);
    let virt = crate::memory::phys_to_virt(phys.as_u64()) as *mut FrameMeta;

    for idx in 0..frame_count as usize {
        // SAFETY: le bloc a été réservé par le boot allocator avec un alignement
        // compatible `FrameMeta` et une taille suffisante pour tout le tableau.
        unsafe {
            ptr::write(virt.add(idx), FrameMeta::new());
        }
    }

    METADATA_FRAME_COUNT.store(frame_count, Ordering::Release);
    METADATA_BASE_VIRT.store(virt as u64, Ordering::Release);
}

/// Get the metadata for a given physical frame.
pub fn get_meta(phys: PhysAddr) -> &'static FrameMeta {
    let base = METADATA_BASE_VIRT.load(Ordering::Acquire);
    let frame_count = METADATA_FRAME_COUNT.load(Ordering::Acquire);
    assert!(base != 0, "frame metadata array is not initialized");

    let pfn = phys.as_u64() / PAGE_SIZE;
    assert!(pfn < frame_count, "frame metadata access out of bounds");

    let byte_offset = pfn as usize * FRAME_META_SIZE;
    // SAFETY: le tableau global couvre au moins `frame_count` entrées et reste
    // vivant pendant toute la durée du noyau.
    unsafe { &*((base as usize + byte_offset) as *const FrameMeta) }
}

/// Physical frame (4KB aligned physical memory)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysFrame {
    pub start_address: PhysAddr,
}

/// Performs the phys frame containing address operation.
impl PhysFrame {
    /// Create a PhysFrame containing the given physical address
    pub fn containing_address(addr: PhysAddr) -> Self {
        PhysFrame {
            start_address: PhysAddr::new(addr.as_u64() & !0xFFF),
        }
    }

    /// Create a PhysFrame from a 4KB-aligned address
    pub fn from_start_address(addr: PhysAddr) -> Result<Self, ()> {
        if addr.is_aligned(4096u64) {
            Ok(PhysFrame {
                start_address: addr,
            })
        } else {
            Err(())
        }
    }

    /// Create an inclusive range of frames
    pub fn range_inclusive(start: PhysFrame, end: PhysFrame) -> FrameRangeInclusive {
        FrameRangeInclusive { start, end }
    }
}

/// Iterator over an inclusive range of physical frames
pub struct FrameRangeInclusive {
    pub start: PhysFrame,
    pub end: PhysFrame,
}

/// Performs the iterator operation for FrameRangeInclusive.
impl Iterator for FrameRangeInclusive {
    type Item = PhysFrame;

    /// Performs the next operation.
    fn next(&mut self) -> Option<Self::Item> {
        if self.start <= self.end {
            let frame = self.start;
            self.start.start_address += 4096u64;
            Some(frame)
        } else {
            None
        }
    }
}

/// Frame allocation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocError {
    /// No memory available
    OutOfMemory,
    /// Invalid order (> MAX_ORDER)
    InvalidOrder,
    /// Invalid address alignment
    InvalidAddress,
}

/// Frame allocator trait
pub trait FrameAllocator {
    /// Allocate `2^order` contiguous frames.
    ///
    /// Le token interdit les appels depuis un contexte où le verrou global de
    /// l'allocateur pourrait être ré-entré par interruption.
    fn alloc(&mut self, order: u8, token: &IrqDisabledToken) -> Result<PhysFrame, AllocError>;

    /// Free `2^order` contiguous frames starting at frame.
    fn free(&mut self, frame: PhysFrame, order: u8, token: &IrqDisabledToken);

    /// Allocate a single frame (convenience method)
    fn alloc_frame(&mut self, token: &IrqDisabledToken) -> Result<PhysFrame, AllocError> {
        self.alloc(0, token)
    }
}
