// Physical frame allocator abstraction

use crate::sync::IrqDisabledToken;
use core::{
    mem,
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
};
use x86_64::PhysAddr;

pub const PAGE_SIZE: u64 = 4096;
pub const FRAME_META_ALIGN: usize = 64;
pub const FRAME_META_SIZE: usize = mem::size_of::<FrameMeta>();
pub const FRAME_META_LINK_NONE: u64 = u64::MAX;

/// Flags persistants stockés dans [`FrameMeta`].
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

/// Métadonnées intrusives d'une frame physique.
#[repr(C, align(64))]
pub struct FrameMeta {
    pub(crate) next: AtomicU64,
    pub(crate) prev: AtomicU64,
    pub(crate) flags: AtomicU32,
    pub(crate) order: u8,
    _reserved0: [u8; 3],
    pub(crate) refcount: AtomicU32,
    _cacheline_pad: [u8; 36],
}

impl FrameMeta {
    /// Crée des métadonnées vides prêtes à être initialisées par le boot allocator.
    pub const fn new() -> Self {
        Self {
            next: AtomicU64::new(FRAME_META_LINK_NONE),
            prev: AtomicU64::new(FRAME_META_LINK_NONE),
            flags: AtomicU32::new(0),
            order: 0,
            _reserved0: [0; 3],
            refcount: AtomicU32::new(0),
            _cacheline_pad: [0; 36],
        }
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
    assert!(mem::size_of::<FrameMeta>() == FRAME_META_ALIGN);
};

/// Taille du tableau de métadonnées nécessaire pour couvrir `ram_size` octets.
pub const fn metadata_size_for(ram_size: u64) -> u64 {
    let frames = (ram_size / PAGE_SIZE) + if ram_size % PAGE_SIZE == 0 { 0 } else { 1 };
    frames * FRAME_META_SIZE as u64
}

/// Physical frame (4KB aligned physical memory)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysFrame {
    pub start_address: PhysAddr,
}

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
