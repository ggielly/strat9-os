//! Architecture-neutral shim mirroring the subset of the `x86_64` crate API
//! used by shared kernel code (address types, page sizes, paging flags).
//!
//! Purpose: the ~42 `use x86_64::...` call-sites outside `arch/` are being
//! rewritten to `use crate::arch::xshim::...` so the riscv64 backend can
//! provide its own implementations. On x86_64 the shim re-exports the real
//! crate types so behaviour is bit-identical.

#[cfg(target_arch = "x86_64")]
pub use x86_64::{
    structures::paging::{
        mapper::TranslateResult, PageTableFlags, PhysFrame, Size2MiB, Size4KiB, Translate,
    },
    PhysAddr, VirtAddr,
};

// riscv64 uses the neutral types defined below.

#[cfg(not(target_arch = "x86_64"))]
mod neutral {
    pub use crate::ostd::mm::{PhysAddr, VirtAddr};

/// Page granularity markers (4 KiB / 2 MiB).
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Size4KiB;
    
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Size2MiB;
    
    pub const SIZE_4KIB: u64 = 4096;
    pub const SIZE_2MIB: u64 = 2 * 1024 * 1024;
    
    bitflags::bitflags! {
        /// Page-table flags, arch-neutral encoding (subset of both ISAs).
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub struct PageTableFlags: u64 {
            const PRESENT = 1 << 0;
            const WRITABLE = 1 << 1;
            const USER_ACCESSIBLE = 1 << 2;
            const NO_EXECUTE = 1 << 3;
            const NO_CACHE = 1 << 4;
            const HUGE_PAGE = 1 << 5;
            const BIT_9 = 1 << 9; // used as COW marker on x86_64
        }
    }
    
    /// Result of a translation walk.
    #[derive(Clone, Copy, Debug)]
    pub enum TranslateResult {
        Mapped { frame: PhysFrame<Size4KiB>, flags: PageTableFlags },
        NotMapped,
        InvalidFrameAddress(PhysAddr),
    }
    
    /// A physical memory frame of a given size.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct PhysFrame<S> {
        start: PhysAddr,
        _size: core::marker::PhantomData<S>,
    }
    
    impl<S> PhysFrame<S> {
        pub fn start_address(&self) -> PhysAddr {
            self.start
        }
    }
    
    impl PhysFrame<Size4KiB> {
        pub fn containing_address(addr: PhysAddr) -> Self {
            Self {
                start: PhysAddr::new(addr.as_u64() & !0xFFF),
                _size: core::marker::PhantomData,
            }
        }
    }
    
    impl PhysFrame<Size2MiB> {
        pub fn containing_address(addr: PhysAddr) -> Self {
            Self {
                start: PhysAddr::new(addr.as_u64() & !(SIZE_2MIB - 1)),
                _size: core::marker::PhantomData,
            }
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub use neutral::*;
