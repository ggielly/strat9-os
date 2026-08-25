// riscv64 stub of the x86_64 crate surface used by not-yet-gated code.
// Every item traps at runtime; this exists only so the riscv build can
// typecheck while call-sites are migrated (jalons R2-R5).
pub mod registers {
    pub mod control {
        pub struct Cr3;
        pub struct Cr4;
        #[derive(Clone, Copy)]
        pub struct Cr3Flags;
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub struct Cr4Flags(pub u64);
        impl Cr4Flags {
            pub const PCID: Cr4Flags = Cr4Flags(1 << 17);
            pub fn contains(self, _o: Cr4Flags) -> bool { false }
            pub fn read() -> Cr4Flags { Cr4Flags(0) }
        }
        impl Cr3 {
            pub fn read() -> (crate::arch::xshim::PhysFrame<crate::arch::xshim::Size4KiB>, Cr3Flags) {
                panic!("Cr3::read on riscv64")
            }
        }
    }
}
pub mod instructions {
    pub mod port {
        pub struct Port<T>(core::marker::PhantomData<T>);
        impl<T> Port<T> {
            pub fn new(_addr: u16) -> Self { panic!("port I/O on riscv64") }
        }
        impl Port<u8> {
            pub fn read(&mut self) -> u8 { panic!("port in on riscv64") }
            pub fn write(&mut self, _v: u8) { panic!("port out on riscv64") }
        }
        impl Port<u16> {
            pub fn read(&mut self) -> u16 { panic!("port in on riscv64") }
            pub fn write(&mut self, _v: u16) { panic!("port out on riscv64") }
        }
        impl Port<u32> {
            pub fn read(&mut self) -> u32 { panic!("port in on riscv64") }
            pub fn write(&mut self, _v: u32) { panic!("port out on riscv64") }
        }
    }
    pub mod hlt {
        pub fn hlt() {}
    }
}
pub mod structures {
    pub mod paging {
        pub use crate::arch::xshim::{PageTableFlags, PhysFrame, Size2MiB, Size4KiB};
        pub use crate::arch::xshim::{PhysAddr, VirtAddr};
        #[derive(Clone, Copy)]
        pub struct Page<S: PageSize> {
            start: VirtAddr,
            _size: core::marker::PhantomData<S>,
        }

        pub trait PageSize {
            const SIZE: u64;
        }
        impl PageSize for Size4KiB { const SIZE: u64 = 4096; }
        impl PageSize for Size2MiB { const SIZE: u64 = 2 * 1024 * 1024; }

        impl<S: PageSize> Page<S> {
            pub fn containing_address(a: VirtAddr) -> Self {
                Self { start: VirtAddr::new(a.as_u64() & !(S::SIZE - 1)), _size: core::marker::PhantomData }
            }
            pub fn start_address(&self) -> VirtAddr {
                self.start
            }
            pub fn from_start_address(a: VirtAddr) -> Result<Self, ()> {
                Ok(Self { start: a, _size: core::marker::PhantomData })
            }
        }

        /// Raw Sv48 PTE (R2 fills in the real walk).
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct PageTableEntry(pub u64);
        impl PageTableEntry {
            pub fn is_unused(&self) -> bool { self.0 == 0 }
        }

        pub struct PageTable {
            entries: [PageTableEntry; 512],
        }

        impl PageTable {
            pub const fn new() -> Self {
                // SAFETY of zeroed PTEs: all-zero means "not present".
                Self { entries: [PageTableEntry(0); 512] }
            }
            pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, PageTableEntry> {
                self.entries.iter_mut()
            }
        }

        impl Default for PageTable {
            fn default() -> Self { Self::new() }
        }
        pub trait Mapper<S> {}
        pub trait Translate {
            fn translate(&self, _a: VirtAddr) -> Option<(PhysAddr, PageTableFlags)> { None }
        }
        /// Sv48 page-table mapper over the active root (real impl in R2).
        pub struct OffsetPageTable<'a> {
            l4: &'a mut PageTable,
            phys_offset: u64,
            _marker: core::marker::PhantomData<&'a ()>,
        }

        impl<'a> OffsetPageTable<'a> {
            /// SAFETY: `l4` must point at the active Sv48 root table.
            pub unsafe fn new(l4: &'a mut PageTable, phys_offset: crate::arch::xshim::VirtAddr) -> Self {
                Self { l4, phys_offset: phys_offset.as_u64(), _marker: core::marker::PhantomData }
            }
        }

        pub struct MapperFlush<S>(core::marker::PhantomData<S>);
        impl<S> MapperFlush<S> {
            pub fn flush(self) {
                // sfence.vma full flush placeholder; per-page flush in R2.
            }
        }
        pub mod mapper {
            pub type TranslateResult = crate::arch::xshim::TranslateResult;
            #[derive(Debug, Clone, Copy)]
            pub enum MapToError<S> {
                FrameAllocationFailed,
                ParentEntryHugePage,
                PageAlreadyMapped(crate::arch::xshim::PhysAddr),
            }
                        pub trait Translate2 {
                fn translate(&self, _a: crate::arch::xshim::VirtAddr) -> Option<crate::arch::xshim::PhysAddr> { None }
            }
        }
        pub trait FrameAllocator<S> {
            fn allocate_frame(&mut self) -> Option<crate::arch::xshim::PhysFrame<S>>;
        }
        pub trait Translate3 {
            fn translate(&self, _a: crate::arch::xshim::VirtAddr) -> Option<crate::arch::xshim::TranslateResult>;
        }
    }
    pub mod tss {
        pub struct TaskStateSegment;
    }
}
pub use structures::paging::{PhysAddr, VirtAddr};
pub mod mapper {
    pub type TranslateResult = crate::arch::xshim::TranslateResult;
}
pub trait FrameAllocator<S> {
    fn allocate_frame(&mut self) -> Option<crate::arch::xshim::PhysFrame<S>>;
}
