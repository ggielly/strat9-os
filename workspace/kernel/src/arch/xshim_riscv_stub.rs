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
            pub fn write(_frame: crate::arch::xshim::PhysFrame<crate::arch::xshim::Size4KiB>, _flags: Cr3Flags) {
                panic!("Cr3::write on riscv64")
            }
        }
        impl Cr4 {
            pub fn read() -> Cr4Flags { Cr4Flags(0) }
        }
        impl Cr3Flags {
            pub const fn empty() -> Cr3Flags { Cr3Flags }
        }
    }
}
pub mod instructions {
    pub mod port {
        // Sealed value trait: which widths a port can transfer.
        pub trait PortValue: Copy {
            fn zero() -> Self;
            fn max() -> Self;
        }
        impl PortValue for u8 { fn zero() -> Self { 0xFF } fn max() -> Self { 0xFF } }
        impl PortValue for u16 { fn zero() -> Self { 0xFFFF } fn max() -> Self { 0xFFFF } }
        impl PortValue for u32 { fn zero() -> Self { 0xFFFF_FFFF } fn max() -> Self { 0xFFFF_FFFF } }

        pub struct Port<T>(core::marker::PhantomData<T>);
        impl<T: PortValue> Port<T> {
            pub fn new(_addr: u16) -> Self { panic!("port I/O on riscv64") }
            pub fn read(&mut self) -> T { panic!("port in on riscv64") }
            pub fn write(&mut self, _v: T) {}
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
            pub fn iter(&self) -> core::slice::Iter<'_, PageTableEntry> {
                self.entries.iter()
            }
        }

        impl Default for PageTable {
            fn default() -> Self { Self::new() }
        }

        impl core::ops::Index<usize> for PageTable {
            type Output = PageTableEntry;
            fn index(&self, i: usize) -> &PageTableEntry {
                &self.entries[i]
            }
        }
        impl core::ops::IndexMut<usize> for PageTable {
            fn index_mut(&mut self, i: usize) -> &mut PageTableEntry {
                &mut self.entries[i]
            }
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
            pub fn ignore(self) {}
        }

        impl<'a> OffsetPageTable<'a> {
            /// Walk the Sv48 tables and return the physical address.
            pub fn translate(
                &self,
                vaddr: crate::arch::xshim::VirtAddr,
            ) -> Option<crate::arch::xshim::TranslateResult> {
                let va = vaddr.as_u64();
                let indexes = [
                    ((va >> 39) & 0x1FF) as usize,
                    ((va >> 30) & 0x1FF) as usize,
                    ((va >> 21) & 0x1FF) as usize,
                    ((va >> 12) & 0x1FF) as usize,
                ];
                let mut table: u64 = self.l4 as *const PageTable as u64;
                for (level, idx) in indexes.iter().enumerate() {
                    if table == 0 {
                        return None;
                    }
                    // SAFETY: table points at a mapped page-table page (HHDM).
                    let pt = unsafe { &*((table + self.phys_offset) as *const PageTable) };
                    let pte = &pt[*idx];
                    if pte.0 & 0x1 == 0 {
                        return None;
                    }
                    // Leaf?
                    if pte.0 & 0x8 != 0 || level == 3 {
                        let ppn_base = (pte.0 >> 10) << 12;
                        let offset_mask = match level {
                            0 => (1 << 12) - 1,
                            1 => (1 << 21) - 1,
                            2 => (1 << 30) - 1,
                            _ => (1 << 39) - 1,
                        };
                        let pa = (ppn_base & !offset_mask) | (va & offset_mask);
                        return Some(crate::arch::xshim::TranslateResult::Mapped {
                            frame: crate::arch::xshim::PhysFrame::<Size4KiB>::containing_address(
                                crate::arch::xshim::PhysAddr::new(pa),
                            ),
                            offset: va & offset_mask,
                            flags: pte.flags(),
                        });
                    }
                    // Next level pointer
                    table = ((pte.0 >> 10) << 12) & !0x3FF;
                }
                None
            }

            pub fn translate_addr(
                &self,
                vaddr: crate::arch::xshim::VirtAddr,
            ) -> Option<crate::arch::xshim::PhysAddr> {
                self.translate(vaddr).map(|r| match r {
                    crate::arch::xshim::TranslateResult::Mapped { frame, .. } => frame.start_address(),
                    _ => crate::arch::xshim::PhysAddr::null(),
                })
            }
        }
        pub mod mapper {
            pub type TranslateResult = crate::arch::xshim::TranslateResult;
            #[derive(Debug, Clone, Copy)]
            pub enum MapToError<S> {
                FrameAllocationFailed,
                ParentEntryHugePage,
                PageAlreadyMapped(crate::arch::xshim::PhysAddr),
                _Phantom(core::marker::PhantomData<S>),
            }
                        pub trait Translate2 {
                fn translate(&self, _a: crate::arch::xshim::VirtAddr) -> Option<crate::arch::xshim::PhysAddr> { None }
            }
        }
        pub trait FrameAllocator<S> {
            fn allocate_frame(&mut self) -> Option<crate::arch::xshim::PhysFrame<S>>;
        }

        // ---- PageTableEntry accessors (Sv48 PTE layout) ----
        impl PageTableEntry {
            pub const fn new() -> Self { PageTableEntry(0) }
            pub fn set_unused(&mut self) { self.0 = 0; }
            pub fn set_frame(&mut self, _f: crate::arch::xshim::PhysFrame<Size4KiB>, _flags: crate::arch::xshim::PageTableFlags) {}
            pub fn flags(&self) -> crate::arch::xshim::PageTableFlags {
                let mut f = crate::arch::xshim::PageTableFlags::empty();
                if self.0 & 0x1 != 0 { f |= crate::arch::xshim::PageTableFlags::PRESENT; }
                if self.0 & 0x2 != 0 { f |= crate::arch::xshim::PageTableFlags::WRITABLE; }
                if self.0 & 0x4 != 0 { f |= crate::arch::xshim::PageTableFlags::USER_ACCESSIBLE; }
                if self.0 & 0x8 != 0 { f |= crate::arch::xshim::PageTableFlags::NO_EXECUTE; }
                if self.0 & 0x80 != 0 { f |= crate::arch::xshim::PageTableFlags::HUGE_PAGE; }
                if self.0 & 0x10 != 0 { f |= crate::arch::xshim::PageTableFlags::NO_CACHE; }
                f
            }
            pub fn frame(&self) -> crate::arch::xshim::PhysFrame<Size4KiB> {
                let ppn = (self.0 >> 10) & 0x0000_FFFF_FFFF_FFFF;
                crate::arch::xshim::PhysFrame::<Size4KiB>::containing_address(
                    crate::arch::xshim::PhysAddr::new(ppn << 12),
                )
            }
        }
        impl Default for PageTableEntry {
            fn default() -> Self { Self::new() }
        }

        /// The Mapper surface shared code expects. R2 replaces the bodies
        /// with a genuine Sv48 walk + sfence.vma.
        impl<'a> OffsetPageTable<'a> {
            pub unsafe fn map_to<S: PageSize>(
                &mut self,
                _page: Page<S>,
                _frame: crate::arch::xshim::PhysFrame<S>,
                _flags: crate::arch::xshim::PageTableFlags,
                _alloc: &mut dyn FrameAllocator<Size4KiB>,
            ) -> Result<MapperFlush<S>, mapper::MapToError<S>> {
                Err(mapper::MapToError::FrameAllocationFailed)
            }
            pub unsafe fn update_flags<S: PageSize>(
                &mut self,
                _page: Page<S>,
                _flags: crate::arch::xshim::PageTableFlags,
            ) -> Result<MapperFlush<S>, mapper::MapToError<S>> {
                Err(mapper::MapToError::FrameAllocationFailed)
            }
            pub fn unmap<S: PageSize>(
                &mut self,
                _page: Page<S>,
            ) -> Result<(crate::arch::xshim::PhysFrame<S>, MapperFlush<S>), ()> {
                panic!("riscv64 paging not yet implemented (jalon R2)")
            }
        }
        pub trait Translate3 {
            fn translate(&self, _a: crate::arch::xshim::VirtAddr) -> Option<crate::arch::xshim::TranslateResult>;
            fn translate_addr(&self, a: crate::arch::xshim::VirtAddr) -> Option<crate::arch::xshim::PhysAddr> {
                self.translate(a).map(|r| match r {
                    crate::arch::xshim::TranslateResult::Mapped { frame, .. } => frame.start_address(),
                    _ => crate::arch::xshim::PhysAddr::null(),
                })
            }
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
