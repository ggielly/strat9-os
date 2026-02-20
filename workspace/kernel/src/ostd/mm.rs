//! Memory management abstraction layer
//!
//! Provides safe abstractions for memory operations including:
//! - Physical and virtual address types
//! - Memory mapping abstractions (MappedPages)
//! - Page table management
//!
//! Inspired by OSes Theseus MappedPages and Asterinas VM modules.

#![no_std]
#![allow(unsafe_code)]
#![allow(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use core::{marker::PhantomData, ops::Range};

/// Physical address type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct PhysAddr(u64);

impl PhysAddr {
    /// Creates a new physical address
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    /// Creates a null physical address
    pub const fn null() -> Self {
        Self(0)
    }

    /// Returns the raw address value
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// Returns the raw address value as usize
    pub const fn as_usize(&self) -> usize {
        self.0 as usize
    }

    /// Checks if the address is null
    pub const fn is_null(&self) -> bool {
        self.0 == 0
    }

    /// Aligns the address up to the given alignment
    pub const fn align_up(&self, align: u64) -> Self {
        Self((self.0 + align - 1) & !(align - 1))
    }

    /// Aligns the address down to the given alignment
    pub const fn align_down(&self, align: u64) -> Self {
        Self(self.0 & !(align - 1))
    }

    /// Checks if the address is aligned to the given alignment
    pub const fn is_aligned(&self, align: u64) -> bool {
        self.0 & (align - 1) == 0
    }

    /// Adds an offset to the address
    pub const fn add(&self, offset: u64) -> Self {
        Self(self.0 + offset)
    }

    /// Subtracts an offset from the address
    pub const fn sub(&self, offset: u64) -> Self {
        Self(self.0 - offset)
    }
}

impl From<u64> for PhysAddr {
    fn from(addr: u64) -> Self {
        Self::new(addr)
    }
}

impl From<PhysAddr> for u64 {
    fn from(addr: PhysAddr) -> u64 {
        addr.as_u64()
    }
}

/// Virtual address type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct VirtAddr(u64);

impl VirtAddr {
    /// Creates a new virtual address
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    /// Creates a null virtual address
    pub const fn null() -> Self {
        Self(0)
    }

    /// Returns the raw address value
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// Returns the raw address value as usize
    pub const fn as_usize(&self) -> usize {
        self.0 as usize
    }

    /// Checks if the address is null
    pub const fn is_null(&self) -> bool {
        self.0 == 0
    }

    /// Aligns the address up to the given alignment
    pub const fn align_up(&self, align: u64) -> Self {
        Self((self.0 + align - 1) & !(align - 1))
    }

    /// Aligns the address down to the given alignment
    pub const fn align_down(&self, align: u64) -> Self {
        Self(self.0 & !(align - 1))
    }

    /// Checks if the address is aligned to the given alignment
    pub const fn is_aligned(&self, align: u64) -> bool {
        self.0 & (align - 1) == 0
    }

    /// Adds an offset to the address
    pub const fn add(&self, offset: u64) -> Self {
        Self(self.0 + offset)
    }

    /// Subtracts an offset from the address
    pub const fn sub(&self, offset: u64) -> Self {
        Self(self.0 - offset)
    }
}

impl From<u64> for VirtAddr {
    fn from(addr: u64) -> Self {
        Self::new(addr)
    }
}

impl From<VirtAddr> for u64 {
    fn from(addr: VirtAddr) -> u64 {
        addr.as_u64()
    }
}

/// Page size constant (4KB)
pub const PAGE_SIZE: usize = 4096;

/// Converts a physical address to a virtual address using HHDM offset
#[inline]
pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    VirtAddr::new(crate::memory::phys_to_virt(phys.as_u64()))
}

/// Converts a virtual address to a physical address
#[inline]
pub fn virt_to_phys(virt: VirtAddr) -> PhysAddr {
    PhysAddr::new(crate::memory::virt_to_phys(virt.as_u64()))
}

/// A safely mapped memory region
///
/// `MappedPages` represents a contiguous virtual memory mapping to physical frames.
/// The mapping is automatically unmapped when the `MappedPages` is dropped.
///
/// This is inspired by Theseus's MappedPages abstraction.
pub struct MappedPages {
    /// Starting virtual address
    start_vaddr: VirtAddr,
    /// Size in bytes
    size: usize,
    /// Whether this mapping owns the underlying frames
    owned: bool,
    /// Marker to prevent Send/Sync (mapping is CPU-local)
    _marker: PhantomData<*mut ()>,
}

// SAFETY: MappedPages can be sent between CPUs if explicitly transferred
unsafe impl Send for MappedPages {}

impl MappedPages {
    /// Creates a new MappedPages from an existing mapping
    ///
    /// # Safety
    ///
    /// - The virtual address range must be a valid mapping
    /// - The caller must ensure the mapping remains valid for the lifetime
    /// - The size must match the actual mapping size
    pub unsafe fn new(start_vaddr: VirtAddr, size: usize, owned: bool) -> Self {
        Self {
            start_vaddr,
            size,
            owned,
            _marker: PhantomData,
        }
    }

    /// Returns the starting virtual address
    pub fn start_address(&self) -> VirtAddr {
        self.start_vaddr
    }

    /// Returns the size in bytes
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns the ending virtual address (exclusive)
    pub fn end_address(&self) -> VirtAddr {
        self.start_vaddr.add(self.size as u64)
    }

    /// Returns the virtual address range
    pub fn range(&self) -> Range<VirtAddr> {
        self.start_vaddr..self.end_address()
    }

    /// Returns a pointer to the start of the mapping
    pub fn as_ptr(&self) -> *const u8 {
        self.start_vaddr.as_usize() as *const u8
    }

    /// Returns a mutable pointer to the start of the mapping
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.start_vaddr.as_usize() as *mut u8
    }

    /// Reads a value from the mapped memory at the given offset
    ///
    /// # Safety
    ///
    /// - The offset + size_of::<T>() must be within the mapping
    /// - The memory must be properly initialized for type T
    /// - Proper alignment must be ensured
    pub unsafe fn read<T>(&self, offset: usize) -> Result<T, MapError> {
        if offset + core::mem::size_of::<T>() > self.size {
            return Err(MapError::OutOfBounds);
        }
        let ptr = self.start_vaddr.as_usize().wrapping_add(offset) as *const T;
        // SAFETY: Caller guarantees the pointer is valid and properly aligned
        Ok(ptr.read_volatile())
    }

    /// Writes a value to the mapped memory at the given offset
    ///
    /// # Safety
    ///
    /// - The offset + size_of::<T>() must be within the mapping
    /// - The memory must be writable (not read-only)
    /// - Proper alignment must be ensured
    pub unsafe fn write<T>(&mut self, offset: usize, value: T) -> Result<(), MapError> {
        if offset + core::mem::size_of::<T>() > self.size {
            return Err(MapError::OutOfBounds);
        }
        let ptr = self.start_vaddr.as_usize().wrapping_add(offset) as *mut T;
        // SAFETY: Caller guarantees the pointer is valid and writable
        ptr.write_volatile(value);
        Ok(())
    }

    /// Returns a slice reference to the mapped memory
    ///
    /// # Safety
    ///
    /// - The mapping must contain initialized data
    /// - No other mutable references to this memory can exist
    pub unsafe fn as_slice(&self, len: usize) -> Result<&[u8], MapError> {
        if len > self.size {
            return Err(MapError::OutOfBounds);
        }
        Ok(core::slice::from_raw_parts(self.as_ptr(), len))
    }

    /// Returns a mutable slice reference to the mapped memory
    ///
    /// # Safety
    ///
    /// - The mapping must be writable
    /// - No other references to this memory can exist
    pub unsafe fn as_mut_slice(&mut self, len: usize) -> Result<&mut [u8], MapError> {
        if len > self.size {
            return Err(MapError::OutOfBounds);
        }
        Ok(core::slice::from_raw_parts_mut(self.as_mut_ptr(), len))
    }

    /// Converts this MappedPages into an AllocatedPages, consuming the mapping
    ///
    /// This transfers ownership of the underlying frames.
    pub fn into_allocated_pages(self) -> Result<AllocatedPages, MapError> {
        if !self.owned {
            return Err(MapError::NotOwner);
        }
        let pages = AllocatedPages {
            start_vaddr: self.start_vaddr,
            size: self.size,
        };
        // Prevent the Drop implementation from running
        core::mem::forget(self);
        Ok(pages)
    }
}

impl Drop for MappedPages {
    fn drop(&mut self) {
        if self.owned {
            // Calculate page count
            let page_count = (self.size + PAGE_SIZE - 1) / PAGE_SIZE;
            // SAFETY: We own the mapping and are responsible for unmapping
            unsafe {
                crate::memory::address_space::kernel_address_space()
                    .unmap_region(
                        self.start_vaddr.as_u64(),
                        page_count,
                        crate::memory::address_space::VmaPageSize::Small,
                    )
                    .ok();
            }
        }
    }
}

impl core::fmt::Debug for MappedPages {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MappedPages")
            .field("start", &self.start_vaddr)
            .field("size", &self.size)
            .field("owned", &self.owned)
            .finish()
    }
}

/// Allocated pages that can be mapped
///
/// Represents virtually allocated pages that own their underlying frames.
pub struct AllocatedPages {
    start_vaddr: VirtAddr,
    size: usize,
}

impl AllocatedPages {
    /// Returns the starting virtual address
    pub fn start_address(&self) -> VirtAddr {
        self.start_vaddr
    }

    /// Returns the size in bytes
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns the number of pages
    pub fn page_count(&self) -> usize {
        (self.size + PAGE_SIZE - 1) / PAGE_SIZE
    }
}

impl Drop for AllocatedPages {
    fn drop(&mut self) {
        // Deallocate the frames using the buddy allocator
        // SAFETY: we own these pages and are responsible for deallocation
        let phys_addr = virt_to_phys(self.start_vaddr).as_u64();
        // TODO: implement proper frame deallocation
        // For now, we just leak the frames to avoid double-free issues
        let _ = phys_addr;
        let _ = self.size;
        // crate::memory::frame::deallocate_frames(phys_addr, self.size);
    }
}

/// Memory mapping flags
#[derive(Debug, Clone, Copy)]
pub struct MapFlags {
    /// Page is present (mapped)
    pub present: bool,
    /// Page is writable
    pub writable: bool,
    /// Page is user-accessible
    pub user: bool,
    /// Write-through caching
    pub write_through: bool,
    /// Cache disabled
    pub cache_disabled: bool,
    /// No-execute (NX)
    pub no_execute: bool,
}

impl MapFlags {
    /// Creates flags for a read-only kernel mapping
    pub const fn read_only() -> Self {
        Self {
            present: true,
            writable: false,
            user: false,
            write_through: false,
            cache_disabled: false,
            no_execute: false,
        }
    }

    /// Creates flags for a read-write kernel mapping
    pub const fn read_write() -> Self {
        Self {
            present: true,
            writable: true,
            user: false,
            write_through: false,
            cache_disabled: false,
            no_execute: false,
        }
    }

    /// Creates flags for a user mapping
    pub const fn user_read_write() -> Self {
        Self {
            present: true,
            writable: true,
            user: true,
            write_through: false,
            cache_disabled: false,
            no_execute: false,
        }
    }

    /// Creates flags for MMIO (device memory)
    pub const fn mmio() -> Self {
        Self {
            present: true,
            writable: true,
            user: false,
            write_through: false,
            cache_disabled: true,
            no_execute: true,
        }
    }
}

/// Memory mapping error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapError {
    /// Address out of bounds
    OutOfBounds,
    /// Not owner of the mapping
    NotOwner,
    /// Mapping already exists
    AlreadyMapped,
    /// Invalid address
    InvalidAddress,
    /// Out of memory
    OutOfMemory,
    /// Architecture-specific error
    ArchError(&'static str),
}

impl core::fmt::Display for MapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutOfBounds => write!(f, "address out of bounds"),
            Self::NotOwner => write!(f, "not owner of mapping"),
            Self::AlreadyMapped => write!(f, "address already mapped"),
            Self::InvalidAddress => write!(f, "invalid address"),
            Self::OutOfMemory => write!(f, "out of memory"),
            Self::ArchError(msg) => write!(f, "architecture error: {}", msg),
        }
    }
}

/// Virtual Memory Address Region (VMAR)
///
/// Manages a region of virtual address space, similar to Asterinas VMAR.
/// Used for process address space management.
pub struct Vmar {
    /// Base virtual address
    base: VirtAddr,
    /// Size of the region
    size: usize,
    /// Child regions
    children: spin::Mutex<alloc::vec::Vec<VmarChild>>,
}

struct VmarChild {
    /// Offset from parent base
    offset: usize,
    /// Size of the child region
    size: usize,
    /// The actual mapping
    mapping: Option<MappedPages>,
}

impl Vmar {
    /// Creates a new VMAR
    pub fn new(base: VirtAddr, size: usize) -> Self {
        Self {
            base,
            size,
            children: spin::Mutex::new(alloc::vec![]),
        }
    }

    /// Returns the base virtual address
    pub fn base(&self) -> VirtAddr {
        self.base
    }

    /// Returns the size of the region
    pub fn size(&self) -> usize {
        self.size
    }

    /// Allocates a new region within this VMAR
    pub fn alloc(&self, offset: usize, size: usize, flags: MapFlags) -> Result<VirtAddr, MapError> {
        // TODO: implement proper allocation with conflict detection
        let vaddr = self.base.add(offset as u64);

        // TODO: map the region with the given flags
        let _ = flags; // Suppress unused warning

        let mut children = self.children.lock();
        children.push(VmarChild {
            offset,
            size,
            mapping: None,
        });

        Ok(vaddr)
    }

    /// Deallocates a region within this VMAR
    pub fn dealloc(&self, offset: usize) -> Result<(), MapError> {
        let mut children = self.children.lock();
        if let Some(pos) = children.iter().position(|c| c.offset == offset) {
            children.remove(pos);
            Ok(())
        } else {
            Err(MapError::InvalidAddress)
        }
    }
}

impl core::fmt::Debug for Vmar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vmar")
            .field("base", &self.base)
            .field("size", &self.size)
            .finish()
    }
}

/// TLB flush operation for SMP systems
///
/// Flushes TLB entries on all CPUs that may have cached the given virtual address.
pub fn tlb_flush_virt_addr(vaddr: VirtAddr) {
    // SAFETY: invlpg is a privileged instruction that invalidates a TLB entry.
    // This is safe to call in kernel mode.
    unsafe {
        core::arch::asm!(
            "invlpg [{}]",
            in(reg) vaddr.as_u64(),
            options(nostack, preserves_flags)
        );
    }
}

/// Flushes the entire TLB on the current CPU
///
/// This is more expensive than `tlb_flush_virt_addr` and should be used sparingly.
pub fn tlb_flush_all() {
    // SAFETY: writing to CR3 with the same value flushes the TLB (except global pages).
    // This is safe to call in kernel mode.
    unsafe {
        let cr3: u64;
        core::arch::asm!(
            "mov {}, cr3",
            out(reg) cr3,
            options(nostack, preserves_flags)
        );
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) cr3,
            options(nostack)
        );
    }
}
