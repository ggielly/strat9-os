//! Mirror of kernel/src/memory — the allocator core, verbatim.
//!
//! Included modules: `boot_alloc`, `zone`, `frame`, `buddy`.
//! Faked at this level: HHDM translation (fixed offset), everything
//! else is the real kernel code under test.

// ---------------------------------------------------------------------------
// Fake address-translation helpers (kernel/src/memory/mod.rs equivalents)
// ---------------------------------------------------------------------------

/// Fixed fake HHDM offset used by all host tests (64 GiB mark).
pub const FAKE_HHDM: u64 = 0x10_0000_0000;

static HHDM_OFFSET: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(FAKE_HHDM);

pub fn set_hhdm_offset(offset: u64) {
    HHDM_OFFSET.store(offset, core::sync::atomic::Ordering::Relaxed);
}

pub fn hhdm_offset() -> u64 {
    HHDM_OFFSET.load(core::sync::atomic::Ordering::Relaxed)
}

#[inline]
pub fn phys_to_virt(phys: u64) -> u64 {
    phys.wrapping_add(HHDM_OFFSET.load(core::sync::atomic::Ordering::Relaxed))
}

#[inline]
pub fn virt_to_phys(virt: u64) -> u64 {
    virt.wrapping_sub(HHDM_OFFSET.load(core::sync::atomic::Ordering::Relaxed))
}

// ---------------------------------------------------------------------------
// Real kernel modules
// ---------------------------------------------------------------------------

#[path = "../../../kernel/src/memory/boot_alloc.rs"]
pub mod boot_alloc;
#[path = "../../../kernel/src/memory/zone.rs"]
pub mod zone;
#[path = "../../../kernel/src/memory/frame.rs"]
pub mod frame;
#[path = "../../../kernel/src/memory/buddy.rs"]
pub mod buddy;

/// Fake paging check: on the host every HHDM page is trivially "mapped".
pub mod paging {
    pub fn is_hhdm_range_mapped_now(_phys_base: u64, _size: u64) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// memory/mod.rs surface used by included modules (allocate_frame/free_frame)
// ---------------------------------------------------------------------------

use crate::sync::IrqDisabledToken;

pub use frame::{AllocError, PhysFrame};

/// Mirror of memory/mod.rs `allocate_frame`: order-0 buddy alloc.
#[inline]
pub fn allocate_frame(token: &IrqDisabledToken) -> Result<PhysFrame, AllocError> {
    buddy::alloc(token, 0)
}

/// Mirror of memory/mod.rs `free_frame`.
#[inline]
pub fn free_frame(token: &IrqDisabledToken, frame: PhysFrame) {
    buddy::free(token, frame, 0);
}

/// Mirror of memory/mod.rs `allocate_frames`.
#[inline]
pub fn allocate_frames(token: &IrqDisabledToken, order: u8) -> Result<PhysFrame, AllocError> {
    buddy::alloc(token, order)
}

/// Mirror of memory/mod.rs `free_frames`.
#[inline]
pub fn free_frames(token: &IrqDisabledToken, frame: PhysFrame, order: u8) {
    buddy::free(token, frame, order);
}

// ---------------------------------------------------------------------------
// Fake user slices: same surface as kernel/src/memory/userslice.rs, but
// pointers are raw host addresses (no page-table walk). Tests only ever
// construct slices over valid leaked buffers, so access is sound.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserSliceError {
    NullPointer,
    TooLong,
    Overflow,
    KernelAddress,
    NotMapped,
    NotWritable,
}

impl From<UserSliceError> for crate::syscall::error::SyscallError {
    fn from(e: UserSliceError) -> Self {
        use crate::syscall::error::SyscallError;
        match e {
            UserSliceError::NullPointer
            | UserSliceError::KernelAddress
            | UserSliceError::NotMapped
            | UserSliceError::NotWritable => SyscallError::Fault,
            UserSliceError::TooLong | UserSliceError::Overflow => SyscallError::InvalidArgument,
        }
    }
}

pub struct UserSliceRead {
    ptr: u64,
    len: usize,
}

impl UserSliceRead {
    pub fn new(ptr: u64, len: usize) -> Result<Self, UserSliceError> {
        if len == 0 {
            return Ok(Self { ptr, len });
        }
        if ptr == 0 {
            return Err(UserSliceError::NullPointer);
        }
        ptr.checked_add(len as u64).ok_or(UserSliceError::Overflow)?;
        Ok(Self { ptr, len })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// SAFETY-reduced host variant: reads directly from the pointer. Tests
    /// must only create slices over live allocations.
    pub fn read_to_vec(&self) -> Vec<u8> {
        if self.len == 0 {
            return Vec::new();
        }
        unsafe {
            core::slice::from_raw_parts(self.ptr as *const u8, self.len).to_vec()
        }
    }

    pub fn copy_to(&self, dest: &mut [u8]) -> usize {
        let n = dest.len().min(self.len);
        unsafe {
            core::ptr::copy_nonoverlapping(self.ptr as *const u8, dest.as_mut_ptr(), n);
        }
        n
    }

    pub fn read_u8(&self, offset: usize) -> Result<u8, UserSliceError> {
        if offset >= self.len {
            return Err(UserSliceError::NotMapped);
        }
        Ok(unsafe { *(self.ptr as *const u8).add(offset) })
    }

    pub fn read_u64(&self, offset: usize) -> Result<u64, UserSliceError> {
        if offset + 8 > self.len {
            return Err(UserSliceError::NotMapped);
        }
        Ok(unsafe { (self.ptr as *const u64).add(offset / 8).read_unaligned() })
    }

    pub fn read_val<T: Copy>(&self) -> Result<T, UserSliceError> {
        if size_of::<T>() > self.len {
            return Err(UserSliceError::NotMapped);
        }
        Ok(unsafe { (self.ptr as *const T).read_unaligned() })
    }

    pub fn as_ptr(&self) -> u64 {
        self.ptr
    }
}

pub struct UserSliceWrite {
    ptr: u64,
    len: usize,
}

impl UserSliceWrite {
    pub fn new(ptr: u64, len: usize) -> Result<Self, UserSliceError> {
        if len == 0 {
            return Ok(Self { ptr, len });
        }
        if ptr == 0 {
            return Err(UserSliceError::NullPointer);
        }
        ptr.checked_add(len as u64).ok_or(UserSliceError::Overflow)?;
        Ok(Self { ptr, len })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn copy_from(&self, src: &[u8]) -> usize {
        let n = src.len().min(self.len);
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), self.ptr as *mut u8, n);
        }
        n
    }

    pub fn zero(&self) {
        unsafe {
            core::ptr::write_bytes(self.ptr as *mut u8, 0, self.len);
        }
    }

    pub fn as_ptr(&self) -> u64 {
        self.ptr
    }
}
