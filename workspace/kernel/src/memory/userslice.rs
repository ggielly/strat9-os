//! Userspace pointer validation for Strat9-OS.
//!
//! The `UserSlice` pattern (inspired by RedoxOS `usercopy.rs`) ensures the
//! kernel never dereferences a raw userspace pointer without first checking:
//!
//! 1. **Range**: The entire region lies in the user half (< `USER_SPACE_END`)
//! 2. **Overflow**: `base + len` doesn't wrap around
//! 3. **Mapping**: Every page in the region is present in the *active* page
//!    tables with the requested permissions (read or write)
//!
//! After validation, `UserSlice` provides safe copy operations that transfer
//! data between userspace and kernel buffers.
//!
//! # Example
//!
//! ```ignore
//! // In a syscall handler:
//! let user_buf = UserSliceRead::new(buf_ptr, buf_len)?;
//! let mut kernel_buf = [0u8; 256];
//! let n = user_buf.copy_to(&mut kernel_buf)?;
//! ```

use crate::syscall::error::SyscallError;
use alloc::vec::Vec;
use x86_64::structures::paging::{PageTableFlags, Translate};
use x86_64::VirtAddr;

/// End of user-accessible virtual address space.
///
/// On x86_64 with 4-level paging, canonical user addresses are
/// `0x0000_0000_0000_0000 ..= 0x0000_7FFF_FFFF_FFFF`.
/// Anything at or above this boundary is kernel space.
const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;

/// Maximum length allowed for a single UserSlice (16 MiB).
///
/// Prevents a malicious userspace from causing the kernel to walk
/// millions of page table entries or allocate huge kernel buffers.
const MAX_USER_SLICE_LEN: usize = 16 * 1024 * 1024;

/// Errors that can occur when constructing or using a `UserSlice`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserSliceError {
    /// The pointer is null.
    NullPointer,
    /// The region extends into or past kernel address space.
    KernelAddress,
    /// `base + len` overflows (wraps around the address space).
    Overflow,
    /// The region exceeds the maximum allowed length.
    TooLong,
    /// One or more pages in the region are not mapped.
    NotMapped,
    /// The mapping lacks the required permission (e.g. not writable).
    PermissionDenied,
}

impl From<UserSliceError> for SyscallError {
    fn from(e: UserSliceError) -> Self {
        match e {
            UserSliceError::NullPointer => SyscallError::Fault,
            UserSliceError::KernelAddress => SyscallError::Fault,
            UserSliceError::Overflow => SyscallError::Fault,
            UserSliceError::TooLong => SyscallError::InvalidArgument,
            UserSliceError::NotMapped => SyscallError::Fault,
            UserSliceError::PermissionDenied => SyscallError::Fault,
        }
    }
}

/// Permission requirements for a user memory region.
#[derive(Debug, Clone, Copy)]
enum Access {
    /// Read-only access (the kernel reads from userspace).
    Read,
    /// Write access (the kernel writes to userspace).
    Write,
}

/// Validate that a user memory region `[base, base+len)` is:
/// - entirely within the user address space
/// - mapped with the required permissions in the active page tables
///
/// Returns `Ok(())` on success, or a `UserSliceError` describing the problem.
fn validate_user_region(base: u64, len: usize, access: Access) -> Result<(), UserSliceError> {
    if len == 0 {
        return Ok(());
    }

    if base == 0 {
        return Err(UserSliceError::NullPointer);
    }

    if len > MAX_USER_SLICE_LEN {
        return Err(UserSliceError::TooLong);
    }

    let end = base
        .checked_add(len as u64)
        .ok_or(UserSliceError::Overflow)?;

    if base >= USER_SPACE_END || end > USER_SPACE_END {
        return Err(UserSliceError::KernelAddress);
    }

    // Walk every page in the region and check the page tables.
    let required_flags = match access {
        Access::Read => PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
        Access::Write => {
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE | PageTableFlags::WRITABLE
        }
    };

    check_pages_mapped(base, len, required_flags)
}

/// Walk the active page tables to verify that every 4 KiB page covering
/// `[base, base+len)` is mapped with at least `required_flags`.
fn check_pages_mapped(
    base: u64,
    len: usize,
    required_flags: PageTableFlags,
) -> Result<(), UserSliceError> {
    use x86_64::registers::control::Cr3;
    use x86_64::structures::paging::{OffsetPageTable, PageTable};

    let hhdm = crate::memory::hhdm_offset();
    let phys_offset = VirtAddr::new(hhdm);

    // Read the active CR3 to get the current process's page table.
    let (l4_frame, _) = Cr3::read();
    let l4_phys = l4_frame.start_address().as_u64();
    let l4_virt = VirtAddr::new(l4_phys + hhdm);

    // SAFETY: The HHDM mapping is always valid for physical RAM.
    // We only read the page tables; no mutation.
    let mapper =
        unsafe { OffsetPageTable::new(&mut *l4_virt.as_mut_ptr::<PageTable>(), phys_offset) };

    let page_size: u64 = 4096;
    let start_page = base & !0xFFF; // Round down to page boundary
    let end_addr = base + len as u64;

    let mut addr = start_page;
    while addr < end_addr {
        let vaddr = VirtAddr::new(addr);

        // Use the x86_64 crate's full translate to get the mapped frame + flags.
        use x86_64::structures::paging::mapper::TranslateResult;
        match mapper.translate(vaddr) {
            TranslateResult::Mapped { flags, .. } => {
                // Check that the mapping has all required flags
                if !flags.contains(required_flags) {
                    log::trace!(
                        "UserSlice: page {:#x} missing flags: have {:?}, need {:?}",
                        addr,
                        flags,
                        required_flags
                    );
                    return Err(UserSliceError::PermissionDenied);
                }
            }
            TranslateResult::NotMapped | TranslateResult::InvalidFrameAddress(_) => {
                log::trace!("UserSlice: page {:#x} not mapped", addr);
                return Err(UserSliceError::NotMapped);
            }
        }

        addr += page_size;
    }

    Ok(())
}

// ============================================================================
// UserSliceRead — validated read-only access to user memory
// ============================================================================

/// A validated read-only reference to a user-space memory region.
///
/// Construction validates that `[ptr, ptr+len)` is mapped and readable
/// by the current process. After construction, the kernel can safely
/// read from this region.
///
/// **Note**: The mapping could theoretically be changed by another thread
/// between validation and use. On our single-core kernel this can't happen
/// because we don't preempt during a syscall handler (interrupts are
/// re-enabled but the scheduler won't remove our mappings). For SMP this
/// would need additional protection (e.g. pinning pages).
pub struct UserSliceRead {
    ptr: u64,
    len: usize,
}

impl UserSliceRead {
    /// Create a new validated read-only user slice.
    ///
    /// Fails if:
    /// - `ptr` is null
    /// - `ptr + len` overflows or crosses into kernel space
    /// - Any page in the range is not mapped or not user-accessible
    pub fn new(ptr: u64, len: usize) -> Result<Self, UserSliceError> {
        validate_user_region(ptr, len, Access::Read)?;
        Ok(UserSliceRead { ptr, len })
    }

    /// The length of the validated region in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the region is empty (zero length).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Copy validated user data into a kernel-owned `Vec<u8>`.
    ///
    /// Returns a vector containing a copy of the user memory.
    pub fn read_to_vec(&self) -> Vec<u8> {
        if self.len == 0 {
            return Vec::new();
        }

        let mut buf = alloc::vec![0u8; self.len];
        // SAFETY: We validated that [ptr, ptr+len) is mapped and user-readable.
        unsafe {
            core::ptr::copy_nonoverlapping(self.ptr as *const u8, buf.as_mut_ptr(), self.len);
        }
        buf
    }

    /// Copy validated user data into a kernel buffer.
    ///
    /// Copies `min(self.len, dest.len())` bytes and returns how many were copied.
    pub fn copy_to(&self, dest: &mut [u8]) -> usize {
        let n = core::cmp::min(self.len, dest.len());
        if n == 0 {
            return 0;
        }

        // SAFETY: We validated that [ptr, ptr+n) is mapped and user-readable.
        // n <= self.len, so we stay within the validated region.
        unsafe {
            core::ptr::copy_nonoverlapping(self.ptr as *const u8, dest.as_mut_ptr(), n);
        }
        n
    }

    /// Get the raw pointer (for logging/debugging only).
    pub fn as_ptr(&self) -> u64 {
        self.ptr
    }
}

// ============================================================================
// UserSliceWrite — validated write access to user memory
// ============================================================================

/// A validated writable reference to a user-space memory region.
///
/// Construction validates that `[ptr, ptr+len)` is mapped, user-accessible,
/// and writable. After construction, the kernel can safely write to this region.
pub struct UserSliceWrite {
    ptr: u64,
    len: usize,
}

impl UserSliceWrite {
    /// Create a new validated writable user slice.
    ///
    /// Fails if:
    /// - `ptr` is null
    /// - `ptr + len` overflows or crosses into kernel space
    /// - Any page in the range is not mapped, not user-accessible, or not writable
    pub fn new(ptr: u64, len: usize) -> Result<Self, UserSliceError> {
        validate_user_region(ptr, len, Access::Write)?;
        Ok(UserSliceWrite { ptr, len })
    }

    /// The length of the validated region in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the region is empty (zero length).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Copy kernel data into validated user memory.
    ///
    /// Copies `min(src.len(), self.len)` bytes and returns how many were copied.
    pub fn copy_from(&self, src: &[u8]) -> usize {
        let n = core::cmp::min(src.len(), self.len);
        if n == 0 {
            return 0;
        }

        // SAFETY: We validated that [ptr, ptr+n) is mapped and user-writable.
        // n <= self.len, so we stay within the validated region.
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), self.ptr as *mut u8, n);
        }
        n
    }

    /// Zero-fill the validated user memory region.
    pub fn zero(&self) {
        if self.len == 0 {
            return;
        }

        // SAFETY: We validated that [ptr, ptr+len) is mapped and user-writable.
        unsafe {
            core::ptr::write_bytes(self.ptr as *mut u8, 0, self.len);
        }
    }

    /// Get the raw pointer (for logging/debugging only).
    pub fn as_ptr(&self) -> u64 {
        self.ptr
    }
}

// ============================================================================
// UserSliceReadWrite — validated read+write access to user memory
// ============================================================================

/// A validated read-write reference to a user-space memory region.
///
/// Construction validates that `[ptr, ptr+len)` is mapped, user-accessible,
/// and writable (writable implies readable on x86_64).
pub struct UserSliceReadWrite {
    ptr: u64,
    len: usize,
}

impl UserSliceReadWrite {
    /// Create a new validated read-write user slice.
    pub fn new(ptr: u64, len: usize) -> Result<Self, UserSliceError> {
        validate_user_region(ptr, len, Access::Write)?;
        Ok(UserSliceReadWrite { ptr, len })
    }

    /// The length of the validated region in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the region is empty (zero length).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Copy validated user data into a kernel buffer.
    pub fn copy_to(&self, dest: &mut [u8]) -> usize {
        let n = core::cmp::min(self.len, dest.len());
        if n == 0 {
            return 0;
        }
        // SAFETY: Validated as writable (which implies readable on x86_64).
        unsafe {
            core::ptr::copy_nonoverlapping(self.ptr as *const u8, dest.as_mut_ptr(), n);
        }
        n
    }

    /// Copy kernel data into validated user memory.
    pub fn copy_from(&self, src: &[u8]) -> usize {
        let n = core::cmp::min(src.len(), self.len);
        if n == 0 {
            return 0;
        }
        // SAFETY: Validated as writable.
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), self.ptr as *mut u8, n);
        }
        n
    }

    /// Get the raw pointer (for logging/debugging only).
    pub fn as_ptr(&self) -> u64 {
        self.ptr
    }
}
