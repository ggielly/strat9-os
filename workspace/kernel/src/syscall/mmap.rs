//! Memory-management syscall handlers: mmap, munmap, brk.
//!
//! Implements:
//!  - [`sys_mmap`]   – map anonymous virtual memory (SYS_MMAP = 100)
//!  - [`sys_munmap`] – unmap a virtual memory range (SYS_MUNMAP = 101)
//!  - [`sys_brk`]    – set / query the program break / heap top (SYS_BRK = 102)

use crate::{
    memory::address_space::{VmaFlags, VmaType},
    process::current_task_clone,
    syscall::error::SyscallError,
};
use core::sync::atomic::Ordering;

// ─────────────────────────────────────────────────────────────────────────────
// Virtual address layout constants
// ─────────────────────────────────────────────────────────────────────────────

/// Base virtual address for the heap (`brk`-managed region).
pub const BRK_BASE: u64 = 0x0000_0000_2000_0000; // 512 MiB

/// Initial hint address for anonymous `mmap` allocations.
pub const MMAP_BASE: u64 = 0x0000_0000_6000_0000; // 1.5 GiB

/// Exclusive upper bound of the canonical user-space address range.
const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;

// ─────────────────────────────────────────────────────────────────────────────
// PROT flags (arg3 of mmap)
// ─────────────────────────────────────────────────────────────────────────────

const PROT_READ: u32 = 1 << 0;
const PROT_WRITE: u32 = 1 << 1;
const PROT_EXEC: u32 = 1 << 2;

// ─────────────────────────────────────────────────────────────────────────────
// MAP flags (arg4 of mmap)
// ─────────────────────────────────────────────────────────────────────────────

const MAP_SHARED: u32 = 1 << 0;
const MAP_PRIVATE: u32 = 1 << 1;
const MAP_FIXED: u32 = 1 << 4;
const MAP_ANONYMOUS: u32 = 1 << 5;
const MAP_HUGETLB: u32 = 1 << 11; // Standard Linux flag for huge pages
const MAP_FIXED_NOREPLACE: u32 = 1 << 20; // Linux-compatible extension bit.

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Round `addr` up to the nearest 4 KiB page boundary.
#[inline]
fn page_align_up(addr: u64) -> u64 {
    (addr.wrapping_add(4095)) & !4095u64
}

/// Round `addr` up to the nearest 2 MiB boundary.
#[inline]
fn huge_page_align_up(addr: u64) -> u64 {
    (addr.wrapping_add((2 * 1024 * 1024) - 1)) & !((2 * 1024 * 1024) - 1)
}

/// Convert POSIX protection flags to `VmaFlags`.
fn prot_to_vma_flags(prot: u32) -> VmaFlags {
    VmaFlags {
        readable: prot & PROT_READ != 0,
        writable: prot & PROT_WRITE != 0,
        executable: prot & PROT_EXEC != 0,
        user_accessible: true,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// sys_mmap
// ─────────────────────────────────────────────────────────────────────────────

/// SYS_MMAP (100): map anonymous virtual memory.
///
/// Only `MAP_ANONYMOUS` mappings are supported at this stage; file-backed mmaps
/// return `NotImplemented`.  Both `MAP_PRIVATE` and `MAP_SHARED` are accepted
/// for anonymous memory (they are equivalent when there is no backing file).
///
/// Returns the mapped virtual address on success, or a negative error code.
pub fn sys_mmap(
    addr: u64,
    len: u64,
    prot: u32,
    flags: u32,
    _fd: u64,
    _offset: u64,
) -> Result<u64, SyscallError> {
    //  Validate arguments
    if len == 0 {
        return Err(SyscallError::InvalidArgument);
    }

    let known_flags =
        MAP_SHARED | MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_HUGETLB | MAP_FIXED_NOREPLACE;
    if flags & !known_flags != 0 {
        return Err(SyscallError::InvalidArgument);
    }

    let is_huge = flags & MAP_HUGETLB != 0;
    let page_size = if is_huge {
        crate::memory::address_space::VmaPageSize::Huge
    } else {
        crate::memory::address_space::VmaPageSize::Small
    };
    let page_bytes = page_size.bytes();

    // File-backed mappings are not yet implemented.
    if flags & MAP_ANONYMOUS == 0 {
        log::warn!("sys_mmap: file-backed mmap not yet supported");
        return Err(SyscallError::NotImplemented);
    }

    let is_private = flags & MAP_PRIVATE != 0;
    let is_shared = flags & MAP_SHARED != 0;
    // Exactly one of MAP_PRIVATE / MAP_SHARED.
    if is_private == is_shared {
        return Err(SyscallError::InvalidArgument);
    }

    // Anonymous mapping currently requires page-aligned zero offset.
    if _offset != 0 {
        return Err(SyscallError::InvalidArgument);
    }

    // Reject unknown PROT bits.
    if prot & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0 {
        return Err(SyscallError::InvalidArgument);
    }

    // Round len up to a page boundary.  Overflow of len itself is caught here.
    let len_aligned = if is_huge {
        huge_page_align_up(len)
    } else {
        page_align_up(len)
    };
    if len_aligned == 0 {
        // len was so large that aligning it overflowed to 0.
        return Err(SyscallError::InvalidArgument);
    }
    let n_pages = (len_aligned / page_bytes) as usize;

    //  Determine the target virtual address
    let task = current_task_clone().ok_or(SyscallError::Fault)?;
    let addr_space = unsafe { &*task.address_space.get() };

    let target = if flags & MAP_FIXED != 0 {
        // MAP_FIXED: the caller demands this exact page-aligned address.
        if addr % page_bytes != 0 || addr == 0 {
            return Err(SyscallError::InvalidArgument);
        }
        if addr.saturating_add(len_aligned) > USER_SPACE_END {
            return Err(SyscallError::InvalidArgument);
        }
        if flags & MAP_FIXED_NOREPLACE != 0 {
            // MAP_FIXED_NOREPLACE: fail if any mapping overlaps.
            if addr_space.has_mapping_in_range(addr, len_aligned) {
                return Err(SyscallError::AlreadyExists);
            }
        } else {
            // Linux MAP_FIXED semantics: unmap overlaps before remap.
            addr_space
                .unmap_range(addr, len_aligned)
                .map_err(|_| SyscallError::InvalidArgument)?;
        }
        addr
    } else {
        // Hint-based: use addr as a hint when non-zero, else use mmap_hint.
        let hint = if addr != 0 {
            addr
        } else {
            task.mmap_hint.load(Ordering::Relaxed)
        };

        // Try the hint first, then fall back to MMAP_BASE.
        addr_space
            .find_free_vma_range(hint, n_pages, page_size)
            .or_else(|| addr_space.find_free_vma_range(MMAP_BASE, n_pages, page_size))
            .ok_or(SyscallError::OutOfMemory)?
    };

    //  Map the region (lazily)
    let vma_flags = prot_to_vma_flags(prot);
    addr_space
        .reserve_region(target, n_pages, vma_flags, VmaType::Anonymous, page_size)
        .map_err(|_| SyscallError::OutOfMemory)?;

    //  Advance mmap_hint past the new mapping (non-fixed only)
    if flags & MAP_FIXED == 0 {
        let new_hint = target.saturating_add(len_aligned);
        // Atomically advance: only update if it moves forward.
        let _ = task.mmap_hint.fetch_max(new_hint, Ordering::Relaxed);
    }

    log::trace!(
        "sys_mmap: mapped {:#x}..{:#x} ({} pages, prot={:#x}, flags={:#x})",
        target,
        target + len_aligned,
        n_pages,
        prot,
        flags,
    );

    Ok(target)
}

// ─────────────────────────────────────────────────────────────────────────────
// sys_munmap
// ─────────────────────────────────────────────────────────────────────────────

/// SYS_MUNMAP (101): unmap a virtual memory range.
///
/// `addr` must be page-aligned.  `len` is rounded up to a page boundary.
/// Unmapping an address range that contains no mappings is silently ignored
/// (POSIX behaviour).
pub fn sys_munmap(addr: u64, len: u64) -> Result<u64, SyscallError> {
    if addr == 0 || addr & 0xFFF != 0 {
        return Err(SyscallError::InvalidArgument);
    }
    if len == 0 {
        return Err(SyscallError::InvalidArgument);
    }

    let len_aligned = page_align_up(len);
    if len_aligned == 0 {
        return Err(SyscallError::InvalidArgument);
    }
    if addr.saturating_add(len_aligned) > USER_SPACE_END {
        return Err(SyscallError::InvalidArgument);
    }

    let task = current_task_clone().ok_or(SyscallError::Fault)?;
    unsafe { &*task.address_space.get() }
        .unmap_range(addr, len_aligned)
        .map_err(|_| SyscallError::InvalidArgument)?;

    log::trace!(
        "sys_munmap: unmapped {:#x}..{:#x}",
        addr,
        addr + len_aligned
    );

    Ok(0)
}

// ─────────────────────────────────────────────────────────────────────────────
// sys_brk
// ─────────────────────────────────────────────────────────────────────────────

/// SYS_BRK (102): set or query the program break (top of heap).
///
/// Calling convention (matches Linux):
///
/// | `addr`          | Behaviour                                              |
/// |-----------------|--------------------------------------------------------|
/// | `0`             | Query — return current break unchanged.                |
/// | `> current_brk` | Extend heap; new pages are zero-filled RW anonymous.   |
/// | `< current_brk` | Shrink heap; backing pages are freed.                  |
/// | `< BRK_BASE`    | Invalid — return current break unchanged (Linux compat).|
///
/// On any error (OOM, out-of-range) the **unchanged** break is returned rather
/// than a negative code — this is the Linux `brk(2)` contract.
pub fn sys_brk(addr: u64) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::Fault)?;

    // ── Lazy initialisation ───────────────────────────────────────────────
    // `task.brk == 0` means this task has never called brk.  The heap starts
    // empty at BRK_BASE; no pages are mapped yet.
    let current_brk = {
        let raw = task.brk.load(Ordering::Relaxed);
        if raw == 0 {
            task.brk.store(BRK_BASE, Ordering::Relaxed);
            BRK_BASE
        } else {
            raw
        }
    };

    // ── Query ─────────────────────────────────────────────────────────────
    if addr == 0 {
        return Ok(current_brk);
    }

    // ── Range checks ─────────────────────────────────────────────────────
    // Reject attempts to move the break below the heap base or into kernel AS.
    if addr < BRK_BASE || addr >= USER_SPACE_END {
        return Ok(current_brk); // return unchanged (Linux behaviour)
    }

    // ── Compute page-aligned extents ──────────────────────────────────────
    // The heap occupies [BRK_BASE, page_align_up(current_brk)).
    // Any bytes in the last partial page are already backed but not accounted
    // for in the page-end calculation — they stay mapped on shrink.
    let old_page_end = page_align_up(current_brk);
    let new_page_end = page_align_up(addr);

    if new_page_end > old_page_end {
        // ── Grow: map [old_page_end, new_page_end) ────────────────────────
        let n_pages = ((new_page_end - old_page_end) / 4096) as usize;
        let vma_flags = VmaFlags {
            readable: true,
            writable: true,
            executable: false,
            user_accessible: true,
        };
        if unsafe { &*task.address_space.get() }
            .reserve_region(
                old_page_end,
                n_pages,
                vma_flags,
                VmaType::Anonymous,
                crate::memory::address_space::VmaPageSize::Small,
            )
            .is_err()
        {
            // OOM — return the unchanged break (Linux behaviour).
            return Ok(current_brk);
        }
        log::trace!(
            "sys_brk: grow {:#x}..{:#x} ({} pages)",
            old_page_end,
            new_page_end,
            n_pages,
        );
    } else if new_page_end < old_page_end {
        // ── Shrink: unmap [new_page_end, old_page_end) ───────────────────
        let len = old_page_end - new_page_end;
        if unsafe { &*task.address_space.get() }
            .unmap_range(new_page_end, len)
            .is_err()
        {
            return Ok(current_brk);
        }
        log::trace!(
            "sys_brk: shrink {:#x}..{:#x} (-{} pages)",
            new_page_end,
            old_page_end,
            len / 4096,
        );
    }
    // If new_page_end == old_page_end, only the sub-page byte offset changed;
    // no page-table operations are needed.

    // ── Commit the new exact-byte program break ───────────────────────────
    task.brk.store(addr, Ordering::Relaxed);
    Ok(addr)
}
