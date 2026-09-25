//! Architecture aware access to physical RAM.

use crate::arch::xshim::PhysAddr;

/// Returns the direct mapped virtual address for a physical byte, when reachable.
#[inline]
pub fn phys_to_virt_checked(phys: u64) -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        let virt = crate::memory::phys_to_virt(phys);
        if crate::memory::paging::is_hhdm_range_mapped_now(phys, 1) { Some(virt) } else { None }
    }
    #[cfg(target_arch = "riscv64")]
    {
        let _ = phys;
        None
    }
}

/// Check access to a physical interval using the current architecture backend.
#[inline]
pub fn range_accessible(phys: u64, size: u64) -> bool {
    #[cfg(target_arch = "x86_64")]
    { crate::memory::paging::is_hhdm_range_mapped_now(phys, size) }
    #[cfg(target_arch = "riscv64")]
    { identity_range_accessible(phys, size) }
}

/// True only when the RISC-V boot path has installed an identity map. The
/// current port does not establish one, so it reports no physical access.
#[inline]
pub fn identity_range_accessible(phys: u64, size: u64) -> bool {
    let _ = (phys, size);
    false
}

/// Clear one physical frame through the architecture's early-access mapping.
pub fn zero_frame(frame: PhysAddr) -> bool {
    let Some(virt) = phys_to_virt_checked(frame.as_u64()) else { return false; };
    // SAFETY: caller owns the frame and the architecture backend confirmed its mapping.
    unsafe { core::ptr::write_bytes(virt as *mut u8, 0, crate::memory::frame::PAGE_SIZE as usize); }
    true
}
