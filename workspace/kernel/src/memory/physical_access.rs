//! Architecture aware access to physical RAM.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::xshim::PhysAddr;

#[cfg(target_arch = "riscv64")]
static RAM_START: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "riscv64")]
static RAM_END: AtomicU64 = AtomicU64::new(0);

/// Returns the direct mapped virtual address for a physical byte, when reachable.
#[inline]
pub fn phys_to_virt_checked(phys: u64) -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        let virt = crate::memory::phys_to_virt(phys);
        if crate::memory::paging::is_hhdm_range_mapped_now(phys, 1) {
            Some(virt)
        } else {
            None
        }
    }
    #[cfg(target_arch = "riscv64")]
    {
        identity_range_accessible(phys, 1).then_some(phys)
    }
}

/// Check access to a physical interval using the current architecture backend.
#[inline]
pub fn range_accessible(phys: u64, size: u64) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        crate::memory::paging::is_hhdm_range_mapped_now(phys, size)
    }
    #[cfg(target_arch = "riscv64")]
    {
        identity_range_accessible(phys, size)
    }
}

/// RISC-V keeps an identity mapping for the RAM covered by the boot mapper.
#[inline]
#[cfg(target_arch = "riscv64")]
pub fn identity_range_accessible(phys: u64, size: u64) -> bool {
    let Some(end) = phys.checked_add(size) else {
        return false;
    };
    end <= RAM_END.load(Ordering::Acquire) && phys >= RAM_START.load(Ordering::Acquire)
}

#[cfg(target_arch = "riscv64")]
pub fn set_riscv_ram_range(start: u64, end: u64) {
    RAM_START.store(start, Ordering::Release);
    RAM_END.store(end, Ordering::Release);
}

/// Clear one physical frame through the architecture's early-access mapping.
pub fn zero_frame(frame: PhysAddr) -> bool {
    let Some(virt) = phys_to_virt_checked(frame.as_u64()) else {
        return false;
    };
    // SAFETY: caller owns the frame and the architecture backend confirmed its mapping.
    unsafe {
        core::ptr::write_bytes(virt as *mut u8, 0, crate::memory::frame::PAGE_SIZE as usize);
    }
    true
}
