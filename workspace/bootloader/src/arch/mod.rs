use crate::os::Os;

// Only x86_64 is currently supported
// x32 and x64 modules have been replaced with x86_64
pub mod x86_64;

// Compatibility aliases for old code
use x86_64 as x64;

pub unsafe fn paging_create(os: &impl Os, kernel_phys: u64, kernel_size: u64) -> Option<usize> {
    unsafe {
        if crate::KERNEL_64BIT {
            x64::paging_create(os, kernel_phys, kernel_size)
        } else {
            x32::paging_create(os, kernel_phys, kernel_size)
        }
    }
}

pub unsafe fn paging_framebuffer(
    os: &impl Os,
    page_phys: usize,
    framebuffer_phys: u64,
    framebuffer_size: u64,
) -> Option<u64> {
    unsafe {
        if crate::KERNEL_64BIT {
            x64::paging_framebuffer(os, page_phys, framebuffer_phys, framebuffer_size)
        } else {
            x32::paging_framebuffer(os, page_phys, framebuffer_phys, framebuffer_size)
        }
    }
}