use core::slice;

use crate::area_add;
use crate::os::{Os, OsMemoryEntry, OsMemoryKind};

const ENTRY_ADDRESS_MASK: u64 = 0x000F_FFFF_FFFF_F000;
const PAGE_ENTRIES: usize = 1024; // For x86 (32-bit) we use 1024 entries
const PAGE_SIZE: usize = 4096;
pub(crate) const PHYS_OFFSET: u64 = 0xC000_0000; // Higher half kernel for x86

unsafe fn paging_allocate(os: &impl Os) -> Option<&'static mut [u64]> {
    unsafe {
        let ptr = os.alloc_zeroed_page_aligned(PAGE_SIZE);
        if !ptr.is_null() {
            area_add(OsMemoryEntry {
                base: ptr as u64,
                size: PAGE_SIZE as u64,
                kind: OsMemoryKind::Reclaim,
            });

            Some(slice::from_raw_parts_mut(ptr as *mut u64, PAGE_ENTRIES))
        } else {
            None
        }
    }
}

const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const LARGE: u64 = 1 << 7;

pub unsafe fn paging_create(os: &impl Os, kernel_phys: u64, kernel_size: u64) -> Option<usize> {
    unsafe {
        // Create Page Directory
        let pd = paging_allocate(os)?;

        // Identity map the first 4 GiB using 4 MiB pages
        for i in 0..1024 {
            let addr = i as u64 * 0x40_0000; // 4 MiB per page
            pd[i] = addr | LARGE | WRITABLE | PRESENT;
        }

        // Create Page Table for kernel mapping
        let pt = paging_allocate(os)?;

        // Map kernel in higher half (0xC0000000)
        let kernel_virt = 0xC000_0000u64;
        let mut kernel_mapped = 0;

        for i in 0..1024 {
            if kernel_mapped >= kernel_size {
                break;
            }

            let phys_addr = kernel_phys + kernel_mapped;
            pt[i] = phys_addr | WRITABLE | PRESENT;
            kernel_mapped += PAGE_SIZE as u64;
        }

        // Put the kernel page table in the right position in the page directory
        // Map virtual address 0xC0000000 to onwards
        let kernel_pd_index = (kernel_virt / (PAGE_SIZE as u64 * 1024)) as usize; // 0xC00
        pd[kernel_pd_index] = pt.as_ptr() as u64 | WRITABLE | PRESENT;

        Some(pd.as_ptr() as usize)
    }
}

pub unsafe fn paging_framebuffer(
    os: &impl Os,
    page_phys: usize,
    framebuffer_phys: u64,
    framebuffer_size: u64,
) -> Option<u64> {
    unsafe {
        // For x86, map the framebuffer to a virtual address
        let fb_virt = 0xFD00_0000; // Somewhere in higher half

        // Get the page directory
        let pd = slice::from_raw_parts_mut(page_phys as *mut u64, PAGE_ENTRIES);

        // Calculate which page table entry to use
        let pd_index = (fb_virt / (PAGE_SIZE as u64 * 1024)) as usize;

        // Create a new page table if needed
        let pt = if pd[pd_index] & PRESENT == 0 {
            let new_pt = paging_allocate(os)?;
            pd[pd_index] = new_pt.as_ptr() as u64 | WRITABLE | PRESENT;
            new_pt
        } else {
            slice::from_raw_parts_mut(
                (pd[pd_index] & ENTRY_ADDRESS_MASK) as *mut u64,
                PAGE_ENTRIES,
            )
        };

        // Calculate the offset within the page table
        let pt_index = ((fb_virt % (PAGE_SIZE as u64 * 1024)) / PAGE_SIZE as u64) as usize;

        // Map the framebuffer
        pt[pt_index] = framebuffer_phys | WRITABLE | PRESENT;

        Some(fb_virt)
    }
}
