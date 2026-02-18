// Heap allocator implementation using buddy allocator

use crate::memory::buddy::get_allocator;
use crate::memory::frame::{FrameAllocator, PhysFrame};
use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use x86_64::PhysAddr;

/// Locked heap wrapper for GlobalAlloc
pub struct LockedHeap;

unsafe impl GlobalAlloc for LockedHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Round up to nearest power of 2 pages
        let size = layout.size().max(layout.align());
        let pages_needed = (size + 4095) / 4096;

        // Calculate order (power of 2 for pages_needed)
        let order = if pages_needed == 0 {
            0
        } else {
            let order_calc = (pages_needed.next_power_of_two().trailing_zeros() as u8).min(11);
            order_calc
        };

        // Allocate from buddy allocator
        let allocator_lock = get_allocator();
        let mut allocator_guard = allocator_lock.lock();

        if let Some(ref mut allocator) = *allocator_guard {
            match allocator.alloc(order) {
                Ok(frame) => super::phys_to_virt(frame.start_address.as_u64()) as *mut u8,
                Err(_) => ptr::null_mut(),
            }
        } else {
            ptr::null_mut()
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let size = layout.size().max(layout.align());
        let pages_needed = (size + 4095) / 4096;
        let order = if pages_needed == 0 {
            0
        } else {
            (pages_needed.next_power_of_two().trailing_zeros() as u8).min(11)
        };

        let allocator_lock = get_allocator();
        let mut allocator_guard = allocator_lock.lock();

        if let Some(ref mut allocator) = *allocator_guard {
            // Convert virtual address back to physical for the buddy allocator
            let hhdm = super::HHDM_OFFSET.load(core::sync::atomic::Ordering::Relaxed);
            let phys_addr = (ptr as u64).wrapping_sub(hhdm);
            let frame = PhysFrame::from_start_address(PhysAddr::new(phys_addr))
                .expect("dealloc called with unaligned pointer");
            allocator.free(frame, order);
        }
    }
}

#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap = LockedHeap;

#[alloc_error_handler]
fn alloc_error_handler(layout: Layout) -> ! {
    panic!("allocation error: {:?}", layout)
}
