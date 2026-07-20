//! Strat9-OS kernel entry point
//!
//! Kernel entry point.

#![no_std]
#![no_main]

extern crate alloc;

/// Kernel entry point
///
/// Convention: rdi = DTB physical address
#[no_mangle]
pub unsafe extern "C" fn kernel_main(dtb_ptr: u64) -> ! {
    strat9_kernel::boot::dtb_boot::kmain(dtb_ptr)
}
