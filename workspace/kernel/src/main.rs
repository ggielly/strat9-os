//! Strat9-OS kernel entry point
//!
//! U-Boot entry point for the kernel.

#![no_std]
#![no_main]

extern crate alloc;

/// U-Boot kernel entry point
///
/// Convention: rdi = DTB physical address
#[no_mangle]
pub unsafe extern "C" fn kernel_main(dtb_ptr: u64) -> ! {
    strat9_kernel::boot::uboot::kmain(dtb_ptr)
}
