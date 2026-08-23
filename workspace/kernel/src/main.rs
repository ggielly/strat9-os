//! Strat9-OS kernel entry point
//!
//! Kernel entry point.

#![no_std]
#![no_main]

extern crate alloc;

/// Kernel entry point
///
/// Convention: rdi = pointer to `KernelArgs` (0 for PVH boot, see
/// `boot::dtb_boot::kmain`)
#[no_mangle]
pub unsafe extern "C" fn kernel_main(args_ptr: u64) -> ! {
    strat9_kernel::boot::dtb_boot::kmain(args_ptr)
}
