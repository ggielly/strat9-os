//! Strat9-OS kernel entry point
//!
//! Legacy entry point for custom bootloader compatibility.
//! The actual kernel_main implementation is in lib.rs.

#![no_std]
#![no_main]

extern crate alloc;

use strat9_kernel::entry::KernelArgs;

/// Legacy kernel entry point - forwards to lib.rs implementation
#[no_mangle]
pub unsafe extern "C" fn kernel_main(args: *const KernelArgs) -> ! {
    strat9_kernel::kernel_main(args)
}
