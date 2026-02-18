//! OSTD-like (OS Trusted Domain) abstraction layer for Strat9-OS
//!
//! This module provides a minimal, auditable unsafe code base that abstracts
//! hardware operations behind safe interfaces. Inspired by Asterinas OSTD.
//!
//! # Design concept
//!
//! - **Minimal TCB**: only essential unsafe code lives here
//! - **Safe Abstractions**: all public APIs are safe wrappers
//! - **Hardware Traits**: platform-independent interfaces
//! - **Confined Unsafe**: all `unsafe` blocks are justified with SAFETY comments

#![no_std]
#![allow(unsafe_code)]
#![allow(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod boot;
pub mod cpu;
pub mod mm;
pub mod task;
pub mod util;

pub use cpu::CpuId;
pub use mm::{PhysAddr, VirtAddr};

/// Early print macro for bootstrap debugging (before full logger is ready)
#[macro_export]
macro_rules! early_println {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = write!($crate::ostd::early_print::EarlyWriter, $($arg)*);
        let _ = writeln!($crate::ostd::early_print::EarlyWriter);
    }};
}

/// Early print macro without newline
#[macro_export]
macro_rules! early_print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = write!($crate::ostd::early_print::EarlyWriter, $($arg)*);
    }};
}

pub mod early_print {
    //! Early debugging output via serial port
    //!
    //! Available before the full logger is initialized.

    use core::fmt::{Result, Write};

    pub struct EarlyWriter;

    impl Write for EarlyWriter {
        fn write_str(&mut self, s: &str) -> Result {
            // SAFETY: serial port is initialized early in boot and is a shared resource.
            // We accept potential race conditions during early boot for debug output.
            use core::fmt::Write;
            crate::arch::x86_64::serial::_print(format_args!("{}", s));
            Ok(())
        }
    }
}
