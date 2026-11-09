/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

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

#![allow(unsafe_code)]
#![allow(unsafe_op_in_unsafe_fn)]

extern crate alloc;

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
        /// Writes str.
        fn write_str(&mut self, s: &str) -> Result {
            // SAFETY: serial port is initialized early in boot and is a shared resource.
            // We accept potential race conditions during early boot for debug output.
            crate::arch::serial::_print(format_args!("{}", s));
            Ok(())
        }
    }
}
