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

//! Hardware Abstraction Layer (HAL) for multi-architecture support.
//!
//! This module defines the trait interface that each architecture must implement,
//! and provides the architecture-specific implementations.

pub mod x86_64;

/// Hardware Abstraction Layer trait.
///
/// Each architecture must implement this trait to provide
/// architecture-specific operations.
pub trait Hal {
    /// Initialize the HAL for the current architecture.
    fn init();

    /// Set up virtual memory paging.
    fn setup_paging();

    /// Initialize the interrupt controller.
    fn init_interrupt_controller();

    /// Enable interrupts.
    fn enable_interrupts();

    /// Disable interrupts.
    fn disable_interrupts();

    /// Halt the CPU until the next interrupt.
    fn halt();

    /// Get the current CPU ID (for SMP).
    fn current_cpu_id() -> u32;

    /// Get the physical address of the kernel text section start.
    fn kernel_text_start() -> u64;

    /// Get the physical address of the kernel text section end.
    fn kernel_text_end() -> u64;
}

/// Initialize the HAL for the current architecture.
///
/// This function dispatches to the correct architecture-specific implementation.
pub fn init_hal() {
    #[cfg(target_arch = "x86_64")]
    x86_64::X86_64Hal::init();

    #[cfg(not(target_arch = "x86_64"))]
    crate::serial_println!("[hal] No HAL implementation for this architecture");
}
