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
