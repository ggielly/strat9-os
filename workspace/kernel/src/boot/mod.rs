//! Boot subsystem
//!
//! Regroups all code involved in the early kernel startup:
//! - assembly stubs (16-bit → 64-bit transition)
//! - bootloader handoff structures (KernelArgs)
//! - Limine boot-protocol entry point
//! - early serial logger
//! - kernel panic handler

// Assembly stub that includes boot64.S
pub mod assembly;

/// KernelArgs structures shared between bootloader and kernel
pub mod entry;

/// Limine boot-protocol entry point
pub mod limine;

/// Early serial logger (used throughout the kernel lifetime)
pub mod logger;

/// Kernel panic handler
pub mod panic;
