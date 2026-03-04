#![no_std]

/// Boot ABI exports shared with kernel handoff.
pub use strat9_abi::boot::{KernelArgs, MemoryKind, MemoryRegion};
