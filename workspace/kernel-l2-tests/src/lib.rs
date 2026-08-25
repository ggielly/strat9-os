//! L2 host-test harness for the Bedrock kernel.
//!
//! This crate compiles **verbatim copies** of the kernel's pure modules via
//! `#[path]` includes, resolving their `crate::` dependencies against
//! functional stand-ins defined here:
//!
//! - `sync::irq` — fake: single-threaded host, `with_irqs_disabled` is a no-op
//!   wrapper handing out a dummy [`IrqDisabledToken`].
//! - `memory` — fake frame allocator backed by an in-memory arena, exposing
//!   the same `allocate_frame`/`free_frame`/`PhysFrame` surface the IPC ring
//!   code uses.
//!
//! Everything else (spinlocks, fixed queues, guardian tokens, IPC rings,
//! TOML boot config parser, syscall error mapping) is the REAL kernel code.
//! The inline `#[cfg(test)]` suites shipped inside those files run here too.

#![feature(negative_impls)]
#![allow(dead_code, unused_imports, unused_variables)]

extern crate alloc;

// ===========================================================================
// Kernel tree mirror — pure modules only
// ===========================================================================

// Root re-export of the fake IRQ layer so included modules resolving
// `crate::sync::*` / memory fakes find it.
pub use sync::irq::{with_irqs_disabled, IrqDisabledToken};

/// Fake arch layer: only the per-CPU preemption hooks the sync primitives
/// touch; on the host there is a single test thread.
pub mod arch {
    pub mod x86_64 {
        /// Fake RFLAGS save/restore: single thread, nothing to mask.
        pub fn save_flags_and_cli() -> u64 {
            0x200 // pretend IF was set
        }
        pub fn restore_flags(_flags: u64) {}

        pub mod percpu {
            pub const MAX_CPUS: usize = 32;

            static COUNT: core::sync::atomic::AtomicUsize =
                core::sync::atomic::AtomicUsize::new(0);

            pub fn preempt_disable() {
                COUNT.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
            }
            pub fn preempt_enable() {
                let prev = COUNT.fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
                debug_assert!(prev > 0, "unbalanced preempt_enable");
            }
            #[allow(dead_code)]
            pub fn preempt_count() -> usize {
                COUNT.load(core::sync::atomic::Ordering::SeqCst)
            }
            #[allow(dead_code)]
            pub fn current_cpu_index() -> usize {
                0
            }
            #[allow(dead_code)]
            pub fn cpu_count() -> usize {
                MAX_CPUS
            }
        }
    }
}

/// Fake process layer: blocking/waking cannot happen on the host.
pub mod process {
    /// Stand-in panic: kernel code must never reach this in host tests.
    pub fn block_current_task() {
        panic!("process::block_current_task called on host — test tried to block");
    }
}

/// Fake silo layer: boot-time debug registration is off on the host.
pub mod silo {
    pub fn debug_boot_reg_active() -> bool {
        false
    }
}

// Kernel serial macros: route to stderr so test output stays visible.
#[macro_export]
macro_rules! serial_println {
    ($($arg:tt)*) => { eprintln!($($arg)*) };
}

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => { eprint!($($arg)*) };
}

#[macro_export]
macro_rules! serial_force_println {
    ($($arg:tt)*) => { eprintln!($($arg)*) };
}

// Real kernel sync primitives, included verbatim into a mirror module tree
// so their internal `use super::...` references keep working.
#[path = "mirror/sync.rs"]
pub mod sync;

/// Mirror of kernel/src/syscall — only the pieces pure modules need.
#[path = "mirror/syscall.rs"]
pub mod syscall;

/// Boot-time TOML configuration parser, verbatim from the kernel.
#[path = "../../kernel/src/boot/toml.rs"]
pub mod boot_toml;

#[path = "mirror/ipc.rs"]
pub mod ipc;

/// Namespace (Plan-9 style scheme table), verbatim; depends only on
/// `sync::SpinLock` and `syscall_error`.
#[path = "../../kernel/src/namespace/mod.rs"]
pub mod namespace;

// ===========================================================================
// Functional stand-ins for hardware-bound kernel modules
// ===========================================================================

/// Mirror of kernel/src/boot — entry types are re-exports of strat9_abi.
pub mod boot {
    pub mod entry {
        pub use strat9_abi::boot::{KernelArgs, MemoryKind, MemoryRegion};
    }
}

/// Real kernel memory core (boot_alloc, zone, frame, buddy) with faked HHDM.
#[path = "mirror/memory.rs"]
pub mod memory;
