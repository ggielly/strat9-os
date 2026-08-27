//! Architecture facade (HAL) for Strat9-OS
//!
//! This module is the ONLY architecture-neutral entry point that non-arch
//! kernel code may use. All references to `crate::arch::x86_64::...` outside
//! of the `arch/` directory have been migrated here (jalon R0 of the RISC-V
//! port plan: see doc/riscv-port-implementation.md).
//!
//! Design:
//! - Under `target_arch = "x86_64"`, this module re-exports the existing
//!   `x86_64` backend verbatim (zero behaviour change).
//! - Under `target_arch = "riscv64"`, a minimal bring-up backend provides
//!   the same API surface (subset growing with each jalon).
//! - New code MUST use these re-exports, never a concrete backend directly.

/// The active backend, as `crate::arch::backend::*`.
#[cfg(target_arch = "x86_64")]
pub mod backend {
    pub use crate::arch::x86_64::{cpuid, percpu, rdtsc, serial, speaker};
    pub use crate::arch::x86_64::{
        cli, hlt, interrupts_enabled, restore_flags, save_flags_and_cli, sti,
    };
}

#[cfg(target_arch = "riscv64")]
pub mod backend {
    pub use super::riscv64::{cpuid, rdtsc, serial, speaker};
    pub use super::riscv64::{
        cli, hlt, interrupts_enabled, restore_flags, save_flags_and_cli, sti,
    };
}

// ---------------------------------------------------------------------------
// Neutral re-exports (module surface shared by both backends)
// ---------------------------------------------------------------------------

/// Per-CPU data. x86_64 uses GS-base blocks; riscv64 will use `sscratch`.
pub use backend::percpu;

/// Serial console (early output, panic path, cmdline source).
pub use backend::serial;

/// Interrupt-state primitives.
pub use backend::{cli, hlt, interrupts_enabled, restore_flags, save_flags_and_cli, sti};

/// Monotonic early-boot counter (TSC on x86_64, `rdtime` on riscv64).
pub use backend::rdtsc;

/// CPU feature discovery (CPUID vs device-tree ISA string).
pub use backend::cpuid;

/// PC speaker (no-op stub on riscv64).
pub use backend::speaker;

// ---------------------------------------------------------------------------
// x86-only surface, still referenced by not-yet-gated kernel code.
//
// These are re-exported from the x86 backend only when compiling for
// x86_64; each one is scheduled to become either per-arch gated or moved
// behind a proper HAL trait in later jalons.
// ---------------------------------------------------------------------------

/// Maximum number of CPUs supported by the kernel (neutral constant).
#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64::percpu::MAX_CPUS;

#[cfg(target_arch = "riscv64")]
pub use crate::arch::riscv64::{
    boot_timestamp, idt, timer, vga, vgabuf,
};

#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64::{
    apic, boot_timestamp, clac, gdt, idt, init_cpu_extensions, io, ioapic,
    keyboard, keyboard_layout, msi, mouse, pci, pic, ring3_diag, rdmsr, smp,
    stac, syscall, timer, tlb, tss, vga, vgabuf, wrmsr, xgetbv, xsetbv,
};
