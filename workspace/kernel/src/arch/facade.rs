//! Architecture facade (HAL) for Strat9-OS
//!
//! This module is the ONLY architecture-neutral entry point that non-arch
//! kernel code may use. All references to `crate::arch::x86_64::...` outside
//! of the `arch/` directory are being migrated here (jalon R0 of the RISC-V
//! port plan: see doc/riscv-port-implementation.md).
//!
//! Design:
//! - Under `target_arch = "x86_64"`, this module re-exports the existing
//!   `x86_64` backend verbatim (zero behaviour change).
//! - Under other architectures (riscv64), a corresponding backend must
//!   provide the same API surface.
//! - New code MUST use these re-exports, never `arch::x86_64` directly.
//!
//! The long-term goal is a trait-based HAL (`InterruptController`,
//! `TlbOps`, `PerCpu`, `TimerSource`, `BootProtocol`, `SerialOut`,
//! `ContextFrame`). This first step is deliberately a thin alias layer so
//! the migration is mechanical and reviewable commit by commit.

#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64 as current;

#[cfg(target_arch = "x86_64")]
pub use x86_backend::*;

#[cfg(target_arch = "x86_64")]
pub mod x86_backend {
    //! Re-export of the x86_64 backend under neutral names.

    pub use crate::arch::x86_64::{
        boot_timestamp, clac, cli, cpuid, gdt, hlt, idt, init_cpu_extensions,
        interrupts_enabled, io, keyboard, mouse, pci, percpu, pic, restore_flags,
        rdtsc, save_flags_and_cli, serial, speaker, smp, stac, sti, syscall, timer,
        tlb, tss,
    };
}

/// Neutral aliases used by migrated call-sites.
///
/// These live directly in `arch` so callers write `crate::arch::percpu::...`.
#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64::{
    apic, boot_timestamp, clac, cli, cpuid, hlt, idt, init_cpu_extensions,
    interrupts_enabled, io, ioapic, keyboard, keyboard_layout, msi, mouse,
    pci, percpu, pic, ring3_diag, rdtsc, restore_flags, save_flags_and_cli,
    serial, speaker, smp, stac, sti, syscall, timer, tlb, tss, vga, vgabuf,
};

/// Maximum number of CPUs supported by the kernel (neutral constant).
///
/// Migrated from `arch::x86_64::percpu::MAX_CPUS`; backends may override
/// this via their own percpu implementation, so it re-exports the active
/// backend's value.
#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64::percpu::MAX_CPUS;

#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64::{rdmsr, wrmsr, xgetbv, xsetbv};

