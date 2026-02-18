//! x86_64 architecture-specific code
//!
//! Inspired by MaestroOS `arch/x86/mod.rs`

pub mod apic;
pub mod gdt;
pub mod idt;
pub mod io;
pub mod ioapic;
pub mod keyboard;
pub mod keyboard_layout;
pub mod keyboard_us;
pub mod percpu;
pub mod pci;
pub mod pic;
pub mod serial;
pub mod smp;
pub mod syscall;
pub mod timer;
pub mod tss;
pub mod vga;

use core::arch::asm;

/// Halt the CPU until the next interrupt
#[inline]
pub fn hlt() {
    unsafe {
        asm!("hlt", options(nomem, nostack, preserves_flags));
    }
}

/// Disable interrupts
#[inline]
pub fn cli() {
    unsafe {
        asm!("cli", options(nomem, nostack));
    }
}

/// Enable interrupts
#[inline]
pub fn sti() {
    unsafe {
        asm!("sti", options(nomem, nostack));
    }
}

/// Check if interrupts are enabled
#[inline]
pub fn interrupts_enabled() -> bool {
    let rflags: u64;
    unsafe {
        asm!("pushfq; pop {}", out(reg) rflags, options(nomem));
    }
    rflags & 0x200 != 0
}

/// Save RFLAGS and disable interrupts. Returns saved flags.
///
/// Used to protect critical sections (e.g., scheduler lock) from
/// being interrupted by the timer, which would cause deadlock on
/// single-core systems.
#[inline]
pub fn save_flags_and_cli() -> u64 {
    let flags: u64;
    // SAFETY: pushfq/pop reads RFLAGS, cli disables interrupts.
    // This is safe and required for single-core mutual exclusion.
    unsafe {
        asm!("pushfq; pop {0}; cli", out(reg) flags, options(nostack));
    }
    flags
}

/// Restore RFLAGS (including interrupt flag) from a previous save.
///
/// Pairs with `save_flags_and_cli()` to restore the previous interrupt state.
#[inline]
pub fn restore_flags(flags: u64) {
    // SAFETY: push/popfq restores RFLAGS to a previously-saved valid state.
    unsafe {
        asm!("push {0}; popfq", in(reg) flags, options(nostack));
    }
}

/// Read from a Model Specific Register
#[inline]
pub fn rdmsr(msr: u32) -> u64 {
    let edx: u32;
    let eax: u32;
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("edx") edx,
            out("eax") eax,
            options(nostack)
        );
    }
    ((edx as u64) << 32) | eax as u64
}

/// Write to a Model Specific Register
#[inline]
pub fn wrmsr(msr: u32, val: u64) {
    let edx = (val >> 32) as u32;
    let eax = val as u32;
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("edx") edx,
            in("eax") eax,
            options(nostack)
        );
    }
}

/// Execute CPUID instruction.
///
/// rbx is reserved by LLVM, so we save/restore it manually.
#[inline]
pub fn cpuid(leaf: u32, sub_leaf: u32) -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inout("eax") leaf => eax,
            inout("ecx") sub_leaf => ecx,
            ebx_out = out(reg) ebx,
            out("edx") edx,
            options(nostack)
        );
    }
    (eax, ebx, ecx, edx)
}
