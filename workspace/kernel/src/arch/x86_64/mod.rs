//! x86_64 architecture-specific code
//!
//! Inspired by MaestroOS `arch/x86/mod.rs`

pub mod apic;
pub mod boot_timestamp;
pub mod cpuid;
pub mod gdt;
pub mod idt;
pub mod io;
pub mod ioapic;
pub mod keyboard;
pub mod keyboard_layout;
pub mod keyboard_us;
pub mod mouse;
pub mod msi;
pub mod pci;
pub mod percpu;
pub mod pic;
pub mod ring3_diag;
pub mod serial;
pub mod smp;
pub mod speaker;
pub mod syscall;
pub mod timer;
pub mod tlb;
pub mod tss;
pub mod vga;
pub mod vgabuf;
pub mod x2apic;

use core::arch::asm;

/// Initialize FPU, SSE, and optionally XSAVE for the current CPU.
pub fn init_cpu_extensions() {
    unsafe {
        let mut cr4: u64;
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
        // OSFXSR (9) + OSXMMEXCPT (10)
        cr4 |= (1 << 9) | (1 << 10);

        if cpuid::host_uses_xsave() {
            // OSXSAVE (18) : required before xsetbv/xgetbv
            cr4 |= 1 << 18;
        }

        // SMEP (20): Supervisor Mode Execution Prevention
        // Prevents the kernel from executing code mapped in user-space pages.
        // Requires CPUID leaf 7, ECX bit 7.
        if crate::arch::x86_64::cpuid::host()
            .features
            .contains(cpuid::CpuFeatures::SMEP)
        {
            cr4 |= 1 << 20;
            log::info!("[init] SMEP enabled (CR4 bit 20)");
        }

        // SMAP (21): Supervisor Mode Access Prevention
        // Prevents the kernel from reading/writing user-space data pages
        // unless EFLAGS.AC is set (via stac/clac).
        // Requires CPUID leaf 7, ECX bit 20.
        if crate::arch::x86_64::cpuid::host()
            .features
            .contains(cpuid::CpuFeatures::SMAP)
        {
            cr4 |= 1 << 21;
            log::info!("[init] SMAP enabled (CR4 bit 21)");
        }

        asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack));

        let mut cr0: u64;
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack));
        cr0 &= !(1 << 2); // clear EM
        cr0 |= 1 << 1; // set MP
        asm!("mov cr0, {}", in(reg) cr0, options(nomem, nostack));

        asm!("fninit", options(nomem, nostack));

        if cpuid::host_uses_xsave() {
            let xcr0 = cpuid::host_default_xcr0();
            xsetbv(0, xcr0);
        }
    }
}

/// Whether CR4.OSXSAVE is currently enabled on this CPU.
///
/// AVX/AVX-512 are only *usable* when the kernel has enabled the state
/// (XSAVE in CR4 + XCR0 bits); CPUID alone only reports hardware capability.
pub fn cpuid_osxsave_enabled() -> bool {
    let cr4: u64;
    unsafe { asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack)) };
    cr4 & (1 << 18) != 0
}

#[inline]
/// Read an Extended Control Register (XGETBV).
pub fn xgetbv(xcr: u32) -> u64 {
    let eax: u32;
    let edx: u32;
    unsafe {
        asm!(
            "xgetbv",
            in("ecx") xcr,
            out("eax") eax,
            out("edx") edx,
            options(nomem, nostack),
        );
    }
    ((edx as u64) << 32) | eax as u64
}

/// Write an Extended Control Register (XSETBV).
///
/// # Safety
/// Caller must ensure CR4.OSXSAVE is set and the value is valid for XCR0.
#[inline]
pub unsafe fn xsetbv(xcr: u32, value: u64) {
    asm!(
        "xsetbv",
        in("ecx") xcr,
        in("eax") value as u32,
        in("edx") (value >> 32) as u32,
        options(nomem, nostack),
    );
}

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

/// Set AC flag in RFLAGS to temporarily disable SMAP.
///
/// Must be paired with `clac()` after the user-memory access is complete.
/// Only needed when CR4.SMAP is set.
#[inline]
pub fn stac() {
    unsafe {
        asm!("stac", options(nomem, nostack, preserves_flags));
    }
}

/// Clear AC flag in RFLAGS to re-enable SMAP protection.
///
/// Paired with `stac()`.
#[inline]
pub fn clac() {
    unsafe {
        asm!("clac", options(nomem, nostack, preserves_flags));
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
        asm!("pushfq; pop {0}; cli", out(reg) flags);
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
        asm!("push {0}; popfq", in(reg) flags);
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
        );
    }
    (eax, ebx, ecx, edx)
}

/// Read the Time Stamp Counter (TSC).
///
/// Returns the number of CPU cycles since reset. Available from the
/// very first instruction : use this as the sole timing source during
/// early boot (before APIC/PIT timers are configured).
#[inline]
pub fn rdtsc() -> u64 {
    let eax: u32;
    let edx: u32;
    unsafe {
        asm!("rdtsc", out("eax") eax, out("edx") edx, options(nomem, nostack));
    }
    ((edx as u64) << 32) | eax as u64
}
