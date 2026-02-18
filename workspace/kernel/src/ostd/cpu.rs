//! CPU abstraction layer
//!
//! Provides safe abstractions for CPU-related operations including:
//! - CPU identification and topology
//! - Per-CPU data access
//! - CPU control (halt, interrupt control)
//!
//! Inspired by Asterinas OSTD CPU module.

#![no_std]
#![allow(unsafe_code)]

use core::sync::atomic::{AtomicUsize, Ordering};

/// CPU identifier
///
/// Represents a logical CPU in the system. On x86_64, this corresponds
/// to the APIC ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct CpuId {
    id: usize,
}

impl CpuId {
    /// Creates a new CpuId from a raw ID
    pub const fn new(id: usize) -> Self {
        Self { id }
    }

    /// Returns the raw CPU ID value
    pub const fn id(&self) -> usize {
        self.id
    }

    /// Returns the CpuId of the bootstrap processor (BSP)
    pub const fn bsp() -> Self {
        Self::new(0)
    }

    /// Returns the CpuId of the currently executing CPU
    ///
    /// # Safety
    ///
    /// This function reads the per-CPU GS base to determine the current CPU.
    /// It requires that per-CPU data has been initialized for this CPU.
    #[inline]
    pub fn current_racy() -> Self {
        // SAFETY: This is safe if per-CPU data has been set up via
        // arch::x86_64::percpu::init_gs_base(). The "racy" suffix indicates
        // that no additional synchronization is performed.
        let apic_id = unsafe { crate::arch::x86_64::apic::lapic_id() };
        Self::new(apic_id as usize)
    }

    /// Returns the number of CPUs in the system
    pub fn num_cpus() -> usize {
        crate::arch::x86_64::percpu::get_cpu_count()
    }

    /// Returns an iterator over all CPUs
    pub fn iter() -> CpuIter {
        CpuIter {
            current: 0,
            end: Self::num_cpus(),
        }
    }
}

impl From<usize> for CpuId {
    fn from(id: usize) -> Self {
        Self::new(id)
    }
}

impl From<CpuId> for usize {
    fn from(cpu_id: CpuId) -> Self {
        cpu_id.id
    }
}

impl core::fmt::Display for CpuId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CPU #{}", self.id)
    }
}

/// Iterator over all CPUs
pub struct CpuIter {
    current: usize,
    end: usize,
}

impl Iterator for CpuIter {
    type Item = CpuId;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current < self.end {
            let cpu = CpuId::new(self.current);
            self.current += 1;
            Some(cpu)
        } else {
            None
        }
    }
}

/// CPU halt function
///
/// Halts the CPU until the next interrupt arrives.
#[inline]
pub fn halt_cpu() {
    // SAFETY: hlt is a privileged instruction that halts the CPU until
    // the next interrupt. This is safe to call in kernel mode.
    unsafe {
        crate::arch::x86_64::hlt();
    }
}

/// Disable interrupts on the current CPU
#[inline]
pub fn disable_irqs() {
    // SAFETY: cli is a privileged instruction that disables interrupts.
    // This is safe to call in kernel mode and is commonly used to
    // protect critical sections.
    unsafe {
        crate::arch::x86_64::cli();
    }
}

/// Enable interrupts on the current CPU
#[inline]
pub fn enable_irqs() {
    // SAFETY: sti is a privileged instruction that enables interrupts.
    // This is safe to call in kernel mode.
    unsafe {
        crate::arch::x86_64::sti();
    }
}

/// Check if interrupts are enabled on the current CPU
#[inline]
pub fn irqs_enabled() -> bool {
    crate::arch::x86_64::interrupts_enabled()
}

/// Save interrupt flags and disable interrupts
///
/// Returns the previous interrupt state.
#[inline]
pub fn save_and_disable_irqs() -> bool {
    let flags = crate::arch::x86_64::save_flags_and_cli();
    (flags & 0x200) != 0
}

/// Restore interrupt flags
///
/// Restores the interrupt state to a previous value.
#[inline]
pub fn restore_irqs(enabled: bool) {
    if enabled {
        enable_irqs();
    } else {
        disable_irqs();
    }
}

/// Execute a closure with interrupts disabled
///
/// Returns the result of the closure.
pub fn without_interrupts<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let irq_enabled = save_and_disable_irqs();
    let result = f();
    restore_irqs(irq_enabled);
    result
}
