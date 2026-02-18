//! CPU abstraction layer
//!
//! Provides safe abstractions for CPU-related operations including:
//! - CPU identification and topology
//! - Per-CPU data access
//! - CPU control (halt, interrupt control)
//!
//! Inspired by Asterinas OSTD CPU module.

#![no_std]
#![deny(unsafe_code)]

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

/// Per-CPU data container
///
/// Provides type-safe per-CPU data storage and retrieval.
/// Each CPU has its own independent instance of the data.
pub struct PerCpuData<T: Send + 'static> {
    data: [PerCpuCell<T>; MAX_CPUS],
    initialized: AtomicUsize,
}

/// Maximum number of CPUs supported
pub const MAX_CPUS: usize = 256;

/// Internal cell for per-CPU data
struct PerCpuCell<T: Send + 'static> {
    // SAFETY: This cell is only accessed by the owning CPU
    data: spin::Once<spin::Mutex<T>>,
}

impl<T: Send + 'static> PerCpuCell<T> {
    const fn new() -> Self {
        Self {
            data: spin::Once::new(),
        }
    }

    fn get(&self) -> Option<&spin::Mutex<T>> {
        self.data.get()
    }

    fn init(&self, value: T) -> Result<(), T> {
        self.data.try_init_once(|| spin::Mutex::new(value))
    }
}

impl<T: Send + 'static> PerCpuData<T> {
    /// Creates a new per-CPU data container (uninitialized)
    pub const fn new() -> Self {
        const UNINIT: PerCpuCell<()> = PerCpuCell { data: spin::Once::new() };
        // SAFETY: PerCpuCell<T> has the same layout as PerCpuCell<()> for any T
        // because it only contains a spin::Once which is ZST-compatible.
        Self {
            data: unsafe { core::mem::transmute([UNINIT; MAX_CPUS]) },
            initialized: AtomicUsize::new(0),
        }
    }

    /// Initializes per-CPU data for a specific CPU
    ///
    /// Must be called once per CPU before accessing the data.
    pub fn init_for_cpu(&self, cpu: CpuId, value: T) -> Result<(), T> {
        if cpu.id >= MAX_CPUS {
            return Err(value);
        }
        let result = self.data[cpu.id].init(value);
        if result.is_ok() {
            self.initialized.fetch_or(1 << cpu.id, Ordering::Relaxed);
        }
        result
    }

    /// Gets a reference to the per-CPU data for a specific CPU
    pub fn get_for_cpu(&self, cpu: CpuId) -> Option<&spin::Mutex<T>> {
        if cpu.id >= MAX_CPUS {
            return None;
        }
        self.data[cpu.id].get()
    }

    /// Gets a reference to the per-CPU data for the current CPU
    pub fn get_current(&self) -> Option<&spin::Mutex<T>> {
        let cpu = CpuId::current_racy();
        self.get_for_cpu(cpu)
    }

    /// Checks if per-CPU data is initialized for a specific CPU
    pub fn is_initialized(&self, cpu: CpuId) -> bool {
        if cpu.id >= MAX_CPUS {
            return false;
        }
        (self.initialized.load(Ordering::Relaxed) & (1 << cpu.id)) != 0
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
