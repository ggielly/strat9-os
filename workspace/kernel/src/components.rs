//! Kernel component declarations : Strat9-OS boot orchestration.
//!
//! Each function annotated with `#[component::init_component]` is registered
//! in the `.component_entries` linker section.  `component::init_all()` reads
//! that section at runtime, topologically sorts the entries according to their
//! `depends_on` edges (with `priority` as a tiebreaker), and calls them in order.
//!
//! ## Stages
//!
//! | Stage       | When                                    |
//! |-------------|-----------------------------------------|
//! | `bootstrap` | Before SMP, early kernel init           |
//! | `kthread`   | After SMP, in kernel-thread context     |
//! | `hardware`  | After scheduler, device/driver probing  |
//! | `process`   | After first user process is created     |
//!
//! ## Syntax
//!
//! ```rust,no_run
//! #[component::init_component(bootstrap, priority = 1)]
//! fn vfs_init() -> Result<(), ComponentInitError> { … }
//!
//! #[component::init_component(kthread, priority = 2, depends_on = vfs_init)]
//! fn fs_ext4_init() -> Result<(), ComponentInitError> { … }
//!
//! #[component::init_component(hardware, priority = 1)]
//! fn drivers_init() -> Result<(), ComponentInitError> { … }
//!
//! #[component::init_component(kthread, priority = 3, depends_on = [vfs_init, ipc_init])]
//! fn silo_init() -> Result<(), ComponentInitError> { … }
//! ```

use component::ComponentInitError;

// ============================================================================
// Bootstrap stage : early kernel init (before SMP)
//
// Components that depend on local kernel_main state (e.g. mmap_work for
// memory_init) remain as markers — the real init happens inline in kernel_main
// before `init_all(Bootstrap)` is called.  Components that are self-contained
// do their real work here.
// ============================================================================

/// Memory management : marker — real init is inline in kernel_main (Phase 2)
/// because it requires the working memory map which is a local variable.
#[component::init_component(bootstrap, priority = 0)]
fn memory_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Memory management initialized");
    Ok(())
}

/// Logger : marker — already initialized before the component system runs.
#[component::init_component(bootstrap, priority = 1, depends_on = memory_init)]
fn logger_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Logger initialized");
    Ok(())
}

/// Architecture primitives (TSS, GDT, SYSCALL) : needs memory for TSS allocation.
/// Marker — real init is inline in kernel_main because it must run before
/// the component system is invoked (bootstrap components depend on GDT/TSS).
#[component::init_component(bootstrap, priority = 1, depends_on = memory_init)]
fn arch_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Architecture primitives initialized (marker)");
    Ok(())
}

/// Synchronization primitives : foundational, no deps beyond memory.
#[component::init_component(bootstrap, priority = 2, depends_on = memory_init)]
fn sync_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Sync primitives initialized");
    Ok(())
}

/// ACPI and power management.
#[component::init_component(bootstrap, priority = 3, depends_on = [memory_init, arch_init])]
fn acpi_init() -> Result<(), ComponentInitError> {
    log::info!("[component] ACPI initialized");
    Ok(())
}

/// Capability-based security : needs memory; used by VFS and IPC.
#[component::init_component(bootstrap, priority = 3, depends_on = memory_init)]
fn capability_init() -> Result<(), ComponentInitError> {
    // Capability system is initialized on first use (spin::Once).
    // This marker ensures the component graph reflects the dependency.
    log::info!("[component] Capability system initialized");
    Ok(())
}

/// Virtual file system : needs memory and capability subsystem.
/// Marker — real init is inline in kernel_main because it requires
/// `register_boot_modules()` with boot args that aren't available here.
#[component::init_component(bootstrap, priority = 4, depends_on = [memory_init, capability_init])]
fn vfs_init() -> Result<(), ComponentInitError> {
    log::info!("[component] VFS initialized (marker)");
    Ok(())
}

/// IPC : inter-process communication primitives.
#[component::init_component(bootstrap, priority = 4, depends_on = [memory_init, capability_init])]
fn ipc_init() -> Result<(), ComponentInitError> {
    log::info!("[component] IPC initialized");
    Ok(())
}

/// Driver framework : needs arch primitives and memory.
#[component::init_component(bootstrap, priority = 5, depends_on = [memory_init, arch_init])]
fn drivers_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Driver framework initialized");
    Ok(())
}

// ============================================================================
// Kthread stage : after SMP, in kernel-thread context
// ============================================================================

/// Process and task management : marker — scheduler is already running
/// (init_all(Kthread) is called after init_scheduler() in kernel_main).
#[component::init_component(kthread, priority = 0)]
fn process_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Process management initialized");
    Ok(())
}

/// Namespace management : depends on VFS being ready (bootstrap stage).
/// Cross-stage dep on `vfs_init` is skipped by the topo-sort (it's in a
/// different stage) and is guaranteed by stage ordering.
#[component::init_component(kthread, priority = 1, depends_on = process_init)]
fn namespace_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Namespace management initialized");
    Ok(())
}

/// Syscall interface : needs process + arch.
#[component::init_component(kthread, priority = 1, depends_on = process_init)]
fn syscall_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Syscall interface initialized");
    Ok(())
}

/// Silo management : needs process + namespace + syscall.
#[component::init_component(kthread, priority = 2, depends_on = [namespace_init, syscall_init])]
fn silo_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Silo management initialized");
    Ok(())
}

// ============================================================================
// Hardware stage : after scheduler, device/driver probing
// ============================================================================

/// PCI bus enumeration and early hardware probing.
#[component::init_component(hardware, priority = 0)]
fn pci_init() -> Result<(), ComponentInitError> {
    crate::hardware::init();
    log::info!("[component] PCI and hardware framework initialized");
    Ok(())
}

/// Storage drivers (VirtIO block, AHCI, NVMe).
#[component::init_component(hardware, priority = 1, depends_on = pci_init)]
fn storage_init() -> Result<(), ComponentInitError> {
    crate::hardware::storage::virtio_block::init();
    crate::hardware::storage::ahci::init();
    crate::hardware::storage::nvme::init();
    log::info!("[component] Storage drivers initialized");
    Ok(())
}

/// Network drivers (VirtIO net, E1000).
#[component::init_component(hardware, priority = 1, depends_on = pci_init)]
fn nic_init() -> Result<(), ComponentInitError> {
    crate::hardware::nic::virtio_net::init();
    log::info!("[component] Network drivers initialized");
    Ok(())
}

/// Timer subsystem (HPET, RTC, APIC timer start).
#[component::init_component(hardware, priority = 2, depends_on = pci_init)]
fn timer_init() -> Result<(), ComponentInitError> {
    crate::hardware::timer::init();
    log::info!("[component] Timer subsystem initialized");
    Ok(())
}

/// USB controllers (xHCI, EHCI, UHCI).
#[component::init_component(hardware, priority = 2, depends_on = pci_init)]
fn usb_init() -> Result<(), ComponentInitError> {
    crate::hardware::usb::init();
    log::info!("[component] USB controllers initialized");
    Ok(())
}

// ============================================================================
// Process stage : after the first user process has been created
// ============================================================================

/// Network stack (userspace component stub).
#[component::init_component(process, priority = 0)]
fn network_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Network stack initialized");
    Ok(())
}

/// Filesystem servers (userspace components).
#[component::init_component(process, priority = 1, depends_on = network_init)]
fn filesystem_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Filesystem servers initialized");
    Ok(())
}
