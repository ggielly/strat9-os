//! Kernel component declarations — Strat9-OS boot orchestration.
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
//! #[component::init_component(kthread, priority = 3, depends_on = [vfs_init, ipc_init])]
//! fn silo_init() -> Result<(), ComponentInitError> { … }
//! ```

use component::ComponentInitError;

// ============================================================================
// Bootstrap stage — early kernel init (before SMP)
// The `priority` tiebreaker applies only when two components have no ordering
// edge between them; explicit `depends_on` edges take precedence.
// ============================================================================

/// Memory management — must be first; everything else implicitly depends on it.
#[component::init_component(bootstrap, priority = 0)]
fn memory_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Memory management initialized");
    Ok(())
}

/// Logger — early debug output (needs memory for heap-backed ring-buffer).
#[component::init_component(bootstrap, priority = 1, depends_on = memory_init)]
fn logger_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Logger initialized");
    Ok(())
}

/// Architecture primitives (GDT, IDT, TSS) — needs memory for TSS allocation.
#[component::init_component(bootstrap, priority = 1, depends_on = memory_init)]
fn arch_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Architecture primitives initialized");
    Ok(())
}

/// Synchronization primitives — foundational, no deps beyond memory.
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

/// Capability-based security — needs memory; used by VFS and IPC.
#[component::init_component(bootstrap, priority = 3, depends_on = memory_init)]
fn capability_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Capability system initialized");
    Ok(())
}

/// Virtual file system — needs memory and capability subsystem.
#[component::init_component(bootstrap, priority = 4, depends_on = [memory_init, capability_init])]
fn vfs_init() -> Result<(), ComponentInitError> {
    log::info!("[component] VFS initialized");
    Ok(())
}

/// IPC — inter-process communication primitives.
#[component::init_component(bootstrap, priority = 4, depends_on = [memory_init, capability_init])]
fn ipc_init() -> Result<(), ComponentInitError> {
    log::info!("[component] IPC initialized");
    Ok(())
}

/// Driver framework — needs arch primitives and memory.
#[component::init_component(bootstrap, priority = 5, depends_on = [memory_init, arch_init])]
fn drivers_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Driver framework initialized");
    Ok(())
}

// ============================================================================
// Kthread stage — after SMP, in kernel-thread context
// ============================================================================

/// Process and task management — needs memory, arch, and the scheduler already
/// running (guaranteed since kthread stage runs after schedule() is called).
#[component::init_component(kthread, priority = 0)]
fn process_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Process management initialized");
    Ok(())
}

/// Namespace management — depends on VFS being ready (bootstrap stage).
/// Cross-stage dep on `vfs_init` is skipped by the topo-sort (it's in a
/// different stage) and is guaranteed by stage ordering.
#[component::init_component(kthread, priority = 1, depends_on = process_init)]
fn namespace_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Namespace management initialized");
    Ok(())
}

/// Syscall interface — needs process + arch.
#[component::init_component(kthread, priority = 1, depends_on = process_init)]
fn syscall_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Syscall interface initialized");
    Ok(())
}

/// Silo management — needs process + namespace + syscall.
#[component::init_component(kthread, priority = 2, depends_on = [namespace_init, syscall_init])]
fn silo_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Silo management initialized");
    Ok(())
}

// ============================================================================
// Process stage — after the first user process has been created
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
