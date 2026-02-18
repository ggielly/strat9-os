//! Example kernel components demonstrating the component initialization system
//!
//! This module shows how to use the `#[init_component]` macro to register
//! initialization functions that run at different stages of kernel boot.

use component::{ComponentInitError, InitStage};

// ============================================================================
// Bootstrap stage : early kernel initialization (before SMP)
// ============================================================================

/// Memory management - MUST be first!
#[component::init_component(bootstrap, priority = 0)]
fn memory_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Memory management initialized");
    Ok(())
}

/// Logger - early debug output
#[component::init_component(bootstrap, priority = 1)]
fn logger_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Logger initialized");
    Ok(())
}

/// Architecture primitives (GDT, IDT, TSS)
#[component::init_component(bootstrap, priority = 2)]
fn arch_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Architecture primitives initialized");
    Ok(())
}

/// VFS - virtual file system
#[component::init_component(bootstrap, priority = 3)]
fn vfs_init() -> Result<(), ComponentInitError> {
    log::info!("[component] VFS initialized");
    Ok(())
}

/// IPC - inter-process communication
#[component::init_component(bootstrap, priority = 4)]
fn ipc_init() -> Result<(), ComponentInitError> {
    log::info!("[component] IPC initialized");
    Ok(())
}

/// Capability-based security
#[component::init_component(bootstrap, priority = 5)]
fn capability_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Capability system initialized");
    Ok(())
}

/// Driver framework
#[component::init_component(bootstrap, priority = 6)]
fn drivers_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Driver framework initialized");
    Ok(())
}

/// ACPI and power management
#[component::init_component(bootstrap, priority = 7)]
fn acpi_init() -> Result<(), ComponentInitError> {
    log::info!("[component] ACPI initialized");
    Ok(())
}

/// Synchronization primitives
#[component::init_component(bootstrap, priority = 8)]
fn sync_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Sync primitives initialized");
    Ok(())
}

// ============================================================================
// Kthread Stage - After SMP enabled, in kernel thread context
// ============================================================================

/// Process and task management
#[component::init_component(kthread, priority = 0)]
fn process_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Process management initialized");
    Ok(())
}

/// Namespace management (depends on VFS)
#[component::init_component(kthread, priority = 1)]
fn namespace_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Namespace management initialized");
    Ok(())
}

/// Syscall interface
#[component::init_component(kthread, priority = 2)]
fn syscall_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Syscall interface initialized");
    Ok(())
}

/// Silo management (depends on Process and Capability)
#[component::init_component(kthread, priority = 3)]
fn silo_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Silo management initialized");
    Ok(())
}

// ============================================================================
// Process Stage - After first user process created
// ============================================================================

/// Network stack (userspace component stub)
#[component::init_component(process, priority = 0)]
fn network_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Network stack initialized");
    Ok(())
}

/// Filesystem servers (userspace components)
#[component::init_component(process, priority = 1)]
fn filesystem_init() -> Result<(), ComponentInitError> {
    log::info!("[component] Filesystem servers initialized");
    Ok(())
}

/// Test component that demonstrates error handling
#[component::init_component(bootstrap, priority = 100)]
#[allow(dead_code)]
fn test_component() -> Result<(), ComponentInitError> {
    // Uncomment to test error handling:
    // return Err(ComponentInitError::InitFailed("simulated error"));
    log::info!("[component] Test component initialized successfully");
    Ok(())
}
