//! Example kernel components demonstrating the component initialization system
//!
//! This module shows how to use the `#[init_component]` macro to register
//! initialization functions that run at different stages of kernel boot.

// TODO HERE
use component::{ComponentInitError, InitStage};

/// Example bootstrap component - runs early in kernel initialization
///
/// This component initializes during the Bootstrap stage, which runs
/// on the BSP before SMP is enabled. Use this for core kernel services
/// that other components depend on.
#[component::init_component(bootstrap)]
fn example_bootstrap_component() -> Result<(), ComponentInitError> {
    log::info!("[component] Bootstrap component initialized");
    Ok(())
}

/// Example kernel thread component - runs after SMP is enabled
///
/// This component initializes during the Kthread stage, which runs
/// in the context of the first kernel thread after SMP is enabled.
/// Use this for services that need multi-processor support.
#[component::init_component(kthread)]
fn example_kthread_component() -> Result<(), ComponentInitError> {
    log::info!("[component] Kthread component initialized");
    Ok(())
}

/// Example process component - runs after first user process
///
/// This component initializes during the Process stage, which runs
/// after the first user process is created. Use this for services
/// that interact with user-space components (silos).
#[component::init_component(process)]
fn example_process_component() -> Result<(), ComponentInitError> {
    log::info!("[component] Process component initialized");
    Ok(())
}

/// Test component that demonstrates error handling
///
/// Components can return errors to indicate initialization failure.
/// The component system will log the error and continue with other
/// components.
#[component::init_component(bootstrap)]
#[allow(dead_code)]
fn example_error_component() -> Result<(), ComponentInitError> {
    // Uncomment to test error handling:
    // return Err(ComponentInitError::InitFailed("simulated error"));
    log::info!("[component] Error-handling component initialized successfully");
    Ok(())
}
