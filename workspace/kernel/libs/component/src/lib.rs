//! Component initialization system for Strat9-OS
//!
//! Provides modular component registration and initialization with dependency ordering.
//!
//! # Usage
//!
//! ```rust,no_run
//! #[component::init_component]
//! fn my_component_init() -> Result<(), component::ComponentInitError> {
//!     // initialization code
//!     Ok(())
//! }
//! ```

#![no_std]
#![deny(unsafe_code)]
#![allow(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::fmt::Debug;

pub use component_macro::init_component;

/// Initialization stages for components
///
/// - `Bootstrap`: Early kernel initialization, before SMP
/// - `Kthread`: After SMP enabled, in kernel thread context
/// - `Process`: After first user process created
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InitStage {
    Bootstrap = 0,
    Kthread = 1,
    Process = 2,
}

/// Component initialization error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentInitError {
    UninitializedDependencies(String),
    InitFailed(&'static str),
    Unknown,
}

impl core::fmt::Display for ComponentInitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UninitializedDependencies(dep) => {
                write!(f, "Uninitialized dependency: {}", dep)
            }
            Self::InitFailed(msg) => write!(f, "Init failed: {}", msg),
            Self::Unknown => write!(f, "Unknown error"),
        }
    }
}

/// Static component registry entry
///
/// Entries are placed in the `.component_entries` linker section by the macro
/// and collected at runtime for initialization.
#[repr(C)]
pub struct ComponentEntry {
    pub stage: InitStage,
    pub init_fn: fn() -> Result<(), ComponentInitError>,
    pub path: &'static str,
    pub priority: u32,
}

impl ComponentEntry {
    pub const fn new(
        stage: InitStage,
        init_fn: fn() -> Result<(), ComponentInitError>,
        path: &'static str,
        priority: u32,
    ) -> Self {
        Self {
            stage,
            init_fn,
            path,
            priority,
        }
    }
}

/// Component information for initialization
#[derive(Debug)]
pub struct ComponentInfo {
    pub name: String,
    pub path: String,
    pub priority: u32,
}

impl ComponentInfo {
    pub const fn new(_name: &'static str, _path: &'static str, priority: u32) -> Self {
        Self {
            name: String::new(),
            path: String::new(),
            priority,
        }
    }
}

impl PartialEq for ComponentInfo {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority
    }
}

impl Eq for ComponentInfo {}

impl Ord for ComponentInfo {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.priority.cmp(&other.priority)
    }
}

impl PartialOrd for ComponentInfo {
    fn partial_cmp(&self, other: &ComponentInfo) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// Linker symbols for the component entries section
//
// These symbols are defined by the linker script and mark the start and end
// of the `.component_entries` section where all component entries are placed.
// Note: We allow improper_ctypes here because these are linker symbols, not FFI.
#[allow(improper_ctypes)]
extern "C" {
    static __start_component_entries: ComponentEntry;
    static __stop_component_entries: ComponentEntry;
}

/// Initialize all components for a given stage
///
/// Iterates over all component entries in the linker section and invokes
/// them in priority order.
///
/// # Example
///
/// ```rust,no_run
/// component::init_all(component::InitStage::Bootstrap);
/// ```
#[allow(unsafe_code)]
pub fn init_all(stage: InitStage) -> Result<(), ComponentInitError> {
    let mut components: Vec<&ComponentEntry> = Vec::new();

    // SAFETY: The linker guarantees that __start_component_entries and
    // __stop_component_entries mark the boundaries of the .component_entries
    // section. All entries in this section are valid ComponentEntry structs
    // placed there by the #[init_component] macro.
    unsafe {
        let start = &__start_component_entries as *const ComponentEntry;
        let stop = &__stop_component_entries as *const ComponentEntry;
        
        let mut current = start;
        while current < stop {
            let entry = &*current;
            if entry.stage == stage {
                components.push(entry);
            }
            current = current.add(1);
        }
    }

    // Sort by priority (lower priority number = earlier init)
    components.sort_by_key(|e| e.priority);

    log::info!("Components initializing in {:?} stage...", stage);

    for entry in components {
        log::info!("Component initializing: {}", entry.path);
        match (entry.init_fn)() {
            Ok(()) => log::info!("Component initialize complete: {}", entry.path),
            Err(e) => log::error!("Component initialize error ({}): {:?}", entry.path, e),
        }
    }

    log::info!("All components initialization in {:?} stage completed", stage);
    Ok(())
}

/// Parse component metadata at compile time (stub for now)
///
/// This macro would normally parse Components.toml, but for simplicity
/// we use a basic implementation that returns an empty vector.
#[macro_export]
macro_rules! parse_metadata {
    () => {
        alloc::vec![]
    };
}
