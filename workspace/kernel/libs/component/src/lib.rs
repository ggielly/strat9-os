//! Component initialization system for Strat9-OS.
//!
//! Provides modular component registration and dependency-ordered initialization.
//! Components are registered at compile time via `#[init_component]` and discovered
//! at runtime through the `.component_entries` linker section.
//!
//! # Usage
//!
//! ```rust,no_run
//! #[component::init_component(bootstrap, priority = 1)]
//! fn vfs_init() -> Result<(), component::ComponentInitError> {
//!     vfs::init();
//!     Ok(())
//! }
//!
//! #[component::init_component(kthread, priority = 2, depends_on = vfs_init)]
//! fn fs_ext4_init() -> Result<(), component::ComponentInitError> {
//!     fs_ext4::init();
//!     Ok(())
//! }
//! ```
//!
//! Call `component::init_all(InitStage::Bootstrap)` at the appropriate point
//! in `kernel_main` to run all registered components in dependency order.

#![no_std]
#![allow(unsafe_code)]
#![allow(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, vec, vec::Vec};

pub use component_macro::{init_component, parse_components_toml};

// ─── Stage ───────────────────────────────────────────────────────────────────

/// Initialization stages for components.
///
/// - `Bootstrap` — Early kernel initialization, before SMP.
/// - `Kthread`   — After SMP enabled, in kernel-thread context.
/// - `Process`   — After first user process created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum InitStage {
    Bootstrap = 0,
    Kthread = 1,
    Process = 2,
}

// ─── Error ───────────────────────────────────────────────────────────────────

/// Errors that a component initializer may return.
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
                write!(f, "Uninitialized dependency: {dep}")
            }
            Self::InitFailed(msg) => write!(f, "Init failed: {msg}"),
            Self::Unknown => write!(f, "Unknown error"),
        }
    }
}

// ─── ComponentEntry ───────────────────────────────────────────────────────────

/// Entry placed in `.component_entries` by `#[init_component]`.
///
/// All fields are `'static` because this struct lives in a `#[used] static`.
///
/// # Memory layout
///
/// `#[repr(C)]` ensures a stable layout so the linker-section scan in
/// `init_all()` can iterate entries with `ptr::add(1)`.
#[repr(C)]
pub struct ComponentEntry {
    /// Function name as written in source — used for dependency resolution.
    pub name: &'static str,
    /// Lifecycle stage this component belongs to.
    pub stage: InitStage,
    /// The registered initializer.
    pub init_fn: fn() -> Result<(), ComponentInitError>,
    /// `"file!():fn_name"` — for log messages only.
    pub path: &'static str,
    /// Lower value = earlier init within the same topological level.
    pub priority: u32,
    /// Names of same-stage functions that must complete before this one.
    pub depends_on: &'static [&'static str],
}

impl ComponentEntry {
    /// Construct a `ComponentEntry` (usable in `const` / `static` contexts).
    pub const fn new(
        name: &'static str,
        stage: InitStage,
        init_fn: fn() -> Result<(), ComponentInitError>,
        path: &'static str,
        priority: u32,
        depends_on: &'static [&'static str],
    ) -> Self {
        Self {
            name,
            stage,
            init_fn,
            path,
            priority,
            depends_on,
        }
    }
}

// ─── ComponentInfo ────────────────────────────────────────────────────────────

/// Human-readable component metadata (not stored in the linker section).
#[derive(Debug)]
pub struct ComponentInfo {
    pub name: String,
    pub path: String,
    pub priority: u32,
}

impl ComponentInfo {
    pub fn new(name: &'static str, path: &'static str, priority: u32) -> Self {
        Self {
            name: String::from(name),
            path: String::from(path),
            priority,
        }
    }
}

impl PartialEq for ComponentInfo {
    fn eq(&self, o: &Self) -> bool {
        self.priority == o.priority
    }
}
impl Eq for ComponentInfo {}
impl Ord for ComponentInfo {
    fn cmp(&self, o: &Self) -> core::cmp::Ordering {
        self.priority.cmp(&o.priority)
    }
}
impl PartialOrd for ComponentInfo {
    fn partial_cmp(&self, o: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

// ─── Linker section symbols ───────────────────────────────────────────────────

// SAFETY: symbols defined by linker-limine.ld; bracket the `.component_entries`
// section.  All objects between them are `ComponentEntry` structs placed by the
// `#[init_component]` macro.
#[allow(improper_ctypes)]
extern "C" {
    static __start_component_entries: ComponentEntry;
    static __stop_component_entries: ComponentEntry;
}

// ─── init_all ────────────────────────────────────────────────────────────────

/// Initialize all components registered for `stage` in dependency order.
///
/// ## Algorithm (Kahn's topological sort)
///
/// 1. Collect every `ComponentEntry` in `.component_entries` that matches the
///    requested stage.
/// 2. Build a directed graph from `depends_on` edges (A→B: A must run first).
/// 3. Topological sort with `priority` as the tiebreaker when multiple
///    components become ready at the same time (lower number = earlier).
/// 4. Execute each initializer in the computed order.
///
/// Cross-stage dependencies (names not found in the current stage) are warned
/// about and skipped — they are assumed to have already run in a prior stage.
///
/// Detected cycles are logged as errors; cyclic components are appended in
/// priority order after the acyclic ones (best-effort fallback).
#[allow(unsafe_code)]
pub fn init_all(stage: InitStage) -> Result<(), ComponentInitError> {
    // ── 1. Collect entries for this stage ────────────────────────────────────
    let mut components: Vec<&'static ComponentEntry> = Vec::new();

    // SAFETY: linker guarantees the section boundaries are valid and all
    // objects in the section are `ComponentEntry` structs placed by the macro.
    unsafe {
        let start = &raw const __start_component_entries as *const ComponentEntry;
        let stop = &raw const __stop_component_entries as *const ComponentEntry;
        let mut cur = start;
        while cur < stop {
            let entry = &*cur;
            if entry.stage == stage {
                components.push(entry);
            }
            cur = cur.add(1);
        }
    }

    if components.is_empty() {
        log::info!("[component] No components registered for {:?} stage", stage);
        return Ok(());
    }

    // ── 2. Build dependency graph ────────────────────────────────────────────
    let n = components.len();

    // name → index in `components`
    let name_to_idx: BTreeMap<&str, usize> = components
        .iter()
        .enumerate()
        .map(|(i, e)| (e.name, i))
        .collect();

    // in_degree[i] = number of unresolved same-stage deps of component i
    let mut in_degree = vec![0usize; n];
    // adj[i] = indices of components that must run AFTER component i
    let mut adj: Vec<Vec<usize>> = (0..n).map(|_| Vec::new()).collect();

    for (i, entry) in components.iter().enumerate() {
        for dep_name in entry.depends_on {
            if let Some(&dep_idx) = name_to_idx.get(dep_name) {
                adj[dep_idx].push(i);
                in_degree[i] += 1;
            } else {
                // Not in this stage — assumed handled in a prior stage.
                log::warn!(
                    "[component] '{}': dep '{}' not in {:?} stage (cross-stage, skipped)",
                    entry.name,
                    dep_name,
                    stage
                );
            }
        }
    }

    // ── 3. Kahn's topological sort with priority tiebreaker ──────────────────
    // `ready` is sorted ascending by priority so `remove(0)` always gives the
    // component with the smallest priority number (= earliest boot precedence).
    let mut ready: Vec<usize> = (0..n).filter(|&i| in_degree[i] == 0).collect();
    ready.sort_by_key(|&i| components[i].priority);

    let mut ordered: Vec<usize> = Vec::with_capacity(n);

    while !ready.is_empty() {
        let idx = ready.remove(0);
        ordered.push(idx);

        let mut newly_ready: Vec<usize> = Vec::new();
        for &succ in &adj[idx] {
            in_degree[succ] -= 1;
            if in_degree[succ] == 0 {
                newly_ready.push(succ);
            }
        }

        // Merge newly-ready nodes while maintaining sort by priority.
        for nr in newly_ready {
            let pos = ready.partition_point(|&i| components[i].priority <= components[nr].priority);
            ready.insert(pos, nr);
        }
    }

    // ── 4. Cycle detection fallback ──────────────────────────────────────────
    if ordered.len() != n {
        log::error!(
            "[component] Dependency cycle in {:?} stage — cyclic components will run last",
            stage
        );
        let mut remaining: Vec<usize> = (0..n).filter(|i| !ordered.contains(i)).collect();
        remaining.sort_by_key(|&i| components[i].priority);
        ordered.extend(remaining);
    }

    // ── 5. Execute ───────────────────────────────────────────────────────────
    log::info!(
        "[component] {:?} stage — {} component(s) to initialize",
        stage,
        ordered.len()
    );

    for idx in &ordered {
        let e = components[*idx];
        log::info!(
            "[component]  [{:3}] {}{}",
            e.priority,
            e.name,
            if e.depends_on.is_empty() {
                String::new()
            } else {
                alloc::format!(" (after: {})", e.depends_on.join(", "))
            }
        );
    }

    let mut failed = 0usize;
    for idx in ordered {
        let entry = components[idx];
        match (entry.init_fn)() {
            Ok(()) => log::info!("[component]   OK  {}", entry.name),
            Err(e) => {
                log::error!("[component]   ERR {}: {}", entry.name, e);
                failed += 1;
            }
        }
    }

    log::info!("[component] {:?} stage complete ({} failed)", stage, failed);
    Ok(())
}

// ─── list_components ─────────────────────────────────────────────────────────

/// Return all registered components sorted by stage then priority (for debug).
#[allow(unsafe_code)]
pub fn list_components() -> Vec<&'static ComponentEntry> {
    let mut components: Vec<&'static ComponentEntry> = Vec::new();

    unsafe {
        let start = &raw const __start_component_entries as *const ComponentEntry;
        let stop = &raw const __stop_component_entries as *const ComponentEntry;
        let mut cur = start;
        while cur < stop {
            components.push(&*cur);
            cur = cur.add(1);
        }
    }

    components.sort_by(|a, b| {
        a.stage
            .cmp(&b.stage)
            .then_with(|| a.priority.cmp(&b.priority))
            .then_with(|| a.name.cmp(b.name))
    });

    components
}

// ─── parse_metadata! ─────────────────────────────────────────────────────────

/// Parse `Components.toml` at compile time and return the dependency metadata.
///
/// Delegates to [`parse_components_toml!`] which searches for `Components.toml`
/// starting from the calling crate's directory.
///
/// Returns `&'static [(&'static str, &'static [&'static str])]`
/// where each element is `(component_name, &[dep1, dep2, ...])`.
#[macro_export]
macro_rules! parse_metadata {
    () => {
        component::parse_components_toml!()
    };
}
