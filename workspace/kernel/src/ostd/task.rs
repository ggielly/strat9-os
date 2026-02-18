//! Task abstraction layer
//!
//! Provides safe abstractions for task/thread operations including:
//! - Task reference counting
//! - Task context access
//! - Task lifecycle management
//!
//! Inspired by Theseus Task and Asterinas thread abstractions.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

/// Unique task identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct TaskId(u32);

impl TaskId {
    /// Creates a new TaskId
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Returns the raw ID value
    pub const fn as_u32(&self) -> u32 {
        self.0
    }

    /// Returns the raw ID value as usize
    pub const fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

impl From<u32> for TaskId {
    fn from(id: u32) -> Self {
        Self::new(id)
    }
}

impl From<TaskId> for u32 {
    fn from(id: TaskId) -> u32 {
        id.0
    }
}

impl core::fmt::Display for TaskId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Task #{}", self.0)
    }
}

/// Task state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Task is runnable
    Runnable,
    /// Task is blocked/sleeping
    Blocked,
    /// Task is sleeping
    Sleeping,
    /// Task is stopped
    Stopped,
    /// Task is exiting
    Exiting,
    /// Task is idle
    Idle,
}

/// Reference-counted task handle
///
/// Similar to Theseus's TaskRef, this provides safe reference counting
/// for task structures.
pub struct TaskRef {
    /// Raw task pointer (must be valid for the lifetime of the process)
    task_ptr: *mut TaskInner,
    /// Reference count tracker
    ref_count: Arc<AtomicUsize>,
}

// SAFETY: TaskRef can be sent between threads if the underlying task supports it
unsafe impl Send for TaskRef {}
// SAFETY: TaskRef can be shared between threads
unsafe impl Sync for TaskRef {}

impl TaskRef {
    /// Creates a new TaskRef from a raw task pointer
    ///
    /// # Safety
    ///
    /// - The task_ptr must be valid for the lifetime of the process
    /// - The caller must ensure proper synchronization
    pub unsafe fn new(task_ptr: *mut TaskInner) -> Self {
        Self {
            task_ptr,
            ref_count: Arc::new(AtomicUsize::new(1)),
        }
    }

    /// Returns a reference to the inner task
    ///
    /// # Safety
    ///
    /// The caller must ensure the task is still valid
    pub unsafe fn as_ref(&self) -> &TaskInner {
        &*self.task_ptr
    }

    /// Returns a mutable reference to the inner task
    ///
    /// # Safety
    ///
    /// The caller must ensure exclusive access to the task
    pub unsafe fn as_mut(&mut self) -> &mut TaskInner {
        &mut *self.task_ptr
    }

    /// Clones the TaskRef
    pub fn clone(&self) -> Self {
        self.ref_count.fetch_add(1, Ordering::Relaxed);
        Self {
            task_ptr: self.task_ptr,
            ref_count: Arc::clone(&self.ref_count),
        }
    }

    /// Returns the reference count
    pub fn ref_count(&self) -> usize {
        self.ref_count.load(Ordering::Relaxed)
    }

    /// Returns true if this is the last reference
    pub fn is_last_ref(&self) -> bool {
        self.ref_count.load(Ordering::Relaxed) == 1
    }
}

impl Drop for TaskRef {
    fn drop(&mut self) {
        if self.ref_count.fetch_sub(1, Ordering::Release) == 1 {
            // Last reference - task can be cleaned up
            // SAFETY: We're the last reference, so we can safely access the task
            unsafe {
                (*self.task_ptr).on_last_ref();
            }
        }
    }
}

impl Clone for TaskRef {
    fn clone(&self) -> Self {
        self.clone()
    }
}

/// Internal task structure
///
/// Contains the core task data that is shared via TaskRef.
pub struct TaskInner {
    /// Task ID
    id: TaskId,
    /// Task name
    name: spin::Once<alloc::string::String>,
    /// Task state
    state: AtomicU32,
    /// CPU affinity (which CPUs this task can run on)
    cpu_affinity: AtomicUsize,
    /// Priority (lower = higher priority)
    priority: AtomicU32,
}

impl TaskInner {
    /// Creates a new TaskInner
    pub fn new(id: TaskId) -> Self {
        Self {
            id,
            name: spin::Once::new(),
            state: AtomicU32::new(TaskState::Runnable as u32),
            cpu_affinity: AtomicUsize::new(usize::MAX), // All CPUs
            priority: AtomicU32::new(0),
        }
    }

    /// Returns the task ID
    pub fn id(&self) -> TaskId {
        self.id
    }

    /// Returns the task name
    pub fn name(&self) -> Option<&alloc::string::String> {
        self.name.get()
    }

    /// Sets the task name
    pub fn set_name(&self, name: alloc::string::String) -> Result<(), ()> {
        self.name.try_init_once(|| name).map_err(|_| ())
    }

    /// Returns the current task state
    pub fn state(&self) -> TaskState {
        match self.state.load(Ordering::Relaxed) {
            0 => TaskState::Runnable,
            1 => TaskState::Blocked,
            2 => TaskState::Sleeping,
            3 => TaskState::Stopped,
            4 => TaskState::Exiting,
            5 => TaskState::Idle,
            _ => TaskState::Runnable,
        }
    }

    /// Sets the task state
    pub fn set_state(&self, state: TaskState) {
        self.state.store(state as u32, Ordering::Relaxed);
    }

    /// Returns the CPU affinity mask
    pub fn cpu_affinity(&self) -> usize {
        self.cpu_affinity.load(Ordering::Relaxed)
    }

    /// Sets the CPU affinity mask
    pub fn set_cpu_affinity(&self, mask: usize) {
        self.cpu_affinity.store(mask, Ordering::Relaxed);
    }

    /// Returns the task priority
    pub fn priority(&self) -> u32 {
        self.priority.load(Ordering::Relaxed)
    }

    /// Sets the task priority
    pub fn set_priority(&self, priority: u32) {
        self.priority.store(priority, Ordering::Relaxed);
    }

    /// Called when the last TaskRef is dropped
    ///
    /// Override this in implementations to handle cleanup.
    pub fn on_last_ref(&self) {
        // Default: do nothing
        // Implementations should override to free resources
    }
}

/// Gets the current task
///
/// Returns None if called before the task system is initialized.
pub fn current_task() -> Option<TaskRef> {
    // TODO: Integrate with the actual process/task system
    // For now, return None as a placeholder
    None
}

/// Task options for spawning new tasks
pub struct TaskOptions {
    name: Option<alloc::string::String>,
    cpu_affinity: Option<usize>,
    priority: Option<u32>,
}

impl TaskOptions {
    /// Creates new task options with default values
    pub fn new() -> Self {
        Self {
            name: None,
            cpu_affinity: None,
            priority: None,
        }
    }

    /// Sets the task name
    pub fn name(mut self, name: alloc::string::String) -> Self {
        self.name = Some(name);
        self
    }

    /// Sets the CPU affinity
    pub fn cpu_affinity(mut self, affinity: usize) -> Self {
        self.cpu_affinity = Some(affinity);
        self
    }

    /// Sets the task priority
    pub fn priority(mut self, priority: u32) -> Self {
        self.priority = Some(priority);
        self
    }
}

impl Default for TaskOptions {
    fn default() -> Self {
        Self::new()
    }
}
