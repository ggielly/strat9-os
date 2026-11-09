/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! Kernel thread API (`kthread`).
//!
//! Ergonomic wrapper over [`Task::new_kernel_task`] + `add_task` for spawning
//! closure-based kernel threads. Kernel threads stay internal: they never go
//! through `/thread/*` because `SYS_THREAD_CREATE` / `/thread/create` refuse
//! kernel parents by design.
//!
//! ```ignore
//! let tid = kthread::spawn("gc-worker", || {
//!     loop { /* ... */ kthread::yield_now(); }
//! })?;
//! ```

use crate::process::{
    scheduler::add_task,
    task::{Task, TaskId, TaskPriority},
};
use alloc::{boxed::Box, sync::Arc};

/// Trampoline for closure-based kernel threads.
///
/// Rebuilds the boxed closure from the raw argument, runs it, then exits the
/// calling task so the scheduler reclaims the kernel stack.
extern "C" fn kthread_trampoline(arg0: u64) -> ! {
    // SAFETY: `arg0` was produced by `Box::into_raw` in `spawn` for this task
    // only; nobody else holds or frees that pointer.
    let closure = unsafe { Box::from_raw(arg0 as *mut Box<dyn FnOnce() + Send>) };
    // Consumes the boxed closure (outer Box included).
    closure();
    crate::process::scheduler::exit_current_task(0)
}

/// Spawn a kernel thread running `f`.
///
/// The task owns its name and releases it when the last task reference is dropped.
///
/// Returns the `TaskId` of the new task once it is registered with the
/// scheduler (it may not have started running yet).
pub fn spawn<F: FnOnce() + Send + 'static>(name: &str, f: F) -> Result<TaskId, &'static str> {
    let stored: Box<dyn FnOnce() + Send> = Box::new(f);
    let arg0 = Box::into_raw(Box::new(stored)) as u64;

    // `Task::new_kernel_task_with_stack` declares `extern "C" fn() -> !`, while
    // the scheduler bootstrap (`task_entry_trampoline` -> `task_post_switch_enter`)
    // always invokes the entry with one register argument (RDI = r13 slot).
    // Transmute here so our trampoline can receive the closure pointer : this
    // mirrors the transmute performed by `task_post_switch_enter` itself.
    let entry: extern "C" fn() -> ! =
        unsafe { core::mem::transmute(kthread_trampoline as *const ()) };

    let task = Task::new_kernel_task_with_stack(
        entry,
        name,
        TaskPriority::Normal,
        Task::DEFAULT_STACK_SIZE,
    )?;

    // CpuContext initial stack layout: r15, r14, r13(arg), r12(entry), rbp, rbx, ret.
    // Seed r13 with the closure pointer: task_entry_trampoline forwards it to
    // `kthread_trampoline` as its single argument, mirroring the user-thread
    // bootstrap seeding in `thread_ops`.
    unsafe {
        let ctx = &mut *task.context.get();
        let frame = ctx.saved_rsp as *mut u64;
        *frame.add(2) = arg0;
    }

    let id = task.id;
    add_task(task);
    Ok(id)
}

/// Cooperative yield for kernel threads.
pub fn yield_now() {
    crate::process::yield_task();
}

/// `TaskId` of the calling kernel thread, if one is current.
pub fn current_tid() -> Option<TaskId> {
    crate::process::current_task_id()
}

/// Convenience: clone of the current task's `Arc<Task>`, if any.
pub fn current_task() -> Option<Arc<Task>> {
    crate::process::current_task_clone()
}
