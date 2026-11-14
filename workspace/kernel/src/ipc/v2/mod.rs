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

//! Kernel core of IPC ABI v2: generation handles, endpoints, reply targets
//! and notifications (§3–§7). Namespace, MemObject and async opcodes are out
//! of scope and return `ENOSYS`.

pub mod endpoint;
pub mod handle;
pub mod notif;

pub use handle::{Entry, HandleTable, ObjRef, MAX_HANDLES};

use crate::{
    process::{process::Process, TaskId},
    sync::SpinLock,
};
use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use endpoint::{cancel_call, CallSlot};

/// Weak registry of live call slots so task/endpoint death can cancel calls
/// without ever touching another address space.
static CALL_SLOTS: SpinLock<Vec<Weak<CallSlot>>> = SpinLock::new(Vec::new());

/// Register a call slot for exit/endpoint cleanup.
pub fn register_call(slot: &Arc<CallSlot>) {
    CALL_SLOTS.lock().push(Arc::downgrade(slot));
}

fn collect_calls<F: Fn(&CallSlot) -> bool>(filter: F) -> Vec<Arc<CallSlot>> {
    let mut guard = CALL_SLOTS.lock();
    let mut found = Vec::new();
    guard.retain(|weak| match weak.upgrade() {
        Some(slot) => {
            if filter(&slot) {
                found.push(slot);
            }
            true
        }
        None => false,
    });
    drop(guard);
    found
}

/// Cancel every call whose caller is `task_id`. Called when a task exits so a
/// late server reply fails with `EPIPE` instead of writing a freed buffer.
pub fn cleanup_for_task(task_id: TaskId) {
    let slots = collect_calls(|slot| *slot.caller.lock() == Some(task_id));
    for slot in slots {
        cancel_call(&slot);
    }
}

/// Cancel every call attached to `endpoint_id` (called on endpoint close).
pub fn cancel_calls_for_endpoint(endpoint_id: u64) {
    let slots = collect_calls(|slot| slot.endpoint_id == endpoint_id);
    for slot in slots {
        cancel_call(&slot);
    }
}

/// Drop every handle owned by a dying process, applying object side effects.
///
/// `fork_clone` shares objects with the parent; the child has its own table,
/// so this only releases the child's references.
pub fn cleanup_process(process: &Process) {
    process.ipc_v2.lock().remove_all();
}
