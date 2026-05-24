//! IPC call/reply support : both synchronous (blocking) and async (ring-based).
//!
//! # Design  concept
//!
//! -  `ReplyTarget::Sync` is analogous to an seL4 endpoint call+reply
//! -  `ReplyTarget::AsyncRing` combines both: the ring *is* the completion port
//! -   Send/Receive/Reply : exactly our sync `wait_for_reply`/`deliver_reply`
//! -   The CQE `user_data` correlates the reply to the original submission

use super::message::IpcMessage;
use crate::{
    async_io::{complete::push_completion_for_ring, ring::find_ring},
    memory::UserSliceWrite,
    process::TaskId,
    sync::{SpinLock, WaitQueue},
};
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

// ===========================================================================
// ReplyTarget : where to route the reply
// ===========================================================================

/// Describes how to deliver a reply once the server responds.
enum ReplyTarget {
    Sync {
        msg: Option<IpcMessage>,
        waitq: Arc<WaitQueue>,
    },

    AsyncRing {
        ring_id: u64,
        user_data: u64,
        reply_buf: u64,
    },
}

struct ReplySlot {
    target: ReplyTarget,

    waiting_on: Option<TaskId>,
}

struct ReplyRegistry {
    slots: BTreeMap<TaskId, ReplySlot>,
}

impl ReplyRegistry {
    const fn new() -> Self {
        ReplyRegistry {
            slots: BTreeMap::new(),
        }
    }
}

static REPLIES: SpinLock<ReplyRegistry> = SpinLock::new(ReplyRegistry::new());

// ===========================================================================
// Helpers
// ===========================================================================

fn epipe_reply() -> IpcMessage {
    let mut err = IpcMessage::new(0x80);
    let epipe: u32 = 32;
    err.payload[0..4].copy_from_slice(&epipe.to_le_bytes());
    err
}

// ===========================================================================
// Public API
// ===========================================================================

/// Block the current task waiting for a reply message (synchronous call path).
///
/// The caller (via `SYS_IPC_CALL`) blocks on a `WaitQueue` until the server
/// calls `deliver_reply`.  Returns the reply message; returns an EPIPE error
/// if the slot was removed while waiting (server died).
pub fn wait_for_reply(task_id: TaskId, waiting_on: TaskId) -> IpcMessage {
    let waitq = {
        let mut registry = REPLIES.lock();
        let slot = registry.slots.entry(task_id).or_insert_with(|| ReplySlot {
            target: ReplyTarget::Sync {
                msg: None,
                waitq: Arc::new(WaitQueue::new()),
            },
            waiting_on: Some(waiting_on),
        });
        slot.waiting_on = Some(waiting_on); // Should never happen — a task cannot be both sync-waiting
                                            // and have an async ring pending on the same slot.
        match &slot.target {
            ReplyTarget::Sync { waitq, .. } => waitq.clone(),
            ReplyTarget::AsyncRing { .. } => {
                return epipe_reply();
            }
        }
    };

    let msg = waitq.wait_until(|| {
        let mut registry = REPLIES.lock();
        match registry.slots.get_mut(&task_id) {
            Some(ReplySlot {
                target: ReplyTarget::Sync { msg, .. },
                ..
            }) => msg.take(),
            _ => Some(epipe_reply()),
        }
    });

    let mut registry = REPLIES.lock();
    registry.slots.remove(&task_id);
    msg
}

/// Register a pending ring-based `IpcCall` for `caller`.
///
/// When the server calls `deliver_reply(caller, msg)`, the kernel will:
///   - Copy `msg` into the caller's buffer at `reply_buf`.
///   - Push a CQE to the caller's ring with the given `user_data`.
///

pub fn register_ring_call(
    caller: TaskId,
    waiting_on: TaskId,
    ring_id: u64,
    user_data: u64,
    reply_buf: u64,
) {
    let mut registry = REPLIES.lock();
    registry.slots.insert(
        caller,
        ReplySlot {
            target: ReplyTarget::AsyncRing {
                ring_id,
                user_data,
                reply_buf,
            },
            waiting_on: Some(waiting_on),
        },
    );
}

pub fn cancel_replies_waiting_on(dead_task: TaskId) {
    let mut actions = alloc::vec::Vec::new();

    {
        let mut registry = REPLIES.lock();
        let to_cancel: Vec<TaskId> = registry
            .slots
            .iter()
            .filter(|(_, slot)| slot.waiting_on == Some(dead_task))
            .map(|(id, _)| *id)
            .collect();

        for id in to_cancel {
            let slot = registry.slots.remove(&id);
            if let Some(slot) = slot {
                actions.push((id, slot.target));
            }
        }
    }

    for (_id, target) in actions {
        match target {
            ReplyTarget::Sync { waitq, .. } => {
                // Slot removed from registry; the blocked task's
                // wait_until closure will return epipe_reply() when it
                // can't find its slot.
                waitq.wake_all();
            }
            ReplyTarget::AsyncRing {
                ring_id, user_data, ..
            } => {
                push_completion_for_ring_by_id(ring_id, user_data, -32, 0);
            }
        }
    }
}

/// Deliver a reply message to the given task.

pub fn deliver_reply(target: TaskId, msg: IpcMessage) -> Result<(), ()> {
    let mut registry = REPLIES.lock();

    // Fast path: look up the slot without inserting a new one.
    let slot = registry.slots.get_mut(&target).ok_or(())?;

    match &mut slot.target {
        ReplyTarget::Sync {
            msg: slot_msg,
            waitq,
        } => {
            slot_msg.replace(msg);
            let wq = waitq.clone();
            drop(registry);
            wq.wake_one();
            Ok(())
        }
        ReplyTarget::AsyncRing {
            ring_id,
            user_data,
            reply_buf,
        } => {
            let ring_id = *ring_id;
            let user_data = *user_data;
            let reply_buf = *reply_buf;

            registry.slots.remove(&target);

            let mut raw = [0u8; 64];
            crate::ipc::message::ipc_message_to_raw(&msg, &mut raw);
            if let Ok(user) = UserSliceWrite::new(reply_buf, 64) {
                let _ = user.copy_from(&raw);
            }

            drop(registry);

            // Push a CQE to the caller's async ring.
            push_completion_for_ring_by_id(ring_id, user_data, 0, 0);
            Ok(())
        }
    }
}

/// Thin wrapper : resolve `ring_id` to `&Ring` and then push CQE.
fn push_completion_for_ring_by_id(ring_id: u64, user_data: u64, result: i32, flags: u32) {
    if let Some(ring) = find_ring(ring_id) {
        push_completion_for_ring(&ring, user_data, result, flags);
    }
}
