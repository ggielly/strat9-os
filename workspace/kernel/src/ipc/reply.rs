//! IPC synchronous call/reply support.

use super::message::IpcMessage;
use crate::{
    process::TaskId,
    sync::{SpinLock, WaitQueue},
};
use alloc::{collections::BTreeMap, sync::Arc};

struct ReplySlot {
    msg: Option<IpcMessage>,
    waitq: Arc<WaitQueue>,
    waiting_on: Option<TaskId>,
}

struct ReplyRegistry {
    slots: BTreeMap<TaskId, ReplySlot>,
}

impl ReplyRegistry {
    /// Creates a new instance.
    const fn new() -> Self {
        ReplyRegistry {
            slots: BTreeMap::new(),
        }
    }
}

static REPLIES: SpinLock<ReplyRegistry> = SpinLock::new(ReplyRegistry::new());

// TODO(migration): Reply slots are still keyed only by caller TaskId, which
// means the kernel implicitly supports at most one outstanding synchronous
// ipc_call per task. If nested or concurrent synchronous calls are ever needed,
// introduce a per-call correlation token, thread it through wait_for_reply /
// deliver_reply / cleanup_ports_for_task, and make cancellation target the
// exact call instance instead of the whole task slot.

fn epipe_reply() -> IpcMessage {
    let mut err = IpcMessage::new(0x80);
    let epipe: u32 = 32;
    err.payload[0..4].copy_from_slice(&epipe.to_le_bytes());
    err
}

/// Block the current task waiting for a reply message.
///
/// Returns an EPIPE error reply if the slot was removed while waiting
/// (e.g. the server died and cleanup ran).
pub fn wait_for_reply(task_id: TaskId, waiting_on: TaskId) -> IpcMessage {
    let waitq = {
        let mut registry = REPLIES.lock();
        let slot = registry.slots.entry(task_id).or_insert_with(|| ReplySlot {
            msg: None,
            waitq: Arc::new(WaitQueue::new()),
            waiting_on: Some(waiting_on),
        });
        slot.waiting_on = Some(waiting_on);
        slot.waitq.clone()
    };

    let msg = waitq.wait_until(|| {
        let mut registry = REPLIES.lock();
        match registry.slots.get_mut(&task_id) {
            Some(slot) => slot.msg.take(),
            None => Some(epipe_reply()),
        }
    });

    let mut registry = REPLIES.lock();
    registry.slots.remove(&task_id);

    msg
}

/// Cancel all pending reply slots and wake blocked callers with EPIPE.
///
/// Called during task cleanup to unblock any tasks waiting for a reply
/// that this dying task should have delivered.
pub fn cancel_replies_waiting_on(dead_task: TaskId) {
    let waiters = {
        let mut registry = REPLIES.lock();
        let mut waitqs = alloc::vec::Vec::new();
        for slot in registry.slots.values_mut() {
            if slot.waiting_on != Some(dead_task) {
                continue;
            }
            if slot.msg.is_none() {
                slot.msg = Some(epipe_reply());
            }
            waitqs.push(slot.waitq.clone());
        }
        waitqs
    };

    for waitq in waiters {
        waitq.wake_all();
    }
}

/// Deliver a reply message to the given task (wakes it if blocked).
pub fn deliver_reply(target: TaskId, msg: IpcMessage) -> Result<(), ()> {
    let waitq = {
        let mut registry = REPLIES.lock();
        let slot = registry.slots.entry(target).or_insert_with(|| ReplySlot {
            msg: None,
            waitq: Arc::new(WaitQueue::new()),
            waiting_on: None,
        });
        slot.msg = Some(msg);
        slot.waitq.clone()
    };

    waitq.wake_one();
    Ok(())
}
