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

/// Block the current task waiting for a reply message.
///
/// Returns an EPIPE error reply if the slot was removed while waiting
/// (e.g. the server died and cleanup ran).
pub fn wait_for_reply(task_id: TaskId) -> IpcMessage {
    let waitq = {
        let mut registry = REPLIES.lock();
        let slot = registry.slots.entry(task_id).or_insert_with(|| ReplySlot {
            msg: None,
            waitq: Arc::new(WaitQueue::new()),
        });
        slot.waitq.clone()
    };

    let msg = waitq.wait_until(|| {
        let mut registry = REPLIES.lock();
        match registry.slots.get_mut(&task_id) {
            Some(slot) => slot.msg.take(),
            None => {
                let mut err = IpcMessage::new(0x80);
                let epipe: u32 = 32;
                err.payload[0..4].copy_from_slice(&epipe.to_le_bytes());
                Some(err)
            }
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
    let registry = REPLIES.lock();
    let has_slot = registry.slots.contains_key(&dead_task);
    drop(registry);

    if has_slot {
        let mut registry = REPLIES.lock();
        if let Some(slot) = registry.slots.remove(&dead_task) {
            slot.waitq.wake_all();
        }
    }
}

/// Deliver a reply message to the given task (wakes it if blocked).
pub fn deliver_reply(target: TaskId, msg: IpcMessage) -> Result<(), ()> {
    let waitq = {
        let mut registry = REPLIES.lock();
        let slot = registry.slots.entry(target).or_insert_with(|| ReplySlot {
            msg: None,
            waitq: Arc::new(WaitQueue::new()),
        });
        slot.msg = Some(msg);
        slot.waitq.clone()
    };

    waitq.wake_one();
    Ok(())
}
