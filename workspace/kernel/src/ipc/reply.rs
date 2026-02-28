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
    const fn new() -> Self {
        ReplyRegistry {
            slots: BTreeMap::new(),
        }
    }
}

static REPLIES: SpinLock<ReplyRegistry> = SpinLock::new(ReplyRegistry::new());

/// Block the current task waiting for a reply message.
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
        let slot = registry.slots.get_mut(&task_id)
            .expect("reply slot removed while waiting");
        slot.msg.take()
    });

    let mut registry = REPLIES.lock();
    registry.slots.remove(&task_id);

    msg
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
