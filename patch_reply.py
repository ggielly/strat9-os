with open('workspace/kernel/src/ipc/reply.rs', 'r') as f:
    content = f.read()

old_wait = """pub fn wait_for_reply(task_id: TaskId) -> IpcMessage {
    loop {
        let waitq = {
            let mut registry = REPLIES.lock();
            let slot = registry.slots.entry(task_id).or_insert_with(|| ReplySlot {
                msg: None,
                waitq: Arc::new(WaitQueue::new()),
            });
            if let Some(msg) = slot.msg.take() {
                return msg;
            }
            slot.waitq.clone()
        };

        waitq.wait();
    }
}"""

new_wait = """pub fn wait_for_reply(task_id: TaskId) -> IpcMessage {
    let waitq = {
        let mut registry = REPLIES.lock();
        let slot = registry.slots.entry(task_id).or_insert_with(|| ReplySlot {
            msg: None,
            waitq: Arc::new(WaitQueue::new()),
        });
        slot.waitq.clone()
    };

    waitq.wait_until(|| {
        let mut registry = REPLIES.lock();
        let slot = registry.slots.get_mut(&task_id).unwrap();
        slot.msg.take()
    })
}"""

content = content.replace(old_wait, new_wait)

with open('workspace/kernel/src/ipc/reply.rs', 'w') as f:
    f.write(content)
