//! IPC ping-pong test.
//!
//! Creates two kernel tasks that communicate via an IPC port:
//! - Task A (sender): creates a port, stores its ID in a shared static,
//!   then sends a message with msg_type=42.
//! - Task B (receiver): spins until the port ID is published, then calls
//!   `recv()` (which blocks if the message hasn't arrived yet), logs the
//!   result, and verifies correctness.
//!
//! This exercises:
//! - Port creation / global registry
//! - Blocking recv (Task B may block waiting for Task A's message)
//! - WaitQueue integration with the scheduler
//! - Message delivery with kernel-filled `sender` field

use crate::ipc::{self, IpcMessage, PortId};
use crate::process::{Task, TaskPriority, add_task};
use core::sync::atomic::{AtomicU64, Ordering};

/// Shared port ID between the two test tasks.
/// 0 = not yet created.
static TEST_PORT_ID: AtomicU64 = AtomicU64::new(0);

/// Create and schedule the IPC test tasks.
pub fn create_ipc_test_tasks() {
    let task_a = Task::new_kernel_task(ipc_sender_main, "ipc-sender", TaskPriority::Normal)
        .expect("Failed to create IPC sender task");
    add_task(task_a);

    let task_b = Task::new_kernel_task(ipc_receiver_main, "ipc-recv", TaskPriority::Normal)
        .expect("Failed to create IPC receiver task");
    add_task(task_b);
}

/// Sender task: creates a port, publishes ID, sends a test message, then exits.
extern "C" fn ipc_sender_main() -> ! {
    crate::serial_println!("[ipc-test] Task A (sender): starting");

    // Get our task ID
    let my_id = crate::process::current_task_id().unwrap();
    crate::serial_println!("[ipc-test] Task A: creating port...");

    let port_id = ipc::create_port(my_id);
    crate::serial_println!("[ipc-test] Task A: port {} created", port_id);

    // Publish the port ID so the receiver can find it
    TEST_PORT_ID.store(port_id.as_u64(), Ordering::Release);

    // Yield a couple of times to give the receiver a chance to call recv() first
    // (this tests the blocking path — receiver blocks, then we wake it)
    crate::process::yield_task();
    crate::process::yield_task();

    // Build a test message
    let mut msg = IpcMessage::new(42); // msg_type = 42
    msg.payload[0] = b'H';
    msg.payload[1] = b'i';
    msg.payload[2] = b'!';

    crate::serial_println!("[ipc-test] Task A: sending message (type=42)...");
    let port = ipc::get_port(port_id).expect("port should exist");
    port.send(msg).expect("send should succeed");
    crate::serial_println!("[ipc-test] Task A: message sent, exiting");

    crate::process::scheduler::exit_current_task();
}

/// Receiver task: waits for port ID, calls recv (blocks if needed), logs result.
extern "C" fn ipc_receiver_main() -> ! {
    crate::serial_println!("[ipc-test] Task B (receiver): starting");

    // Wait for the sender to publish the port ID
    let port_id = loop {
        let id = TEST_PORT_ID.load(Ordering::Acquire);
        if id != 0 {
            break PortId(id);
        }
        crate::process::yield_task();
    };

    crate::serial_println!("[ipc-test] Task B: found port {}, calling recv...", port_id);

    let port = ipc::get_port(port_id).expect("port should exist");
    let msg = port.recv().expect("recv should succeed");

    let sender = msg.sender;
    let msg_type = msg.msg_type;
    crate::serial_println!(
        "[ipc-test] Task B: received message (type={}, sender={})",
        msg_type,
        sender,
    );

    // Verify correctness
    if msg_type == 42 && msg.payload[0] == b'H' && msg.payload[1] == b'i' && msg.payload[2] == b'!' {
        crate::serial_println!("[ipc-test] IPC ping-pong test PASSED");
    } else {
        crate::serial_println!("[ipc-test] IPC ping-pong test FAILED (unexpected data)");
    }

    crate::process::scheduler::exit_current_task();
}

// The PortId(u64) constructor is pub(crate) via the struct definition,
// so this test module in the same crate can use it directly.
