//! IPC ping-pong test (Port-based) + MPMC SyncChannel test (IPC-02).
//!
//! ## Port test (Task A / Task B)
//! Creates two kernel tasks that communicate via an IPC port:
//! - Task A (sender): creates a port, stores its ID in a shared static,
//!   then sends a message with msg_type=42.
//! - Task B (receiver): spins until the port ID is published, then calls
//!   `recv()` (which blocks if the message hasn't arrived yet), logs the
//!   result, and verifies correctness.
//!
//! ## Channel test (IPC-02)
//! Three kernel tasks share a `channel::<u64>(4)`:
//! - Producer-1: sends 1, 2, 3 then drops its Sender endpoint.
//! - Producer-2: yields once (so the consumer may block), then sends 4, 5.
//! - Consumer: blocks on `recv()` until both producers disconnect,
//!   verifies it received exactly 5 messages.

use crate::{
    ipc::{self, channel, IpcMessage, PortId},
    process::{add_task, Task, TaskPriority},
    sync::SpinLock,
};
use core::sync::atomic::{AtomicU64, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// Port ping-pong test
// ─────────────────────────────────────────────────────────────────────────────

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

    crate::process::scheduler::exit_current_task(0);
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
    if msg_type == 42 && msg.payload[0] == b'H' && msg.payload[1] == b'i' && msg.payload[2] == b'!'
    {
        crate::serial_println!("[ipc-test] IPC ping-pong test PASSED");
    } else {
        crate::serial_println!("[ipc-test] IPC ping-pong test FAILED (unexpected data)");
    }

    crate::process::scheduler::exit_current_task(0);
}

// The PortId(u64) constructor is pub(crate) via the struct definition,
// so this test module in the same crate can use it directly.

// ─────────────────────────────────────────────────────────────────────────────
// IPC-02: typed MPMC SyncChannel test
// ─────────────────────────────────────────────────────────────────────────────
//
// Exercises:
//   - channel() constructor (Sender<u64> + Receiver<u64> cloning → MPMC)
//   - Blocking recv  (consumer blocks; producer-2 yields first to force it)
//   - Disconnect detection (last Sender drop → Receiver sees Disconnected)
//   - wait_until round-trip through the scheduler

/// Endpoint slots: each task takes its endpoint out (Option::take) once.
/// SpinLock<Option<T>>: Sync when T: Send — no private-field access needed.
static CHAN_TX1: SpinLock<Option<channel::Sender<u64>>> = SpinLock::new(None);
static CHAN_TX2: SpinLock<Option<channel::Sender<u64>>> = SpinLock::new(None);
static CHAN_RX: SpinLock<Option<channel::Receiver<u64>>> = SpinLock::new(None);

/// Schedule the three channel test tasks.
pub fn create_channel_test_tasks() {
    let (tx, rx) = channel::channel::<u64>(4);
    let tx2 = tx.clone(); // MPMC: second producer on the same channel

    *CHAN_TX1.lock() = Some(tx);
    *CHAN_TX2.lock() = Some(tx2);
    *CHAN_RX.lock() = Some(rx);

    let producer1 =
        Task::new_kernel_task(chan_producer1_main, "chan-prod-1", TaskPriority::Normal)
            .expect("chan-prod-1 alloc failed");
    let producer2 =
        Task::new_kernel_task(chan_producer2_main, "chan-prod-2", TaskPriority::Normal)
            .expect("chan-prod-2 alloc failed");
    let consumer =
        Task::new_kernel_task(chan_consumer_main, "chan-consumer", TaskPriority::Normal)
            .expect("chan-consumer alloc failed");

    add_task(producer1);
    add_task(producer2);
    add_task(consumer);
}

/// Producer-1: sends 1, 2, 3 then drops Sender (decrements sender_count).
extern "C" fn chan_producer1_main() -> ! {
    crate::serial_println!("[chan-test] Producer-1: starting");
    let tx = CHAN_TX1.lock().take().expect("CHAN_TX1 empty");

    for v in [1u64, 2, 3] {
        crate::serial_println!("[chan-test] Producer-1: sending {}", v);
        tx.send(v).expect("prod1 send failed");
    }

    crate::serial_println!("[chan-test] Producer-1: done");
    drop(tx); // explicit: sender_count--
    crate::process::scheduler::exit_current_task(0);
}

/// Producer-2: yields first so the consumer blocks, then sends 4, 5.
extern "C" fn chan_producer2_main() -> ! {
    crate::serial_println!("[chan-test] Producer-2: starting");
    let tx = CHAN_TX2.lock().take().expect("CHAN_TX2 empty");

    crate::process::yield_task(); // ensure consumer reaches recv() first

    for v in [4u64, 5] {
        crate::serial_println!("[chan-test] Producer-2: sending {}", v);
        tx.send(v).expect("prod2 send failed");
    }

    crate::serial_println!("[chan-test] Producer-2: done");
    drop(tx); // last Sender → receiver wakes with Disconnected next call
    crate::process::scheduler::exit_current_task(0);
}

/// Consumer: drains all messages; expects exactly 5, then Disconnected.
extern "C" fn chan_consumer_main() -> ! {
    crate::serial_println!("[chan-test] Consumer: starting");
    let rx = CHAN_RX.lock().take().expect("CHAN_RX empty");

    let mut received: u64 = 0;
    loop {
        match rx.recv() {
            Ok(v) => {
                crate::serial_println!("[chan-test] Consumer: got {}", v);
                received += 1;
            }
            Err(channel::ChannelError::Disconnected) => {
                crate::serial_println!("[chan-test] Consumer: disconnected after {} msgs", received);
                break;
            }
            Err(e) => {
                crate::serial_println!("[chan-test] Consumer: unexpected error {:?}", e);
                break;
            }
        }
    }

    if received == 5 {
        crate::serial_println!("[chan-test] SyncChannel MPMC test PASSED ({} msgs)", received);
    } else {
        crate::serial_println!(
            "[chan-test] SyncChannel MPMC test FAILED (expected 5, got {})",
            received
        );
    }

    crate::process::scheduler::exit_current_task(0);
}
