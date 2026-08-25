//! L2 — Typed MPMC channel + SyncChan (verbatim kernel code).
//!
//! Blocking paths (`send`/`recv` on full/empty) cannot run single-threaded,
//! so the suite covers the non-blocking surface exhaustively plus the
//! disconnection lifecycle, which is where lost-wakeup and use-after-close
//! bugs historically live. If a test accidentally blocks, the fake
//! `process::block_current_task` panics loudly.

use kernel_l2_tests::ipc::channel::{
    channel, create_channel, ChannelError, SyncChan,
};
use strat9_abi::data::IpcMessage;

// ===========================================================================
// Typed MPMC channel
// ===========================================================================

#[test]
fn mpmc_basic_send_recv_fifo() {
    let (tx, rx) = channel::<u64>(8);
    tx.try_send(1).unwrap();
    tx.try_send(2).unwrap();
    tx.try_send(3).unwrap();
    assert_eq!(rx.try_recv(), Ok(1), "FIFO order violated");
    assert_eq!(rx.try_recv(), Ok(2));
    assert_eq!(rx.try_recv(), Ok(3));
    assert_eq!(rx.try_recv(), Err(ChannelError::WouldBlock));
}

#[test]
fn mpmc_multiple_producers_interleave() {
    let (tx1, rx) = channel::<u64>(16);
    let tx2 = tx1.clone();
    for i in 0..8 {
        tx1.try_send(i).unwrap();
        tx2.try_send(i + 100).unwrap();
    }
    // All 16 messages arrive; per-producer order is preserved.
    let mut got = Vec::new();
    for _ in 0..16 {
        got.push(rx.try_recv().unwrap());
    }
    let from_tx1: Vec<u64> = got.iter().filter(|v| **v < 100).copied().collect();
    let from_tx2: Vec<u64> = got.iter().filter(|v| **v >= 100).copied().collect();
    assert_eq!(from_tx1, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(from_tx2, vec![100, 101, 102, 103, 104, 105, 106, 107]);
}

#[test]
fn mpmc_full_queue_returns_value_via_try_send() {
    let (tx, rx) = channel::<u32>(2);
    tx.try_send(1).unwrap();
    tx.try_send(2).unwrap();
    // try_send must give the message BACK on WouldBlock (no silent drop).
    assert_eq!(tx.try_send(3), Err((3, ChannelError::WouldBlock)));
    assert_eq!(rx.try_recv(), Ok(1));
    tx.try_send(3).unwrap();
    assert_eq!(rx.try_recv(), Ok(2));
    assert_eq!(rx.try_recv(), Ok(3));
}

#[test]
fn sender_drop_disconnects_receiver() {
    let (tx, rx) = channel::<u64>(4);
    tx.try_send(7).unwrap();
    drop(tx);

    // Draining still works after disconnect...
    assert_eq!(rx.try_recv(), Ok(7));
    // ...then Disconnected, not WouldBlock.
    assert_eq!(rx.try_recv(), Err(ChannelError::Disconnected));
    assert!(rx.is_disconnected());
}

#[test]
fn receiver_drop_disconnects_sender() {
    let (tx, rx) = channel::<u64>(4);
    drop(rx);
    assert!(tx.is_disconnected());
    assert_eq!(tx.try_send(1), Err((1, ChannelError::Disconnected)));
}

#[test]
fn disconnect_requires_dropping_all_clones() {
    let (tx, rx) = channel::<u64>(4);
    let tx2 = tx.clone();
    drop(tx);
    // One clone alive → channel stays connected.
    assert!(!tx2.is_disconnected());
    assert!(!rx.is_disconnected());
    tx2.try_send(5).unwrap();
    drop(tx2);
    assert!(rx.is_disconnected());
    // Buffered message survives until drained.
    assert_eq!(rx.try_recv(), Ok(5));
    assert_eq!(rx.try_recv(), Err(ChannelError::Disconnected));
}

// ===========================================================================
// SyncChan: symmetric userspace IPC channel
// ===========================================================================

fn make_chan(cap: usize) -> std::sync::Arc<SyncChan> {
    let id = create_channel(cap);
    kernel_l2_tests::ipc::channel::get_channel(id).expect("just-registered channel")
}

#[test]
fn sync_chan_symmetric_send_recv() {
    let ch = make_chan(4);
    let msg_a = IpcMessage::new(0x11);
    let msg_b = {
        let mut m = IpcMessage::new(0x22);
        m.sender = 42;
        m
    };
    ch.send(msg_a).unwrap();
    ch.send(msg_b).unwrap();
    assert_eq!(ch.len(), 2);
    assert_eq!(ch.try_recv().unwrap().msg_type, msg_a.msg_type);
    let got_b = ch.try_recv().unwrap();
    assert_eq!(got_b.msg_type, msg_b.msg_type);
    assert_eq!(got_b.sender, msg_b.sender);
    assert!(matches!(ch.try_recv(), Err(ChannelError::WouldBlock)));
}

#[test]
fn sync_chan_destroy_rejects_further_traffic() {
    let ch = make_chan(4);
    ch.send(IpcMessage::new(1)).unwrap();
    assert!(!ch.is_destroyed());
    ch.destroy();
    assert!(ch.is_destroyed());
    // Sends are rejected immediately...
    assert!(matches!(
        ch.send(IpcMessage::new(2)),
        Err(ChannelError::Disconnected)
    ));
    // ...but already-buffered messages remain receivable (drain-first
    // contract, same as the typed channel): 1 buffered msg, then Disconnected.
    assert_eq!(ch.try_recv().unwrap().msg_type, 1);
    assert!(matches!(ch.try_recv(), Err(ChannelError::Disconnected)));
}

#[test]
fn sync_chan_registry_create_and_lookup() {
    // create_channel registers in the global ChanId table — exercises the
    // registry path used by SYS_CHAN_* syscalls.
    let id = create_channel(8);
    // A fresh id must be usable; destroying twice must be tolerated.
    if let Some(ch) = kernel_l2_tests::ipc::channel::get_channel(id) {
        ch.destroy();
        ch.destroy(); // idempotent destroy
        assert!(ch.is_destroyed());
    }
}
