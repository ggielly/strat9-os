//! Inter-Process Communication (IPC) subsystem.
//!
//! Strat9-OS uses two complementary IPC mechanisms:
//!
//! ## 1. IPC Ports (synchronous message-passing, service endpoints)
//!
//! Each port has a bounded FIFO queue of 64-byte [`IpcMessage`]s.
//! Senders block when the queue is full; receivers block when empty.
//! Ports are owned by a single task and accessed via syscalls:
//! - `SYS_IPC_CREATE_PORT` (200) — create a new port
//! - `SYS_IPC_SEND` (201) — send a message to a port
//! - `SYS_IPC_RECV` (202) — receive a message from a port
//! - `SYS_IPC_CALL` (203) — send and wait for reply
//! - `SYS_IPC_REPLY` (204) — reply to an IPC call
//! - `SYS_IPC_BIND_PORT` (205) — bind a port to the namespace
//! - `SYS_IPC_UNBIND_PORT` (206) — unbind a port
//!
//! ## 2. Typed MPMC sync-channels (IPC-02)
//!
//! [`channel::channel`]`<T>(capacity)` creates a typed
//! Multi-Producer/Multi-Consumer channel for kernel-internal use.
//! [`channel::SyncChan`] provides a symmetric [`IpcMessage`] channel
//! exposed to userspace silos via:
//! - `SYS_CHAN_CREATE` (220) — create a channel
//! - `SYS_CHAN_SEND`   (221) — send (blocking)
//! - `SYS_CHAN_RECV`   (222) — receive (blocking)
//! - `SYS_CHAN_TRY_RECV` (223) — receive (non-blocking)
//! - `SYS_CHAN_CLOSE`  (224) — destroy the channel

pub mod channel;
pub mod message;
pub mod port;
pub mod reply;
pub mod test;

pub use channel::{
    channel, create_channel, destroy_channel, get_channel, ChanId, ChannelError, Receiver, Sender,
    SyncChan,
};
pub use message::IpcMessage;
pub use port::{create_port, destroy_port, get_port, IpcError, Port, PortId};
