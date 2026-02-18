//! Inter-Process Communication (IPC) subsystem.
//!
//! Strat9-OS uses synchronous message-passing ports as its primary IPC
//! mechanism. Each port has a bounded FIFO queue of 64-byte inline messages.
//! Senders block when the queue is full; receivers block when it's empty.
//!
//! Ports are kernel objects accessed via syscalls:
//! - `SYS_IPC_CREATE_PORT` (200) — create a new port
//! - `SYS_IPC_SEND` (201) — send a message to a port
//! - `SYS_IPC_RECV` (202) — receive a message from a port
//! - `SYS_IPC_CALL` (203) — send and wait for reply
//! - `SYS_IPC_REPLY` (204) — reply to an IPC call
//! - `SYS_IPC_BIND_PORT` (205) — bind a port to the namespace
//! - `SYS_IPC_UNBIND_PORT` (206) — unbind a port

pub mod message;
pub mod port;
pub mod reply;
pub mod test;

pub use message::IpcMessage;
pub use port::{Port, PortId, IpcError, create_port, get_port, destroy_port};
