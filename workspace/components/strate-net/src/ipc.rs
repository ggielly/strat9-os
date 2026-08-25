//! Typed helpers to build and parse the VFS scheme wire protocol.
//!
//! Every function here delegates to the typed ABI layer
//! (`strat9_abi::ipc_payload`) instead of hand-rolled payload offsets,
//! so the wire contract has a single source of truth.

use strat9_abi::ipc_payload::{
    OpenReply, OpenRequest, ReadReply, ReadRequest, WriteReply, WriteRequest,
};
use strat9_syscall::data::{
    IPC_FILE_FLAG_CHUNK_READ, IPC_FILE_FLAG_CHUNK_WRITE, IPC_FILE_FLAG_PIPE, IpcMessage,
};

pub(crate) const HANDLE_FLAG_INFO: u32 = IPC_FILE_FLAG_CHUNK_READ;
pub(crate) const HANDLE_FLAG_CONTROL: u32 = 0;
pub(crate) const HANDLE_FLAG_STREAM: u32 =
    IPC_FILE_FLAG_PIPE | IPC_FILE_FLAG_CHUNK_READ | IPC_FILE_FLAG_CHUNK_WRITE;
pub(crate) const HANDLE_FLAG_DATAGRAM: u32 = IPC_FILE_FLAG_CHUNK_READ;

/// Errno value returned for malformed requests (`EINVAL`).
const EINVAL: i32 = -22;

pub(crate) fn reply_open(sender: u64, file_id: u64, size: u64, flags: u32) -> IpcMessage {
    let mut msg = IpcMessage::new(IpcMessage::REPLY_MSG_TYPE);
    msg.sender = sender;
    OpenReply {
        status: 0,
        file_id,
        size,
        file_flags: flags,
    }
    .encode_into(&mut msg.payload);
    msg
}

pub(crate) fn reply_read(sender: u64, data: &[u8]) -> IpcMessage {
    let (msg, _n) = ReadReply::encode_ok(sender, data);
    msg
}

pub(crate) fn reply_write(sender: u64, n: usize) -> IpcMessage {
    WriteReply::encode_ok(sender, n)
}

pub(crate) fn reply_write_data_len(sender: u64, msg: &IpcMessage) -> IpcMessage {
    match WriteRequest::parse_prefix(&msg.payload) {
        Some(req) => reply_write(sender, req.data_len as usize),
        None => reply_write(sender, 0),
    }
}

pub(crate) fn reply_ok(sender: u64) -> IpcMessage {
    IpcMessage::status_reply(sender, 0)
}

/// Extract the path from an OPEN request, with any leading `/` trimmed.
pub(crate) fn open_path(msg: &IpcMessage) -> Result<&str, i32> {
    let (_flags, path) = OpenRequest::parse(&msg.payload).ok_or(EINVAL)?;
    if path.len() > IpcMessage::OPEN_INLINE_CAPACITY {
        return Err(EINVAL);
    }
    Ok(path.trim_start_matches('/'))
}

pub(crate) fn message_file_id(msg: &IpcMessage) -> u64 {
    // Used for CLOSE-style requests whose payload is a single `ino: u64`.
    u64::from_le_bytes(msg.payload[0..8].try_into().unwrap_or([0u8; 8]))
}

/// Parse a READ request payload into `(file_id, offset, requested_count)`.
pub(crate) fn read_request(msg: &IpcMessage) -> (u64, u64, usize) {
    match ReadRequest::parse(&msg.payload) {
        Some(req) => (req.ino, req.offset, req.count_usize()),
        None => (0, 0, 0),
    }
}

pub(crate) fn write_data(msg: &IpcMessage) -> &[u8] {
    WriteRequest::parse_prefix(&msg.payload)
        .and_then(|req| req.data(&msg.payload))
        .unwrap_or(&[])
}
