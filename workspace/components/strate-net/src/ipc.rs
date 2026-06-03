use core::str;

use strat9_syscall::data::{
    IPC_FILE_FLAG_CHUNK_READ, IPC_FILE_FLAG_CHUNK_WRITE, IPC_FILE_FLAG_PIPE,
};
use strate_net::IpcMessage;

pub(crate) const HANDLE_FLAG_INFO: u32 = IPC_FILE_FLAG_CHUNK_READ;
pub(crate) const HANDLE_FLAG_CONTROL: u32 = 0;
pub(crate) const HANDLE_FLAG_STREAM: u32 =
    IPC_FILE_FLAG_PIPE | IPC_FILE_FLAG_CHUNK_READ | IPC_FILE_FLAG_CHUNK_WRITE;
pub(crate) const HANDLE_FLAG_DATAGRAM: u32 = IPC_FILE_FLAG_CHUNK_READ;

pub(crate) fn reply_open(sender: u64, file_id: u64, size: u64, flags: u32) -> IpcMessage {
    let mut msg = IpcMessage::new(0x80);
    msg.sender = sender;
    msg.payload[0..4].copy_from_slice(&0u32.to_le_bytes());
    msg.payload[4..12].copy_from_slice(&file_id.to_le_bytes());
    msg.payload[12..20].copy_from_slice(&size.to_le_bytes());
    msg.payload[20..24].copy_from_slice(&flags.to_le_bytes());
    msg
}

pub(crate) fn reply_read(sender: u64, data: &[u8]) -> IpcMessage {
    let mut msg = IpcMessage::new(0x80);
    msg.sender = sender;
    msg.payload[0..4].copy_from_slice(&0u32.to_le_bytes());
    let n = data.len().min(IpcMessage::READ_INLINE_CAPACITY);
    msg.payload[4..8].copy_from_slice(&(n as u32).to_le_bytes());
    msg.payload[8..8 + n].copy_from_slice(&data[..n]);
    msg
}

pub(crate) fn reply_write(sender: u64, n: usize) -> IpcMessage {
    let mut msg = IpcMessage::new(0x80);
    msg.sender = sender;
    msg.payload[0..4].copy_from_slice(&0u32.to_le_bytes());
    msg.payload[4..8].copy_from_slice(&(n as u32).to_le_bytes());
    msg
}

pub(crate) fn reply_write_data_len(sender: u64, msg: &IpcMessage) -> IpcMessage {
    let data_len = u16::from_le_bytes([msg.payload[16], msg.payload[17]]) as usize;
    reply_write(sender, data_len)
}

pub(crate) fn reply_ok(sender: u64) -> IpcMessage {
    let mut msg = IpcMessage::new(0x80);
    msg.sender = sender;
    msg.payload[0..4].copy_from_slice(&0u32.to_le_bytes());
    msg
}

pub(crate) fn open_path<'a>(msg: &'a IpcMessage) -> Result<&'a str, i32> {
    let path_len = u16::from_le_bytes([msg.payload[4], msg.payload[5]]) as usize;
    if path_len > IpcMessage::OPEN_INLINE_CAPACITY {
        return Err(-22);
    }
    let path_bytes = &msg.payload[6..6 + path_len];
    let path = str::from_utf8(path_bytes).map_err(|_| -22)?;
    Ok(path.trim_start_matches('/'))
}

pub(crate) fn message_file_id(msg: &IpcMessage) -> u64 {
    u64::from_le_bytes(msg.payload[0..8].try_into().unwrap_or([0u8; 8]))
}

pub(crate) fn read_request(msg: &IpcMessage) -> (u64, u64, usize) {
    let file_id = message_file_id(msg);
    let offset = u64::from_le_bytes(msg.payload[8..16].try_into().unwrap_or([0u8; 8]));
    let requested = u32::from_le_bytes(msg.payload[16..20].try_into().unwrap_or([0u8; 4]));
    (file_id, offset, requested as usize)
}

pub(crate) fn write_data_len(msg: &IpcMessage) -> usize {
    let data_len = u16::from_le_bytes([msg.payload[16], msg.payload[17]]) as usize;
    core::cmp::min(data_len, msg.payload.len().saturating_sub(18))
}

pub(crate) fn write_data(msg: &IpcMessage) -> &[u8] {
    let data_len = write_data_len(msg);
    &msg.payload[18..18 + data_len]
}
