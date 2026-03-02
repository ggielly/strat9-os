use alloc::{collections::BTreeMap, format, string::String, vec::Vec};
use strat9_syscall::data::IpcMessage;
use strat9_syscall::call;
use strat9_syscall::error::ENOSYS;

use crate::BusDriver;

const OPCODE_OPEN: u32 = 0x01;
const OPCODE_READ: u32 = 0x02;
const OPCODE_WRITE: u32 = 0x03;
const OPCODE_CLOSE: u32 = 0x04;
const OPCODE_READDIR: u32 = 0x08;
const REPLY_MSG_TYPE: u32 = 0x80;
const STATUS_OK: u32 = 0;

const EINVAL: u32 = 22;
const EBADF: u32 = 9;

struct OpenHandle {
    path: String,
}

pub struct BusSchemeServer<D: BusDriver> {
    driver: D,
    port_handle: u64,
    handles: BTreeMap<u64, OpenHandle>,
    next_id: u64,
}

impl<D: BusDriver> BusSchemeServer<D> {
    pub fn new(driver: D, port_handle: u64) -> Self {
        Self {
            driver,
            port_handle,
            handles: BTreeMap::new(),
            next_id: 1,
        }
    }

    fn ok_reply(sender: u64) -> IpcMessage {
        let mut reply = IpcMessage::new(REPLY_MSG_TYPE);
        reply.sender = sender;
        reply.payload[0..4].copy_from_slice(&STATUS_OK.to_le_bytes());
        reply
    }

    fn err_reply(sender: u64, code: u32) -> IpcMessage {
        let mut reply = IpcMessage::new(REPLY_MSG_TYPE);
        reply.sender = sender;
        reply.payload[0..4].copy_from_slice(&code.to_le_bytes());
        reply
    }

    fn handle_open(&mut self, sender: u64, payload: &[u8]) -> IpcMessage {
        let path_len = u16::from_le_bytes([payload[4], payload[5]]) as usize;
        if path_len > 42 {
            return Self::err_reply(sender, EINVAL);
        }
        let path_bytes = &payload[6..6 + path_len];
        let path = match core::str::from_utf8(path_bytes) {
            Ok(s) => String::from(s),
            Err(_) => return Self::err_reply(sender, EINVAL),
        };

        let file_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.handles.insert(file_id, OpenHandle { path });

        let mut reply = Self::ok_reply(sender);
        reply.payload[4..12].copy_from_slice(&file_id.to_le_bytes());
        reply.payload[12..20].copy_from_slice(&0u64.to_le_bytes());
        reply.payload[20..24].copy_from_slice(&0u32.to_le_bytes());
        reply
    }

    fn handle_read(&self, sender: u64, payload: &[u8]) -> IpcMessage {
        let file_id = u64::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3],
            payload[4], payload[5], payload[6], payload[7],
        ]);
        let offset = u64::from_le_bytes([
            payload[8], payload[9], payload[10], payload[11],
            payload[12], payload[13], payload[14], payload[15],
        ]);

        let handle = match self.handles.get(&file_id) {
            Some(h) => h,
            None => return Self::err_reply(sender, EBADF),
        };

        let content = self.generate_read_content(&handle.path, offset as usize);
        let n = content.len().min(40);

        let mut reply = Self::ok_reply(sender);
        reply.payload[4..8].copy_from_slice(&(n as u32).to_le_bytes());
        reply.payload[8..8 + n].copy_from_slice(&content[..n]);
        reply
    }

    fn generate_read_content(&self, path: &str, offset: usize) -> Vec<u8> {
        let data = match path {
            "" | "/" => {
                let mut s = format!("driver: {}\n", self.driver.name());
                for c in self.driver.compatible() {
                    s.push_str(&format!("compatible: {}\n", c));
                }
                s.push_str(&format!("errors: {}\n", self.driver.error_count()));
                s.into_bytes()
            }
            "status" => {
                format!("driver: {}\nerrors: {}\n",
                    self.driver.name(), self.driver.error_count()
                ).into_bytes()
            }
            "error_count" => {
                format!("{}\n", self.driver.error_count()).into_bytes()
            }
            _ => {
                if let Some(reg_str) = path.strip_prefix("reg/") {
                    if let Ok(reg_offset) = usize::from_str_radix(reg_str.trim_start_matches("0x"), 16) {
                        match self.driver.read_reg(reg_offset) {
                            Ok(val) => format!("0x{:08x}\n", val).into_bytes(),
                            Err(_) => b"error\n".to_vec(),
                        }
                    } else {
                        b"invalid register\n".to_vec()
                    }
                } else {
                    b"unknown path\n".to_vec()
                }
            }
        };

        if offset >= data.len() {
            Vec::new()
        } else {
            data[offset..].to_vec()
        }
    }

    fn handle_write(&mut self, sender: u64, payload: &[u8]) -> IpcMessage {
        let file_id = u64::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3],
            payload[4], payload[5], payload[6], payload[7],
        ]);
        let len = u16::from_le_bytes([payload[16], payload[17]]) as usize;

        if !self.handles.contains_key(&file_id) {
            return Self::err_reply(sender, EBADF);
        }

        if len > 30 {
            return Self::err_reply(sender, EINVAL);
        }

        let handle = match self.handles.get(&file_id) {
            Some(h) => h,
            None => return Self::err_reply(sender, EBADF),
        };

        let reg_str = match handle.path.strip_prefix("reg/") {
            Some(s) => s,
            None => return Self::err_reply(sender, ENOSYS as u32),
        };
        let reg_offset = match usize::from_str_radix(reg_str.trim_start_matches("0x"), 16) {
            Ok(v) => v,
            Err(_) => return Self::err_reply(sender, EINVAL),
        };
        if len < 4 {
            return Self::err_reply(sender, EINVAL);
        }
        let val = u32::from_le_bytes([
            payload[18], payload[19], payload[20], payload[21],
        ]);
        if self.driver.write_reg(reg_offset, val).is_err() {
            return Self::err_reply(sender, EINVAL);
        }

        let mut reply = Self::ok_reply(sender);
        reply.payload[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        reply
    }

    fn handle_close(&mut self, sender: u64, payload: &[u8]) -> IpcMessage {
        let file_id = u64::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3],
            payload[4], payload[5], payload[6], payload[7],
        ]);
        if self.handles.remove(&file_id).is_some() {
            Self::ok_reply(sender)
        } else {
            Self::err_reply(sender, EBADF)
        }
    }

    fn handle_readdir(&self, sender: u64, payload: &[u8]) -> IpcMessage {
        let children = self.driver.children();
        let mut reply = Self::ok_reply(sender);
        let cursor = u16::from_le_bytes([payload[8], payload[9]]) as usize;
        if cursor >= children.len() {
            reply.payload[4..6].copy_from_slice(&u16::MAX.to_le_bytes());
            reply.payload[6] = 0;
            reply.payload[7] = 0;
            return reply;
        }

        let mut offset = 8usize;
        let mut count = 0u8;
        let mut next_cursor = u16::MAX;
        let mut index = cursor;

        for child in &children[cursor..] {
            let name_bytes = child.name.as_bytes();
            let entry_size = 10 + name_bytes.len();
            if offset + entry_size > 48 {
                let candidate = index.min(u16::MAX as usize) as u16;
                next_cursor = candidate;
                break;
            }
            reply.payload[offset..offset + 8].copy_from_slice(&child.base_addr.to_le_bytes());
            reply.payload[offset + 8] = 4; // DT_DIR
            reply.payload[offset + 9] = name_bytes.len() as u8;
            let end = offset + 10 + name_bytes.len();
            reply.payload[offset + 10..end].copy_from_slice(name_bytes);
            offset = end;
            count += 1;
            index += 1;
        }

        reply.payload[4..6].copy_from_slice(&next_cursor.to_le_bytes());
        reply.payload[6] = count;
        reply.payload[7] = (offset - 8) as u8;
        reply
    }

    pub fn serve(&mut self) -> ! {
        loop {
            let mut msg = IpcMessage::new(0);
            if call::ipc_recv(self.port_handle as usize, &mut msg).is_err() {
                let _ = call::sched_yield();
                continue;
            }

            let reply = match msg.msg_type {
                OPCODE_OPEN => self.handle_open(msg.sender, &msg.payload),
                OPCODE_READ => self.handle_read(msg.sender, &msg.payload),
                OPCODE_WRITE => self.handle_write(msg.sender, &msg.payload),
                OPCODE_CLOSE => self.handle_close(msg.sender, &msg.payload),
                OPCODE_READDIR => self.handle_readdir(msg.sender, &msg.payload),
                _ => Self::err_reply(msg.sender, ENOSYS as u32),
            };
            let _ = call::ipc_reply(&reply);
        }
    }
}
