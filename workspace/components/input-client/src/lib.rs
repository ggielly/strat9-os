/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! Client side of the strat9-os input server (`inputd`).
//!
//! [`Client::open`] creates a private port, binds it to `/srv/input/c/<pid>`,
//! connects to `/srv/input` and sends one `Subscribe`. The server then pushes
//! [`InputBatch`]es and `Reset` payloads to that private port, which
//! [`Client::poll`] / [`Client::wait`] decode without allocating.
//!
//! Focus policy: the server keeps a single focused surface and sends input to
//! it only. The first subscriber is focused by default; [`Client::request_focus`]
//! asks the server to transfer focus to this client.
//!
//! `SubscribeAck` and unknown message types are ignored so newer servers can
//! add messages without breaking older clients. A malformed payload makes
//! `poll` return [`Poll::Error`]; it never panics.

#![no_std]

#[cfg(test)]
extern crate std;

use input_protocol::{
    Focus, InputBatch, Reset, Subscribe, INPUT_BATCH_FIXED_LEN, INPUTD_MSG_BATCH,
    INPUTD_MSG_FOCUS, INPUTD_MSG_RESET, INPUT_RECORD_LEN, MAX_INPUT_RECORDS,
    MAX_SUBSCRIBE_PATH, RESET_LEN,
};
use strat9_syscall::{
    call,
    data::IpcMessage,
    error::Error,
};

/// Namespace prefix of the per-client subscription ports.
pub const CLIENT_PATH_PREFIX: &[u8] = b"/srv/input/c/";
/// Maximum subscription path length (`input-protocol` A.5).
pub const CLIENT_PATH_MAX: usize = MAX_SUBSCRIBE_PATH;

const MSG_BATCH: u32 = INPUTD_MSG_BATCH as u32;
const MSG_RESET: u32 = INPUTD_MSG_RESET as u32;

/// Result of one non-blocking receive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Poll {
    /// No message was pending.
    Empty,
    /// One decoded input batch.
    Batch(InputBatch),
    /// Input state must be resynchronised.
    Reset {
        /// Epoch the server expects the client to adopt.
        focus_epoch: u32,
        /// One of the `RESET_REASON_*` constants.
        reason: u32,
    },
    /// The port failed, or a payload was malformed.
    Error,
}

/// Decoded message, before it is turned into a [`Poll`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Decoded {
    Batch(InputBatch),
    Reset(Reset),
    /// Known or unknown message that carries nothing for the client.
    Ignore,
    /// Payload that does not satisfy the A.5 wire rules.
    Malformed,
}

/// Format `/srv/input/c/<pid>` into `out`. Returns the path length, or `None`
/// if it would not fit.
pub(crate) fn client_path(pid: usize, out: &mut [u8; CLIENT_PATH_MAX]) -> Option<u8> {
    let mut digits = [0u8; 20];
    let mut count = 0usize;
    let mut value = pid;
    loop {
        digits[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }

    let len = CLIENT_PATH_PREFIX.len() + count;
    if len > CLIENT_PATH_MAX {
        return None;
    }
    out[..CLIENT_PATH_PREFIX.len()].copy_from_slice(CLIENT_PATH_PREFIX);
    for index in 0..count {
        out[CLIENT_PATH_PREFIX.len() + index] = digits[count - 1 - index];
    }
    Some(len as u8)
}

/// Decode one message body without allocating.
///
/// `IpcMessage` carries no payload length, so the exact encoded length is
/// derived from the payload's own header (batch `count`, fixed `Reset` size).
pub(crate) fn decode(msg_type: u32, payload: &[u8]) -> Decoded {
    match msg_type {
        MSG_BATCH => {
            if payload.len() < INPUT_BATCH_FIXED_LEN {
                return Decoded::Malformed;
            }
            let count = u16::from_le_bytes([payload[0], payload[1]]) as usize;
            if count > MAX_INPUT_RECORDS {
                return Decoded::Malformed;
            }
            let required = INPUT_BATCH_FIXED_LEN + INPUT_RECORD_LEN * count;
            if required > payload.len() {
                return Decoded::Malformed;
            }
            match InputBatch::decode(&payload[..required]) {
                Ok(batch) => Decoded::Batch(batch),
                Err(_) => Decoded::Malformed,
            }
        }
        MSG_RESET => {
            if payload.len() < RESET_LEN {
                return Decoded::Malformed;
            }
            match Reset::decode(&payload[..RESET_LEN]) {
                Ok(reset) => Decoded::Reset(reset),
                Err(_) => Decoded::Malformed,
            }
        }
        // `SubscribeAck` and unknown tags are intentionally ignored.
        _ => Decoded::Ignore,
    }
}

/// A subscribed input client.
pub struct Client {
    port: usize,
    /// Connected `/srv/input` handle, kept for `request_focus`.
    service: usize,
    path_len: u8,
    path: [u8; CLIENT_PATH_MAX],
    focus_epoch: u32,
}

impl Client {
    /// Subscribe to `inputd` at `focus_epoch`.
    ///
    /// Returns `None` if the private port cannot be created, bound or
    /// registered; every partially created resource is closed first.
    pub fn open(focus_epoch: u32) -> Option<Self> {
        let port = call::ipc_create_port(0).ok()?;

        let mut path = [0u8; CLIENT_PATH_MAX];
        let pid = match call::getpid() {
            Ok(pid) => pid,
            Err(_) => {
                close_port(port);
                return None;
            }
        };
        let Some(path_len) = client_path(pid, &mut path) else {
            close_port(port);
            return None;
        };
        if call::ipc_bind_port(port, &path[..path_len as usize]).is_err() {
            close_port(port);
            return None;
        }

        let Some(service) = connect_and_subscribe(focus_epoch, &path[..path_len as usize]) else {
            let _ = call::ipc_unbind_port(&path[..path_len as usize]);
            close_port(port);
            return None;
        };

        Some(Client {
            port,
            service,
            path_len,
            path,
            focus_epoch,
        })
    }

    /// Ask `inputd` to give this client input focus.
    ///
    /// Sends one `Focus` with the client's own path. Returns `true` when the
    /// message was queued. The server still ignores it if the path is not a
    /// current subscriber, so a focus request can never steal another
    /// client's focus.
    pub fn request_focus(&self) -> bool {
        let mut msg = IpcMessage::new(INPUTD_MSG_FOCUS as u32);
        let request = Focus {
            focus_epoch: self.focus_epoch,
            path: &self.path[..self.path_len as usize],
        };
        if request.encode(&mut msg.payload).is_err() {
            return false;
        }
        let mut result = call::ipc_try_send(self.service, &msg);
        if matches!(result, Err(Error::Again)) {
            result = call::ipc_send(self.service, &msg);
        }
        result.is_ok()
    }

    /// Focus epoch this client subscribed with.
    pub fn focus_epoch(&self) -> u32 {
        self.focus_epoch
    }

    /// Non-blocking receive. Decodes at most one batch or reset per call.
    pub fn poll(&mut self) -> Poll {
        let mut msg = IpcMessage::new(0);
        loop {
            match call::ipc_try_recv(self.port, &mut msg) {
                Ok(_) => match decode(msg.msg_type, &msg.payload) {
                    Decoded::Batch(batch) => return Poll::Batch(batch),
                    Decoded::Reset(reset) => {
                        return Poll::Reset {
                            focus_epoch: reset.focus_epoch,
                            reason: reset.reason,
                        }
                    }
                    Decoded::Ignore => continue,
                    Decoded::Malformed => return Poll::Error,
                },
                Err(Error::Interrupted) => continue,
                Err(Error::Again) => return Poll::Empty,
                Err(_) => return Poll::Error,
            }
        }
    }

    /// Wait up to `timeout_ns` for a message, then decode it.
    pub fn wait(&mut self, timeout_ns: u64) -> Poll {
        use strat9_syscall::data::{
            WaitSource, WAIT_EVENT_READABLE, WAIT_SOURCE_HANDLE,
        };
        let mut source = [WaitSource {
            kind: WAIT_SOURCE_HANDLE,
            events: WAIT_EVENT_READABLE,
            id: self.port as u64,
            revents: 0,
        }];
        match call::handle_wait_many(&mut source, timeout_ns) {
            Ok(_) => self.poll(),
            Err(Error::TimedOut | Error::Interrupted | Error::Again) => Poll::Empty,
            Err(_) => Poll::Error,
        }
    }

    /// Unbind the private path and close the port.
    pub fn close(self) {
        let _ = call::ipc_unbind_port(&self.path[..self.path_len as usize]);
        close_port(self.service);
        close_port(self.port);
    }
}

fn close_port(port: usize) {
    let _ = call::handle_close(port);
}

/// Connect to `/srv/input` and send the `Subscribe` payload.
fn connect_and_subscribe(focus_epoch: u32, path: &[u8]) -> Option<usize> {
    let service = call::ipc_connect(b"/srv/input").ok()?;

    let mut msg = IpcMessage::new(input_protocol::INPUTD_MSG_SUBSCRIBE as u32);
    Subscribe { focus_epoch, path }
        .encode(&mut msg.payload)
        .ok()?;

    let mut result = call::ipc_try_send(service, &msg);
    if matches!(result, Err(Error::Again)) {
        result = call::ipc_send(service, &msg);
    }
    if result.is_err() {
        let _ = call::handle_close(service);
        return None;
    }
    Some(service)
}

#[cfg(test)]
mod tests {
    use super::*;
    use input_protocol::{
        InputRecord, NormalizedEvent, INPUTD_MSG_SUBSCRIBE, INPUTD_MSG_SUBSCRIBE_ACK,
        INPUT_EVENT_KEY, RESET_REASON_RESYNC,
    };
    use std::vec;

    fn record(code: u16, value: i32) -> InputRecord {
        InputRecord {
            event: NormalizedEvent {
                timestamp_ns: 7,
                sequence: 3,
                device_id: 1,
                event_type: INPUT_EVENT_KEY,
                code,
                value,
                flags: 0,
            },
            text: [0; 16],
        }
    }

    fn encode_batch(epoch: u32, records: &[InputRecord]) -> vec::Vec<u8> {
        let mut batch = InputBatch {
            count: records.len() as u16,
            reserved: 0,
            focus_epoch: epoch,
            records: [InputRecord::default(); MAX_INPUT_RECORDS],
        };
        batch.records[..records.len()].copy_from_slice(records);
        let mut out = vec![0u8; 800];
        let len = batch.encode(&mut out).unwrap();
        out.truncate(len);
        out
    }

    #[test]
    fn path_is_formatted_without_alloc() {
        let mut buf = [0u8; CLIENT_PATH_MAX];
        let len = client_path(0, &mut buf).unwrap();
        assert_eq!(&buf[..len as usize], b"/srv/input/c/0");
        let len = client_path(1234, &mut buf).unwrap();
        assert_eq!(&buf[..len as usize], b"/srv/input/c/1234");
        let len = client_path(usize::MAX, &mut buf).unwrap();
        assert!(len as usize <= CLIENT_PATH_MAX);
        assert!(buf[..len as usize].starts_with(CLIENT_PATH_PREFIX));
    }

    #[test]
    fn batch_roundtrip() {
        let body = encode_batch(42, &[record(0x10, 1), record(0x90, 0)]);
        match decode(INPUTD_MSG_BATCH as u32, &body) {
            Decoded::Batch(batch) => {
                assert_eq!(batch.focus_epoch, 42);
                assert_eq!(batch.records().len(), 2);
                assert_eq!(batch.records()[0].event.code, 0x10);
                assert_eq!(batch.records()[1].event.value, 0);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn reset_roundtrip() {
        let mut body = [0u8; RESET_LEN];
        Reset {
            focus_epoch: 9,
            reason: RESET_REASON_RESYNC,
        }
        .encode(&mut body)
        .unwrap();
        assert_eq!(
            decode(INPUTD_MSG_RESET as u32, &body),
            Decoded::Reset(Reset {
                focus_epoch: 9,
                reason: RESET_REASON_RESYNC,
            })
        );
    }

    #[test]
    fn ack_and_unknown_types_are_ignored() {
        assert_eq!(
            decode(INPUTD_MSG_SUBSCRIBE_ACK as u32, &[0u8; 4]),
            Decoded::Ignore
        );
        assert_eq!(decode(0xDEAD_BEEF, &[0u8; 4]), Decoded::Ignore);
        assert_eq!(decode(INPUTD_MSG_SUBSCRIBE as u32, &[0u8; 4]), Decoded::Ignore);
    }

    #[test]
    fn malformed_payloads_are_rejected() {
        // Nothing at all.
        assert_eq!(decode(INPUTD_MSG_BATCH as u32, &[]), Decoded::Malformed);
        // count = 1, but no record.
        assert_eq!(
            decode(INPUTD_MSG_BATCH as u32, &[1, 0, 0, 0, 0, 0, 0, 0]),
            Decoded::Malformed
        );
        // count > 16.
        assert_eq!(
            decode(INPUTD_MSG_BATCH as u32, &[17, 0, 0, 0, 0, 0, 0, 0]),
            Decoded::Malformed
        );
        // reserved != 0.
        assert_eq!(
            decode(INPUTD_MSG_BATCH as u32, &[0, 0, 1, 0, 0, 0, 0, 0]),
            Decoded::Malformed
        );
        // Byte-for-byte truncated reset.
        assert_eq!(decode(INPUTD_MSG_RESET as u32, &[0u8; 7]), Decoded::Malformed);
        // Invalid reset reason.
        let mut body = [0u8; RESET_LEN];
        body[4] = 0xFF;
        assert_eq!(decode(INPUTD_MSG_RESET as u32, &body), Decoded::Malformed);
    }

    #[test]
    fn random_payloads_never_panic() {
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        let mut payload = [0u8; 128];
        for msg_type in 0..64u32 {
            for _ in 0..64 {
                for byte in payload.iter_mut() {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    *byte = state as u8;
                }
                let _ = decode(msg_type, &payload[..(state as usize) % payload.len()]);
            }
        }
    }
}
