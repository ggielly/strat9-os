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

//! `inputd` : the strat9-os input server.
//!
//! Reads raw PS/2 scancodes from `/dev/input/kbd` and 7-byte mouse packets
//! from `/dev/input/mouse`, normalizes them with `strate-input`'s host-tested
//! library into A.5 `InputBatch`es and pushes them to the focused subscriber.
//!
//! Architecture:
//!   hardware => PS/2 IRQ => kernel ring buffer => /dev/input/* => THIS SERVER
//!   => normalization (input-protocol A.5) => /srv/input/c/<pid> => clients
//!
//! Focus policy: one focused client at a time, the **first** subscriber
//! (lowest occupied slot, normally the rescue console). Keyboard, mouse and
//! focus events go to it only; a later client gets FOCUS_LOST until the
//! focused one dies, then the next first subscriber is refocused. A client can
//! explicitly take focus with `INPUTD_MSG_FOCUS`: the request is honoured only
//! when its path matches a current subscriber, and the old focused client then
//! gets FOCUS_LOST.
//!
//! `INPUTD_MSG_UNSUBSCRIBE` is accepted but deliberately does not remove the
//! subscriber: the message carries no port identity, and the path in
//! `IpcMessage` would be guessable. A closed client is detected by the send
//! failure and removed then.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use input_protocol::{
    Focus, InputBatch, InputRecord, NormalizedEvent, Subscribe, FOCUS_FIXED_LEN,
    INPUTD_MSG_BATCH, INPUTD_MSG_FOCUS, INPUTD_MSG_SUBSCRIBE, INPUT_EVENT_FOCUS_GAINED,
    INPUT_EVENT_FOCUS_LOST, INPUT_TEXT_LEN, MAX_FOCUS_PATH, MAX_SUBSCRIBE_PATH,
    SUBSCRIBE_FIXED_LEN,
};
use strate_input::{mouse_packet, EventBuffer, KbdNormalizer};
use strat9_syscall::{
    call,
    data::{IpcMessage, TimeSpec},
    error::Error,
    flag,
};

/// Subscription table size.
const MAX_SUBSCRIBERS: usize = 8;
/// Keyboard read size.
const KBD_BUF_LEN: usize = 64;
/// Mouse read size: 8 packets of 7 bytes.
const MOUSE_BUF_LEN: usize = 56;
/// Accepted client path prefix.
const CLIENT_PREFIX: &[u8] = b"/srv/input/c/";
/// Idle sleep between empty loops.
const IDLE_NS: i64 = 2_000_000;

/// One subscribed client.
#[derive(Clone, Copy)]
struct Subscriber {
    path: [u8; MAX_SUBSCRIBE_PATH],
    path_len: u8,
    port: usize,
    focus_epoch: u32,
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let kbd_fd = open_device("/dev/input/kbd");
    let mouse_fd = open_device("/dev/input/mouse");
    if kbd_fd.is_none() {
        log(b"[input-server] no keyboard after retries\n");
    }
    if mouse_fd.is_none() {
        log(b"[input-server] no mouse after retries\n");
    }

    let port = match create_server_port() {
        Some(port) => port,
        None => {
            log(b"[input-server] cannot bind /srv/input\n");
            call::exit(2);
        }
    };
    log(b"[input-server] listening on /srv/input\n");

    let mut subscribers: [Option<Subscriber>; MAX_SUBSCRIBERS] = [None; MAX_SUBSCRIBERS];
    let mut focused = None;
    let mut kbd = KbdNormalizer::new();
    let mut prev_buttons = 0u8;
    let mut seq = 0u64;
    let mut buf = EventBuffer::new();
    let mut overflow = false;
    let mut kbd_buf = [0u8; KBD_BUF_LEN];
    let mut mouse_buf = [0u8; MOUSE_BUF_LEN];
    let mut msg = IpcMessage::new(0);

    loop {
        // Drain subscription and focus requests (bounded, never starve input).
        for _ in 0..MAX_SUBSCRIBERS {
            match call::ipc_try_recv(port, &mut msg) {
                Ok(_) => match msg.msg_type as u16 {
                    INPUTD_MSG_SUBSCRIBE => {
                        handle_subscribe(&mut subscribers, &mut focused, &msg, &mut seq)
                    }
                    INPUTD_MSG_FOCUS => {
                        handle_focus(&mut subscribers, &mut focused, &msg, &mut seq)
                    }
                    _ => {}
                },
                Err(Error::Interrupted) => continue,
                _ => break,
            }
        }

        let now = now_ns();
        buf.clear(now);
        let mut had_events = false;

        if let Some(fd) = kbd_fd {
            if let Ok(n) = call::read(fd, &mut kbd_buf) {
                for &sc in &kbd_buf[..n] {
                    kbd.feed(sc, &mut seq, &mut buf);
                }
            }
        }

        if let Some(fd) = mouse_fd {
            if let Ok(n) = call::read(fd, &mut mouse_buf) {
                for chunk in mouse_buf[..n].chunks_exact(7) {
                    let mut packet = [0u8; 7];
                    packet.copy_from_slice(chunk);
                    mouse_packet(&packet, &mut prev_buttons, &mut seq, &mut buf);
                }
            }
        }

        if !buf.is_empty() {
            had_events = true;
            // A focus slot is cleared before `focused` is updated in the
            // subscribe paths; keep the loop panic-free anyway (a panic here
            // would kill the only input service).
            if focused.is_some_and(|index| subscribers[index].is_none()) {
                focused = None;
                refocus(&mut subscribers, &mut focused, &mut seq);
            }
            if let Some(index) = focused {
                if let Some(subscriber) = subscribers[index] {
                    match send_batch(subscriber.port, &buf, subscriber.focus_epoch) {
                        Ok(()) => {}
                        Err(err) if err.is_retryable() => {
                            // Queue full: drop this batch and remember the loss.
                            if !overflow {
                                overflow = true;
                                log(b"[input-server] subscriber queue full, dropping\n");
                            }
                        }
                        Err(_) => {
                            // BadHandle/NotFound/...: the client is gone.
                            subscribers[index] = None;
                            focused = None;
                            refocus(&mut subscribers, &mut focused, &mut seq);
                        }
                    }
                }
            }
        }

        if had_events {
            let _ = call::sched_yield();
        } else {
            let req = TimeSpec {
                tv_sec: 0,
                tv_nsec: IDLE_NS,
            };
            let mut rem = TimeSpec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let _ = call::nanosleep(&req, &mut rem);
        }
    }
}

/// First remaining subscriber: the lowest occupied slot. This keeps the
/// rescue console (started before graphical/s9vm clients) focused.
fn focused_index(subscribers: &[Option<Subscriber>; MAX_SUBSCRIBERS]) -> Option<usize> {
    (0..MAX_SUBSCRIBERS).find(|&i| subscribers[i].is_some())
}

/// Notify the newest remaining subscriber that it now has focus.
fn refocus(
    subscribers: &mut [Option<Subscriber>; MAX_SUBSCRIBERS],
    focused: &mut Option<usize>,
    seq: &mut u64,
) {
    *focused = focused_index(subscribers);
    if let Some(index) = *focused {
        let subscriber = subscribers[index].unwrap();
        let _ = send_focus(
            subscriber.port,
            subscriber.focus_epoch,
            INPUT_EVENT_FOCUS_GAINED,
            seq,
        );
    }
}

/// Handle one server-port message.
fn handle_subscribe(
    subscribers: &mut [Option<Subscriber>; MAX_SUBSCRIBERS],
    focused: &mut Option<usize>,
    msg: &IpcMessage,
    seq: &mut u64,
) {
    // `INPUTD_MSG_UNSUBSCRIBE` needs no action; see the module docs.
    if msg.msg_type != INPUTD_MSG_SUBSCRIBE as u32 {
        return;
    }
    let payload = &msg.payload;
    if payload.len() < SUBSCRIBE_FIXED_LEN {
        return;
    }
    let path_len = u16::from_le_bytes([payload[4], payload[5]]) as usize;
    if path_len == 0 || path_len > MAX_SUBSCRIBE_PATH {
        return;
    }
    let required = SUBSCRIBE_FIXED_LEN + path_len;
    if required > payload.len() {
        return;
    }
    let Ok(request) = Subscribe::decode(&payload[..required]) else {
        return;
    };
    if !request.path.starts_with(CLIENT_PREFIX) {
        return;
    }

    // Re-subscribing with the same path replaces the old subscription.
    if let Some(index) = subscribers.iter().position(|slot| {
        matches!(slot, Some(existing)
            if existing.path_len as usize == path_len
                && &existing.path[..path_len] == request.path)
    }) {
        if let Some(previous) = subscribers[index].take() {
            let _ = call::handle_close(previous.port);
        }
        if *focused == Some(index) {
            *focused = None;
        }
    }

    let Some(index) = subscribers.iter().position(|slot| slot.is_none()) else {
        return;
    };
    let Ok(port) = call::ipc_connect(request.path) else {
        return;
    };

    let mut path = [0u8; MAX_SUBSCRIBE_PATH];
    path[..path_len].copy_from_slice(request.path);
    subscribers[index] = Some(Subscriber {
        path,
        path_len: path_len as u8,
        port,
        focus_epoch: request.focus_epoch,
    });

    if focused.is_none() {
        *focused = Some(index);
        let _ = send_focus(port, request.focus_epoch, INPUT_EVENT_FOCUS_GAINED, seq);
    } else {
        // Focus stays with the first (rescue) subscriber.
        let _ = send_focus(port, request.focus_epoch, INPUT_EVENT_FOCUS_LOST, seq);
    }
}

/// Handle one explicit `Focus` request.
///
/// The path must exactly match a current subscriber; an unknown path is
/// ignored so a focus request cannot steal focus from an absent client. The
/// previous focused subscriber (if any) receives FOCUS_LOST, then the matched
/// subscriber receives FOCUS_GAINED. A request from the already-focused client
/// is a no-op.
fn handle_focus(
    subscribers: &mut [Option<Subscriber>; MAX_SUBSCRIBERS],
    focused: &mut Option<usize>,
    msg: &IpcMessage,
    seq: &mut u64,
) {
    let payload = &msg.payload;
    if payload.len() < FOCUS_FIXED_LEN {
        return;
    }
    let path_len = u16::from_le_bytes([payload[4], payload[5]]) as usize;
    if path_len == 0 || path_len > MAX_FOCUS_PATH {
        return;
    }
    let required = FOCUS_FIXED_LEN + path_len;
    if required > payload.len() {
        return;
    }
    let Ok(request) = Focus::decode(&payload[..required]) else {
        return;
    };

    // Exact path match against the subscriber table only.
    let Some(index) = subscribers.iter().position(|slot| {
        matches!(slot, Some(existing)
            if existing.path_len as usize == path_len
                && &existing.path[..path_len] == request.path)
    }) else {
        return;
    };
    if *focused == Some(index) {
        return;
    }

    if let Some(old) = *focused {
        if let Some(previous) = subscribers[old] {
            let _ = send_focus(
                previous.port,
                previous.focus_epoch,
                INPUT_EVENT_FOCUS_LOST,
                seq,
            );
        }
    }

    *focused = Some(index);
    let subscriber = subscribers[index].unwrap();
    let _ = send_focus(
        subscriber.port,
        subscriber.focus_epoch,
        INPUT_EVENT_FOCUS_GAINED,
        seq,
    );
}

/// Send a one-record focus batch.
fn send_focus(
    port: usize,
    focus_epoch: u32,
    event_type: u16,
    seq: &mut u64,
) -> Result<(), Error> {
    *seq += 1;
    let mut batch = InputBatch::default();
    batch.count = 1;
    batch.focus_epoch = focus_epoch;
    batch.records[0] = InputRecord {
        event: NormalizedEvent {
            timestamp_ns: now_ns(),
            sequence: *seq,
            device_id: 0,
            event_type,
            code: 0,
            value: 0,
            flags: 0,
        },
        text: [0; INPUT_TEXT_LEN],
    };
    send_batch_obj(port, &batch)
}

/// Send the accumulated records to one subscriber.
fn send_batch(port: usize, buf: &EventBuffer, focus_epoch: u32) -> Result<(), Error> {
    let mut batch = InputBatch::default();
    batch.count = buf.len() as u16;
    batch.focus_epoch = focus_epoch;
    batch.records[..buf.len()].copy_from_slice(buf.as_slice());
    send_batch_obj(port, &batch)
}

fn send_batch_obj(port: usize, batch: &InputBatch) -> Result<(), Error> {
    let mut msg = IpcMessage::new(INPUTD_MSG_BATCH as u32);
    batch
        .encode(&mut msg.payload)
        .map_err(|_| Error::InvalidArgument)?;
    call::ipc_try_send(port, &msg).map(|_| ())
}

/// Create the server port and bind `/srv/input`, with bounded retries.
fn create_server_port() -> Option<usize> {
    const RETRIES: usize = 20;
    let mut port = None;
    for attempt in 0..RETRIES {
        match call::ipc_create_port(0) {
            Ok(handle) => {
                port = Some(handle);
                break;
            }
            Err(_) => backoff(attempt),
        }
    }
    let port = port?;

    for attempt in 0..RETRIES {
        if call::ipc_bind_port(port, b"/srv/input").is_ok() {
            return Some(port);
        }
        if attempt + 1 == RETRIES {
            break;
        }
        backoff(attempt);
    }
    let _ = call::handle_close(port);
    None
}

fn backoff(attempt: usize) {
    for _ in 0..(64 * (attempt + 1)) {
        let _ = call::sched_yield();
    }
}

/// Open an input device non-blocking, retrying while it is busy or missing.
fn open_device(path: &str) -> Option<usize> {
    const RETRIES: usize = 25;
    for attempt in 0..RETRIES {
        match call::open(path, flag::O_RDONLY | flag::O_NONBLOCK) {
            Ok(fd) => return Some(fd),
            Err(_) => {
                if attempt + 1 < RETRIES {
                    backoff(attempt);
                }
            }
        }
    }
    None
}

fn now_ns() -> u64 {
    let mut ts = TimeSpec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let _ = call::clock_gettime(strat9_syscall::CLOCK_MONOTONIC, &mut ts);
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn log(text: &[u8]) {
    let _ = call::write(2, text);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    strat9_syscall::call::handle_panic("strate-input", info)
}
