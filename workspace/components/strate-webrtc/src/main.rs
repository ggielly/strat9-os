#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use alloc::{
    collections::{BTreeMap, VecDeque},
    format,
    string::String,
    vec::Vec,
};
use core::{
    alloc::Layout,
    panic::PanicInfo,
    sync::atomic::{AtomicU64, Ordering},
};
use strat9_syscall::{call, data::IpcMessage, CLOCK_MONOTONIC};

alloc_freelist::define_freelist_brk_allocator!(
    pub struct BumpAllocator;
    brk = strat9_syscall::call::brk;
    heap_max = 16 * 1024 * 1024;
);

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    let _ = call::debug_log(b"[strate-webrtc] OOM\n");
    call::exit(12);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let _ = call::debug_log(b"[strate-webrtc] PANIC\n");
    call::exit(1);
}

const OP_BOOTSTRAP: u32 = 0x10;
const OP_SESSION_OPEN: u32 = 0x300;
const OP_SESSION_CLOSE: u32 = 0x301;
const OP_SESSION_PUT_OFFER: u32 = 0x302;
const OP_SESSION_GET_OFFER: u32 = 0x303;
const OP_SESSION_PUT_ANSWER: u32 = 0x304;
const OP_SESSION_GET_ANSWER: u32 = 0x305;
const OP_SESSION_ADD_CANDIDATE: u32 = 0x306;
const OP_SESSION_POP_CANDIDATE: u32 = 0x307;
const OP_INPUT_EVENT: u32 = 0x308;
const OP_FRAME_PUSH: u32 = 0x309;
const OP_SESSION_INFO: u32 = 0x30A;
const OP_POLICY_REFRESH: u32 = 0x30B;

const REPLY_MSG_TYPE: u32 = 0x80;
const RESP_OK: u32 = 0;
const RESP_BAD_REQ: u32 = 1;
const RESP_NOT_FOUND: u32 = 2;
const RESP_DENIED: u32 = 3;
const RESP_DISABLED: u32 = 4;
const RESP_FULL: u32 = 5;
const RESP_EXPIRED: u32 = 6;

const SILO_FLAG_GRAPHICS: u64 = 1 << 1;
const SILO_FLAG_WEBRTC_NATIVE: u64 = 1 << 2;
const SILO_FLAG_GRAPHICS_READ_ONLY: u64 = 1 << 3;

const MAX_SESSIONS: usize = 32;
const MAX_SDP_BYTES: usize = 256;
const MAX_CANDIDATES: usize = 32;

#[derive(Clone, Copy)]
struct SiloGraphicsPolicy {
    flags: u64,
    max_sessions: u16,
    ttl_sec: u32,
}

#[derive(Clone)]
struct Candidate {
    direction: u8,
    data: [u8; 38],
    len: u8,
}

struct Session {
    id: u64,
    silo_id: u32,
    token: u64,
    flags: u64,
    expires_at_ns: u64,
    offer_len: u16,
    answer_len: u16,
    offer: [u8; MAX_SDP_BYTES],
    answer: [u8; MAX_SDP_BYTES],
    candidates: VecDeque<Candidate>,
    last_input: [u8; 24],
    last_input_len: u8,
    last_frame_seq: u64,
}

impl Session {
    fn new(id: u64, silo_id: u32, token: u64, flags: u64, ttl_sec: u32, now_ns: u64) -> Self {
        Self {
            id,
            silo_id,
            token,
            flags,
            expires_at_ns: now_ns.saturating_add((ttl_sec as u64).saturating_mul(1_000_000_000)),
            offer_len: 0,
            answer_len: 0,
            offer: [0u8; MAX_SDP_BYTES],
            answer: [0u8; MAX_SDP_BYTES],
            candidates: VecDeque::new(),
            last_input: [0u8; 24],
            last_input_len: 0,
            last_frame_seq: 0,
        }
    }

    fn is_expired(&self, now_ns: u64) -> bool {
        now_ns >= self.expires_at_ns
    }
}

struct Runtime {
    sessions: BTreeMap<u64, Session>,
    policies: BTreeMap<u32, SiloGraphicsPolicy>,
}

impl Runtime {
    fn new() -> Self {
        Self {
            sessions: BTreeMap::new(),
            policies: BTreeMap::new(),
        }
    }
}

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

fn log(msg: &str) {
    let _ = call::debug_log(msg.as_bytes());
}

fn now_ns() -> u64 {
    let mut ts = strat9_syscall::data::TimeSpec::zero();
    if call::clock_gettime(CLOCK_MONOTONIC, &mut ts).is_ok() {
        ts.to_nanos()
    } else {
        NEXT_SESSION_ID.load(Ordering::Relaxed)
    }
}

fn derive_token(session_id: u64, sid: u32, t: u64) -> u64 {
    let mut x = session_id ^ ((sid as u64) << 32) ^ t.rotate_left(17);
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
    x ^ (x >> 33)
}

fn parse_u16(payload: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    if end > payload.len() {
        return None;
    }
    Some(u16::from_le_bytes([payload[off], payload[off + 1]]))
}

fn parse_u32(payload: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    if end > payload.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        payload[off],
        payload[off + 1],
        payload[off + 2],
        payload[off + 3],
    ]))
}

fn parse_u64(payload: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    if end > payload.len() {
        return None;
    }
    Some(u64::from_le_bytes([
        payload[off],
        payload[off + 1],
        payload[off + 2],
        payload[off + 3],
        payload[off + 4],
        payload[off + 5],
        payload[off + 6],
        payload[off + 7],
    ]))
}

fn read_text_file(path: &str) -> Option<String> {
    let fd = call::openat(0, path, 0x1, 0).ok()?;
    let mut out = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        match call::read(fd as usize, &mut chunk) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(_) => {
                let _ = call::close(fd as usize);
                return None;
            }
        }
        if out.len() > 256 * 1024 {
            break;
        }
    }
    let _ = call::close(fd as usize);
    core::str::from_utf8(&out).ok().map(String::from)
}

fn refresh_policies(rt: &mut Runtime) {
    let mut next = BTreeMap::new();
    let Some(text) = read_text_file("/proc/silos") else {
        rt.policies = next;
        return;
    };

    for (idx, line) in text.lines().enumerate() {
        if idx == 0 || line.is_empty() {
            continue;
        }
        let mut cols = line.split('\t');
        let sid = cols.next().and_then(|v| v.parse::<u32>().ok());
        let _state = cols.next();
        let _tasks = cols.next();
        let _mem_used = cols.next();
        let _mem_min = cols.next();
        let _mem_max = cols.next();
        let flags = cols.next().and_then(|v| v.parse::<u64>().ok());
        let max_sessions = cols.next().and_then(|v| v.parse::<u16>().ok());
        let ttl = cols.next().and_then(|v| v.parse::<u32>().ok());

        let (Some(sid), Some(flags), Some(max_sessions), Some(ttl_sec)) = (sid, flags, max_sessions, ttl) else {
            continue;
        };
        next.insert(
            sid,
            SiloGraphicsPolicy {
                flags,
                max_sessions,
                ttl_sec,
            },
        );
    }
    rt.policies = next;
}

fn cleanup_expired(rt: &mut Runtime, now: u64) {
    let mut expired = Vec::new();
    for (id, s) in rt.sessions.iter() {
        if s.is_expired(now) {
            expired.push(*id);
        }
    }
    for id in expired {
        let _ = rt.sessions.remove(&id);
    }
}

fn send_response(sender: u64, status: u32, fill: impl FnOnce(&mut IpcMessage)) {
    let mut msg = IpcMessage::new(REPLY_MSG_TYPE);
    msg.sender = sender;
    msg.payload[0..4].copy_from_slice(&status.to_le_bytes());
    fill(&mut msg);
    let _ = call::ipc_reply(&msg);
}

fn bind_alias(port_h: usize, label: &str) {
    let p = format!("/srv/strate-webrtc/{}", label);
    let _ = call::ipc_bind_port(port_h, p.as_bytes());
}

fn extract_label(payload: &[u8]) -> String {
    let len = payload[0] as usize;
    if len == 0 {
        return String::from("default");
    }
    let end = core::cmp::min(1 + len, payload.len());
    let raw = &payload[1..end];
    let mut out = String::new();
    for &b in raw {
        let c = b as char;
        if c.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' {
            out.push(c);
        }
    }
    if out.is_empty() {
        String::from("default")
    } else {
        out
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    let mut rt = Runtime::new();
    let port_h = call::ipc_create_port(0).unwrap_or_else(|_| call::exit(2));

    let _ = call::ipc_bind_port(port_h, b"/srv/strate-webrtc/bootstrap");
    bind_alias(port_h, "default");
    log("[strate-webrtc] online\n");

    loop {
        cleanup_expired(&mut rt, now_ns());

        let mut msg = IpcMessage::new(0);
        if call::ipc_recv(port_h, &mut msg).is_err() {
            let _ = call::sched_yield();
            continue;
        }

        match msg.msg_type {
            OP_BOOTSTRAP => {
                let label = extract_label(&msg.payload);
                bind_alias(port_h, &label);
                send_response(msg.sender, RESP_OK, |_| {});
            }
            OP_POLICY_REFRESH => {
                refresh_policies(&mut rt);
                send_response(msg.sender, RESP_OK, |_| {});
            }
            OP_SESSION_OPEN => {
                refresh_policies(&mut rt);
                let sid = parse_u32(&msg.payload, 0).unwrap_or(0);
                let force_ro = msg.payload[4] != 0;
                let Some(policy) = rt.policies.get(&sid).copied() else {
                    send_response(msg.sender, RESP_NOT_FOUND, |_| {});
                    continue;
                };
                if policy.flags & SILO_FLAG_GRAPHICS == 0 {
                    send_response(msg.sender, RESP_DISABLED, |_| {});
                    continue;
                }
                if policy.flags & SILO_FLAG_WEBRTC_NATIVE == 0 {
                    send_response(msg.sender, RESP_DENIED, |_| {});
                    continue;
                }
                let active_for_sid = rt.sessions.values().filter(|s| s.silo_id == sid).count();
                if rt.sessions.len() >= MAX_SESSIONS || active_for_sid >= policy.max_sessions as usize {
                    send_response(msg.sender, RESP_FULL, |_| {});
                    continue;
                }

                let id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
                let t = now_ns();
                let mut flags = policy.flags;
                if force_ro {
                    flags |= SILO_FLAG_GRAPHICS_READ_ONLY;
                }
                let token = derive_token(id, sid, t);
                rt.sessions
                    .insert(id, Session::new(id, sid, token, flags, policy.ttl_sec, t));

                send_response(msg.sender, RESP_OK, |out| {
                    out.payload[4..12].copy_from_slice(&id.to_le_bytes());
                    out.payload[12..20].copy_from_slice(&token.to_le_bytes());
                    out.payload[20..24].copy_from_slice(&policy.ttl_sec.to_le_bytes());
                });
            }
            OP_SESSION_CLOSE => {
                let Some(id) = parse_u64(&msg.payload, 0) else {
                    send_response(msg.sender, RESP_BAD_REQ, |_| {});
                    continue;
                };
                if rt.sessions.remove(&id).is_some() {
                    send_response(msg.sender, RESP_OK, |_| {});
                } else {
                    send_response(msg.sender, RESP_NOT_FOUND, |_| {});
                }
            }
            OP_SESSION_PUT_OFFER | OP_SESSION_PUT_ANSWER => {
                let Some(id) = parse_u64(&msg.payload, 0) else {
                    send_response(msg.sender, RESP_BAD_REQ, |_| {});
                    continue;
                };
                let Some(len) = parse_u16(&msg.payload, 8) else {
                    send_response(msg.sender, RESP_BAD_REQ, |_| {});
                    continue;
                };
                let len = core::cmp::min(len as usize, 38);
                let Some(s) = rt.sessions.get_mut(&id) else {
                    send_response(msg.sender, RESP_NOT_FOUND, |_| {});
                    continue;
                };
                if s.is_expired(now_ns()) {
                    let _ = rt.sessions.remove(&id);
                    send_response(msg.sender, RESP_EXPIRED, |_| {});
                    continue;
                }
                if msg.msg_type == OP_SESSION_PUT_OFFER {
                    let dst_off = s.offer_len as usize;
                    let n = core::cmp::min(len, MAX_SDP_BYTES.saturating_sub(dst_off));
                    s.offer[dst_off..dst_off + n].copy_from_slice(&msg.payload[10..10 + n]);
                    s.offer_len = (dst_off + n) as u16;
                } else {
                    let dst_off = s.answer_len as usize;
                    let n = core::cmp::min(len, MAX_SDP_BYTES.saturating_sub(dst_off));
                    s.answer[dst_off..dst_off + n].copy_from_slice(&msg.payload[10..10 + n]);
                    s.answer_len = (dst_off + n) as u16;
                }
                send_response(msg.sender, RESP_OK, |_| {});
            }
            OP_SESSION_GET_OFFER | OP_SESSION_GET_ANSWER => {
                let Some(id) = parse_u64(&msg.payload, 0) else {
                    send_response(msg.sender, RESP_BAD_REQ, |_| {});
                    continue;
                };
                let Some(offset) = parse_u16(&msg.payload, 8) else {
                    send_response(msg.sender, RESP_BAD_REQ, |_| {});
                    continue;
                };
                let Some(s) = rt.sessions.get(&id) else {
                    send_response(msg.sender, RESP_NOT_FOUND, |_| {});
                    continue;
                };
                if s.is_expired(now_ns()) {
                    send_response(msg.sender, RESP_EXPIRED, |_| {});
                    continue;
                }
                let (buf, total_len) = if msg.msg_type == OP_SESSION_GET_OFFER {
                    (&s.offer[..], s.offer_len as usize)
                } else {
                    (&s.answer[..], s.answer_len as usize)
                };
                let off = core::cmp::min(offset as usize, total_len);
                let n = core::cmp::min(38, total_len.saturating_sub(off));
                send_response(msg.sender, RESP_OK, |out| {
                    out.payload[4..6].copy_from_slice(&(total_len as u16).to_le_bytes());
                    out.payload[6..8].copy_from_slice(&(off as u16).to_le_bytes());
                    out.payload[8..10].copy_from_slice(&(n as u16).to_le_bytes());
                    out.payload[10..10 + n].copy_from_slice(&buf[off..off + n]);
                });
            }
            OP_SESSION_ADD_CANDIDATE => {
                let Some(id) = parse_u64(&msg.payload, 0) else {
                    send_response(msg.sender, RESP_BAD_REQ, |_| {});
                    continue;
                };
                let dir = msg.payload[8];
                let len = core::cmp::min(msg.payload[9] as usize, 38);
                let Some(s) = rt.sessions.get_mut(&id) else {
                    send_response(msg.sender, RESP_NOT_FOUND, |_| {});
                    continue;
                };
                if s.candidates.len() >= MAX_CANDIDATES {
                    let _ = s.candidates.pop_front();
                }
                let mut c = Candidate {
                    direction: dir,
                    data: [0u8; 38],
                    len: len as u8,
                };
                c.data[..len].copy_from_slice(&msg.payload[10..10 + len]);
                s.candidates.push_back(c);
                send_response(msg.sender, RESP_OK, |_| {});
            }
            OP_SESSION_POP_CANDIDATE => {
                let Some(id) = parse_u64(&msg.payload, 0) else {
                    send_response(msg.sender, RESP_BAD_REQ, |_| {});
                    continue;
                };
                let Some(s) = rt.sessions.get_mut(&id) else {
                    send_response(msg.sender, RESP_NOT_FOUND, |_| {});
                    continue;
                };
                if let Some(c) = s.candidates.pop_front() {
                    send_response(msg.sender, RESP_OK, |out| {
                        out.payload[4] = c.direction;
                        out.payload[5] = c.len;
                        let n = c.len as usize;
                        out.payload[6..6 + n].copy_from_slice(&c.data[..n]);
                    });
                } else {
                    send_response(msg.sender, RESP_NOT_FOUND, |_| {});
                }
            }
            OP_INPUT_EVENT => {
                let Some(id) = parse_u64(&msg.payload, 0) else {
                    send_response(msg.sender, RESP_BAD_REQ, |_| {});
                    continue;
                };
                let Some(s) = rt.sessions.get_mut(&id) else {
                    send_response(msg.sender, RESP_NOT_FOUND, |_| {});
                    continue;
                };
                let n = core::cmp::min(msg.payload[8] as usize, 24);
                s.last_input_len = n as u8;
                s.last_input[..n].copy_from_slice(&msg.payload[9..9 + n]);
                send_response(msg.sender, RESP_OK, |_| {});
            }
            OP_FRAME_PUSH => {
                let Some(id) = parse_u64(&msg.payload, 0) else {
                    send_response(msg.sender, RESP_BAD_REQ, |_| {});
                    continue;
                };
                let Some(s) = rt.sessions.get_mut(&id) else {
                    send_response(msg.sender, RESP_NOT_FOUND, |_| {});
                    continue;
                };
                s.last_frame_seq = s.last_frame_seq.wrapping_add(1);
                send_response(msg.sender, RESP_OK, |out| {
                    out.payload[4..12].copy_from_slice(&s.last_frame_seq.to_le_bytes());
                });
            }
            OP_SESSION_INFO => {
                let Some(id) = parse_u64(&msg.payload, 0) else {
                    send_response(msg.sender, RESP_BAD_REQ, |_| {});
                    continue;
                };
                let Some(s) = rt.sessions.get(&id) else {
                    send_response(msg.sender, RESP_NOT_FOUND, |_| {});
                    continue;
                };
                send_response(msg.sender, RESP_OK, |out| {
                    out.payload[4..12].copy_from_slice(&s.id.to_le_bytes());
                    out.payload[12..16].copy_from_slice(&s.silo_id.to_le_bytes());
                    out.payload[16..24].copy_from_slice(&s.token.to_le_bytes());
                    out.payload[24..32].copy_from_slice(&s.flags.to_le_bytes());
                    out.payload[32..40].copy_from_slice(&s.expires_at_ns.to_le_bytes());
                });
            }
            _ => send_response(msg.sender, RESP_BAD_REQ, |_| {}),
        }
    }
}
