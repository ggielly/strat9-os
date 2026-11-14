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

//! Scheduler-independent executable model of the IPC ABI v2 state machines
//! (see `docs-site/src/ipc-abi-v2.md`: §3 handles/rights, §4 messages,
//! §5 endpoints, §6 call/reply, §7 notifications, §12 quotas).
//!
//! The model runs on a **single CPU** and owns several simulated processes,
//! each with its own generation-tagged handle table (`(index:24, gen:32)`,
//! §3.1). It mirrors the kernel state machines closely enough that a later
//! kernel implementation can be compared against it handle-for-handle.
//!
//! # Deliberate simplifications
//!
//! * **No blocking, no time and no preemption.** Every operation either
//!   completes or returns a typed [`Error`]. A blocking operation that cannot
//!   make progress (full queue, empty receive) reports [`Error::Again`]; the
//!   real scheduler would park the thread and retry it later.
//! * **One CPU, no interleavings.** This crate is the sequential oracle; the
//!   `loom` interleaving exploration mentioned in `Cargo.toml` is a follow-up.
//! * **No user address spaces.** Messages carry only [`MsgMeta`] lengths; the
//!   caller reads a reply with [`IpcCore::read_reply`] (`take_reply` also
//!   exists). There is no copy-in/copy-out and no `EFAULT`.
//! * **No namespace (§8).** A SEND capability therefore cannot be obtained
//!   through the model's public API: [`IpcCore::ipc_mint`] only derives
//!   `EP_SEND` from an endpoint's `RECV|MINT` handle (so the endpoint owner can
//!   bootstrap). Because `NS_LOOKUP` is what grants `EP_XFER` in the real
//!   system, capability-transfer tests inject `EP_XFER` directly into a
//!   handle's table entry (the tests live in this crate).
//! * **`MemObject` is a right-holder only.** The [`ObjKind::MemObj`] variant and
//!   the `MEM_*` rights exist so handles compare with the ABI crate, but no
//!   syscall allocates a memory object.
//! * **No silo accounting (§12).** `owner_silo`/`sender_silo` are set to the
//!   simulated process id; quota limits are not charged.
//! * **No connection ids.** `next_conn` is kept for parity with the kernel's
//!   namespace counter but is not yet allocated by any operation.
//!
//! # Enforced semantics (each has a test)
//!
//! Badges come only from a minted handle, never from [`MsgMeta`] (§3.3). Send
//! validates and commits in two phases with all-or-nothing failure (§4.4).
//! Receive checks buffer sizes (`EMSGSIZE`) and reserves handle slots
//! (`ENOSPC`) before dequeuing (§4.5). Pending bound-notification bits are
//! delivered before queued messages (§5.2). Closing the last `EP_RECV` handle
//! closes the endpoint and fails every live call with `EPIPE` (§5.3). A Reply
//! handle is single-use and generation-bound (§6.2).

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::{collections::VecDeque, vec::Vec};

/// Hard upper bound on `MsgMeta::data_len` (§4.3 `IPC_MAX_DATA`).
pub const MAX_DATA_LEN: u32 = 4096;
/// Hard upper bound on transferred capabilities per message (§4.3 `IPC_MAX_CAPS`).
pub const MAX_TRANSFER_CAPS: usize = 4;
/// Per-process handle table limit; a receive needing more slots fails `ENOSPC`.
pub const HANDLE_LIMIT: usize = 256;

// §3.2 generic rights.
pub const RIGHT_TRANSFER: u32 = 1 << 0;
pub const RIGHT_DUPLICATE: u32 = 1 << 1;
pub const RIGHT_INSPECT: u32 = 1 << 2;
pub const RIGHT_WAIT: u32 = 1 << 3;
pub const GENERIC_RIGHTS_MASK: u32 = 0xF;

// §3.2 endpoint rights.
pub const EP_SEND: u32 = 1 << 8;
pub const EP_RECV: u32 = 1 << 9;
pub const EP_MINT: u32 = 1 << 10;
pub const EP_XFER: u32 = 1 << 11;

// §3.2 notification rights.
pub const NOTIF_SIGNAL: u32 = 1 << 8;
pub const NOTIF_WAIT: u32 = 1 << 9;
pub const NOTIF_MINT: u32 = 1 << 10;

// §3.2 memobject rights (right-holder only; no MemObject syscall in the model).
pub const MEM_READ: u32 = 1 << 8;
pub const MEM_WRITE: u32 = 1 << 9;
pub const MEM_EXEC: u32 = 1 << 10;
pub const MEM_MAP: u32 = 1 << 11;

// §4.1 message kinds.
pub const MSG_KIND_SEND: u8 = 1;
pub const MSG_KIND_CALL: u8 = 2;
pub const MSG_KIND_NOTIF: u8 = 3;
pub const MSG_KIND_REPLY: u8 = 4;

// §4.2 capability transfer modes.
pub const XFER_MOVE: u32 = 1;
pub const XFER_COPY: u32 = 2;
/// Keep every right the source handle holds.
pub const RIGHTS_SAME: u32 = u32::MAX;

/// A process-local handle, encoded per §3.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Handle(pub u64);

impl Handle {
    /// Build a handle from a table index and a slot generation.
    pub const fn new(index: u32, generation: u32) -> Self {
        let idx = (index as u64) & 0x00FF_FFFF;
        let gen = (generation as u64) & 0xFFFF_FFFF;
        Handle((gen << 24) | idx)
    }

    /// Reinterpret a raw `u64` (e.g. from a `CapXfer`).
    pub const fn from_raw(raw: u64) -> Self {
        Handle(raw)
    }

    /// The raw encoded value.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Table index (bits 0..24).
    pub const fn index(self) -> u32 {
        (self.0 & 0x00FF_FFFF) as u32
    }

    /// Slot generation (bits 24..56).
    pub const fn generation(self) -> u32 {
        ((self.0 >> 24) & 0xFFFF_FFFF) as u32
    }

    /// A handle is valid when it is non-zero and bits 56..64 are clear.
    pub const fn is_valid(self) -> bool {
        self.0 != 0 && (self.0 >> 56) == 0
    }
}

/// Identifier of a simulated process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcId(pub u32);

/// Identifier of an endpoint (its index in the object table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EndpointId(pub u64);

/// Identifier of an in-flight call. Monotonic; never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CallId(pub u64);

/// §13.1 error model. Only the variants the model can produce are used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// EPERM: missing right.
    Perm,
    /// EBADF: invalid, stale, consumed or wrong-type handle.
    BadHandle,
    /// EINVAL: over a hard limit, bad mode/flags.
    Inval,
    /// EAGAIN: the operation would block.
    Again,
    /// ETIMEDOUT: would block past a timeout.
    TimedOut,
    /// EINTR: interrupted while blocked.
    Intr,
    /// EPIPE: peer endpoint closed / reply to a cancelled call.
    Pipe,
    /// EMSGSIZE: receive buffers too small.
    MsgSize,
    /// ENOSPC: receiver handle table full.
    NoSpace,
    /// ENOMEM: quota / memory exhausted.
    NoMem,
    /// ENOENT: not bound.
    NoEnt,
    /// EEXIST: already bound.
    Exists,
}

impl Error {
    /// Negative errno value, matching §13.1.
    pub const fn errno(self) -> i32 {
        match self {
            Error::Perm => 1,
            Error::BadHandle => 9,
            Error::Inval => 22,
            Error::Again => 11,
            Error::TimedOut => 110,
            Error::Intr => 4,
            Error::Pipe => 32,
            Error::MsgSize => 90,
            Error::NoSpace => 28,
            Error::NoMem => 12,
            Error::NoEnt => 2,
            Error::Exists => 17,
        }
    }
}

/// Message metadata. There is deliberately **no badge field**: the badge is a
/// property of the sending capability, not of the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsgMeta {
    pub label: u32,
    pub data_len: u32,
    pub flags: u16,
}

/// §4.2 capability transfer descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapXfer {
    /// Send: source handle in the sender's table. Receive side rewrites it in
    /// [`InstalledCap`]; the model leaves this field as the original source.
    pub handle: u64,
    /// Send: requested rights (`RIGHTS_SAME` keeps all). Receive: effective.
    pub rights: u32,
    /// Send: `XFER_MOVE` or `XFER_COPY`.
    pub mode: u32,
}

/// A capability installed into the receiver's table by `recv`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstalledCap {
    /// New handle in the receiver's table.
    pub handle: u64,
    /// Effective rights (intersection of requested and source rights).
    pub rights: u32,
    /// Object type (`ObjType`: 1 endpoint, 2 reply, 3 notification, 4 memobj).
    pub obj_type: u32,
}

/// The result of a successful receive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    pub msg: MsgMeta,
    pub kind: u8,
    /// Endpoint badge of the sending handle, or the signalled bits for
    /// [`MSG_KIND_NOTIF`].
    pub badge: u64,
    /// Sending simulated process id (stands in for the sender silo).
    pub sender_silo: u32,
    pub caps: Vec<InstalledCap>,
    /// Single-use reply handle for [`MSG_KIND_CALL`].
    pub reply: Option<Handle>,
}

/// Lifecycle state of a call (§6.2). `Cancelled` is what the caller observes
/// as `EPIPE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    Queued,
    Received,
    Done,
    Cancelled,
}

impl CallState {
    /// Whether no further transition is possible.
    pub fn is_terminal(self) -> bool {
        matches!(self, CallState::Done | CallState::Cancelled)
    }
}

/// The kind of object a handle refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObjKind {
    Endpoint(u64),
    Reply(u64),
    Notif(u64),
    #[allow(dead_code)] // right-holder only; no MemObject syscall in the model
    MemObj(u64),
}

impl ObjKind {
    const fn obj_type(self) -> u32 {
        match self {
            ObjKind::Endpoint(_) => 1,
            ObjKind::Reply(_) => 2,
            ObjKind::Notif(_) => 3,
            ObjKind::MemObj(_) => 4,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    rights: u32,
    kind: ObjKind,
    badge: u64,
}

#[derive(Debug, Clone, Copy)]
struct Slot {
    gen: u32,
    entry: Option<Entry>,
}

struct HandleTable {
    slots: Vec<Slot>,
    free: Vec<u32>,
    limit: usize,
}

impl HandleTable {
    fn new() -> Self {
        HandleTable {
            slots: Vec::new(),
            free: Vec::new(),
            limit: HANDLE_LIMIT,
        }
    }

    fn get(&self, h: Handle) -> Result<&Entry, Error> {
        if !h.is_valid() {
            return Err(Error::BadHandle);
        }
        let slot = self.slots.get(h.index() as usize).ok_or(Error::BadHandle)?;
        if slot.gen != h.generation() {
            return Err(Error::BadHandle);
        }
        slot.entry.as_ref().ok_or(Error::BadHandle)
    }

    #[cfg(test)]
    fn get_mut(&mut self, h: Handle) -> Result<&mut Entry, Error> {
        if !h.is_valid() {
            return Err(Error::BadHandle);
        }
        let slot = self
            .slots
            .get_mut(h.index() as usize)
            .ok_or(Error::BadHandle)?;
        if slot.gen != h.generation() {
            return Err(Error::BadHandle);
        }
        slot.entry.as_mut().ok_or(Error::BadHandle)
    }

    fn available(&self) -> usize {
        self.free.len() + self.limit.saturating_sub(self.slots.len())
    }

    fn reserve(&self, count: usize) -> Result<(), Error> {
        if self.available() < count {
            Err(Error::NoSpace)
        } else {
            Ok(())
        }
    }

    fn insert(&mut self, entry: Entry) -> Result<Handle, Error> {
        if let Some(index) = self.free.pop() {
            let slot = &mut self.slots[index as usize];
            // A reused slot must never hand out the previous generation.
            slot.gen = slot.gen.wrapping_add(1).max(1);
            slot.entry = Some(entry);
            Ok(Handle::new(index, slot.gen))
        } else {
            if self.slots.len() >= self.limit {
                return Err(Error::NoSpace);
            }
            let index = self.slots.len() as u32;
            self.slots.push(Slot {
                gen: 1,
                entry: Some(entry),
            });
            Ok(Handle::new(index, 1))
        }
    }

    fn remove(&mut self, h: Handle) -> Result<Entry, Error> {
        if !h.is_valid() {
            return Err(Error::BadHandle);
        }
        let slot = self
            .slots
            .get_mut(h.index() as usize)
            .ok_or(Error::BadHandle)?;
        if slot.gen != h.generation() {
            return Err(Error::BadHandle);
        }
        let entry = slot.entry.take().ok_or(Error::BadHandle)?;
        self.free.push(h.index());
        Ok(entry)
    }

    fn live_handles(&self) -> Vec<Handle> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.entry.as_ref().map(|_| Handle::new(i as u32, s.gen)))
            .collect()
    }

    fn clear(&mut self) {
        self.slots.clear();
        self.free.clear();
    }
}

struct Proc {
    table: HandleTable,
    alive: bool,
}

impl Proc {
    fn new() -> Self {
        Proc {
            table: HandleTable::new(),
            alive: true,
        }
    }
}

/// A capability carried by an in-flight message.
///
/// Deviation from the literal `Vec<CapXfer>` sketch: after `XFER_MOVE` the
/// source handle is gone, so the resolved object and badge are stored
/// alongside the wire descriptor (which keeps the original source handle for
/// diagnostics only).
struct QueuedCap {
    wire: CapXfer,
    obj: ObjKind,
    badge: u64,
}

struct InFlight {
    msg: MsgMeta,
    kind: u8,
    badge: u64,
    sender_silo: u32,
    caps: Vec<QueuedCap>,
    call: Option<u64>,
}

struct CallRecord {
    id: u64,
    caller: ProcId,
    caller_gen: u32,
    gen: u32,
    state: CallState,
    reply_msg: Option<MsgMeta>,
    reply_buf_cap: (u32, u32),
}

struct Endpoint {
    id: u64,
    alive: bool,
    queue_depth: u32,
    flags: u16,
    queue: VecDeque<InFlight>,
    calls: Vec<CallRecord>,
    recv_refs: u32,
    bound_notif: Option<u64>,
    pending_bits: u64,
    owner_silo: u32,
}

struct Notification {
    id: u64,
    word: u64,
    bound_ep: Option<u64>,
    alive: bool,
}

/// The deterministic IPC v2 state machine.
pub struct IpcCore {
    procs: Vec<Proc>,
    endpoints: Vec<Endpoint>,
    notifications: Vec<Notification>,
    next_endpoint: u64,
    next_call: u64,
    #[allow(dead_code)] // namespace connection counter; unused without §8
    next_conn: u64,
}

impl Default for IpcCore {
    fn default() -> Self {
        Self::new()
    }
}

struct PendingCap {
    wire: CapXfer,
    obj: ObjKind,
    badge: u64,
}

struct Prepared {
    ep_id: u64,
    badge: u64,
    caps: Vec<PendingCap>,
}

impl IpcCore {
    /// Create an empty core.
    pub fn new() -> Self {
        IpcCore {
            procs: Vec::new(),
            endpoints: Vec::new(),
            notifications: Vec::new(),
            next_endpoint: 0,
            next_call: 1,
            next_conn: 1,
        }
    }

    /// Create a simulated process and return its id.
    pub fn create_process(&mut self) -> ProcId {
        let id = self.procs.len() as u32;
        self.procs.push(Proc::new());
        ProcId(id)
    }

    fn proc_ref(&self, p: ProcId) -> Result<&Proc, Error> {
        let proc = self.procs.get(p.0 as usize).ok_or(Error::BadHandle)?;
        if !proc.alive {
            return Err(Error::BadHandle);
        }
        Ok(proc)
    }

    fn proc_mut(&mut self, p: ProcId) -> Result<&mut Proc, Error> {
        let proc = self.procs.get_mut(p.0 as usize).ok_or(Error::BadHandle)?;
        if !proc.alive {
            return Err(Error::BadHandle);
        }
        Ok(proc)
    }

    fn entry(&self, p: ProcId, h: Handle) -> Result<Entry, Error> {
        self.proc_ref(p)?.table.get(h).copied()
    }

    fn endpoint(&self, id: u64) -> Option<&Endpoint> {
        self.endpoints.get(id as usize).filter(|e| e.id == id)
    }

    fn notif(&self, id: u64) -> Option<&Notification> {
        self.notifications.get(id as usize).filter(|n| n.id == id)
    }

    fn call(&self, id: u64) -> Option<&CallRecord> {
        self.endpoints
            .iter()
            .flat_map(|e| e.calls.iter())
            .find(|c| c.id == id)
    }

    fn call_mut(&mut self, id: u64) -> Option<&mut CallRecord> {
        self.endpoints
            .iter_mut()
            .flat_map(|e| e.calls.iter_mut())
            .find(|c| c.id == id)
    }

    // --- public introspection -------------------------------------------

    /// Endpoint id a handle refers to, or `None` if it is not an endpoint.
    pub fn endpoint_of(&self, p: ProcId, h: Handle) -> Option<u64> {
        match self.entry(p, h).ok()?.kind {
            ObjKind::Endpoint(id) => Some(id),
            _ => None,
        }
    }

    /// Configured queue depth of an endpoint.
    pub fn endpoint_queue_depth(&self, id: u64) -> Option<u32> {
        self.endpoint(id).map(|e| e.queue_depth)
    }

    /// Creation flags of an endpoint.
    pub fn endpoint_flags(&self, id: u64) -> Option<u16> {
        self.endpoint(id).map(|e| e.flags)
    }

    /// Owning simulated process of an endpoint.
    pub fn endpoint_owner(&self, id: u64) -> Option<u32> {
        self.endpoint(id).map(|e| e.owner_silo)
    }

    /// Whether an endpoint is still open.
    pub fn endpoint_alive(&self, id: u64) -> Option<bool> {
        self.endpoint(id).map(|e| e.alive)
    }

    /// Number of queued messages.
    pub fn queued_len(&self, id: u64) -> usize {
        self.endpoint(id).map(|e| e.queue.len()).unwrap_or(0)
    }

    /// `(data_len, ncaps)` of the head message, without dequeuing it.
    pub fn head_requirements(&self, id: u64) -> Option<(u32, u16)> {
        self.endpoint(id)
            .and_then(|e| e.queue.front())
            .map(|m| (m.msg.data_len, m.caps.len() as u16))
    }

    /// Lifecycle state of a call.
    pub fn call_state(&self, call: CallId) -> Option<CallState> {
        self.call(call.0).map(|c| c.state)
    }

    /// Reply payload of a call (copy; does not consume it).
    pub fn read_reply(&self, call: CallId) -> Option<MsgMeta> {
        self.call(call.0).and_then(|c| c.reply_msg)
    }

    /// Take the reply payload out of a call.
    pub fn take_reply(&mut self, call: CallId) -> Option<MsgMeta> {
        self.call_mut(call.0).and_then(|c| c.reply_msg.take())
    }

    /// `(caller, caller_gen)` of a call.
    pub fn call_caller(&self, call: CallId) -> Option<(ProcId, u32)> {
        self.call(call.0).map(|c| (c.caller, c.caller_gen))
    }

    /// Response-buffer capacity recorded at `call` time.
    pub fn reply_buf_cap(&self, call: CallId) -> Option<(u32, u32)> {
        self.call(call.0).map(|c| c.reply_buf_cap)
    }

    // --- object construction --------------------------------------------

    /// `SYS_EP_CREATE`: create an endpoint, returning its `RECV|MINT` handle.
    /// The creator gets no SEND right (§5.1).
    pub fn ep_create(&mut self, p: ProcId, queue_depth: u32, flags: u16) -> Result<Handle, Error> {
        if queue_depth > 256 {
            return Err(Error::Inval);
        }
        let depth = if queue_depth == 0 { 16 } else { queue_depth };
        if self.proc_ref(p)?.table.available() < 1 {
            return Err(Error::NoSpace);
        }
        let id = self.next_endpoint;
        self.next_endpoint += 1;
        self.endpoints.push(Endpoint {
            id,
            alive: true,
            queue_depth: depth,
            flags,
            queue: VecDeque::new(),
            calls: Vec::new(),
            recv_refs: 1,
            bound_notif: None,
            pending_bits: 0,
            owner_silo: p.0,
        });
        self.proc_mut(p)?.table.insert(Entry {
            rights: EP_RECV | EP_MINT | RIGHT_WAIT | RIGHT_INSPECT,
            kind: ObjKind::Endpoint(id),
            badge: 0,
        })
    }

    /// `SYS_IPC_MINT`: derive a badged SEND (endpoint) or SIGNAL
    /// (notification) handle.
    pub fn ipc_mint(
        &mut self,
        p: ProcId,
        src: Handle,
        badge: u64,
        rights: u32,
    ) -> Result<Handle, Error> {
        let e = self.entry(p, src)?;
        let (kind, new_rights) = match e.kind {
            ObjKind::Endpoint(id) => {
                if e.rights & EP_MINT == 0 {
                    return Err(Error::Perm);
                }
                (
                    ObjKind::Endpoint(id),
                    EP_SEND | (rights & GENERIC_RIGHTS_MASK & e.rights),
                )
            }
            ObjKind::Notif(id) => {
                if e.rights & NOTIF_MINT == 0 {
                    return Err(Error::Perm);
                }
                (
                    ObjKind::Notif(id),
                    NOTIF_SIGNAL | (rights & GENERIC_RIGHTS_MASK & e.rights),
                )
            }
            _ => return Err(Error::BadHandle),
        };
        self.proc_mut(p)?.table.insert(Entry {
            rights: new_rights,
            kind,
            badge,
        })
    }

    /// `SYS_NOTIF_CREATE`: a notification handle can signal, wait and mint.
    pub fn notif_create(&mut self, p: ProcId) -> Result<Handle, Error> {
        if self.proc_ref(p)?.table.available() < 1 {
            return Err(Error::NoSpace);
        }
        let id = self.notifications.len() as u64;
        self.notifications.push(Notification {
            id,
            word: 0,
            bound_ep: None,
            alive: true,
        });
        self.proc_mut(p)?.table.insert(Entry {
            rights: NOTIF_SIGNAL | NOTIF_WAIT | NOTIF_MINT | RIGHT_WAIT | RIGHT_INSPECT,
            kind: ObjKind::Notif(id),
            badge: u64::MAX,
        })
    }

    // --- handle operations ----------------------------------------------

    /// `SYS_HANDLE_DUPLICATE`: derive a handle with a rights subset.
    pub fn handle_duplicate(&mut self, p: ProcId, h: Handle, rights: u32) -> Result<Handle, Error> {
        let e = self.entry(p, h)?;
        if e.rights & RIGHT_DUPLICATE == 0 {
            return Err(Error::Perm);
        }
        let new_rights = rights & e.rights;
        let new = self.proc_mut(p)?.table.insert(Entry {
            rights: new_rights,
            kind: e.kind,
            badge: e.badge,
        })?;
        if let ObjKind::Endpoint(id) = e.kind {
            if new_rights & EP_RECV != 0 {
                self.cap_ref_add(ObjKind::Endpoint(id), EP_RECV);
            }
        }
        Ok(new)
    }

    /// `SYS_HANDLE_CLOSE`: drop a handle, applying object side effects.
    pub fn handle_close(&mut self, p: ProcId, h: Handle) -> Result<(), Error> {
        let e = self.proc_mut(p)?.table.remove(h)?;
        self.drop_entry(e);
        Ok(())
    }

    // --- send / call ----------------------------------------------------

    fn prepare(
        &self,
        p: ProcId,
        send_h: Handle,
        msg: MsgMeta,
        caps: &[CapXfer],
    ) -> Result<Prepared, Error> {
        let e = self.entry(p, send_h)?;
        let ep_id = match e.kind {
            ObjKind::Endpoint(id) => id,
            _ => return Err(Error::BadHandle),
        };
        if e.rights & EP_SEND == 0 {
            return Err(Error::Perm);
        }
        let ep = self.endpoint(ep_id).ok_or(Error::BadHandle)?;
        if !ep.alive {
            return Err(Error::Pipe);
        }
        if msg.data_len > MAX_DATA_LEN || caps.len() > MAX_TRANSFER_CAPS {
            return Err(Error::Inval);
        }
        if !caps.is_empty() && e.rights & EP_XFER == 0 {
            return Err(Error::Perm);
        }
        let mut out = Vec::with_capacity(caps.len());
        for c in caps {
            if c.mode != XFER_MOVE && c.mode != XFER_COPY {
                return Err(Error::Inval);
            }
            let src = self.entry(p, Handle::from_raw(c.handle))?;
            if src.rights & RIGHT_TRANSFER == 0 {
                return Err(Error::Perm);
            }
            if c.mode == XFER_COPY && src.rights & RIGHT_DUPLICATE == 0 {
                return Err(Error::Perm);
            }
            let eff = if c.rights == RIGHTS_SAME {
                src.rights
            } else {
                c.rights & src.rights
            };
            out.push(PendingCap {
                wire: CapXfer {
                    handle: c.handle,
                    rights: eff,
                    mode: c.mode,
                },
                obj: src.kind,
                badge: src.badge,
            });
        }
        Ok(Prepared {
            ep_id,
            badge: e.badge,
            caps: out,
        })
    }

    fn has_room(&self, ep_id: u64) -> Result<(), Error> {
        let ep = self.endpoint(ep_id).ok_or(Error::BadHandle)?;
        if !ep.alive {
            return Err(Error::Pipe);
        }
        if ep.queue.len() >= ep.queue_depth as usize {
            return Err(Error::Again);
        }
        Ok(())
    }

    fn commit(
        &mut self,
        p: ProcId,
        prepared: &Prepared,
        msg: MsgMeta,
        kind: u8,
        call: Option<u64>,
    ) -> Result<(), Error> {
        let ep = self
            .endpoints
            .get_mut(prepared.ep_id as usize)
            .ok_or(Error::BadHandle)?;
        let caps: Vec<QueuedCap> = prepared
            .caps
            .iter()
            .map(|c| QueuedCap {
                wire: c.wire,
                obj: c.obj,
                badge: c.badge,
            })
            .collect();
        ep.queue.push_back(InFlight {
            msg,
            kind,
            badge: prepared.badge,
            sender_silo: p.0,
            caps,
            call,
        });
        // COPY adds a reference that lives in the message.
        for c in &prepared.caps {
            if c.wire.mode == XFER_COPY {
                self.cap_ref_add(c.obj, c.wire.rights);
            }
        }
        // MOVE removes the source handle *after* enqueue; the reference moves
        // into the message, so no refcount changes.
        for c in &prepared.caps {
            if c.wire.mode == XFER_MOVE {
                if let Some(proc) = self.procs.get_mut(p.0 as usize) {
                    let _ = proc.table.remove(Handle::from_raw(c.wire.handle));
                }
            }
        }
        Ok(())
    }

    /// `SYS_EP_SEND`: buffered send.
    pub fn ep_send(
        &mut self,
        p: ProcId,
        send_h: Handle,
        msg: MsgMeta,
        caps: Vec<CapXfer>,
        _nonblock: bool,
    ) -> Result<(), Error> {
        let prepared = self.prepare(p, send_h, msg, &caps)?;
        self.has_room(prepared.ep_id)?;
        self.commit(p, &prepared, msg, MSG_KIND_SEND, None)
    }

    /// `SYS_EP_CALL`: enqueue a request and register the call atomically.
    pub fn ep_call(
        &mut self,
        p: ProcId,
        send_h: Handle,
        msg: MsgMeta,
        resp_caps: (u32, u32),
        caps: Vec<CapXfer>,
        _nonblock: bool,
    ) -> Result<CallId, Error> {
        let prepared = self.prepare(p, send_h, msg, &caps)?;
        self.has_room(prepared.ep_id)?;
        let id = self.next_call;
        self.next_call += 1;
        self.endpoints
            .get_mut(prepared.ep_id as usize)
            .ok_or(Error::BadHandle)?
            .calls
            .push(CallRecord {
                id,
                caller: p,
                caller_gen: send_h.generation(),
                gen: 0,
                state: CallState::Queued,
                reply_msg: None,
                reply_buf_cap: resp_caps,
            });
        self.commit(p, &prepared, msg, MSG_KIND_CALL, Some(id))?;
        Ok(CallId(id))
    }

    // --- receive --------------------------------------------------------

    /// `SYS_EP_RECV`: deliver a bound-notification signal or the head message.
    pub fn ep_recv(
        &mut self,
        p: ProcId,
        recv_h: Handle,
        data_cap: u32,
        caps_cap: u32,
        _nonblock: bool,
    ) -> Result<Received, Error> {
        let e = self.entry(p, recv_h)?;
        let ep_id = match e.kind {
            ObjKind::Endpoint(id) => id,
            _ => return Err(Error::BadHandle),
        };
        if e.rights & EP_RECV == 0 {
            return Err(Error::Perm);
        }
        let pending = {
            let ep = self.endpoint(ep_id).ok_or(Error::BadHandle)?;
            if !ep.alive {
                return Err(Error::Pipe);
            }
            ep.pending_bits
        };
        if pending != 0 {
            self.endpoints
                .get_mut(ep_id as usize)
                .expect("validated endpoint")
                .pending_bits = 0;
            return Ok(Received {
                msg: MsgMeta {
                    label: 0,
                    data_len: 0,
                    flags: 0,
                },
                kind: MSG_KIND_NOTIF,
                badge: pending,
                sender_silo: 0,
                caps: Vec::new(),
                reply: None,
            });
        }
        let needed = {
            let ep = self.endpoint(ep_id).ok_or(Error::BadHandle)?;
            let head = match ep.queue.front() {
                Some(h) => h,
                None => return Err(Error::Again),
            };
            if data_cap < head.msg.data_len || caps_cap < head.caps.len() as u32 {
                return Err(Error::MsgSize);
            }
            head.caps.len() + usize::from(head.call.is_some())
        };
        self.proc_ref(p)?.table.reserve(needed)?;

        let inflight = self
            .endpoints
            .get_mut(ep_id as usize)
            .ok_or(Error::BadHandle)?
            .queue
            .pop_front()
            .ok_or(Error::Again)?;
        let mut installed = Vec::with_capacity(inflight.caps.len());
        for cap in inflight.caps {
            let rights = cap.wire.rights;
            let new = self.proc_mut(p)?.table.insert(Entry {
                rights,
                kind: cap.obj,
                badge: cap.badge,
            })?;
            installed.push(InstalledCap {
                handle: new.raw(),
                rights,
                obj_type: cap.obj.obj_type(),
            });
        }
        let reply = if let Some(cid) = inflight.call {
            let gen = {
                let ep = self
                    .endpoints
                    .get_mut(ep_id as usize)
                    .expect("validated endpoint");
                match ep.calls.iter_mut().find(|r| r.id == cid) {
                    Some(rec) if rec.state == CallState::Queued => {
                        rec.state = CallState::Received;
                        Some(rec.gen)
                    }
                    _ => None,
                }
            };
            match gen {
                Some(g) => Some(self.proc_mut(p)?.table.insert(Entry {
                    rights: RIGHT_TRANSFER,
                    kind: ObjKind::Reply(cid),
                    badge: g as u64,
                })?),
                None => None,
            }
        } else {
            None
        };
        Ok(Received {
            msg: inflight.msg,
            kind: inflight.kind,
            badge: inflight.badge,
            sender_silo: inflight.sender_silo,
            caps: installed,
            reply,
        })
    }

    // --- reply ----------------------------------------------------------

    /// `SYS_EP_REPLY`: consume the single-use reply handle and store the reply.
    pub fn ep_reply(&mut self, p: ProcId, reply_h: Handle, msg: MsgMeta) -> Result<(), Error> {
        if msg.data_len > MAX_DATA_LEN {
            return Err(Error::Inval);
        }
        let e = self.entry(p, reply_h)?;
        let cid = match e.kind {
            ObjKind::Reply(cid) => cid,
            _ => return Err(Error::BadHandle),
        };
        let stored_gen = e.badge as u32;
        // Consume the handle whether or not the reply succeeds (§5.3, §6.2).
        let _ = self.proc_mut(p)?.table.remove(reply_h);
        match self.call_mut(cid) {
            Some(rec) if rec.state == CallState::Received && rec.gen == stored_gen => {
                rec.state = CallState::Done;
                rec.reply_msg = Some(msg);
                Ok(())
            }
            _ => Err(Error::Pipe),
        }
    }

    /// `SYS_EP_REPLY_RECV`: complete the reply first, then attempt the receive.
    pub fn ep_reply_recv(
        &mut self,
        p: ProcId,
        reply_h: Handle,
        reply_msg: MsgMeta,
        recv_h: Handle,
        data_cap: u32,
        caps_cap: u32,
        nonblock: bool,
    ) -> Result<Received, Error> {
        self.ep_reply(p, reply_h, reply_msg)?;
        self.ep_recv(p, recv_h, data_cap, caps_cap, nonblock)
    }

    /// `Cancel` a call. A queued request is removed so the server never sees
    /// it; a received one is invalidated. Any live reply handle becomes stale.
    pub fn cancel_call(&mut self, p: ProcId, call: CallId) -> Result<(), Error> {
        let id = call.0;
        let found = self.endpoints.iter().position(|ep| {
            ep.calls
                .iter()
                .any(|r| r.id == id && r.caller == p && !r.state.is_terminal())
        });
        let Some(epos) = found else {
            return Err(Error::BadHandle);
        };
        let state = self.endpoints[epos]
            .calls
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.state);
        match state {
            Some(CallState::Queued) => {
                let pos = self.endpoints[epos]
                    .queue
                    .iter()
                    .position(|m| m.call == Some(id));
                let removed = pos.and_then(|i| self.endpoints[epos].queue.remove(i));
                if let Some(m) = removed {
                    self.release_caps(m.caps);
                }
                let rec = self.endpoints[epos]
                    .calls
                    .iter_mut()
                    .find(|r| r.id == id)
                    .expect("record present");
                rec.state = CallState::Cancelled;
                rec.gen = rec.gen.wrapping_add(1);
            }
            Some(CallState::Received) => {
                let rec = self.endpoints[epos]
                    .calls
                    .iter_mut()
                    .find(|r| r.id == id)
                    .expect("record present");
                rec.state = CallState::Cancelled;
                rec.gen = rec.gen.wrapping_add(1);
            }
            _ => {}
        }
        Ok(())
    }

    // --- notifications --------------------------------------------------

    /// `SYS_EP_BIND_NOTIF`: bind a notification to an endpoint.
    pub fn ep_bind_notif(
        &mut self,
        p: ProcId,
        recv_h: Handle,
        notif_h: Handle,
    ) -> Result<(), Error> {
        let e = self.entry(p, recv_h)?;
        let ep_id = match e.kind {
            ObjKind::Endpoint(id) => id,
            _ => return Err(Error::BadHandle),
        };
        if e.rights & EP_RECV == 0 {
            return Err(Error::Perm);
        }
        if !self.endpoint(ep_id).ok_or(Error::BadHandle)?.alive {
            return Err(Error::Pipe);
        }
        let n = self.entry(p, notif_h)?;
        let nid = match n.kind {
            ObjKind::Notif(id) => id,
            _ => return Err(Error::BadHandle),
        };
        if n.rights & NOTIF_WAIT == 0 {
            return Err(Error::Perm);
        }
        if !self.notif(nid).ok_or(Error::BadHandle)?.alive {
            return Err(Error::BadHandle);
        }
        let old = self
            .endpoints
            .get_mut(ep_id as usize)
            .expect("validated endpoint")
            .bound_notif;
        if let Some(old) = old {
            if let Some(n) = self.notifications.get_mut(old as usize) {
                if n.bound_ep == Some(ep_id) {
                    n.bound_ep = None;
                }
            }
        }
        self.endpoints
            .get_mut(ep_id as usize)
            .expect("validated endpoint")
            .bound_notif = Some(nid);
        self.notifications
            .get_mut(nid as usize)
            .expect("validated notif")
            .bound_ep = Some(ep_id);
        Ok(())
    }

    /// `SYS_NOTIF_SIGNAL`: `word |= bits & badge`; also raises the bound
    /// endpoint's pending bits.
    pub fn notif_signal(&mut self, p: ProcId, h: Handle, bits: u64) -> Result<(), Error> {
        let e = self.entry(p, h)?;
        if e.rights & NOTIF_SIGNAL == 0 {
            return Err(Error::Perm);
        }
        let id = match e.kind {
            ObjKind::Notif(id) => id,
            _ => return Err(Error::BadHandle),
        };
        let mask = bits & e.badge;
        let bound = {
            let n = self
                .notifications
                .get_mut(id as usize)
                .ok_or(Error::BadHandle)?;
            if !n.alive {
                return Err(Error::Pipe);
            }
            n.word |= mask;
            n.bound_ep
        };
        if let Some(ep_id) = bound {
            if let Some(ep) = self.endpoints.get_mut(ep_id as usize) {
                if ep.alive && ep.bound_notif == Some(id) {
                    ep.pending_bits |= mask;
                }
            }
        }
        Ok(())
    }

    /// `SYS_NOTIF_WAIT`: atomically read and clear the word.
    pub fn notif_wait(&mut self, p: ProcId, h: Handle, _nonblock: bool) -> Result<u64, Error> {
        let e = self.entry(p, h)?;
        if e.rights & NOTIF_WAIT == 0 {
            return Err(Error::Perm);
        }
        let id = match e.kind {
            ObjKind::Notif(id) => id,
            _ => return Err(Error::BadHandle),
        };
        let n = self
            .notifications
            .get_mut(id as usize)
            .ok_or(Error::BadHandle)?;
        if !n.alive {
            return Err(Error::Pipe);
        }
        if n.word == 0 {
            return Err(Error::Again);
        }
        let word = n.word;
        n.word = 0;
        Ok(word)
    }

    // --- process lifetime ----------------------------------------------

    /// Close every handle a process holds, cancel its calls, and mark it dead.
    pub fn exit_process(&mut self, p: ProcId) {
        let handles = match self.procs.get_mut(p.0 as usize) {
            Some(proc) if proc.alive => proc.table.live_handles(),
            _ => return,
        };
        for h in handles {
            let _ = self.handle_close(p, h);
        }
        let calls: Vec<CallId> = self
            .endpoints
            .iter()
            .flat_map(|ep| ep.calls.iter())
            .filter(|r| r.caller == p && !r.state.is_terminal())
            .map(|r| CallId(r.id))
            .collect();
        for c in calls {
            let _ = self.cancel_call(p, c);
        }
        if let Some(proc) = self.procs.get_mut(p.0 as usize) {
            proc.alive = false;
            proc.table.clear();
        }
    }

    // --- internals ------------------------------------------------------

    fn cap_ref_add(&mut self, obj: ObjKind, rights: u32) {
        if let ObjKind::Endpoint(id) = obj {
            if rights & EP_RECV != 0 {
                if let Some(ep) = self.endpoints.get_mut(id as usize) {
                    if ep.alive {
                        ep.recv_refs = ep.recv_refs.saturating_add(1);
                    }
                }
            }
        }
    }

    fn cap_ref_drop(&mut self, obj: ObjKind, rights: u32) {
        if let ObjKind::Endpoint(id) = obj {
            if rights & EP_RECV != 0 {
                let close = if let Some(ep) = self.endpoints.get_mut(id as usize) {
                    if ep.alive {
                        ep.recv_refs = ep.recv_refs.saturating_sub(1);
                        ep.recv_refs == 0
                    } else {
                        false
                    }
                } else {
                    false
                };
                if close {
                    self.close_endpoint(id);
                }
            }
        }
    }

    fn release_caps(&mut self, caps: Vec<QueuedCap>) {
        for c in caps {
            self.cap_ref_drop(c.obj, c.wire.rights);
        }
    }

    fn any_handle_to_notif(&self, id: u64) -> bool {
        self.procs.iter().any(|p| {
            p.alive
                && p.table.slots.iter().any(|s| match s.entry {
                    Some(Entry {
                        kind: ObjKind::Notif(n),
                        ..
                    }) => n == id,
                    _ => false,
                })
        })
    }

    /// Apply the object-side effect of dropping a handle.
    fn drop_entry(&mut self, e: Entry) {
        match e.kind {
            ObjKind::Endpoint(id) => {
                if e.rights & EP_RECV != 0 {
                    self.cap_ref_drop(ObjKind::Endpoint(id), EP_RECV);
                }
            }
            ObjKind::Reply(cid) => {
                // Closed without replying: the caller observes EPIPE and the
                // call becomes Cancelled (§6.2).
                let stored_gen = e.badge as u32;
                if let Some(rec) = self.call_mut(cid) {
                    if rec.state == CallState::Received && rec.gen == stored_gen {
                        rec.state = CallState::Cancelled;
                        rec.gen = rec.gen.wrapping_add(1);
                    }
                }
            }
            ObjKind::Notif(id) => {
                if !self.any_handle_to_notif(id) {
                    if let Some(n) = self.notifications.get_mut(id as usize) {
                        n.alive = false;
                    }
                    for ep in self.endpoints.iter_mut() {
                        if ep.bound_notif == Some(id) {
                            ep.bound_notif = None;
                            ep.pending_bits = 0;
                        }
                    }
                }
            }
            ObjKind::MemObj(_) => {}
        }
    }

    fn close_endpoint(&mut self, id: u64) {
        let msgs = {
            let ep = match self.endpoints.get_mut(id as usize) {
                Some(e) => e,
                None => return,
            };
            if !ep.alive {
                return;
            }
            ep.alive = false;
            ep.recv_refs = 0;
            ep.pending_bits = 0;
            ep.bound_notif = None;
            for rec in ep.calls.iter_mut() {
                if matches!(rec.state, CallState::Queued | CallState::Received) {
                    rec.state = CallState::Cancelled;
                    rec.gen = rec.gen.wrapping_add(1);
                }
            }
            let msgs: Vec<InFlight> = ep.queue.drain(..).collect();
            msgs
        };
        for m in msgs {
            self.release_caps(m.caps);
        }
    }
}

#[cfg(test)]
mod tests;
