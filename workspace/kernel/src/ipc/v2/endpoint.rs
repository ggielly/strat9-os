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

//! Endpoint and reply-target objects (IPC ABI v2, §5 and §6).

use super::{handle::ObjRef, notif::Notification};
use crate::{
    process::TaskId,
    sync::{SpinLock, WaitQueue},
    syscall::error::SyscallError,
};
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use strat9_abi::ipc_v2::{
    CapXfer, MsgBuf, MsgHeader, EP_DEFAULT_QUEUE_DEPTH, EP_RECV, IPC_MAX_CAPS, MSG_KIND_NOTIF,
};

/// Monotonic endpoint id. Internal only; never exposed to userspace.
static NEXT_ENDPOINT_ID: AtomicU64 = AtomicU64::new(1);

/// A capability carried inside an in-flight message or reply payload.
#[derive(Clone)]
pub struct OwnedCap {
    /// Referenced object.
    pub obj: ObjRef,
    /// Effective rights.
    pub rights: u32,
    /// Immutable badge of the source handle (sender badge / signal mask).
    pub badge: u64,
}

/// A message waiting in an endpoint queue.
pub struct InFlight {
    /// Header with `kind`/`label`/`flags`/`data_len` and kernel-filled badge.
    pub header: MsgHeader,
    /// Exactly `header.data_len` bytes.
    pub data: Vec<u8>,
    /// Transferred capabilities.
    pub caps: Vec<OwnedCap>,
    /// Reply target when `header.kind == MSG_KIND_CALL`.
    pub call: Option<Arc<CallSlot>>,
}

/// Endpoint state protected by the endpoint lock.
pub struct EpState {
    /// False once the last `EP_RECV` reference is gone.
    pub alive: bool,
    /// FIFO message queue.
    pub queue: VecDeque<InFlight>,
    /// Pending bound-notification bits.
    pub pending_bits: u64,
    /// Notification currently bound to this endpoint.
    pub bound_notif: Option<Arc<Notification>>,
    /// Configured queue depth.
    pub depth: u32,
}

/// An IPC endpoint.
pub struct Endpoint {
    id: u64,
    /// Mutable endpoint state.
    pub state: SpinLock<EpState>,
    /// Configured queue depth (mirrors `state.depth`).
    pub depth: u32,
    /// `EP_FLAG_*` creation flags.
    pub flags: u16,
    /// Owning silo id (0 when unattributed).
    pub owner_silo: u32,
    /// Live handles carrying `EP_RECV`.
    pub recv_refs: AtomicU32,
    /// Senders blocked on a full queue.
    pub send_waitq: WaitQueue,
    /// Receivers blocked on an empty queue.
    pub recv_waitq: WaitQueue,
}

/// Call lifecycle (§6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    /// Committed, not yet received by a server.
    Queued,
    /// Delivered to a server; a Reply handle exists.
    Received,
    /// Reply payload stored and the caller woken.
    Done,
    /// Caller died / endpoint closed / reply handle dropped.
    Cancelled,
}

/// Caller-side description of an in-flight call.
pub struct CallSlot {
    /// Generation, bumped on cancellation. A Reply handle snapshots it.
    pub gen: AtomicU32,
    /// Lifecycle state.
    pub state: SpinLock<CallState>,
    /// Caller wait queue.
    pub waitq: WaitQueue,
    /// Reply payload once `Done`.
    pub reply: SpinLock<Option<ReplyPayload>>,
    /// Task registered as the caller (used by exit cleanup).
    pub caller: SpinLock<Option<TaskId>>,
    /// Endpoint id, used to cancel calls when the endpoint closes.
    pub endpoint_id: u64,
    /// Response buffers validated at call time.
    pub resp: MsgBuf,
}

impl CallSlot {
    /// Build a queued call slot.
    pub fn new(endpoint_id: u64, caller: Option<TaskId>, resp: MsgBuf) -> Self {
        CallSlot {
            gen: AtomicU32::new(0),
            state: SpinLock::new(CallState::Queued),
            waitq: WaitQueue::new(),
            reply: SpinLock::new(None),
            caller: SpinLock::new(caller),
            endpoint_id,
            resp,
        }
    }
}

/// A stored reply, ready for copy-out in the caller's context.
pub struct ReplyPayload {
    /// Response header (`kind == MSG_KIND_REPLY`).
    pub header: MsgHeader,
    /// Response data.
    pub data: Vec<u8>,
    /// Response capabilities.
    pub caps: Vec<OwnedCap>,
}

/// Result of a successful `recv`.
pub struct RecvItem {
    /// Kernel-filled header.
    pub header: MsgHeader,
    /// Message data.
    pub data: Vec<u8>,
    /// Transferable capabilities (not yet installed).
    pub caps: Vec<OwnedCap>,
    /// Reply target for `MSG_KIND_CALL`.
    pub call: Option<Arc<CallSlot>>,
}

/// Result of [`Endpoint::pop`].
pub enum PopOutcome {
    /// A message (or bound-notification signal) was dequeued.
    Item(RecvItem),
    /// The head needs this many handle slots, more than the caller reserved.
    /// Nothing was dequeued.
    NeedSlots(usize),
}

/// Shape of the endpoint head, used to size a handle-table reservation before
/// dequeuing (§4.5 step 3).
#[derive(Clone, Copy)]
pub struct PeekPlan {
    /// Bytes of message data.
    pub data_len: u32,
    /// Number of transferred capabilities.
    pub ncaps: u16,
    /// Whether the head carries a Reply target (+1 handle).
    pub has_call: bool,
}

impl Endpoint {
    /// Create an endpoint.
    pub fn create(depth: u32, flags: u16, owner_silo: u32) -> Result<Arc<Endpoint>, SyscallError> {
        let depth = if depth == 0 {
            EP_DEFAULT_QUEUE_DEPTH
        } else {
            depth
        };
        if depth == 0 || depth > 256 {
            return Err(SyscallError::InvalidArgument);
        }
        Ok(Arc::new(Endpoint {
            id: NEXT_ENDPOINT_ID.fetch_add(1, Ordering::Relaxed),
            state: SpinLock::new(EpState {
                alive: true,
                queue: VecDeque::new(),
                pending_bits: 0,
                bound_notif: None,
                depth,
            }),
            depth,
            flags,
            owner_silo,
            recv_refs: AtomicU32::new(1),
            send_waitq: WaitQueue::new(),
            recv_waitq: WaitQueue::new(),
        }))
    }

    /// Internal object id.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Whether the endpoint is still open.
    pub fn is_alive(&self) -> bool {
        self.state.lock().alive
    }

    /// Push a message, blocking while the queue is full unless `nonblock`.
    ///
    /// `deadline_ns` (absolute, [`crate::sync::scheduler_clock_ns`]) bounds the
    /// wait; on expiry nothing is committed and `ETIMEDOUT` is returned.
    pub fn push(
        &self,
        msg: InFlight,
        nonblock: bool,
        deadline_ns: Option<u64>,
    ) -> Result<(), SyscallError> {
        let mut msg = Some(msg);
        let outcome = self.send_waitq.wait_until_deadline(deadline_ns, || {
            let mut state = self.state.lock();
            if !state.alive {
                return Some(Err(SyscallError::Pipe));
            }
            if state.queue.len() < state.depth as usize {
                // The message is only visible after the call slot is linked
                // (it was placed into `InFlight` before this call).
                state.queue.push_back(msg.take().expect("push called once"));
                return Some(Ok(()));
            }
            if nonblock {
                return Some(Err(SyscallError::Again));
            }
            // Only reached when this send would block: a pending signal must
            // interrupt it (EINTR) without consuming anything (§5.2).
            if crate::process::signal::has_pending_signals() {
                return Some(Err(SyscallError::Interrupted));
            }
            None
        });
        let outcome = outcome.unwrap_or(Err(SyscallError::TimedOut));
        if outcome.is_ok() {
            self.recv_waitq.wake_one();
        }
        outcome
    }

    /// Pop a message or a pending bound-notification signal.
    ///
    /// `reserved` is the number of handle-table slots the receiver has
    /// **already reserved**. The handle count of the head (`ncaps` plus one
    /// for a Reply) is compared with it under the endpoint lock, in the same
    /// critical section as the dequeue:
    ///
    /// - if it fits, the message is dequeued: every install that follows is
    ///   covered by the reservation, so delivery is all-or-nothing (§4.5);
    /// - if not, nothing is dequeued and [`PopOutcome::NeedSlots`] reports the
    ///   exact count; the caller grows its reservation (outside this lock)
    ///   and retries.
    ///
    /// This replaces a peek-then-pop sizing that a second receiver thread,
    /// or a message arriving while the receiver was blocked on an empty
    /// queue, could invalidate. No lock is nested: the handle-table lock is
    /// never taken under the endpoint lock (handle removal takes them in the
    /// opposite order).
    pub fn pop(
        &self,
        data_cap: u32,
        caps_cap: u32,
        nonblock: bool,
        reserved: usize,
        deadline_ns: Option<u64>,
    ) -> Result<PopOutcome, SyscallError> {
        let outcome = self.recv_waitq.wait_until_deadline(deadline_ns, || {
            let mut state = self.state.lock();
            if state.pending_bits != 0 {
                let bits = core::mem::take(&mut state.pending_bits);
                return Some(Ok(PopOutcome::Item(RecvItem {
                    header: MsgHeader {
                        kind: MSG_KIND_NOTIF,
                        badge: bits,
                        ..MsgHeader::default()
                    },
                    data: Vec::new(),
                    caps: Vec::new(),
                    call: None,
                })));
            }
            if let Some(head) = state.queue.front() {
                if head.header.data_len > data_cap || head.caps.len() > caps_cap as usize {
                    return Some(Err(SyscallError::MessageSize));
                }
                if head.caps.len() > IPC_MAX_CAPS {
                    // Unreachable: senders are bounded by IPC_MAX_CAPS.
                    return Some(Err(SyscallError::InvalidArgument));
                }
                let needed = head.caps.len() + usize::from(head.call.is_some());
                if needed > reserved {
                    return Some(Ok(PopOutcome::NeedSlots(needed)));
                }
                let mut item = state.queue.pop_front().expect("head present");
                if let Some(call) = item.call.take() {
                    if mark_received(&call) {
                        item.call = Some(call);
                    }
                }
                return Some(Ok(PopOutcome::Item(RecvItem {
                    header: item.header,
                    data: item.data,
                    caps: item.caps,
                    call: item.call,
                })));
            }
            if !state.alive {
                return Some(Err(SyscallError::Pipe));
            }
            // A signal interrupts a blocking recv without consuming a message
            // (§5.2 / §6.2).
            if crate::process::signal::has_pending_signals() {
                return Some(Err(SyscallError::Interrupted));
            }
            if nonblock {
                return Some(Err(SyscallError::Again));
            }
            None
        });
        let outcome = outcome.unwrap_or(Err(SyscallError::TimedOut));
        if matches!(outcome, Ok(PopOutcome::Item(_))) {
            // A queue slot may have been freed: let one blocked sender retry.
            // Woken outside the receive wait-queue lock (no nested wakes).
            self.send_waitq.wake_one();
        }
        outcome
    }

    /// `(data_len, ncaps)` of the queued head, without dequeuing it.
    pub fn head_requirements(&self) -> Option<(u32, u16)> {
        self.state
            .lock()
            .queue
            .front()
            .map(|m| (m.header.data_len, m.caps.len() as u16))
    }

    /// Shape of what the next [`Endpoint::pop`] would return, without
    /// dequeuing or consuming pending notification bits.
    ///
    /// Returns `None` when a blocking receive would have to wait. A pending
    /// notification is reported as an empty message with no capabilities.
    pub fn peek_plan(&self) -> Option<PeekPlan> {
        let state = self.state.lock();
        if state.pending_bits != 0 {
            return Some(PeekPlan {
                data_len: 0,
                ncaps: 0,
                has_call: false,
            });
        }
        state.queue.front().map(|m| PeekPlan {
            data_len: m.header.data_len,
            ncaps: m.caps.len() as u16,
            has_call: m.call.is_some(),
        })
    }

    /// Close the endpoint (idempotent). Queued messages are dropped, every
    /// live call attached to this endpoint is cancelled, and all waiters wake.
    pub fn close(&self) {
        let (queued, bound_notif) = {
            let mut state = self.state.lock();
            if !state.alive {
                return;
            }
            state.alive = false;
            state.pending_bits = 0;
            let queued: Vec<InFlight> = state.queue.drain(..).collect();
            let bound = state.bound_notif.take();
            (queued, bound)
        };
        for msg in queued {
            if let Some(call) = msg.call {
                cancel_call(&call);
            }
            release_caps(msg.caps);
        }
        if let Some(notif) = bound_notif {
            notif.unbind_if(self.id);
        }
        self.send_waitq.wake_all();
        self.recv_waitq.wake_all();
        super::cancel_calls_for_endpoint(self.id);
    }

    /// Bind a notification to this endpoint.
    pub fn bind_notif(self: &Arc<Self>, notif: Arc<Notification>) -> Result<(), SyscallError> {
        let old = {
            let mut state = self.state.lock();
            if !state.alive {
                return Err(SyscallError::Pipe);
            }
            state.bound_notif.replace(notif.clone())
        };
        if let Some(old) = old {
            old.unbind_if(self.id);
        }
        notif.bind_arc(self.clone());
        Ok(())
    }
}

/// Mark a call as received by a server. Returns false when it was cancelled
/// before the server dequeued it.
pub fn mark_received(slot: &CallSlot) -> bool {
    let mut state = slot.state.lock();
    if *state == CallState::Queued {
        *state = CallState::Received;
        true
    } else {
        false
    }
}

/// Cancel a call: bump the generation and wake the caller.
///
/// Used by the server side (Reply handle dropped, endpoint closed) and by
/// teardown. A caller abandoning its own call must use
/// [`abandon_call`], which also reclaims a reply that raced with it.
pub fn cancel_call(slot: &CallSlot) {
    let mut state = slot.state.lock();
    if matches!(*state, CallState::Queued | CallState::Received) {
        *state = CallState::Cancelled;
        slot.gen.fetch_add(1, Ordering::AcqRel);
    }
    drop(state);
    slot.waitq.wake_all();
}

/// Caller-side cancellation after `EINTR` / `ETIMEDOUT`.
///
/// Between the caller deciding to give up and taking the state lock, the
/// server may already have replied (`Done`). That reply will never be copied
/// out, so its capabilities are released here instead of leaking with the
/// slot (each one may hold an endpoint's last `EP_RECV` reference).
pub fn abandon_call(slot: &CallSlot) {
    let late = {
        let mut state = slot.state.lock();
        match *state {
            CallState::Queued | CallState::Received => {
                *state = CallState::Cancelled;
                slot.gen.fetch_add(1, Ordering::AcqRel);
                None
            }
            CallState::Done => {
                *state = CallState::Cancelled;
                slot.reply.lock().take()
            }
            CallState::Cancelled => None,
        }
    };
    if let Some(payload) = late {
        release_caps(payload.caps);
    }
    slot.waitq.wake_all();
}

/// Deliver a reply into a call slot. The copy to userspace happens later, in
/// the caller's own context.
///
/// The payload is stored **before** the state becomes `Done`, both under the
/// state lock: a caller that observes `Done` always finds the payload.
pub fn deliver_reply(slot: &CallSlot, gen: u32, payload: ReplyPayload) -> Result<(), SyscallError> {
    let mut state = slot.state.lock();
    match *state {
        CallState::Queued => Err(SyscallError::InvalidArgument),
        CallState::Received if slot.gen.load(Ordering::Acquire) == gen => {
            *slot.reply.lock() = Some(payload);
            *state = CallState::Done;
            drop(state);
            slot.waitq.wake_one();
            Ok(())
        }
        _ => Err(SyscallError::Pipe),
    }
}

/// Extra reference for a newly duplicated/inherited `EP_RECV` handle.
pub fn retain_handle(entry: &super::handle::Entry) {
    if entry.rights & EP_RECV == 0 {
        return;
    }
    if let ObjRef::Endpoint(ep) = &entry.obj {
        ep.recv_refs.fetch_add(1, Ordering::AcqRel);
    }
}

/// Extra reference for a capability copied into a message.
pub fn retain_cap(cap: &OwnedCap) {
    if cap.rights & EP_RECV == 0 {
        return;
    }
    if let ObjRef::Endpoint(ep) = &cap.obj {
        ep.recv_refs.fetch_add(1, Ordering::AcqRel);
    }
}

/// Drop one reference held by a capability owned by the kernel.
pub fn release_cap(cap: &OwnedCap) {
    if cap.rights & EP_RECV == 0 {
        return;
    }
    if let ObjRef::Endpoint(ep) = &cap.obj {
        let decremented = ep
            .recv_refs
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                if n > 0 {
                    Some(n - 1)
                } else {
                    None
                }
            });
        if decremented.ok() == Some(1) {
            ep.close();
        }
    }
}

/// Release every capability in a payload/queue record.
pub fn release_caps(caps: Vec<OwnedCap>) {
    for cap in caps {
        release_cap(&cap);
    }
}

/// Apply the side effect of dropping a table entry.
pub fn release_handle(entry: &super::handle::Entry) {
    // A Reply handle dropped without replying cancels the call; the caller's
    // blocked `call` then fails with `EPIPE` (§6.2 rule 3, §13).
    if let ObjRef::Reply(slot) = &entry.obj {
        cancel_call(slot);
        return;
    }
    if entry.rights & EP_RECV == 0 {
        return;
    }
    if let ObjRef::Endpoint(ep) = &entry.obj {
        let decremented = ep
            .recv_refs
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                if n > 0 {
                    Some(n - 1)
                } else {
                    None
                }
            });
        if decremented.ok() == Some(1) {
            ep.close();
        }
    }
}

/// Build the wire `CapXfer` written back to a receiver.
pub fn installed_cap_wire(handle: u64, rights: u32, obj_type: u32) -> CapXfer {
    CapXfer {
        handle,
        rights,
        mode: obj_type,
    }
}
