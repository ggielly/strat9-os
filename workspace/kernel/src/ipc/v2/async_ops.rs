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

//! IPC v2 operations on async rings: `AsyncOp` 13–17 (spec §11).
//!
//! # Execution model
//!
//! Every operation, at submission and at every retry, runs in the **ring
//! owner's** context: `SYS_ASYNC_ENTER` is only accepted from the owning
//! process, and both [`submit`] and [`poll`] are called from it. All user
//! copies therefore target the owner's address space, outside any IPC lock;
//! nothing is ever written from a peer's context (the defect of the v1
//! `AsyncRing` reply path).
//!
//! An operation that cannot complete without blocking is *parked*. IPC events
//! (enqueue, dequeue, reply, cancellation, signal, close) call
//! [`notify_event`], which kicks every ring that has parked operations; the
//! owner's `SYS_ASYNC_ENTER` then calls [`poll`], which retries them
//! non-blockingly and posts a CQE for each one that completes.

use super::endpoint::{self, CallSlot, CallState};
use crate::{
    async_io::{complete::push_completion, ring::find_ring},
    process::process::Process,
    sync::SpinLock,
    syscall::{
        error::SyscallError,
        ipc_v2::{self as sys, WaitSpec},
    },
};
use alloc::{sync::Arc, vec::Vec};
use core::{
    mem::size_of,
    sync::atomic::{AtomicUsize, Ordering},
};
use strat9_abi::ipc_v2::{MsgBuf, MsgCall, IPC_NONBLOCK};

/// `AsyncOp` opcodes owned by this module.
pub const OP_EP_SEND: u8 = 13;
pub const OP_EP_CALL: u8 = 14;
pub const OP_EP_RECV: u8 = 15;
pub const OP_EP_REPLY: u8 = 16;
pub const OP_NOTIF_WAIT: u8 = 17;

/// What a parked operation is waiting for.
enum Kind {
    /// `EpSend`: queue full or quota exhausted.
    Send,
    /// `EpRecv`: queue empty.
    Recv,
    /// `NotifWait`: word is zero.
    NotifWait,
    /// `EpCall`: the enqueue itself would block (full queue or exhausted
    /// quota). Holds the `*MsgBuf` request and response descriptors until
    /// `call_submit` commits, then becomes `Call`.
    CallSubmit { req: u64, resp: u64 },
    /// `EpCall`: committed, waiting for the reply.
    Call { slot: Arc<CallSlot>, resp: MsgBuf },
}

struct Parked {
    ring_id: u64,
    user_data: u64,
    handle: u64,
    addr: u64,
    kind: Kind,
}

static PARKED: SpinLock<Vec<Parked>> = SpinLock::new(Vec::new());
/// Fast path for [`notify_event`]: no lock when nothing is parked.
static PARKED_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Result of one non-blocking attempt.
enum Attempt {
    /// Completed: CQE `res` value (`>= 0` or `-errno`).
    Done(i32),
    /// Would block: keep parked.
    Pending,
}

fn errno(error: SyscallError) -> i32 {
    error as i64 as i32
}

fn finished(result: Result<u64, SyscallError>) -> Attempt {
    match result {
        Ok(value) => Attempt::Done(value as i32),
        Err(SyscallError::Again) => Attempt::Pending,
        Err(error) => Attempt::Done(errno(error)),
    }
}

const NONBLOCK: u64 = IPC_NONBLOCK as u64;

fn attempt(process: &Process, op: &mut Parked) -> Attempt {
    if let Kind::CallSubmit { req, resp } = &op.kind {
        let (req, resp) = (*req, *resp);
        match sys::call_submit(process, op.handle, req, resp, WaitSpec::NONBLOCK) {
            Ok((slot, resp)) => op.kind = Kind::Call { slot, resp },
            Err(SyscallError::Again) => return Attempt::Pending,
            Err(error) => return Attempt::Done(errno(error)),
        }
    }
    match &op.kind {
        Kind::Send => finished(sys::sys_ep_send(process, op.handle, op.addr, NONBLOCK, 0)),
        Kind::Recv => finished(sys::sys_ep_recv(process, op.handle, op.addr, NONBLOCK, 0)),
        Kind::NotifWait => finished(sys::sys_notif_wait(
            process, op.handle, op.addr, NONBLOCK, 0,
        )),
        Kind::CallSubmit { .. } => unreachable!("converted to Kind::Call above"),
        Kind::Call { slot, resp } => {
            let state = *slot.state.lock();
            match state {
                CallState::Done | CallState::Cancelled => {
                    match sys::call_finish(process, slot, resp) {
                        Ok(_) => Attempt::Done(0),
                        Err(error) => Attempt::Done(errno(error)),
                    }
                }
                _ => Attempt::Pending,
            }
        }
    }
}

/// Submission outcome reported to the async dispatcher.
pub enum Submitted {
    /// A CQE was already posted.
    Completed,
    /// Parked; a CQE will follow from [`poll`].
    InFlight,
}

/// Submit one IPC v2 SQE (`AsyncOp` 13–17) for `ring_id`.
///
/// `handle` = SQE `off`, `addr` = SQE `addr`, `len` = SQE `len` (must equal
/// the descriptor size, which versions it). Errors are returned as `-errno`
/// for the dispatcher to post.
pub fn submit(
    process: &Process,
    ring_id: u64,
    opcode: u8,
    handle: u64,
    addr: u64,
    len: u32,
    user_data: u64,
) -> Result<Submitted, i32> {
    let expected = match opcode {
        OP_EP_SEND | OP_EP_RECV | OP_EP_REPLY => size_of::<MsgBuf>(),
        OP_EP_CALL => size_of::<MsgCall>(),
        OP_NOTIF_WAIT => size_of::<u64>(),
        _ => return Err(errno(SyscallError::InvalidArgument)),
    };
    if len as usize != expected {
        return Err(errno(SyscallError::InvalidArgument));
    }

    let mut op = Parked {
        ring_id,
        user_data,
        handle,
        addr,
        kind: Kind::Send,
    };
    let first = match opcode {
        OP_EP_SEND => attempt(process, &mut op),
        OP_EP_RECV => {
            op.kind = Kind::Recv;
            attempt(process, &mut op)
        }
        OP_NOTIF_WAIT => {
            op.kind = Kind::NotifWait;
            attempt(process, &mut op)
        }
        // A reply never blocks (§6.2 rule 5).
        OP_EP_REPLY => Attempt::Done(match sys::sys_ep_reply(process, handle, addr) {
            Ok(_) => 0,
            Err(error) => errno(error),
        }),
        OP_EP_CALL => {
            // `MsgCall { req, resp }`: req at `addr`, resp right after it.
            op.kind = Kind::CallSubmit {
                req: addr,
                resp: addr + size_of::<MsgBuf>() as u64,
            };
            attempt(process, &mut op)
        }
        _ => unreachable!("opcode validated above"),
    };

    match first {
        Attempt::Done(res) => {
            push_completion(ring_id, user_data, res, 0);
            Ok(Submitted::Completed)
        }
        Attempt::Pending => {
            PARKED.lock().push(op);
            PARKED_COUNT.fetch_add(1, Ordering::AcqRel);
            Ok(Submitted::InFlight)
        }
    }
}

/// Retry the parked operations of `ring_id`. Must run in the ring owner's
/// context (called from `SYS_ASYNC_ENTER`). Returns how many completed.
pub fn poll(process: &Process, ring_id: u64) -> u32 {
    if PARKED_COUNT.load(Ordering::Acquire) == 0 {
        return 0;
    }
    // Take this ring's operations out; attempts run with no lock held.
    let mine: Vec<Parked> = {
        let mut parked = PARKED.lock();
        let (mine, rest): (Vec<Parked>, Vec<Parked>) =
            parked.drain(..).partition(|op| op.ring_id == ring_id);
        *parked = rest;
        mine
    };
    PARKED_COUNT.fetch_sub(mine.len(), Ordering::AcqRel);

    let mut completed = 0;
    let mut still = Vec::new();
    for mut op in mine {
        match attempt(process, &mut op) {
            Attempt::Done(res) => {
                push_completion(op.ring_id, op.user_data, res, 0);
                completed += 1;
            }
            Attempt::Pending => still.push(op),
        }
    }
    if !still.is_empty() {
        PARKED_COUNT.fetch_add(still.len(), Ordering::AcqRel);
        PARKED.lock().extend(still);
    }
    completed
}

/// An IPC v2 event happened: kick every ring that has parked operations.
///
/// Called after the event, outside IPC locks. Cheap when nothing is parked.
pub fn notify_event() {
    if PARKED_COUNT.load(Ordering::Acquire) == 0 {
        return;
    }
    let mut rings: Vec<u64> = Vec::new();
    {
        let parked = PARKED.lock();
        for op in parked.iter() {
            if !rings.contains(&op.ring_id) {
                rings.push(op.ring_id);
            }
        }
    }
    for id in rings {
        if let Some(ring) = find_ring(id) {
            ring.ipc_kick.store(1, Ordering::Release);
            ring.wq.wake_all();
        }
    }
}

/// Cancel the parked operation of `ring_id` whose `user_data == target`.
///
/// The cancelled operation's CQE reports `-ECANCELED`; a `Kind::Call` that was
/// already committed is abandoned exactly like a signal on the sync path
/// (`abandon_call`, §6.2), so a late reply releases its capabilities instead
/// of leaking them. `Kind::CallSubmit` holds no resources yet.
///
/// Returns `Err(NotFound)` when no such parked operation exists (including the
/// benign race where `poll` already took it).
pub fn cancel(ring_id: u64, target: u64) -> Result<(), SyscallError> {
    let op = {
        let mut parked = PARKED.lock();
        match parked
            .iter()
            .position(|op| op.ring_id == ring_id && op.user_data == target)
        {
            Some(index) => parked.remove(index),
            None => return Err(SyscallError::NotFound),
        }
    };
    PARKED_COUNT.fetch_sub(1, Ordering::AcqRel);
    // No lock held across `abandon_call` or the completion push.
    if let Kind::Call { slot, .. } = op.kind {
        endpoint::abandon_call(&slot);
    }
    push_completion(ring_id, target, errno(SyscallError::Canceled), 0);
    Ok(())
}

/// Drop every parked operation of a destroyed ring. Pending calls are
/// abandoned so a late reply's capabilities are released (§6.2).
pub fn drop_ring(ring_id: u64) {
    let dropped: Vec<Parked> = {
        let mut parked = PARKED.lock();
        let (dropped, rest): (Vec<Parked>, Vec<Parked>) =
            parked.drain(..).partition(|op| op.ring_id == ring_id);
        *parked = rest;
        dropped
    };
    PARKED_COUNT.fetch_sub(dropped.len(), Ordering::AcqRel);
    for op in dropped {
        if let Kind::Call { slot, .. } = op.kind {
            endpoint::abandon_call(&slot);
        }
    }
}
