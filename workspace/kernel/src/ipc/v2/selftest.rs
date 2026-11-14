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

//! Runtime self-tests of the IPC v2 object layer (feature `selftest`).
//!
//! These run as kernel tasks under the selftest orchestrator, on the real
//! scheduler, wait queues and timer tick: the parts the host model in
//! `workspace/ipc-core` cannot exercise. Covered:
//!
//! 1. receive reservation: a head needing more handle slots than reserved is
//!    reported (`NeedSlots`) and left queued; delivery with enough slots;
//! 2. `EMSGSIZE` leaves the message queued;
//! 3. timeouts: `pop`, `push` and notification wait return `ETIMEDOUT` no
//!    earlier than the deadline;
//! 4. a sender blocked on a full queue is woken when a receiver dequeues;
//! 5. call state machine: a reply is visible as soon as the call is `Done`,
//!    `abandon_call` reclaims a reply that raced with cancellation, and a
//!    reply to a cancelled call fails with `EPIPE`.
//!
//! Each check prints `[ipc-v2] ok|FAIL <name>`; the task exits with the
//! number of failures as its exit code.

use super::{
    endpoint::{self, CallSlot, CallState, Endpoint, InFlight, OwnedCap, PopOutcome, ReplyPayload},
    handle::ObjRef,
    notif::Notification,
};
use crate::{
    process::{add_task, sleep_current_task_ticks, Task, TaskPriority},
    sync::{scheduler_clock_ns, SpinLock},
    syscall::error::SyscallError,
};
use alloc::{sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use strat9_abi::ipc_v2::{MsgBuf, MsgHeader, MSG_KIND_REPLY, MSG_KIND_SEND, NOTIF_SIGNAL};

/// Failure counter for the current run.
static FAILURES: AtomicU64 = AtomicU64::new(0);

/// Endpoint shared with the helper sender task (test 4).
static SHARED_EP: SpinLock<Option<Arc<Endpoint>>> = SpinLock::new(None);
/// Helper sender outcome: 0 = pending, 1 = pushed, 2 = error.
static SENDER_RESULT: AtomicU64 = AtomicU64::new(0);

/// 30 ms: three ticks at 100 Hz, long enough to observe a real block.
const SHORT_TIMEOUT_NS: u64 = 30_000_000;

fn check(cond: bool, what: &str) {
    if cond {
        crate::serial_println!("[ipc-v2] ok   {}", what);
    } else {
        FAILURES.fetch_add(1, Ordering::Relaxed);
        crate::serial_println!("[ipc-v2] FAIL {}", what);
    }
}

fn message(data_len: u32, caps: Vec<OwnedCap>) -> InFlight {
    InFlight {
        header: MsgHeader {
            kind: MSG_KIND_SEND,
            data_len,
            ncaps: caps.len() as u16,
            ..MsgHeader::default()
        },
        data: vec![0xA5; data_len as usize],
        caps,
        call: None,
    }
}

fn notif_cap() -> OwnedCap {
    OwnedCap {
        obj: ObjRef::Notif(Notification::create()),
        rights: NOTIF_SIGNAL,
        badge: u64::MAX,
    }
}

fn new_endpoint(depth: u32) -> Option<Arc<Endpoint>> {
    let ep = Endpoint::create(depth, 0, 0).ok();
    check(ep.is_some(), "endpoint create");
    ep
}

/// 1. Reservation is checked in the dequeue critical section.
fn test_reservation() {
    let Some(ep) = new_endpoint(4) else { return };
    check(
        ep.push(message(8, vec![notif_cap(), notif_cap()]), true, None)
            .is_ok(),
        "push message with 2 caps",
    );
    check(
        matches!(ep.pop(64, 4, true, 0, None), Ok(PopOutcome::NeedSlots(2))),
        "pop with 0 reserved slots reports NeedSlots(2)",
    );
    check(
        ep.head_requirements() == Some((8, 2)),
        "message still queued after NeedSlots",
    );
    match ep.pop(64, 4, true, 2, None) {
        Ok(PopOutcome::Item(item)) => {
            check(
                item.caps.len() == 2 && item.data.len() == 8,
                "pop with 2 reserved slots delivers data and caps",
            );
            endpoint::release_caps(item.caps);
        }
        _ => check(false, "pop with 2 reserved slots delivers data and caps"),
    }
    ep.close();
}

/// 2. `EMSGSIZE` leaves the head in place.
fn test_message_size() {
    let Some(ep) = new_endpoint(4) else { return };
    let _ = ep.push(message(16, Vec::new()), true, None);
    check(
        matches!(ep.pop(8, 4, true, 0, None), Err(SyscallError::MessageSize)),
        "pop into an 8-byte buffer fails with EMSGSIZE",
    );
    check(
        ep.head_requirements() == Some((16, 0)),
        "message still queued after EMSGSIZE",
    );
    check(
        matches!(ep.pop(16, 4, true, 0, None), Ok(PopOutcome::Item(_))),
        "pop into a 16-byte buffer succeeds",
    );
    check(
        matches!(ep.pop(16, 4, true, 0, None), Err(SyscallError::Again)),
        "nonblocking pop on an empty queue fails with EAGAIN",
    );
    ep.close();
}

/// 3. Timeouts on pop, push and notification wait.
fn test_timeouts() {
    let Some(ep) = new_endpoint(1) else { return };

    let deadline = scheduler_clock_ns() + SHORT_TIMEOUT_NS;
    let res = ep.pop(64, 4, false, 0, Some(deadline));
    check(
        matches!(res, Err(SyscallError::TimedOut)) && scheduler_clock_ns() >= deadline,
        "blocking pop on an empty queue times out at the deadline",
    );

    let _ = ep.push(message(4, Vec::new()), true, None);
    let deadline = scheduler_clock_ns() + SHORT_TIMEOUT_NS;
    let res = ep.push(message(4, Vec::new()), false, Some(deadline));
    check(
        matches!(res, Err(SyscallError::TimedOut)) && scheduler_clock_ns() >= deadline,
        "blocking push on a full queue times out at the deadline",
    );
    check(
        ep.head_requirements() == Some((4, 0)),
        "timed-out push committed nothing",
    );
    ep.close();

    let notif = Notification::create();
    let deadline = scheduler_clock_ns() + SHORT_TIMEOUT_NS;
    check(
        matches!(notif.wait(false, Some(deadline)), Err(SyscallError::TimedOut))
            && scheduler_clock_ns() >= deadline,
        "notification wait times out at the deadline",
    );
    let _ = notif.signal(0b101);
    check(
        matches!(notif.wait(false, Some(scheduler_clock_ns() + SHORT_TIMEOUT_NS)), Ok(0b101)),
        "signalled notification returns its bits before the deadline",
    );
}

extern "C" fn sender_main() -> ! {
    let ep = SHARED_EP.lock().clone();
    let result = match ep {
        Some(ep) => {
            // Generous deadline: without the dequeue wake this push would only
            // return at the deadline, with ETIMEDOUT.
            let deadline = scheduler_clock_ns() + 2_000_000_000;
            match ep.push(message(4, Vec::new()), false, Some(deadline)) {
                Ok(()) => 1,
                Err(_) => 2,
            }
        }
        None => 2,
    };
    SENDER_RESULT.store(result, Ordering::Release);
    crate::process::scheduler::exit_current_task(0);
}

/// 4. A sender blocked on a full queue is woken by the dequeue.
fn test_sender_wakeup() {
    let Some(ep) = new_endpoint(1) else { return };
    let _ = ep.push(message(4, Vec::new()), true, None);
    SENDER_RESULT.store(0, Ordering::Release);
    *SHARED_EP.lock() = Some(ep.clone());

    let Ok(sender) = Task::new_kernel_task(sender_main, "ipc-v2-sender", TaskPriority::Normal)
    else {
        check(false, "spawn helper sender");
        return;
    };
    add_task(sender);
    // Let the helper reach the full queue and block.
    sleep_current_task_ticks(3);

    check(
        matches!(ep.pop(64, 4, true, 0, None), Ok(PopOutcome::Item(_))),
        "receiver dequeues from the full queue",
    );
    // 20 ticks (200 ms) is far below the helper's 2 s deadline.
    let mut waited = 0;
    while SENDER_RESULT.load(Ordering::Acquire) == 0 && waited < 20 {
        sleep_current_task_ticks(1);
        waited += 1;
    }
    check(
        SENDER_RESULT.load(Ordering::Acquire) == 1,
        "blocked sender is woken by the dequeue and commits",
    );
    *SHARED_EP.lock() = None;
    ep.close();
}

fn reply_payload() -> ReplyPayload {
    ReplyPayload {
        header: MsgHeader {
            kind: MSG_KIND_REPLY,
            ..MsgHeader::default()
        },
        data: Vec::new(),
        caps: vec![notif_cap()],
    }
}

/// 5. Call state machine invariants.
fn test_call_states() {
    // Reply visible as soon as the call is Done.
    let slot = CallSlot::new(0, None, MsgBuf::default());
    check(endpoint::mark_received(&slot), "queued call becomes Received");
    let gen = slot.gen.load(Ordering::Acquire);
    check(
        endpoint::deliver_reply(&slot, gen, reply_payload()).is_ok(),
        "reply delivered to a Received call",
    );
    check(
        *slot.state.lock() == CallState::Done && slot.reply.lock().is_some(),
        "Done call always carries its reply",
    );

    // Caller gives up after the reply raced in: the reply is reclaimed.
    endpoint::abandon_call(&slot);
    check(
        *slot.state.lock() == CallState::Cancelled && slot.reply.lock().is_none(),
        "abandon_call reclaims a reply that raced with cancellation",
    );

    // Reply to a call the caller already abandoned.
    let slot = CallSlot::new(0, None, MsgBuf::default());
    let _ = endpoint::mark_received(&slot);
    let gen = slot.gen.load(Ordering::Acquire);
    endpoint::abandon_call(&slot);
    let payload = reply_payload();
    let res = endpoint::deliver_reply(&slot, gen, payload);
    check(
        matches!(res, Err(SyscallError::Pipe)),
        "reply to an abandoned call fails with EPIPE",
    );
}

extern "C" fn ipc_v2_main() -> ! {
    crate::serial_println!("[ipc-v2] start");
    FAILURES.store(0, Ordering::Relaxed);

    test_reservation();
    test_message_size();
    test_timeouts();
    test_sender_wakeup();
    test_call_states();

    let failures = FAILURES.load(Ordering::Relaxed);
    if failures == 0 {
        crate::serial_println!("[ipc-v2] PASS");
    } else {
        crate::serial_println!("[ipc-v2] FAILED ({} checks)", failures);
    }
    crate::process::scheduler::exit_current_task(failures.min(i32::MAX as u64) as i32);
}

/// Spawn the IPC v2 self-test task (`ipc-v2-test`).
pub fn create_ipc_v2_test_task() {
    match Task::new_kernel_task(ipc_v2_main, "ipc-v2-test", TaskPriority::Normal) {
        Ok(task) => add_task(task),
        Err(_) => crate::serial_println!("[ipc-v2] FAIL could not spawn test task"),
    }
}
