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

//! L2: s9vm exit event queue (real kernel code).

extern crate alloc;

#[path = "../../kernel/src/s9vm/exitqueue.rs"]
mod exitqueue;

use exitqueue::{ExitQueue, QueueError, DEFAULT_CAPACITY};
use strat9_abi::vmm::{exit_kind, VmmExitEvent};

fn event(seq: u64) -> VmmExitEvent {
    VmmExitEvent {
        abi_version: 1,
        kind: exit_kind::IO_PORT,
        vcpu_id: 1,
        gpa: 0,
        size: 1,
        flags: 0,
        value: seq,
        port: 0xE9,
        reserved: 0,
    }
}

#[test]
fn default_capacity_is_positive() {
    assert!(DEFAULT_CAPACITY >= 1);
    assert_eq!(ExitQueue::default().capacity(), DEFAULT_CAPACITY);
}

#[test]
fn push_pop_preserves_order() {
    let mut queue = ExitQueue::new(4);
    queue.push(event(1)).expect("push 1");
    queue.push(event(2)).expect("push 2");
    assert_eq!(queue.len(), 2);
    assert_eq!(queue.pop().expect("pop 1").value, 1);
    assert_eq!(queue.pop().expect("pop 2").value, 2);
    assert_eq!(queue.pop(), Err(QueueError::Empty));
}

#[test]
fn rejects_push_when_full_and_counts_drops() {
    let mut queue = ExitQueue::new(2);
    queue.push(event(1)).expect("first");
    queue.push(event(2)).expect("second");
    assert_eq!(queue.push(event(3)), Err(QueueError::Full));
    assert_eq!(queue.len(), 2);
    assert_eq!(queue.dropped(), 1);
    // The first two are still there, in order.
    assert_eq!(queue.pop().expect("pop").value, 1);
    assert_eq!(queue.pop().expect("pop").value, 2);
}

#[test]
fn zero_capacity_is_clamped_to_one() {
    let mut queue = ExitQueue::new(0);
    assert_eq!(queue.capacity(), 1);
    queue.push(event(1)).expect("first");
    assert_eq!(queue.push(event(2)), Err(QueueError::Full));
}

#[test]
fn drain_and_clear() {
    let mut queue = ExitQueue::new(8);
    for index in 0..3 {
        queue.push(event(index)).expect("push");
    }
    let drained = queue.drain();
    assert_eq!(drained.len(), 3);
    assert!(queue.is_empty());

    queue.push(event(9)).expect("push");
    queue.clear();
    assert!(queue.is_empty());
    assert_eq!(queue.dropped(), 0);
}
