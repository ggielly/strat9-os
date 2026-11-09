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

use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
};

/// Implements noop raw waker.
fn noop_raw_waker() -> RawWaker {
    /// Implements noop.
    fn noop(_: *const ()) {}
    /// Implements clone.
    fn clone(_: *const ()) -> RawWaker {
        noop_raw_waker()
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    RawWaker::new(core::ptr::null(), &VTABLE)
}

pub fn block_on<F: Future>(mut f: F) -> F::Output {
    // SAFETY: we never move `f` after pinning; single-threaded context.
    let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    loop {
        let pinned = unsafe { Pin::new_unchecked(&mut f) };
        match pinned.poll(&mut cx) {
            Poll::Ready(val) => return val,
            Poll::Pending => {
                let _ = strat9_syscall::call::sched_yield();
            }
        }
    }
}
