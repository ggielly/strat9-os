use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

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
