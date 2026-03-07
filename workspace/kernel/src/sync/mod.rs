// Synchronization primitives module

pub mod preempt;
mod spinlock;
pub mod waitqueue;

pub use preempt::PreemptGuard;
pub use spinlock::{
    debug_clear_watch_lock_addr, debug_set_watch_lock_addr, SpinLock, SpinLockGuard,
};
pub use waitqueue::{WaitCondition, WaitQueue};
