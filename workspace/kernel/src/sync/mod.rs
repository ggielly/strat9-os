// Synchronization primitives module

mod irq;
pub mod preempt;
mod spinlock;
pub mod waitqueue;

pub use irq::IrqDisabledToken;
pub use preempt::PreemptGuard;
pub use spinlock::{
    debug_clear_watch_lock_addr, debug_set_watch_lock_addr, SpinLock, SpinLockGuard,
};
pub use waitqueue::{WaitCondition, WaitQueue};
