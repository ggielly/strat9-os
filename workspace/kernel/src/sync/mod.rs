// Synchronization primitives module

pub mod preempt;
mod spinlock;
pub mod waitqueue;

pub use preempt::PreemptGuard;
pub use spinlock::{SpinLock, SpinLockGuard};
pub use waitqueue::{WaitCondition, WaitQueue};
