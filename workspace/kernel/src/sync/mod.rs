// Synchronization primitives module

mod spinlock;
pub mod preempt;
pub mod waitqueue;

pub use preempt::PreemptGuard;
pub use spinlock::{SpinLock, SpinLockGuard};
pub use waitqueue::WaitQueue;
