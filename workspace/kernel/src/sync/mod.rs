// Synchronization primitives module

mod fixed_queue;
pub mod guardian;
mod irq;
pub mod preempt;
mod spinlock;
pub mod waitqueue;

pub use fixed_queue::FixedQueue;
pub use guardian::{Guardian, IrqDisabled, PreemptDisabled};
pub use irq::{with_irqs_disabled, IrqDisabledToken};
pub use preempt::PreemptGuard;
pub use spinlock::{
    debug_clear_watch_lock_addr, debug_set_trace_buddy_addr, debug_set_trace_lock_addr,
    debug_set_trace_slab_addr, debug_set_watch_lock_addr, SpinLock, SpinLockGuard,
};
pub use waitqueue::{WaitCondition, WaitQueue};
