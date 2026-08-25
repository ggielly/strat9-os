//! Mirror of kernel/src/sync: real primitives + fake irq submodule.
//!
//! File-backed so that `use super::{...}` inside the included sources
//! resolves against this module exactly like in the kernel tree.

// Fake IRQ layer replaces kernel/src/sync/irq.rs (x86 cli/sti).
#[path = "../fake_irq.rs"]
#[path = "../fake_irq.rs"]
pub mod irq;

#[path = "../../../kernel/src/sync/fixed_queue.rs"]
pub mod fixed_queue;
#[path = "../../../kernel/src/sync/guardian.rs"]
pub mod guardian;
#[path = "../../../kernel/src/sync/preempt.rs"]
pub mod preempt;
#[path = "../../../kernel/src/sync/spinlock.rs"]
pub mod spinlock;

pub use fixed_queue::FixedQueue;
pub use guardian::{Guardian, IrqDisabled, PreemptDisabled};
pub use irq::{with_irqs_disabled, IrqDisabledToken};
pub use irq::irq_probe_token;
pub use preempt::PreemptGuard;
pub use spinlock::{
    debug_clear_watch_lock_addr, debug_set_trace_buddy_addr, debug_set_trace_lock_addr,
    debug_set_trace_slab_addr, debug_set_watch_lock_addr,
};
pub use spinlock::{SpinLock, SpinLockGuard};
