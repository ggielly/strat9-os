//! Asynchronous I/O subsystem.
//!
//! Provides shared ring buffers (SQ/CQ) for zero-copy I/O submission
//! and completion between userspace and kernel.
//!
//! # Status
//!
//! - IMPLEMENTED : ring buffer, dispatch (Nop/VFS/IPC/Storage),
//!   AHCI IRQ => CQE bridge. See GitLab issue for details.
//!
//! # TODO
//!
//! - `Read`/`Write` VFS: switch from synchronous (blocking scheme::read) to
//!   truly async via the `AsyncScheme` trait
//! - `Open`/`Close`/`Stat`: implement dispatch handlers
//! - `IpcCall`: implement combined send+recv
//! - `PollAdd`/`PollRemove`: epoll-like support
//! - `Timeout`/`TimeoutRemove`: async timer
//! - `Accept`/`Connect`: async networking
//! - `Cancel`: implement actual cancellation of in-flight ops
//! - Efficient blocking: use `ring.wq.wait_until()` instead of
//!   `yield_task()` in `SYS_ASYNC_ENTER`
//! - Multi-slot AHCI (queue depth > 1 per port)
//! - Userspace runtime (`libasync`) + Rust async/await compatibility
//! - Safety audit (IRQ-safety of SpinLocks, stack overflow)
//!
//! Tracking : <https://git.strat9-os.org/strat9-os/strat9-os/-/issues/53>

pub mod complete;
pub mod dispatch;
pub mod ops;
pub mod ring;
pub mod syscall;
