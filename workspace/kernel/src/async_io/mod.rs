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
