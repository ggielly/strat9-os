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

//! rendezlarjan : userspace threading for Strat9-OS.
//!
//! "Tout est fichier": every operation maps to a file under `/thread`, the
//! Plan 9 style scheme exported by the kernel. This crate layers ergonomic
//! Rust APIs on top of the raw file protocol:
//!
//! - [`thread`] : level 1: one function per control file.
//! - [`Thread`]/[`Builder`] : level 2: closure-based `spawn`/`join`/`detach`.
//! - [`sync`] : futex-based Mutex/RwLock/Condvar/Barrier/Once/Semaphore.
//!
//! The library is `no_std` + `alloc`; the consumer provides the global
//! allocator (required only by level 2 and `thread_list`).
//!
//! Steady-state overhead is minimal: the yield fd is cached process-wide
//! ([`OnceLock`]) and shared between threads, which is semantically correct
//! because reads execute in the caller's context. `Thread::current()` is not
//! cached in v1 and costs 3 syscalls (open/read/close) per call.

#![no_std]

extern crate alloc;

pub mod sync;
pub mod thread;

pub use thread::{
    thread_create, thread_current, thread_exit, thread_join, thread_kill, thread_list,
    thread_yield, Builder, Thread, ThreadInfo,
};
