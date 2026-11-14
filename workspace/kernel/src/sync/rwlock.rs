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

//! Reader/writer lock with configurable guard behaviour.
//!
//! Modelled on [`SpinLock`](super::SpinLock): the same [`Guardian`] hook
//! (`enter()` before any waiting, `exit()` on release) wraps the atomic
//! protocol so IRQs / preemption are handled exactly like the existing
//! spin-style primitives.
//!
//! # Protocol
//!
//! ```text
//! writer  : AtomicBool   -> true while a writer holds the lock
//! readers : AtomicUsize  -> number of active readers
//! ```
//!
//! A reader waits for `writer == false`, then `fetch_add(1, Acquire)` on
//! `readers`, then re-checks `writer`. If a writer slipped in between, the
//! reader backs out (`fetch_sub(1, Release)`) and retries; otherwise it holds
//! a shared guard.
//!
//! A writer CASes `writer` from false to true, then waits until `readers == 0`
//! before handing out the exclusive guard. On release it clears `owner_cpu`
//! and stores `writer = false` with `Release`.
//!
//! # Fairness
//!
//! There is no fairness machinery: a steady stream of readers can starve a
//! pending writer. This matches the existing spin-style primitives (no queue,
//! no ticket) and keeps the implementation dependency-free. `try_*` variants
//! never block and never leak the guardian state.

use super::{
    guardian::{Guardian, GuardianState, IrqDisabled},
    IrqDisabledToken,
};
use core::{
    cell::UnsafeCell,
    marker::PhantomData,
    mem::ManuallyDrop,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

// =========================== RwLock ==========================================

/// A reader/writer lock parameterised by a [`Guardian`].
///
/// The default guardian is [`IrqDisabled`], matching
/// [`SpinLock`](super::SpinLock). Supports `T: ?Sized`; the `data` field is
/// last so the struct can hold dynamically sized types.
pub struct RwLock<T: ?Sized, G: Guardian = IrqDisabled> {
    /// True while a writer holds the lock.
    writer: AtomicBool,
    /// Number of active readers.
    readers: AtomicUsize,
    /// CPU index of the current writer (`usize::MAX` when unlocked).
    /// Used for deadlock diagnostics only.
    owner_cpu: AtomicUsize,
    _guardian: PhantomData<G>,
    /// Must be the last field: when `T: ?Sized`, this is a DST and Rust
    /// requires the dynamically sized field to be last in the struct.
    data: UnsafeCell<T>,
}

// SAFETY: Readers hand out `&T`, so `T: Sync` is required; the writer path
// additionally requires `T: Send` because the guard can move `T` across
// threads (`DerefMut`). The atomic protocol above guarantees that no reader and
// no other writer can observe the data while a write guard is alive.
unsafe impl<T: ?Sized + Send + Sync, G: Guardian> Sync for RwLock<T, G> {}
// SAFETY: Sending the lock itself only transfers the right to acquire it; the
// same protocol prevents aliasing, and the lock owns its `T` (needs `T: Send`).
unsafe impl<T: ?Sized + Send, G: Guardian> Send for RwLock<T, G> {}

impl<T, G: Guardian> RwLock<T, G> {
    /// Create a new, unlocked reader/writer lock.
    pub const fn new(data: T) -> Self {
        RwLock {
            writer: AtomicBool::new(false),
            readers: AtomicUsize::new(0),
            owner_cpu: AtomicUsize::new(usize::MAX),
            _guardian: PhantomData,
            data: UnsafeCell::new(data),
        }
    }
}

impl<T: ?Sized, G: Guardian> RwLock<T, G> {
    /// Acquire a shared read guard, spinning until a writer is not present.
    ///
    /// The guardian's `enter()` hook runs **before** the spin loop so the CPU
    /// is already in the protected mode while waiting.
    pub fn read(&self) -> RwLockReadGuard<'_, T, G> {
        let state = G::enter();
        loop {
            while self.writer.load(Ordering::Acquire) {
                core::hint::spin_loop();
            }
            self.readers.fetch_add(1, Ordering::Acquire);
            // Re-check: a writer may have won the race between our wait and
            // the increment. Back out and retry so we never observe the data
            // concurrently with a writer.
            if !self.writer.load(Ordering::Acquire) {
                break;
            }
            self.readers.fetch_sub(1, Ordering::Release);
        }
        RwLockReadGuard {
            lock: self,
            state: ManuallyDrop::new(state),
        }
    }

    /// Try to acquire a shared read guard without spinning.
    ///
    /// Returns `None` (and releases the guardian) if a writer holds the lock.
    pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T, G>> {
        let state = G::enter();
        if self.writer.load(Ordering::Acquire) {
            G::exit(state);
            return None;
        }
        self.readers.fetch_add(1, Ordering::Acquire);
        if self.writer.load(Ordering::Acquire) {
            self.readers.fetch_sub(1, Ordering::Release);
            G::exit(state);
            return None;
        }
        Some(RwLockReadGuard {
            lock: self,
            state: ManuallyDrop::new(state),
        })
    }

    /// Acquire an exclusive write guard, spinning until no reader or writer
    /// remains.
    pub fn write(&self) -> RwLockWriteGuard<'_, T, G> {
        let state = G::enter();
        while self
            .writer
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        while self.readers.load(Ordering::Acquire) != 0 {
            core::hint::spin_loop();
        }
        let this_cpu = crate::arch::percpu::current_cpu_index();
        self.owner_cpu.store(this_cpu, Ordering::Relaxed);
        RwLockWriteGuard {
            lock: self,
            state: ManuallyDrop::new(state),
        }
    }

    /// Try to acquire an exclusive write guard without spinning.
    ///
    /// Returns `None` (and releases the guardian) if the lock is contended.
    pub fn try_write(&self) -> Option<RwLockWriteGuard<'_, T, G>> {
        let state = G::enter();
        if self
            .writer
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            G::exit(state);
            return None;
        }
        if self.readers.load(Ordering::Acquire) != 0 {
            self.writer.store(false, Ordering::Release);
            G::exit(state);
            return None;
        }
        let this_cpu = crate::arch::percpu::current_cpu_index();
        self.owner_cpu.store(this_cpu, Ordering::Relaxed);
        Some(RwLockWriteGuard {
            lock: self,
            state: ManuallyDrop::new(state),
        })
    }

    /// Returns the writer CPU index (`usize::MAX` if unlocked).
    pub fn owner_cpu(&self) -> usize {
        self.owner_cpu.load(Ordering::Relaxed)
    }

    /// Returns a mutable reference to the underlying data.
    ///
    /// By holding `&mut self`, the compiler guarantees exclusive access; no
    /// other guard can exist, so the inner data is accessed without locking.
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }
}

impl<T: ?Sized, G: Guardian> core::fmt::Debug for RwLock<T, G> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Deliberately does not require `T: Debug`: this only exists so that
        // owners deriving `Debug` (e.g. display `Handle`) keep compiling.
        f.debug_struct("RwLock").finish_non_exhaustive()
    }
}

// =========================== Read guard ======================================

/// RAII shared guard; carries the guardian state and releases the read count
/// on drop.
pub struct RwLockReadGuard<'a, T: ?Sized, G: Guardian = IrqDisabled> {
    lock: &'a RwLock<T, G>,
    /// Wrapped in ManuallyDrop so `Drop::drop` can move it into `G::exit()`
    /// without a compiler-generated second drop.
    state: ManuallyDrop<GuardianState<G::Token>>,
}

impl<'a, T: ?Sized> RwLockReadGuard<'a, T, IrqDisabled> {
    /// Return the typed proof that IRQs are disabled.
    #[inline]
    pub fn token(&self) -> &IrqDisabledToken {
        &self.state.token
    }
}

impl<'a, T: ?Sized, G: Guardian> Deref for RwLockReadGuard<'a, T, G> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: a live read guard means `readers > 0` and `writer == false`,
        // so no writer can hold a `&mut` and we only hand out a shared `&`.
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T: ?Sized, G: Guardian> Drop for RwLockReadGuard<'a, T, G> {
    fn drop(&mut self) {
        self.lock.readers.fetch_sub(1, Ordering::Release);
        // SAFETY: `state` is initialised exactly once and never dropped
        // elsewhere (ManuallyDrop suppresses the automatic drop).
        let state = unsafe { ManuallyDrop::take(&mut self.state) };
        G::exit(state);
    }
}

// =========================== Write guard =====================================

/// RAII exclusive guard; carries the guardian state and releases the lock on
/// drop.
pub struct RwLockWriteGuard<'a, T: ?Sized, G: Guardian = IrqDisabled> {
    lock: &'a RwLock<T, G>,
    /// See [`RwLockReadGuard::state`].
    state: ManuallyDrop<GuardianState<G::Token>>,
}

impl<'a, T: ?Sized> RwLockWriteGuard<'a, T, IrqDisabled> {
    /// Return the typed proof that IRQs are disabled.
    #[inline]
    pub fn token(&self) -> &IrqDisabledToken {
        &self.state.token
    }
}

impl<'a, T: ?Sized, G: Guardian> Deref for RwLockWriteGuard<'a, T, G> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the write guard owns exclusive access (`writer == true`,
        // `readers == 0`), so no other reference to the data exists.
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T: ?Sized, G: Guardian> DerefMut for RwLockWriteGuard<'a, T, G> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as above; the exclusive guard is the sole owner, so a
        // mutable reference is sound.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T: ?Sized, G: Guardian> Drop for RwLockWriteGuard<'a, T, G> {
    fn drop(&mut self) {
        self.lock.owner_cpu.store(usize::MAX, Ordering::Relaxed);
        self.lock.writer.store(false, Ordering::Release);
        // SAFETY: `state` is initialised exactly once and never dropped
        // elsewhere (ManuallyDrop suppresses the automatic drop).
        let state = unsafe { ManuallyDrop::take(&mut self.state) };
        G::exit(state);
    }
}

// The guardian's invariant (e.g. preemption depth, IF flag) is per-CPU.
// Sending a guard to another CPU would violate it.
impl<T: ?Sized, G: Guardian> !Send for RwLockReadGuard<'_, T, G> {}
impl<T: ?Sized, G: Guardian> !Send for RwLockWriteGuard<'_, T, G> {}
