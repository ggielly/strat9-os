//! Generic spinlock with configurable guard behaviour.
//!
//! # Choosing a guardian
//!
//! ```text
//! SpinLock<T>                  →  SpinLock<T, IrqDisabled>   (default)
//! SpinLock<T, IrqDisabled>     →  saves RFLAGS + clears IF (equiv. spin_lock_irqsave)
//! SpinLock<T, PreemptDisabled> →  disables preemption only, IRQs untouched
//! ```
//!
//! **Use `IrqDisabled` (the default) for**:
//! - Data shared across CPUs (heap, VFS, IPC queues, network rings, …)
//! - Any data touched from interrupt handlers
//!
//! **Use `PreemptDisabled` for**:
//! - Per-CPU data never accessed from interrupt handlers
//!   (scheduler run-queues, per-CPU frame caches, statistics counters …)
//!
//! All call sites that use `SpinLock<T>` without a type argument continue to
//! compile unchanged — `IrqDisabled` is the default guardian.
//!
//! # Debug helpers
//!
//! `debug_set_watch_lock_addr` / `debug_clear_watch_lock_addr` emit a serial
//! trace on every `drop` of a specific lock instance — useful when hunting
//! deadlocks.

use super::{guardian::{Guardian, GuardianState, IrqDisabled}, IrqDisabledToken};
use core::{
    cell::UnsafeCell,
    marker::PhantomData,
    mem::ManuallyDrop,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

static DEBUG_WATCH_LOCK_ADDR: AtomicUsize = AtomicUsize::new(usize::MAX);

// ─── SpinLock ──────────────────────────────────────────────────────────────────

/// A spinlock parameterised by a [`Guardian`].
///
/// The default guardian is [`IrqDisabled`], preserving existing call-site
/// semantics with no source changes required.
///
/// Supports `T: ?Sized` for `SpinLock<dyn Trait>` and other DST types.
/// The `data` field is last so that the struct can hold dynamically sized types.
pub struct SpinLock<T: ?Sized, G: Guardian = IrqDisabled> {
    locked: AtomicBool,
    /// CPU index of the current lock holder (`usize::MAX` when unlocked).
    /// Used for deadlock diagnostics only.
    owner_cpu: AtomicUsize,
    _guardian: PhantomData<G>,
    /// Must be the last field: when `T: ?Sized`, this is a DST and Rust
    /// requires the dynamically sized field to be last in the struct.
    data: UnsafeCell<T>,
}

// SAFETY: The guardian ensures mutual exclusion; T must itself be Send.
unsafe impl<T: ?Sized + Send, G: Guardian> Sync for SpinLock<T, G> {}
unsafe impl<T: ?Sized + Send, G: Guardian> Send for SpinLock<T, G> {}

impl<T, G: Guardian> SpinLock<T, G> {
    /// Create a new, unlocked spinlock.
    ///
    /// `T` must be `Sized` here because we construct a new value.
    pub const fn new(data: T) -> Self {
        SpinLock {
            locked: AtomicBool::new(false),
            owner_cpu: AtomicUsize::new(usize::MAX),
            _guardian: PhantomData,
            data: UnsafeCell::new(data),
        }
    }
}

impl<T: ?Sized, G: Guardian> SpinLock<T, G> {
    /// Acquire the lock, spinning until available.
    ///
    /// The guardian's `enter()` hook runs **before** the spin loop so that the
    /// CPU is already in the protected mode while we wait. This closes the
    /// window where an IRQ or preempt-switch could occur between protect and
    /// acquire.
    pub fn lock(&self) -> SpinLockGuard<'_, T, G> {
        let state = G::enter();
        let mut spins: usize = 0;
        let this_cpu = crate::arch::x86_64::percpu::current_cpu_index();

        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            spins = spins.saturating_add(1);
            if spins == 5_000_000 {
                let owner = self.owner_cpu.load(Ordering::Relaxed);
                crate::serial_println!(
                    "[trace][spin] long-wait lock={:#x} cpu={} owner_cpu={}",
                    self as *const _ as *const () as usize,
                    this_cpu,
                    owner,
                );
                spins = 0;
            }
            core::hint::spin_loop();
        }
        self.owner_cpu.store(this_cpu, Ordering::Relaxed);

        SpinLockGuard { lock: self, state: ManuallyDrop::new(state) }
    }

    /// Try to acquire the lock without spinning.
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T, G>> {
        let state = G::enter();
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            self.owner_cpu
                .store(crate::arch::x86_64::percpu::current_cpu_index(), Ordering::Relaxed);
            Some(SpinLockGuard { lock: self, state: ManuallyDrop::new(state) })
        } else {
            G::exit(state);
            None
        }
    }

    /// Returns the owner CPU index (`usize::MAX` if unlocked).
    pub fn owner_cpu(&self) -> usize {
        self.owner_cpu.load(Ordering::Relaxed)
    }

    /// Returns a mutable reference to the underlying data.
    ///
    /// By holding `&mut self`, the compiler guarantees exclusive access to the
    /// lock; no other reference exists, so the inner data can be accessed
    /// without acquiring the lock.
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }
}

// ─── IrqDisabled-specific extensions ────────────────────────────────────────────

impl<T: ?Sized> SpinLock<T, IrqDisabled> {
    /// Try to acquire without touching RFLAGS.
    ///
    /// Returns `None` if IRQs are currently enabled (no `IrqDisabledToken` can
    /// be produced) or the lock is already held. The caller must ensure that
    /// IRQs remain disabled for the entire lifetime of the returned guard.
    pub fn try_lock_no_irqsave(&self) -> Option<SpinLockGuard<'_, T, IrqDisabled>> {
        let token = IrqDisabledToken::verify()?;
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            self.owner_cpu
                .store(crate::arch::x86_64::percpu::current_cpu_index(), Ordering::Relaxed);
            Some(SpinLockGuard {
                lock: self,
                state: ManuallyDrop::new(GuardianState {
                    token,
                    saved_flags: 0,
                    restore_flags: false,
                }),
            })
        } else {
            None
        }
    }
}

// ─── Debug helpers ─────────────────────────────────────────────────────────────

/// Register a lock address to trace on every drop (serial console output).
pub fn debug_set_watch_lock_addr(addr: usize) {
    DEBUG_WATCH_LOCK_ADDR.store(addr, Ordering::Relaxed);
}

/// Clear the watched lock address.
pub fn debug_clear_watch_lock_addr() {
    DEBUG_WATCH_LOCK_ADDR.store(usize::MAX, Ordering::Relaxed);
}

// ─── SpinLockGuard ────────────────────────────────────────────────────────────

/// RAII guard that holds the lock and carries the guardian state.
pub struct SpinLockGuard<'a, T: ?Sized, G: Guardian = IrqDisabled> {
    lock: &'a SpinLock<T, G>,
    /// Wrapped in ManuallyDrop so that `Drop::drop` can move it into
    /// `G::exit()` without triggering a compiler-generated second drop of
    /// the field.
    state: ManuallyDrop<GuardianState<G::Token>>,
}

impl<'a, T: ?Sized> SpinLockGuard<'a, T, IrqDisabled> {
    /// Return the typed proof that IRQs are disabled.
    #[inline]
    pub fn token(&self) -> &IrqDisabledToken {
        &self.state.token
    }

    #[inline]
    pub(crate) fn with_mut_and_token<R>(
        &mut self,
        f: impl FnOnce(&mut T, &IrqDisabledToken) -> R,
    ) -> R {
        let token = &self.state.token;
        // SAFETY: this guard owns the lock, guaranteeing exclusive access.
        let data = unsafe { &mut *self.lock.data.get() };
        f(data, token)
    }
}

impl<'a, T: ?Sized, G: Guardian> Deref for SpinLockGuard<'a, T, G> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: we hold the lock.
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T: ?Sized, G: Guardian> DerefMut for SpinLockGuard<'a, T, G> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: we hold the lock.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T: ?Sized, G: Guardian> Drop for SpinLockGuard<'a, T, G> {
    fn drop(&mut self) {
        let lock_addr = self.lock as *const _ as *const () as usize;
        let watched = DEBUG_WATCH_LOCK_ADDR.load(Ordering::Relaxed);
        let trace = watched == lock_addr;

        if trace {
            crate::serial_force_println!(
                "[trace][spin] drop begin lock={:#x} owner_cpu={} saved_flags={:#x}",
                lock_addr,
                self.lock.owner_cpu.load(Ordering::Relaxed),
                self.state.saved_flags,
            );
        }

        self.lock.owner_cpu.store(usize::MAX, Ordering::Relaxed);
        self.lock.locked.store(false, Ordering::Release);

        if trace {
            crate::serial_force_println!("[trace][spin] drop unlocked lock={:#x}", lock_addr);
        }

        // SAFETY: `state` is valid and initialised. We move it out of its
        // ManuallyDrop wrapper so that G::exit() can consume it. The compiler
        // will NOT run a second destructor on the field because ManuallyDrop
        // suppresses automatic drops.
        let state = unsafe { ManuallyDrop::take(&mut self.state) };
        G::exit(state);

        if trace {
            crate::serial_force_println!(
                "[trace][spin] drop guardian-exit done lock={:#x}",
                lock_addr
            );
        }
    }
}

// The guardian's invariant (e.g. preemption depth, IF flag) is per-CPU.
// Sending the guard to another CPU would violate it.
impl<T: ?Sized, G: Guardian> !Send for SpinLockGuard<'_, T, G> {}
