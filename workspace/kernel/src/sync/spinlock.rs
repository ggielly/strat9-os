// Spinlock implementation for kernel synchronization

use core::{
    cell::UnsafeCell,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicBool, Ordering},
};

/// A simple spinlock
pub struct SpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: SpinLock can be safely shared between threads
// because it uses atomic operations for synchronization
unsafe impl<T: Send> Sync for SpinLock<T> {}
unsafe impl<T: Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// Create a new unlocked spinlock
    pub const fn new(data: T) -> Self {
        SpinLock {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    /// Acquire the lock, spinning until it's available
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        let saved_flags = crate::arch::x86_64::save_flags_and_cli();
        // Spin until we can set locked from false to true
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Hint to CPU that we're spinning
            core::hint::spin_loop();
        }

        SpinLockGuard { lock: self, saved_flags }
    }

    /// Try to acquire the lock without spinning.
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        let saved_flags = crate::arch::x86_64::save_flags_and_cli();
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(SpinLockGuard { lock: self, saved_flags })
        } else {
            crate::arch::x86_64::restore_flags(saved_flags);
            None
        }
    }
}

/// RAII guard for SpinLock
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
    saved_flags: u64,
}

impl<'a, T> Deref for SpinLockGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: We hold the lock, so exclusive access is guaranteed
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> DerefMut for SpinLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: We hold the lock, so exclusive access is guaranteed
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> Drop for SpinLockGuard<'a, T> {
    fn drop(&mut self) {
        // Release the lock
        self.lock.locked.store(false, Ordering::Release);
        crate::arch::x86_64::restore_flags(self.saved_flags);
    }
}
