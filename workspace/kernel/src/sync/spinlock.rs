// Spinlock implementation for kernel synchronization

use core::{
    cell::UnsafeCell,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

/// A simple spinlock
pub struct SpinLock<T> {
    locked: AtomicBool,
    owner_cpu: AtomicUsize,
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
            owner_cpu: AtomicUsize::new(usize::MAX),
            data: UnsafeCell::new(data),
        }
    }

    /// Acquire the lock, spinning until it's available
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        let saved_flags = crate::arch::x86_64::save_flags_and_cli();
        let mut spins: usize = 0;
        let this_cpu = crate::arch::x86_64::percpu::current_cpu_index();
        // Spin until we can set locked from false to true
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
                    self as *const _ as usize,
                    this_cpu,
                    owner
                );
                spins = 0;
            }
            // Hint to CPU that we're spinning
            core::hint::spin_loop();
        }
        self.owner_cpu.store(this_cpu, Ordering::Relaxed);

        SpinLockGuard {
            lock: self,
            saved_flags,
        }
    }

    /// Try to acquire the lock without spinning.
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        let saved_flags = crate::arch::x86_64::save_flags_and_cli();
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            self.owner_cpu
                .store(crate::arch::x86_64::percpu::current_cpu_index(), Ordering::Relaxed);
            Some(SpinLockGuard {
                lock: self,
                saved_flags,
            })
        } else {
            crate::arch::x86_64::restore_flags(saved_flags);
            None
        }
    }

    /// Returns the owner CPU index for deadlock tracing (`usize::MAX` if unlocked).
    pub fn owner_cpu(&self) -> usize {
        self.owner_cpu.load(Ordering::Relaxed)
    }
}

/// RAII guard for SpinLock
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
    saved_flags: u64,
}

impl<'a, T> Deref for SpinLockGuard<'a, T> {
    type Target = T;

    /// Performs the deref operation.
    fn deref(&self) -> &T {
        // SAFETY: We hold the lock, so exclusive access is guaranteed
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> DerefMut for SpinLockGuard<'a, T> {
    /// Performs the deref mut operation.
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: We hold the lock, so exclusive access is guaranteed
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> Drop for SpinLockGuard<'a, T> {
    /// Performs the drop operation.
    fn drop(&mut self) {
        // Release the lock
        self.lock.owner_cpu.store(usize::MAX, Ordering::Relaxed);
        self.lock.locked.store(false, Ordering::Release);
        crate::arch::x86_64::restore_flags(self.saved_flags);
    }
}
