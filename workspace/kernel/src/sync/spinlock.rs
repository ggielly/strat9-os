// Spinlock implementation for kernel synchronization

use super::IrqDisabledToken;
use core::{
    cell::UnsafeCell,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

static DEBUG_WATCH_LOCK_ADDR: AtomicUsize = AtomicUsize::new(usize::MAX);

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
        // SAFETY: `save_flags_and_cli()` has just disabled interrupts on this CPU.
        let irq_token = unsafe { IrqDisabledToken::new_unchecked() };
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
            restore_flags_on_drop: true,
            irq_token,
        }
    }

    /// Try to acquire the lock without spinning.
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        let saved_flags = crate::arch::x86_64::save_flags_and_cli();
        // SAFETY: `save_flags_and_cli()` has just disabled interrupts on this CPU.
        let irq_token = unsafe { IrqDisabledToken::new_unchecked() };
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
                restore_flags_on_drop: true,
                irq_token,
            })
        } else {
            crate::arch::x86_64::restore_flags(saved_flags);
            None
        }
    }

    /// Try to acquire the lock without touching interrupt flags.
    ///
    /// Caller must enforce IRQ/preemption constraints.
    pub fn try_lock_no_irqsave(&self) -> Option<SpinLockGuard<'_, T>> {
        let irq_token = IrqDisabledToken::verify()?;
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            self.owner_cpu
                .store(crate::arch::x86_64::percpu::current_cpu_index(), Ordering::Relaxed);
            Some(SpinLockGuard {
                lock: self,
                saved_flags: 0,
                restore_flags_on_drop: false,
                irq_token,
            })
        } else {
            None
        }
    }

    /// Returns the owner CPU index for deadlock tracing (`usize::MAX` if unlocked).
    pub fn owner_cpu(&self) -> usize {
        self.owner_cpu.load(Ordering::Relaxed)
    }
}

/// Set a lock address to trace during `SpinLockGuard::drop`.
pub fn debug_set_watch_lock_addr(addr: usize) {
    DEBUG_WATCH_LOCK_ADDR.store(addr, Ordering::Relaxed);
}

/// Clear the watched lock address.
pub fn debug_clear_watch_lock_addr() {
    DEBUG_WATCH_LOCK_ADDR.store(usize::MAX, Ordering::Relaxed);
}

/// RAII guard for SpinLock
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
    saved_flags: u64,
    restore_flags_on_drop: bool,
    irq_token: IrqDisabledToken,
}

impl<'a, T> SpinLockGuard<'a, T> {
    /// Retourne la preuve typée que les interruptions sont désactivées.
    #[inline]
    pub fn token(&self) -> &IrqDisabledToken {
        &self.irq_token
    }

    #[inline]
    pub(crate) fn with_mut_and_token<R>(
        &mut self,
        f: impl FnOnce(&mut T, &IrqDisabledToken) -> R,
    ) -> R {
        let token = &self.irq_token;
        // SAFETY: ce guard possède le verrou et protège l'accès exclusif à `data`.
        let data = unsafe { &mut *self.lock.data.get() };
        f(data, token)
    }
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
        let lock_addr = self.lock as *const _ as usize;
        let watched = DEBUG_WATCH_LOCK_ADDR.load(Ordering::Relaxed);
        let trace = watched == lock_addr;
        if trace {
            crate::serial_force_println!(
                "[trace][spin] drop begin lock={:#x} owner_cpu={} saved_flags={:#x}",
                lock_addr,
                self.lock.owner_cpu.load(Ordering::Relaxed),
                self.saved_flags
            );
        }
        // Release the lock
        self.lock.owner_cpu.store(usize::MAX, Ordering::Relaxed);
        self.lock.locked.store(false, Ordering::Release);
        if trace {
            crate::serial_force_println!("[trace][spin] drop unlocked lock={:#x}", lock_addr);
            crate::serial_force_println!(
                "[trace][spin] drop restore_flags begin lock={:#x}",
                lock_addr
            );
        }
        if self.restore_flags_on_drop {
            crate::arch::x86_64::restore_flags(self.saved_flags);
            if trace {
                crate::serial_force_println!(
                    "[trace][spin] drop restore_flags done lock={:#x}",
                    lock_addr
                );
            }
        } else if trace {
            crate::serial_force_println!(
                "[trace][spin] drop restore_flags skipped lock={:#x}",
                lock_addr
            );
        }
    }
}
