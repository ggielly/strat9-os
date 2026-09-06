//! Generation barrier: counter + phase packed in one atomic word.

use super::futex_wake_all;
use core::sync::atomic::{AtomicU32, Ordering};

/// Cyclic barrier for `total` participants.
///
/// `wait()` blocks until all participants arrived, then releases everyone for
/// the next round. The last arrival is reported via the return value (`true`).
pub struct Barrier {
    total: u32,
    /// Low 16 bits: arrivals in current phase. High 16 bits: phase.
    state: AtomicU32,
}

impl Barrier {
    /// Creates a barrier for `total` participants (1..=65535).
    pub fn new(total: u32) -> Self {
        debug_assert!(total >= 1 && total <= u16::MAX as u32);
        Barrier {
            total,
            state: AtomicU32::new(0),
        }
    }

    /// Arrive and wait. Returns `true` for exactly one thread per round.
    pub fn wait(&self) -> bool {
        loop {
            let s = self.state.load(Ordering::Acquire);
            let phase = s >> 16;
            let count = s & 0xFFFF;
            if count + 1 < self.total {
                if self
                    .state
                    .compare_exchange(s, s + 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    // Spin until the phase flips (v1 policy: bounded spin then
                    // futex on the same word — value change wakes us).
                    loop {
                        let cur = self.state.load(Ordering::Acquire);
                        if cur >> 16 != phase {
                            return false;
                        }
                        super::futex_wait(&self.state, cur);
                        core::hint::spin_loop();
                    }
                }
                continue;
            }
            if self
                .state
                .compare_exchange(
                    s,
                    (phase.wrapping_add(1)) << 16,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                futex_wake_all(&self.state);
                return true;
            }
        }
    }
}
