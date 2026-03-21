//! Lightweight TSC-based performance counters for critical kernel paths.
//!
//! Each counter pair tracks total TSC cycles spent + call count.
//! Use `PerfScope` (RAII) to instrument a section without touching the
//! hot path more than two `rdtsc` calls + two relaxed atomic adds.

use core::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

/// Timer IRQ handler (`timer_tick`).
pub static IRQ_TIMER_COUNT: AtomicU64 = AtomicU64::new(0);
pub static IRQ_TIMER_TSC: AtomicU64 = AtomicU64::new(0);

/// Scheduler lock acquisition in `yield_task`.
pub static SCHED_YIELD_COUNT: AtomicU64 = AtomicU64::new(0);
pub static SCHED_YIELD_TSC: AtomicU64 = AtomicU64::new(0);

/// Preemption path (`maybe_preempt`).
pub static SCHED_PREEMPT_COUNT: AtomicU64 = AtomicU64::new(0);
pub static SCHED_PREEMPT_TSC: AtomicU64 = AtomicU64::new(0);

/// Post-switch fixup (`finish_interrupt_switch`).
pub static CTX_SWITCH_COUNT: AtomicU64 = AtomicU64::new(0);
pub static CTX_SWITCH_TSC: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// RAII scope helper
// ---------------------------------------------------------------------------

/// Measures elapsed TSC cycles between construction and drop, accumulating
/// into the given counter pair.
///
/// Usage:
/// ```ignore
/// let _perf = PerfScope::new(&IRQ_TIMER_TSC, &IRQ_TIMER_COUNT);
/// // ... measured code ...
/// // counters updated on drop
/// ```
pub struct PerfScope {
    start: u64,
    accumulator: &'static AtomicU64,
    counter: &'static AtomicU64,
}

impl PerfScope {
    #[inline]
    pub fn new(accumulator: &'static AtomicU64, counter: &'static AtomicU64) -> Self {
        Self {
            start: crate::arch::x86_64::rdtsc(),
            accumulator,
            counter,
        }
    }
}

impl Drop for PerfScope {
    #[inline]
    fn drop(&mut self) {
        let elapsed = crate::arch::x86_64::rdtsc().wrapping_sub(self.start);
        self.accumulator.fetch_add(elapsed, Ordering::Relaxed);
        self.counter.fetch_add(1, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Snapshot for display
// ---------------------------------------------------------------------------

/// Summary of one counter pair, ready for display.
pub struct PerfStat {
    pub name: &'static str,
    pub count: u64,
    pub total_tsc: u64,
}

impl PerfStat {
    /// Average in microseconds (requires TSC_KHZ).
    pub fn avg_us(&self, tsc_khz: u64) -> u64 {
        if self.count == 0 || tsc_khz == 0 {
            return 0;
        }
        // avg_tsc = total_tsc / count
        // avg_us  = avg_tsc * 1000 / tsc_khz
        (self.total_tsc / self.count).saturating_mul(1_000) / tsc_khz
    }
}

/// Return a snapshot of all perf counters.
pub fn snapshot() -> [PerfStat; 4] {
    [
        PerfStat {
            name: "irq_timer",
            count: IRQ_TIMER_COUNT.load(Ordering::Relaxed),
            total_tsc: IRQ_TIMER_TSC.load(Ordering::Relaxed),
        },
        PerfStat {
            name: "sched_yield",
            count: SCHED_YIELD_COUNT.load(Ordering::Relaxed),
            total_tsc: SCHED_YIELD_TSC.load(Ordering::Relaxed),
        },
        PerfStat {
            name: "preempt",
            count: SCHED_PREEMPT_COUNT.load(Ordering::Relaxed),
            total_tsc: SCHED_PREEMPT_TSC.load(Ordering::Relaxed),
        },
        PerfStat {
            name: "ctx_switch",
            count: CTX_SWITCH_COUNT.load(Ordering::Relaxed),
            total_tsc: CTX_SWITCH_TSC.load(Ordering::Relaxed),
        },
    ]
}
