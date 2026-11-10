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

//! s9vm — pure timing and exit-latency measurement.
//!
//! This module performs **no hardware access**: every sample is supplied by
//! the caller (time-stamp counter cycles, nanoseconds, or any other monotonic
//! unit) and all computations are integer arithmetic. It can therefore be
//! compiled and exercised on the host.
//!
//! # Units
//!
//! Samples are opaque `u64` values. A histogram never converts units: the
//! caller decides whether it records cycles or nanoseconds and must keep the
//! same unit for every sample recorded in a given histogram. Reporting code is
//! responsible for the conversion and for remembering the time-stamp counter
//! frequency.
//!
//! # Contents
//!
//! | Type | Role | Memory |
//! |---|---|---|
//! | [`ExitLatencyHistogram`] | fixed 32-bucket log histogram | ~280 bytes |
//! | [`ExitRateMeter`] | total / sliding window / peak counter | ~100 bytes |
//! | [`WorldTiming`] | per-exit-class aggregation of both | ~9 KiB |
//!
//! All counters saturate: a long-running measurement degrades into an
//! imprecise value instead of wrapping or panicking.

use super::exit::{ExitClass, ExitReason};

// --- Constants -------------------------------------------------------------

/// Number of latency buckets in an [`ExitLatencyHistogram`].
///
/// Buckets are logarithmic: bucket 0 holds a sample of zero, bucket `k >= 1`
/// holds the samples in `[2^(k-1), 2^k)`. The last bucket is open-ended so
/// that any `u64` sample has a home.
pub const EXIT_LATENCY_BUCKETS: usize = 32;

/// Number of slots of an [`ExitRateMeter`] sliding window.
pub const EXIT_RATE_WINDOW: usize = 8;

/// Number of [`ExitClass`] variants aggregated by [`WorldTiming`].
pub const EXIT_CLASS_COUNT: usize = 23;

/// Empty histogram, used to initialize the per-class array.
const EMPTY_HISTOGRAM: ExitLatencyHistogram = ExitLatencyHistogram::new();

/// Empty rate meter, used to initialize the per-class array.
const EMPTY_RATE_METER: ExitRateMeter = ExitRateMeter::new();

// --- Latency histogram -----------------------------------------------------

/// Fixed-memory histogram of exit latencies.
///
/// The histogram keeps enough state to report the count, minimum, maximum,
/// mean and a conservative percentile without storing the samples. This is
/// what a hot path can afford: one comparison chain and a few integer
/// operations per exit, no allocation and no lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitLatencyHistogram {
    /// Number of samples per bucket.
    buckets: [u64; EXIT_LATENCY_BUCKETS],
    /// Total number of samples.
    count: u64,
    /// Saturating sum of every sample (used by [`Self::mean`]).
    sum: u64,
    /// Smallest sample, `u64::MAX` while the histogram is empty.
    min: u64,
    /// Largest sample, 0 while the histogram is empty.
    max: u64,
}

impl Default for ExitLatencyHistogram {
    fn default() -> Self {
        Self::new()
    }
}

impl ExitLatencyHistogram {
    /// Creates an empty histogram.
    pub const fn new() -> Self {
        Self {
            buckets: [0; EXIT_LATENCY_BUCKETS],
            count: 0,
            sum: 0,
            min: u64::MAX,
            max: 0,
        }
    }

    /// Returns the bucket index for `sample`.
    ///
    /// * `0` maps to bucket 0;
    /// * `1` maps to bucket 1, `2..=3` to bucket 2, `4..=7` to bucket 3, and
    ///   so on (`2^(k-1) .. 2^k` maps to bucket `k`);
    /// * every sample that would fall beyond the last bucket is clamped into
    ///   it, so this function never returns a value `>= EXIT_LATENCY_BUCKETS`.
    pub const fn bucket_for(sample: u64) -> usize {
        if sample == 0 {
            return 0;
        }
        // Position of the most significant bit: 0 for 1, 1 for 2..=3, ...
        let exponent = 63 - sample.leading_zeros() as usize;
        let index = exponent + 1;
        if index >= EXIT_LATENCY_BUCKETS {
            EXIT_LATENCY_BUCKETS - 1
        } else {
            index
        }
    }

    /// Lower bound (inclusive) of `index`, or `u64::MAX` for an invalid index.
    ///
    /// Bucket 0 has a lower bound of 0; bucket `k >= 1` starts at `2^(k-1)`.
    /// The last bucket starts at `2^(EXIT_LATENCY_BUCKETS - 2)` and is
    /// open-ended.
    pub const fn bucket_lower_bound(index: usize) -> u64 {
        if index == 0 {
            0
        } else if index < EXIT_LATENCY_BUCKETS {
            1u64 << (index - 1)
        } else {
            u64::MAX
        }
    }

    /// Upper bound (exclusive) of `index` as an integer, or `u64::MAX` for an
    /// invalid index.
    ///
    /// Bucket 0 holds only 0, so its upper bound is 1. The last bucket is
    /// open-ended (it also absorbs every sample that would fall beyond it),
    /// so its reported upper bound is `u64::MAX`.
    pub const fn bucket_upper_bound(index: usize) -> u64 {
        if index == 0 {
            1
        } else if index < EXIT_LATENCY_BUCKETS - 1 {
            1u64 << index
        } else {
            u64::MAX
        }
    }

    /// Records one sample.
    ///
    /// The bucket population, the count and the sum saturate; the minimum and
    /// the maximum are exact.
    pub fn record(&mut self, sample: u64) {
        let bucket = Self::bucket_for(sample);
        if let Some(population) = self.buckets.get_mut(bucket) {
            *population = population.saturating_add(1);
        }
        self.count = self.count.saturating_add(1);
        self.sum = self.sum.saturating_add(sample);
        if sample < self.min {
            self.min = sample;
        }
        if sample > self.max {
            self.max = sample;
        }
    }

    /// Number of recorded samples.
    pub const fn count(&self) -> u64 {
        self.count
    }

    /// Total (saturating) sum of the recorded samples.
    pub const fn sum(&self) -> u64 {
        self.sum
    }

    /// Smallest recorded sample, or `None` if the histogram is empty.
    pub const fn min(&self) -> Option<u64> {
        if self.count == 0 {
            None
        } else {
            Some(self.min)
        }
    }

    /// Largest recorded sample, or `None` if the histogram is empty.
    pub const fn max(&self) -> Option<u64> {
        if self.count == 0 {
            None
        } else {
            Some(self.max)
        }
    }

    /// Integer mean of the recorded samples, or `None` if the histogram is
    /// empty.
    ///
    /// The division truncates towards zero. If the sum saturated, the mean is
    /// a lower bound of the true mean (documented, never a panic).
    pub const fn mean(&self) -> Option<u64> {
        if self.count == 0 {
            None
        } else {
            Some(self.sum / self.count)
        }
    }

    /// Population of `index`, or 0 for an invalid index.
    pub fn bucket_count(&self, index: usize) -> u64 {
        self.buckets.get(index).copied().unwrap_or(0)
    }

    /// Conservative percentile of the distribution.
    ///
    /// `p` is clamped to `0..=100`. The returned value is the **upper bound of
    /// the bucket that contains the nearest-rank sample**, not an exact
    /// sample: it is therefore always greater than or equal to the exact
    /// percentile, and it is expressed in the same unit as the samples. This
    /// keeps the histogram allocation-free; a caller that needs exact
    /// percentiles must keep the raw samples elsewhere.
    ///
    /// `p = 0` returns the upper bound of the first non-empty bucket (the
    /// lowest latency bucket in use), never a panic. An empty histogram
    /// returns `None`.
    pub fn percentile(&self, p: u8) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        let clamped = if p > 100 { 100 } else { p } as u64;
        let scaled = clamped.saturating_mul(self.count);
        let mut rank = scaled / 100;
        if scaled % 100 != 0 || rank == 0 {
            rank = rank.saturating_add(1);
        }
        let mut cumulative = 0u64;
        for (index, population) in self.buckets.iter().enumerate() {
            cumulative = cumulative.saturating_add(*population);
            if cumulative >= rank {
                return Some(Self::bucket_upper_bound(index));
            }
        }
        // Defensive fallback: the population sums to `count`, so the loop
        // always returns. Never reached in practice.
        self.max()
    }

    /// Resets the histogram to its initial (empty) state.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

// --- Exit rate meter -------------------------------------------------------

/// Sliding-window counter for exit rates.
///
/// The meter owns a small ring of slots. [`record`](Self::record) increments
/// both the running total and the current slot; the caller calls
/// [`advance_window`](Self::advance_window) when a time slice ends, which
/// closes the current slot, reuses the oldest one, and keeps
/// [`window`](Self::window) equal to the number of records in the last
/// `EXIT_RATE_WINDOW` slices. The meter has no notion of time: the caller
/// decides the slice duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitRateMeter {
    /// Total number of records since creation or last reset.
    total: u64,
    /// Records per sliding-window slot.
    slots: [u64; EXIT_RATE_WINDOW],
    /// Slot written by the next [`record`](Self::record).
    cursor: usize,
    /// Sum of the slots (saturating).
    window: u64,
    /// Highest value ever observed for `window`.
    peak: u64,
}

impl Default for ExitRateMeter {
    fn default() -> Self {
        Self::new()
    }
}

impl ExitRateMeter {
    /// Creates an empty rate meter.
    pub const fn new() -> Self {
        Self {
            total: 0,
            slots: [0; EXIT_RATE_WINDOW],
            cursor: 0,
            window: 0,
            peak: 0,
        }
    }

    /// Records one event in the current slot.
    pub fn record(&mut self) {
        self.total = self.total.saturating_add(1);
        self.window = self.window.saturating_add(1);
        if let Some(slot) = self.slots.get_mut(self.cursor) {
            *slot = slot.saturating_add(1);
        }
        if self.window > self.peak {
            self.peak = self.window;
        }
    }

    /// Closes the current slot and opens the next one.
    ///
    /// The oldest slot is subtracted from the sliding window before being
    /// reused. Arithmetic is saturating so that a corrupted state can never
    /// panic.
    pub fn advance_window(&mut self) {
        let next = (self.cursor + 1) % EXIT_RATE_WINDOW;
        self.cursor = next;
        let expired = self.slots.get(next).copied().unwrap_or(0);
        if let Some(slot) = self.slots.get_mut(next) {
            *slot = 0;
        }
        self.window = self.window.saturating_sub(expired);
    }

    /// Total number of records since creation or last reset.
    pub const fn total(&self) -> u64 {
        self.total
    }

    /// Number of records in the last `EXIT_RATE_WINDOW` slots.
    pub const fn window(&self) -> u64 {
        self.window
    }

    /// Highest value ever observed for [`window`](Self::window).
    pub const fn peak_window(&self) -> u64 {
        self.peak
    }

    /// Population of one slot, or 0 for an invalid index. Mostly useful for
    /// diagnostics and tests.
    pub fn slot_count(&self, index: usize) -> u64 {
        self.slots.get(index).copied().unwrap_or(0)
    }

    /// Resets the meter to its initial (empty) state.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

// --- Per-world aggregation -------------------------------------------------

/// Timing aggregate of one virtual machine, split by exit class.
///
/// The engine records one sample per hardware exit, in whatever unit the
/// caller uses. Per-class histograms keep the measurement cost independent of
/// the class while still exposing which class dominates. A global rate meter
/// tracks the total exit rate; per-class meters track each class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorldTiming {
    /// Latency histogram per exit class.
    latency: [ExitLatencyHistogram; EXIT_CLASS_COUNT],
    /// Rate meter per exit class.
    rates: [ExitRateMeter; EXIT_CLASS_COUNT],
    /// Rate meter across every class.
    total_rate: ExitRateMeter,
}

impl Default for WorldTiming {
    fn default() -> Self {
        Self::new()
    }
}

impl WorldTiming {
    /// Creates an empty aggregate.
    pub const fn new() -> Self {
        Self {
            latency: [EMPTY_HISTOGRAM; EXIT_CLASS_COUNT],
            rates: [EMPTY_RATE_METER; EXIT_CLASS_COUNT],
            total_rate: ExitRateMeter::new(),
        }
    }

    /// Number of aggregated exit classes.
    pub const fn class_count() -> usize {
        EXIT_CLASS_COUNT
    }

    /// Stable dense index of an exit class, in the declaration order of
    /// [`ExitClass`].
    ///
    /// The mapping is exhaustive: adding a variant to [`ExitClass`] without
    /// updating this function is a compile error.
    pub const fn class_index(class: ExitClass) -> usize {
        match class {
            ExitClass::ExceptionOrNmi => 0,
            ExitClass::ExternalInterrupt => 1,
            ExitClass::TripleFault => 2,
            ExitClass::InterruptWindow => 3,
            ExitClass::Cpuid => 4,
            ExitClass::Halt => 5,
            ExitClass::Pause => 6,
            ExitClass::IoPort => 7,
            ExitClass::ControlRegister => 8,
            ExitClass::DebugRegister => 9,
            ExitClass::Msr => 10,
            ExitClass::MonitorWait => 11,
            ExitClass::Apic => 12,
            ExitClass::EptViolation => 13,
            ExitClass::EptMisconfiguration => 14,
            ExitClass::PreemptionTimer => 15,
            ExitClass::Call => 16,
            ExitClass::ExtendedState => 17,
            ExitClass::Tlb => 18,
            ExitClass::Timestamp => 19,
            ExitClass::Cache => 20,
            ExitClass::EntryFailure => 21,
            ExitClass::Unknown => 22,
        }
    }

    /// Inverse of [`class_index`](Self::class_index), or `None` if `index` is
    /// out of range. Useful to walk the aggregates in a report.
    pub const fn class_at(index: usize) -> Option<ExitClass> {
        match index {
            0 => Some(ExitClass::ExceptionOrNmi),
            1 => Some(ExitClass::ExternalInterrupt),
            2 => Some(ExitClass::TripleFault),
            3 => Some(ExitClass::InterruptWindow),
            4 => Some(ExitClass::Cpuid),
            5 => Some(ExitClass::Halt),
            6 => Some(ExitClass::Pause),
            7 => Some(ExitClass::IoPort),
            8 => Some(ExitClass::ControlRegister),
            9 => Some(ExitClass::DebugRegister),
            10 => Some(ExitClass::Msr),
            11 => Some(ExitClass::MonitorWait),
            12 => Some(ExitClass::Apic),
            13 => Some(ExitClass::EptViolation),
            14 => Some(ExitClass::EptMisconfiguration),
            15 => Some(ExitClass::PreemptionTimer),
            16 => Some(ExitClass::Call),
            17 => Some(ExitClass::ExtendedState),
            18 => Some(ExitClass::Tlb),
            19 => Some(ExitClass::Timestamp),
            20 => Some(ExitClass::Cache),
            21 => Some(ExitClass::EntryFailure),
            22 => Some(ExitClass::Unknown),
            _ => None,
        }
    }

    /// Records one sample for `class`.
    pub fn record(&mut self, class: ExitClass, sample: u64) {
        let index = Self::class_index(class);
        self.latency[index].record(sample);
        self.rates[index].record();
        self.total_rate.record();
    }

    /// Records one decoded exit with its measured latency.
    ///
    /// Convenience wrapper over [`record`](Self::record) that applies the
    /// classification of [`ExitReason`], including the guest-entry-failure
    /// bit.
    pub fn record_exit(&mut self, exit: ExitReason, sample: u64) {
        self.record(exit.class(), sample);
    }

    /// Latency histogram of `class`.
    pub fn latency(&self, class: ExitClass) -> &ExitLatencyHistogram {
        &self.latency[Self::class_index(class)]
    }

    /// Rate meter of `class`.
    pub fn rate(&self, class: ExitClass) -> &ExitRateMeter {
        &self.rates[Self::class_index(class)]
    }

    /// Rate meter across every class.
    pub const fn total_rate(&self) -> &ExitRateMeter {
        &self.total_rate
    }

    /// Advances the sliding window of every rate meter.
    ///
    /// Callers should call this once per measurement slice, after the slice's
    /// exits have been recorded.
    pub fn advance_window(&mut self) {
        for rate in &mut self.rates {
            rate.advance_window();
        }
        self.total_rate.advance_window();
    }

    /// Resets every aggregate.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}
