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

//! L2: s9vm timing aggregates (real kernel code).
//!
//! The module under test is pure: it never touches hardware, so the same
//! source file is compiled verbatim here and exercised with host tests.

#[path = "../../kernel/src/s9vm/exit.rs"]
mod exit;
#[path = "../../kernel/src/s9vm/timing.rs"]
mod timing;

use exit::{ExitClass, ExitReason, CPUID, IO_INSTRUCTION};
use timing::{
    ExitLatencyHistogram, ExitRateMeter, WorldTiming, EXIT_CLASS_COUNT, EXIT_LATENCY_BUCKETS,
    EXIT_RATE_WINDOW,
};

#[test]
fn histogram_starts_empty() {
    let histogram = ExitLatencyHistogram::new();
    assert_eq!(histogram.count(), 0);
    assert_eq!(histogram.sum(), 0);
    assert_eq!(histogram.min(), None);
    assert_eq!(histogram.max(), None);
    assert_eq!(histogram.mean(), None);
    assert_eq!(histogram.percentile(50), None);
}

#[test]
fn bucket_mapping_boundaries() {
    assert_eq!(ExitLatencyHistogram::bucket_for(0), 0);
    assert_eq!(ExitLatencyHistogram::bucket_for(1), 1);
    assert_eq!(ExitLatencyHistogram::bucket_for(2), 2);
    assert_eq!(ExitLatencyHistogram::bucket_for(3), 2);
    assert_eq!(ExitLatencyHistogram::bucket_for(4), 3);
    assert_eq!(ExitLatencyHistogram::bucket_for(7), 3);
    assert_eq!(ExitLatencyHistogram::bucket_for(8), 4);
    assert_eq!(ExitLatencyHistogram::bucket_for(1024), 11);
    assert_eq!(
        ExitLatencyHistogram::bucket_for(1 << 30),
        EXIT_LATENCY_BUCKETS - 1
    );
    assert_eq!(
        ExitLatencyHistogram::bucket_for(u64::MAX),
        EXIT_LATENCY_BUCKETS - 1
    );
}

#[test]
fn bucket_bounds_are_contiguous() {
    for index in 0..EXIT_LATENCY_BUCKETS - 1 {
        let lower = ExitLatencyHistogram::bucket_lower_bound(index);
        let upper = ExitLatencyHistogram::bucket_upper_bound(index);
        assert!(lower < upper, "bucket {}: {} >= {}", index, lower, upper);
        assert_eq!(
            upper,
            ExitLatencyHistogram::bucket_lower_bound(index + 1),
            "bucket {} upper bound must equal bucket {} lower bound",
            index,
            index + 1
        );
    }
    assert_eq!(
        ExitLatencyHistogram::bucket_upper_bound(EXIT_LATENCY_BUCKETS - 1),
        u64::MAX
    );
    assert_eq!(
        ExitLatencyHistogram::bucket_upper_bound(EXIT_LATENCY_BUCKETS),
        u64::MAX
    );
    assert_eq!(
        ExitLatencyHistogram::bucket_lower_bound(EXIT_LATENCY_BUCKETS),
        u64::MAX
    );
}

#[test]
fn record_updates_summary() {
    let mut histogram = ExitLatencyHistogram::new();
    for sample in [10u64, 20, 30] {
        histogram.record(sample);
    }
    assert_eq!(histogram.count(), 3);
    assert_eq!(histogram.sum(), 60);
    assert_eq!(histogram.min(), Some(10));
    assert_eq!(histogram.max(), Some(30));
    assert_eq!(histogram.mean(), Some(20));
}

#[test]
fn mean_truncates_towards_zero() {
    let mut histogram = ExitLatencyHistogram::new();
    histogram.record(1);
    histogram.record(2);
    assert_eq!(histogram.mean(), Some(1));
}

#[test]
fn percentile_is_nearest_rank_upper_bound() {
    let mut histogram = ExitLatencyHistogram::new();
    for sample in [8u64, 16, 32, 64] {
        histogram.record(sample);
    }
    // 0 -> bucket 4 upper bound 16; 25 -> rank 1 -> 16; 50 -> rank 2 -> 32;
    // 75 -> rank 3 -> 64; 100 -> rank 4 -> last used bucket 7, upper bound 128.
    assert_eq!(histogram.percentile(0), Some(16));
    assert_eq!(histogram.percentile(25), Some(16));
    assert_eq!(histogram.percentile(50), Some(32));
    assert_eq!(histogram.percentile(75), Some(64));
    assert_eq!(histogram.percentile(100), Some(128));
}

#[test]
fn percentile_clamps_out_of_range_values() {
    let mut histogram = ExitLatencyHistogram::new();
    for sample in [8u64, 16, 32, 64] {
        histogram.record(sample);
    }
    assert_eq!(histogram.percentile(100), histogram.percentile(255));
}

#[test]
fn percentile_zero_never_returns_a_missing_bucket() {
    let mut histogram = ExitLatencyHistogram::new();
    histogram.record(0);
    // Sample 0 lives in bucket 0, whose documented upper bound is 1.
    assert_eq!(histogram.percentile(0), Some(1));
}

#[test]
fn reset_clears_histogram() {
    let mut histogram = ExitLatencyHistogram::new();
    histogram.record(1234);
    histogram.record(5678);
    histogram.reset();
    assert_eq!(histogram.count(), 0);
    assert_eq!(histogram.sum(), 0);
    assert_eq!(histogram.min(), None);
    assert_eq!(histogram.max(), None);
    assert_eq!(histogram.mean(), None);
    assert_eq!(
        histogram.bucket_count(ExitLatencyHistogram::bucket_for(1234)),
        0
    );
}

#[test]
fn sum_saturates_without_panic() {
    let mut histogram = ExitLatencyHistogram::new();
    histogram.record(u64::MAX);
    histogram.record(u64::MAX);
    assert_eq!(histogram.count(), 2);
    assert_eq!(histogram.sum(), u64::MAX);
    assert_eq!(histogram.mean(), Some(u64::MAX / 2));
    assert_eq!(histogram.max(), Some(u64::MAX));
}

#[test]
fn bucket_population_matches_total_count() {
    let mut histogram = ExitLatencyHistogram::new();
    for sample in [0u64, 1, 2, 3, 4, 1024, u64::MAX] {
        histogram.record(sample);
    }
    let population: u64 = (0..EXIT_LATENCY_BUCKETS)
        .map(|index| histogram.bucket_count(index))
        .sum();
    assert_eq!(population, histogram.count());
    assert_eq!(histogram.bucket_count(0), 1);
    assert_eq!(histogram.bucket_count(EXIT_LATENCY_BUCKETS - 1), 1);
}

#[test]
fn rate_meter_counts_total_and_window() {
    let mut meter = ExitRateMeter::new();
    for _ in 0..3 {
        meter.record();
    }
    assert_eq!(meter.total(), 3);
    assert_eq!(meter.window(), 3);
    assert_eq!(meter.peak_window(), 3);
}

#[test]
fn rate_meter_slides_window() {
    let mut meter = ExitRateMeter::new();
    for _ in 0..EXIT_RATE_WINDOW {
        meter.record();
        meter.advance_window();
    }
    // The window reached 8 records before the first slot expired; after the
    // last advance the oldest slot is empty, so 7 records remain visible.
    assert_eq!(meter.total(), EXIT_RATE_WINDOW as u64);
    assert_eq!(meter.window(), (EXIT_RATE_WINDOW - 1) as u64);
    assert_eq!(meter.peak_window(), EXIT_RATE_WINDOW as u64);
    meter.advance_window();
    assert_eq!(meter.window(), (EXIT_RATE_WINDOW - 2) as u64);
}

#[test]
fn rate_meter_reset_clears_state() {
    let mut meter = ExitRateMeter::new();
    meter.record();
    meter.record();
    meter.advance_window();
    meter.reset();
    assert_eq!(meter.total(), 0);
    assert_eq!(meter.window(), 0);
    assert_eq!(meter.peak_window(), 0);
    assert_eq!(meter.slot_count(0), 0);
}

#[test]
fn world_timing_aggregates_per_class() {
    let mut timing = WorldTiming::new();
    timing.record(ExitClass::IoPort, 100);
    timing.record(ExitClass::IoPort, 300);
    timing.record(ExitClass::Cpuid, 50);

    assert_eq!(timing.latency(ExitClass::IoPort).count(), 2);
    assert_eq!(timing.latency(ExitClass::IoPort).min(), Some(100));
    assert_eq!(timing.latency(ExitClass::IoPort).max(), Some(300));
    assert_eq!(timing.latency(ExitClass::IoPort).mean(), Some(200));
    assert_eq!(timing.latency(ExitClass::Cpuid).count(), 1);
    assert_eq!(timing.latency(ExitClass::Halt).count(), 0);

    assert_eq!(timing.rate(ExitClass::IoPort).window(), 2);
    assert_eq!(timing.rate(ExitClass::Cpuid).window(), 1);
    assert_eq!(timing.total_rate().window(), 3);
}

#[test]
fn world_timing_class_index_round_trip() {
    assert_eq!(WorldTiming::class_count(), EXIT_CLASS_COUNT);
    let mut seen = [false; EXIT_CLASS_COUNT];
    for index in 0..EXIT_CLASS_COUNT {
        let class = WorldTiming::class_at(index).expect("index in range");
        assert_eq!(WorldTiming::class_index(class), index);
        assert!(!seen[index]);
        seen[index] = true;
    }
    assert!(seen.iter().all(|value| *value));
    assert_eq!(WorldTiming::class_at(EXIT_CLASS_COUNT), None);
}

#[test]
fn world_timing_records_decoded_reasons() {
    let mut timing = WorldTiming::new();
    timing.record_exit(ExitReason::decode(IO_INSTRUCTION as u32), 120);
    timing.record_exit(ExitReason::decode(CPUID as u32), 240);
    timing.record_exit(ExitReason::decode(0x8000_0000 | 33), 10);

    assert_eq!(timing.latency(ExitClass::IoPort).count(), 1);
    assert_eq!(timing.latency(ExitClass::Cpuid).count(), 1);
    assert_eq!(timing.latency(ExitClass::EntryFailure).count(), 1);
}

#[test]
fn world_timing_window_and_reset() {
    let mut timing = WorldTiming::new();
    timing.record(ExitClass::EptViolation, 500);
    timing.record(ExitClass::EptViolation, 600);
    timing.advance_window();
    timing.record(ExitClass::PreemptionTimer, 300);

    assert_eq!(timing.rate(ExitClass::EptViolation).window(), 2);
    assert_eq!(timing.total_rate().total(), 3);
    assert_eq!(timing.total_rate().window(), 3);

    timing.reset();
    assert_eq!(timing.total_rate().total(), 0);
    assert_eq!(timing.latency(ExitClass::EptViolation).count(), 0);
    assert_eq!(timing.rate(ExitClass::PreemptionTimer).window(), 0);
}
