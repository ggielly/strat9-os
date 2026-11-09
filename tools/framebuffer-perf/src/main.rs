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

use framebuffer_perf::framebuffer::{DirtyRectSet, FramebufferOps, PRESENT_MIN_TICKS};
use std::{hint::black_box, time::Instant};

fn main() {
    let ops = FramebufferOps::detect();
    let n = 1600 * 1200;
    let src = vec![0x12345678u32; n];
    let mut dst = vec![0u32; n];
    const RUNS: usize = 100;
    let start = Instant::now();
    for _ in 0..RUNS {
        unsafe { (ops.blit)(black_box(dst.as_mut_ptr()), black_box(src.as_ptr()), n); }
    }
    black_box(&dst);
    println!("RAM blit 1600x1200: {:.2} GiB/s (not VRAM/QEMU)",
        (n * 4 * RUNS) as f64 / start.elapsed().as_secs_f64() / (1u64 << 30) as f64);
    let mut dirty = DirtyRectSet::empty();
    for x in 0..200 { dirty.include(x * 8, 32, 8, 16); }
    println!("200 adjacent glyphs: {} region(s), {} pixels", dirty.len,
        dirty.iter().map(|r| u64::from(r.width()) * u64::from(r.height())).sum::<u64>());
    println!("Pacing ceiling at 100 Hz: {} FPS, {} ms", 100 / PRESENT_MIN_TICKS, PRESENT_MIN_TICKS * 10);
}
