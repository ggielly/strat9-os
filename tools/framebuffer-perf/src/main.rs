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
