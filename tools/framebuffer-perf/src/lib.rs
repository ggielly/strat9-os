//! Host checks of the actual kernel pixel operations; no privileged instructions.
extern crate alloc;
#[path = "../../../workspace/kernel/src/framebuffer/mod.rs"]
pub mod framebuffer;
#[path = "../../../workspace/kernel/src/arch/x86_64/vga/log_queue.rs"]
pub mod log_queue;

#[cfg(test)]
mod regression {
    use super::framebuffer::*;

    #[test]
    fn saturated_log_queue_recovers_and_owns_consumed_bytes() {
        let queue = super::log_queue::LogQueue::new();
        for _ in 0..super::log_queue::CAPACITY { queue.push(b"old"); }
        queue.push(b"dropped");
        assert_eq!(queue.dropped(), 1);
        let first = queue.pop().unwrap();
        for _ in 1..super::log_queue::CAPACITY { assert!(queue.pop().is_some()); }
        for _ in 0..super::log_queue::CAPACITY { queue.push(b"new"); }
        assert_eq!(first.as_bytes(), b"old");
        for _ in 0..super::log_queue::CAPACITY { assert_eq!(queue.pop().unwrap().as_bytes(), b"new"); }
        assert!(queue.pop().is_none());
    }

    #[test]
    fn concurrent_logs_publish_complete_lines() {
        use std::sync::Arc;
        let queue = Arc::new(super::log_queue::LogQueue::new());
        let threads: Vec<_> = (1..=4u8).map(|id| {
            let queue = queue.clone();
            std::thread::spawn(move || {
                for _ in 0..10_000 { queue.push(&[id; 200]); }
            })
        }).collect();
        let mut received = 0;
        loop {
            while let Some(line) = queue.pop() {
                assert_eq!(line.len, 200);
                assert!(line.as_bytes().iter().all(|&b| b == line.bytes[0]));
                received += 1;
            }
            if threads.iter().all(|t| t.is_finished()) { break; }
            std::thread::yield_now();
        }
        for thread in threads { thread.join().unwrap(); }
        while queue.pop().is_some() { received += 1; }
        assert_eq!(received, queue.written());
        assert_eq!(received + queue.dropped(), 40_000);
    }

    fn canvas(hw: &mut [u32], width: usize, height: usize, stride: usize) -> CanvasBuffer {
        CanvasBuffer {
            addr: hw.as_mut_ptr().cast(), width, height, pitch: stride * 4, bpp: 32,
            back_buffer: None, draw_to_back: false, dirty: DirtyRectSet::empty(),
            track_dirty: false, present_pending: false, last_present_tick: 0,
            ops: FramebufferOps::detect(), present_row_buf: None,
        }
    }

    #[test]
    fn pitched_snapshot_skips_padding() {
        let mut hw = vec![1, 2, 99, 3, 4, 99];
        let mut c = canvas(&mut hw, 2, 2, 3);
        assert!(c.enable_back_buffer());
        assert_eq!(c.back_buffer.as_deref(), Some(&[1, 2, 3, 4][..]));
    }

    #[test]
    fn narrow_dirty_rect_copies_each_row_and_preserves_neighbours() {
        for stride in [8, 11] {
            let mut hw = vec![77; stride * 5];
            let mut c = canvas(&mut hw, 8, 5, stride);
            c.enable_back_buffer();
            c.fill_rect(2, 1, 3, 3, 42);
            c.present();
            for y in 0..5 {
                for x in 0..stride {
                    let expected = if (1..4).contains(&y) && (2..5).contains(&x) { 42 } else { 77 };
                    assert_eq!(hw[y * stride + x], expected, "x={x} y={y} stride={stride}");
                }
            }
        }
    }

    #[test]
    fn glyph_runs_coalesce_without_overdraw() {
        let mut dirty = DirtyRectSet::empty();
        for x in 0..200 { dirty.include(x * 8, 32, 8, 16); }
        assert_eq!(dirty.len, 1);
        let r = dirty.rects[0];
        assert_eq!((r.x0, r.y0, r.width(), r.height()), (0, 32, 1600, 16));
        dirty.include(1590, 100, 10, 600);
        assert_eq!(dirty.len, 2, "distant scrollbar must remain separate");
    }

    #[test]
    fn pacing_retains_damage_until_deadline_and_force_bypasses_it() {
        let mut hw = vec![0; 32];
        let mut c = canvas(&mut hw, 8, 4, 8);
        c.enable_back_buffer();
        c.last_present_tick = 100;
        c.fill_rect(0, 0, 2, 1, 7);
        c.request_present();
        c.present_if_due(false, 101);
        assert!(c.present_pending);
        assert!(hw.iter().all(|&p| p == 0));
        c.fill_rect(4, 2, 2, 1, 9);
        c.present_if_due(false, 102);
        assert_eq!(&hw[..2], &[7, 7]);
        assert_eq!(&hw[20..22], &[9, 9]);
        assert!(!c.present_pending);
        c.fill_rect(7, 3, 1, 1, 11);
        c.request_present();
        c.present_if_due(true, 102);
        assert_eq!(hw[31], 11);
    }

    #[test]
    fn large_and_unaligned_sse2_ops_terminate_and_preserve_guards() {
        // Above the previous threshold even on machines with a large L2.
        let n = 2 * 1024 * 1024 + 3;
        let mut dst = vec![17; n + 2];
        let src: Vec<u32> = (0..n + 2).map(|i| i as u32).collect();
        unsafe {
            x86::sse2::fill_sse2(dst.as_mut_ptr().add(1), 42, n);
        }
        assert!(dst[1..=n].iter().all(|&p| p == 42));
        unsafe {
            x86::sse2::blit_sse2(dst.as_mut_ptr().add(1), src.as_ptr().add(1), n);
        }
        assert_eq!(dst[1..=n], src[1..=n]);
        assert_eq!((dst[0], dst[n + 1]), (17, 17));
    }
}
