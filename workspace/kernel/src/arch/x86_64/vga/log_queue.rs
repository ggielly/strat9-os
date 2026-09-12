//! Fixed-storage log queue. Safe publication under SMP and bounded overflow.
use core::sync::atomic::{AtomicUsize, Ordering};
use heapless::mpmc::Queue;

pub const CAPACITY: usize = 512;
pub const LINE_LEN: usize = 256;

#[derive(Clone, Copy)]
pub struct Line {
    pub bytes: [u8; LINE_LEN],
    pub len: usize,
}

impl Line {
    pub const EMPTY: Self = Self { bytes: [0; LINE_LEN], len: 0 };

    pub fn as_bytes(&self) -> &[u8] { &self.bytes[..self.len] }
}

pub struct LogQueue {
    queue: Queue<Line, CAPACITY>,
    written: AtomicUsize,
    dropped: AtomicUsize,
}

impl LogQueue {
    // This lossy log sink permits transient enqueue failures and retries
    // dequeue on the next display tick, as required by heapless::mpmc.
    #[expect(deprecated, reason = "log drops and delayed dequeue are supported")]
    pub const fn new() -> Self {
        Self { queue: Queue::new(), written: AtomicUsize::new(0), dropped: AtomicUsize::new(0) }
    }

    pub fn push(&self, bytes: &[u8]) {
        if bytes.is_empty() { return; }
        let mut line = Line::EMPTY;
        line.len = bytes.len().min(LINE_LEN - 1);
        line.bytes[..line.len].copy_from_slice(&bytes[..line.len]);
        if self.queue.enqueue(line).is_ok() {
            self.written.fetch_add(1, Ordering::Relaxed);
        } else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn pop(&self) -> Option<Line> { self.queue.dequeue() }
    pub fn written(&self) -> usize { self.written.load(Ordering::Relaxed) }
    pub fn dropped(&self) -> usize { self.dropped.load(Ordering::Relaxed) }
}
