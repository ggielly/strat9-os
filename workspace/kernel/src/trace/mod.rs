//! Lightweight kernel trace buffers for low-level debugging.
//!
//! Design goals:
//! - no_std friendly
//! - fixed-size per-CPU ring buffers
//! - category filtering
//! - minimal lock contention (`try_lock` drops on contention)

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::{arch::x86_64::percpu, process::scheduler, sync::SpinLock};

pub mod category {
    pub const MEM_PF: u64 = 1 << 0;
    pub const MEM_MAP: u64 = 1 << 1;
    pub const MEM_UNMAP: u64 = 1 << 2;
    pub const MEM_COW: u64 = 1 << 3;
    pub const MEM_COPY: u64 = 1 << 4;
    pub const MEM_ALL: u64 = MEM_PF | MEM_MAP | MEM_UNMAP | MEM_COW | MEM_COPY;
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceKind {
    Unknown = 0,
    MemPageFault = 1,
    MemMap = 2,
    MemUnmap = 3,
    MemCow = 4,
    MemCopy = 5,
}

#[derive(Clone, Copy, Debug)]
pub struct TraceEvent {
    pub seq: u64,
    pub ticks: u64,
    pub cpu: u16,
    pub kind: u16,
    pub category: u64,
    pub flags: u64,
    pub task_id: u64,
    pub pid: u32,
    pub tid: u32,
    pub cr3: u64,
    pub rip: u64,
    pub vaddr: u64,
    pub arg0: u64,
    pub arg1: u64,
}

impl TraceEvent {
    pub const EMPTY: Self = Self {
        seq: 0,
        ticks: 0,
        cpu: 0,
        kind: TraceKind::Unknown as u16,
        category: 0,
        flags: 0,
        task_id: 0,
        pid: 0,
        tid: 0,
        cr3: 0,
        rip: 0,
        vaddr: 0,
        arg0: 0,
        arg1: 0,
    };
}

#[derive(Clone, Copy, Debug)]
pub struct TraceTaskCtx {
    pub task_id: u64,
    pub pid: u32,
    pub tid: u32,
    pub cr3: u64,
}

impl TraceTaskCtx {
    pub const fn empty() -> Self {
        Self {
            task_id: 0,
            pid: 0,
            tid: 0,
            cr3: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TraceStats {
    pub dropped: u64,
    pub stored: u64,
}

const TRACE_CAPACITY: usize = 512;

struct CpuTraceRing {
    head: usize,
    len: usize,
    stored: u64,
    events: [TraceEvent; TRACE_CAPACITY],
}

impl CpuTraceRing {
    const fn new() -> Self {
        Self {
            head: 0,
            len: 0,
            stored: 0,
            events: [TraceEvent::EMPTY; TRACE_CAPACITY],
        }
    }

    fn push(&mut self, event: TraceEvent) {
        self.events[self.head] = event;
        self.head = (self.head + 1) % TRACE_CAPACITY;
        if self.len < TRACE_CAPACITY {
            self.len += 1;
        }
        self.stored = self.stored.saturating_add(1);
    }

    fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
        self.stored = 0;
    }

    fn snapshot(&self, limit: usize) -> Vec<TraceEvent> {
        let n = self.len.min(limit);
        let mut out = Vec::with_capacity(n);
        if n == 0 {
            return out;
        }

        let start = (self.head + TRACE_CAPACITY - n) % TRACE_CAPACITY;
        for i in 0..n {
            let idx = (start + i) % TRACE_CAPACITY;
            out.push(self.events[idx]);
        }
        out
    }
}

static TRACE_SEQ: AtomicU64 = AtomicU64::new(1);
// Default: keep early boot noise low but always surface PF/COW instantly.
static TRACE_MASK: AtomicU64 = AtomicU64::new(category::MEM_PF | category::MEM_COW);
static TRACE_SERIAL_ECHO: AtomicBool = AtomicBool::new(true);
static TRACE_DROPPED_TOTAL: AtomicU64 = AtomicU64::new(0);
static TRACE_RINGS: [SpinLock<CpuTraceRing>; percpu::MAX_CPUS] =
    [const { SpinLock::new(CpuTraceRing::new()) }; percpu::MAX_CPUS];

#[inline]
pub fn mask() -> u64 {
    TRACE_MASK.load(Ordering::Relaxed)
}

#[inline]
pub fn set_mask(new_mask: u64) {
    TRACE_MASK.store(new_mask, Ordering::Relaxed);
}

#[inline]
pub fn enable(bits: u64) {
    TRACE_MASK.fetch_or(bits, Ordering::Relaxed);
}

#[inline]
pub fn disable(bits: u64) {
    TRACE_MASK.fetch_and(!bits, Ordering::Relaxed);
}

#[inline]
pub fn enabled(category: u64) -> bool {
    (mask() & category) != 0
}

#[inline]
pub fn set_serial_echo(on: bool) {
    TRACE_SERIAL_ECHO.store(on, Ordering::Relaxed);
}

#[inline]
pub fn serial_echo() -> bool {
    TRACE_SERIAL_ECHO.load(Ordering::Relaxed)
}

pub fn clear_all() {
    for ring in TRACE_RINGS.iter() {
        if let Some(mut guard) = ring.try_lock() {
            guard.clear();
        }
    }
}

pub fn stats() -> TraceStats {
    let mut out = TraceStats::default();
    out.dropped = TRACE_DROPPED_TOTAL.load(Ordering::Relaxed);
    for ring in TRACE_RINGS.iter() {
        if let Some(guard) = ring.try_lock() {
            out.stored = out.stored.saturating_add(guard.stored);
        }
    }
    out
}

pub fn snapshot_all(limit_per_cpu: usize) -> Vec<TraceEvent> {
    let mut out = Vec::new();
    let limit = limit_per_cpu.max(1);

    for ring in TRACE_RINGS.iter() {
        if let Some(guard) = ring.try_lock() {
            let mut events = guard.snapshot(limit);
            out.append(&mut events);
        }
    }

    out.sort_unstable_by_key(|e| e.seq);
    out
}

#[inline]
fn current_cpu() -> usize {
    percpu::cpu_index_from_gs().unwrap_or(0)
}

pub fn record(
    category: u64,
    kind: TraceKind,
    flags: u64,
    ctx: TraceTaskCtx,
    rip: u64,
    vaddr: u64,
    arg0: u64,
    arg1: u64,
) {
    if !enabled(category) {
        return;
    }

    let cpu = current_cpu();
    let seq = TRACE_SEQ.fetch_add(1, Ordering::Relaxed);
    let event = TraceEvent {
        seq,
        ticks: scheduler::ticks(),
        cpu: cpu as u16,
        kind: kind as u16,
        category,
        flags,
        task_id: ctx.task_id,
        pid: ctx.pid,
        tid: ctx.tid,
        cr3: ctx.cr3,
        rip,
        vaddr,
        arg0,
        arg1,
    };

    if let Some(mut ring) = TRACE_RINGS[cpu].try_lock() {
        ring.push(event);
    } else {
        TRACE_DROPPED_TOTAL.fetch_add(1, Ordering::Relaxed);
        return;
    }

    if serial_echo() {
        crate::serial_println!(
            "[trace] seq={} cpu={} kind={} pid={} tid={} rip={:#x} vaddr={:#x} a0={:#x} a1={:#x} fl={:#x}",
            event.seq,
            event.cpu,
            kind_name(event.kind),
            event.pid,
            event.tid,
            event.rip,
            event.vaddr,
            event.arg0,
            event.arg1,
            event.flags
        );
    }
}

#[inline]
pub fn kind_name(kind: u16) -> &'static str {
    match kind {
        x if x == TraceKind::MemPageFault as u16 => "mem_pf",
        x if x == TraceKind::MemMap as u16 => "mem_map",
        x if x == TraceKind::MemUnmap as u16 => "mem_unmap",
        x if x == TraceKind::MemCow as u16 => "mem_cow",
        x if x == TraceKind::MemCopy as u16 => "mem_copy",
        _ => "unknown",
    }
}

pub fn mask_human(mask: u64) -> &'static str {
    if mask == 0 {
        "none"
    } else if (mask & category::MEM_ALL) == category::MEM_ALL {
        "mem:*"
    } else {
        "custom"
    }
}

#[macro_export]
macro_rules! trace_mem {
    ($cat:expr, $kind:expr, $flags:expr, $ctx:expr, $rip:expr, $vaddr:expr, $arg0:expr, $arg1:expr) => {
        $crate::trace::record($cat, $kind, $flags, $ctx, $rip, $vaddr, $arg0, $arg1)
    };
}
