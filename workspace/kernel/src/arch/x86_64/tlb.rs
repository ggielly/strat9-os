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

//! TLB (Translation Lookaside Buffer) shootdown for SMP.
//!
//! When a page table entry is modified on one CPU, all other CPUs that might
//! have cached that entry in their TLB must be notified to invalidate it.
//!
//! This implementation uses a per-CPU mailbox system inspired by Asterinas :
//! 1. Each CPU has its own queue of pending TLB operations.
//! 2. The initiator pushes an operation into each target's queue and allocates
//!    a monotonically increasing request generation (`TLB_REQ`).
//! 3. The initiator sends a TLB shootdown IPI to all targets.
//! 4. Each target drains its queue and publishes the highest generation it has
//!    completed into `TLB_DONE`.
//! 5. The initiator waits until every target's `TLB_DONE` reaches the
//!    generation it allocated.
//!
//! Generation counters avoid the lost/stale acknowledgement race of a per-CPU
//! boolean: an initiator cannot observe "done" for an operation still queued,
//! and a concurrent shootdown cannot clobber another's acknowledgement.

use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::VirtAddr;

use crate::sync::SpinLock;

/// Type of TLB shootdown operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlbShootdownKind {
    /// No pending shootdown.
    None,
    /// Invalidate a single page.
    SinglePage,
    /// Invalidate a range of pages.
    Range,
    /// Flush all TLB entries (full CR3 reload).
    Full,
}

/// A single TLB operation.
#[derive(Debug, Clone, Copy)]
struct TlbOp {
    kind: TlbShootdownKind,
    vaddr_start: u64,
    vaddr_end: u64,
}

impl TlbOp {
    const NONE: Self = Self {
        kind: TlbShootdownKind::None,
        vaddr_start: 0,
        vaddr_end: 0,
    };
}

/// Per-CPU queue of pending TLB operations.
struct TlbQueue {
    ops: [TlbOp; 16],
    count: usize,
}

impl TlbQueue {
    const fn new() -> Self {
        Self {
            ops: [TlbOp::NONE; 16],
            count: 0,
        }
    }

    fn push(&mut self, op: TlbOp) {
        if self.count < 16 {
            self.ops[self.count] = op;
            self.count += 1;
        } else {
            // Queue full: upgrade to a full flush to be safe.
            self.ops[0] = TlbOp {
                kind: TlbShootdownKind::Full,
                vaddr_start: 0,
                vaddr_end: 0,
            };
            self.count = 1;
        }
    }

    fn clear(&mut self) {
        self.count = 0;
    }
}

/// Page-count threshold above which a ranged shootdown falls back to a full
/// CR3 reload (`shootdown_all`) rather than issuing one `invlpg` per page.
///
/// Rationale: on x86, a CR3 write flushes all non-global TLB entries in a
/// single pipeline stage. Individual `invlpg` instructions have a per-entry
/// cost that grows linearly with the number of pages. Empirically, the
/// crossover point is around 32–64 pages (µarch-dependent); 64 is a
/// conservative upper bound that keeps the fast path below ~256 ns on modern
/// hardware while avoiding spurious full flushes on small vmalloc frees.
///
/// The same constant governs both the sender side (`shootdown_range`,
/// `local_range`) and the receiver side (IPI handler's `Range` arm) so the
/// two never disagree on what "small range" means.
pub const TLB_RANGE_THRESHOLD_PAGES: usize = 64;

/// Global array of per-CPU TLB queues.
static TLB_QUEUES: [SpinLock<TlbQueue>; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { SpinLock::new(TlbQueue::new()) }; crate::arch::x86_64::percpu::MAX_CPUS];

/// Per-CPU generation of the last request pushed into that CPU's mailbox.
///
/// The counter is bumped under the mailbox lock at the same time the matching
/// operation is queued, so the receiver always observes a consistent
/// `(queue, TLB_REQ)` pair.
static TLB_REQ: [AtomicU64; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::x86_64::percpu::MAX_CPUS];

/// Per-CPU generation of the last request whose operations have been executed.
///
/// Only ever advanced with `fetch_max`, so it is monotonic and can never claim
/// completion of a generation that has not been processed.
static TLB_DONE: [AtomicU64; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::x86_64::percpu::MAX_CPUS];

/// Initialize TLB shootdown system.
pub fn init() {
    log::debug!(
        "TLB shootdown initialized (vector {:#x})",
        crate::arch::x86_64::apic::IPI_TLB_SHOOTDOWN_VECTOR
    );
}

/// Invalidate a single page on all CPUs.
pub fn shootdown_page(vaddr: VirtAddr) {
    let op = TlbOp {
        kind: TlbShootdownKind::SinglePage,
        vaddr_start: vaddr.as_u64(),
        vaddr_end: vaddr.as_u64() + 4096,
    };

    // Flush local TLB.
    unsafe { invlpg(vaddr) };

    dispatch_op(op);
}

/// Invalidate a single page on the current CPU only.
#[inline]
pub fn local_page(vaddr: VirtAddr) {
    unsafe { invlpg(vaddr) };
}

/// Invalidate a range on the current CPU only.
pub fn local_range(start: VirtAddr, end: VirtAddr) {
    if end.as_u64() <= start.as_u64() {
        unsafe { flush_tlb_all() };
        return;
    }

    let page_count = (end.as_u64() - start.as_u64()) / 4096;
    if page_count > TLB_RANGE_THRESHOLD_PAGES as u64 {
        unsafe { flush_tlb_all() };
        return;
    }

    for i in 0..page_count {
        let addr = start + (i * 4096);
        unsafe { invlpg(addr) };
    }
}

/// Flush all TLB entries on the current CPU only.
///
/// Public wrapper around the internal CR3-reload flush so other subsystems can
/// invalidate the whole local TLB without a shootdown.
pub fn flush_local_all() {
    unsafe { flush_tlb_all() };
}

/// Invalidate a range of pages on all CPUs.
///
/// Falls back to [`shootdown_all`] when the range exceeds
/// [`TLB_RANGE_THRESHOLD_PAGES`] pages, because a full CR3 reload is cheaper
/// than that many `invlpg` instructions on both the initiating and receiving
/// CPUs.
pub fn shootdown_range(start: VirtAddr, end: VirtAddr) {
    // Guard: end must be strictly after start; silently promote to full flush
    // if the range is invalid rather than underflowing in u64 arithmetic.
    if end.as_u64() <= start.as_u64() {
        log::warn!(
            "TLB shootdown_range: invalid range [{:#x}, {:#x}), using full flush",
            start.as_u64(),
            end.as_u64(),
        );
        shootdown_all();
        return;
    }

    let page_count = (end.as_u64() - start.as_u64()) / 4096;
    if page_count > TLB_RANGE_THRESHOLD_PAGES as u64 {
        shootdown_all();
        return;
    }

    let op = TlbOp {
        kind: TlbShootdownKind::Range,
        vaddr_start: start.as_u64(),
        vaddr_end: end.as_u64(),
    };

    // Flush local TLB.
    for i in 0..page_count {
        let addr = start + (i * 4096);
        unsafe { invlpg(addr) };
    }

    dispatch_op(op);
}

/// Flush all TLB entries on all CPUs.
pub fn shootdown_all() {
    let op = TlbOp {
        kind: TlbShootdownKind::Full,
        vaddr_start: 0,
        vaddr_end: 0,
    };

    // Flush local TLB.
    unsafe { flush_tlb_all() };

    dispatch_op(op);
}

/// Internal helper to dispatch an operation to target CPUs.
fn dispatch_op(op: TlbOp) {
    if !crate::arch::x86_64::apic::is_initialized() {
        return;
    }

    let mut targets = [0u32; crate::arch::x86_64::percpu::MAX_CPUS];
    let count = collect_tlb_targets(&mut targets);
    if count == 0 {
        return;
    }

    // `(apic_id, cpu_idx, seq)` for each target that was successfully queued.
    // An IPI is sent, and an acknowledgement awaited, only for entries here :
    // sending to, or waiting on, an AP whose queue was skipped would waste
    // cycles or spin forever.
    let mut queued = [(0u32, 0usize, 0u64); crate::arch::x86_64::percpu::MAX_CPUS];
    let mut queued_count = 0usize;

    // 1. Push the op into each target's mailbox and allocate a request
    //    generation.  The push and the counter bump are done under the mailbox
    //    lock so the receiver observes a consistent (queue, TLB_REQ) pair.
    for i in 0..count {
        let apic_id = targets[i];
        // cpu_index_by_apic can return None if the AP went offline between
        // collect_tlb_targets and here; skip silently rather than panicking
        // in an IPI-send path.
        let cpu_idx = match crate::arch::x86_64::percpu::cpu_index_by_apic(apic_id) {
            Some(idx) => idx,
            None => {
                log::warn!(
                    "TLB dispatch: APIC {} not in per-CPU table, skipping",
                    apic_id
                );
                continue;
            }
        };
        let seq;
        {
            let mut queue = TLB_QUEUES[cpu_idx].lock();
            queue.push(op);
            seq = TLB_REQ[cpu_idx].fetch_add(1, Ordering::AcqRel) + 1;
            drop(queue);
        }
        queued[queued_count] = (apic_id, cpu_idx, seq);
        queued_count += 1;
    }

    if queued_count == 0 {
        return;
    }

    // 2. Send IPI only to targets that actually received a queued op.
    for i in 0..queued_count {
        send_tlb_ipi(queued[i].0);
    }

    // 3. Wait for each target to acknowledge its own generation.
    wait_for_acks(&queued[..queued_count]);
}

/// IPI handler for TLB shootdown (called on receiving CPU).
pub extern "C" fn tlb_shootdown_ipi_handler() {
    // Drain until the mailbox stays empty across a lock acquisition, then EOI
    // once for the whole batch.  Looping is required: an operation pushed after
    // a batch copy but before the matching `TLB_DONE` update must still run.
    drain_local_queue();
    crate::arch::x86_64::apic::eoi();
}

/// Drain and execute this CPU's TLB mailbox.
///
/// Repeats until the mailbox is observed empty under the lock.  For each batch
/// the ops are copied and cleared and the current request generation is read
/// under the *same* lock hold, so `req` covers exactly the ops copied (any
/// concurrent push is serialized behind the lock).  The generation is then
/// published with `fetch_max`, which is monotonic.
///
/// Returns `true` if at least one operation was executed.  Does **not** send
/// EOI, so it can be reused from the shootdown wait loop.
fn drain_local_queue() -> bool {
    let cpu_idx = current_cpu_index();
    let mut processed_any = false;

    loop {
        let mut local_ops = [TlbOp::NONE; 16];
        let count;
        let req;
        {
            let mut queue = TLB_QUEUES[cpu_idx].lock();
            if queue.count == 0 {
                // Empty: read TLB_REQ under the lock so the empty observation
                // is ordered after any concurrent push, then stop.
                let _ = TLB_REQ[cpu_idx].load(Ordering::Acquire);
                drop(queue);
                break;
            }
            count = queue.count;
            for i in 0..count {
                local_ops[i] = queue.ops[i];
            }
            queue.clear();
            // Same critical section as the copy/clear: a dispatcher cannot bump
            // TLB_REQ between the clear and this load, so `req` is exactly the
            // generation of the ops we just copied.
            req = TLB_REQ[cpu_idx].load(Ordering::Acquire);
            drop(queue);
        }

        // Perform the operations.
        for i in 0..count {
            let op = &local_ops[i];
            match op.kind {
                TlbShootdownKind::None => {}
                TlbShootdownKind::SinglePage => {
                    unsafe { invlpg(VirtAddr::new(op.vaddr_start)) };
                }
                TlbShootdownKind::Range => {
                    let start = op.vaddr_start;
                    let end = op.vaddr_end;
                    // Guard: corrupt TlbOp must not underflow in release build.
                    // Also cap to TLB_RANGE_THRESHOLD_PAGES for defense-in-depth:
                    // the sender already guarantees this, but a stale or malformed
                    // op must not spend thousands of invlpg cycles on the receiver.
                    if end > start {
                        let page_count = (end - start) / 4096;
                        if page_count > TLB_RANGE_THRESHOLD_PAGES as u64 {
                            unsafe { flush_tlb_all() };
                        } else {
                            for j in 0..page_count {
                                let addr = VirtAddr::new(start + j * 4096);
                                unsafe { invlpg(addr) };
                            }
                        }
                    } else {
                        unsafe { flush_tlb_all() };
                    }
                }
                TlbShootdownKind::Full => {
                    unsafe { flush_tlb_all() };
                }
            }
        }

        // Publish completion of this generation.  `fetch_max` keeps the counter
        // monotonic even if a newer generation was somehow already published.
        TLB_DONE[cpu_idx].fetch_max(req, Ordering::Release);
        processed_any = true;
    }

    processed_any
}

/// Invalidate a single TLB entry (local CPU only).
#[inline]
unsafe fn invlpg(vaddr: VirtAddr) {
    core::arch::asm!("invlpg [{}]", in(reg) vaddr.as_u64(), options(nostack, preserves_flags));
}

/// Flush all TLB entries by reloading CR3 (local CPU only).
#[inline]
unsafe fn flush_tlb_all() {
    use x86_64::registers::control::Cr3;
    let (frame, flags) = Cr3::read();
    Cr3::write(frame, flags);
}

/// Send TLB IPI.
fn send_tlb_ipi(target_apic_id: u32) {
    // Fixed delivery, edge-triggered, physical destination.
    // Level bit = 0 (reserved for Fixed mode per Intel SDM Vol. 3A Table 10-1).
    let icr_low = crate::arch::x86_64::apic::IPI_TLB_SHOOTDOWN_VECTOR as u32;
    crate::arch::x86_64::apic::send_ipi_raw(target_apic_id, icr_low);
}

/// Collect target APIC IDs into a pre-allocated buffer.
fn collect_tlb_targets(targets: &mut [u32]) -> usize {
    let my_cpu = crate::arch::x86_64::percpu::current_cpu_index();
    let mut count = 0;
    for cpu_idx in 0..crate::arch::x86_64::percpu::MAX_CPUS {
        if !crate::arch::x86_64::percpu::tlb_ready(cpu_idx) {
            continue;
        }
        if let Some(apic_id) = crate::arch::x86_64::percpu::apic_id_by_cpu_index(cpu_idx) {
            if cpu_idx != my_cpu {
                if count < targets.len() {
                    targets[count] = apic_id;
                    count += 1;
                }
            }
        }
    }
    count
}

/// Wait for generation acknowledgements from the given targets.
///
/// Each entry is `(apic_id, cpu_idx, seq)` captured at queue time.  While
/// waiting, this CPU services its *own* mailbox if a request is pending :
/// otherwise two initiators with interrupts disabled would spin forever, each
/// waiting for the other's IPI handler that can never run.
fn wait_for_acks(targets: &[(u32, usize, u64)]) {
    const MAX_WAIT_CYCLES: usize = 10_000_000;
    let my_cpu = current_cpu_index();

    for &(_apic_id, cpu_idx, seq) in targets {
        let mut success = false;
        for _ in 0..MAX_WAIT_CYCLES {
            if TLB_DONE[cpu_idx].load(Ordering::Acquire) >= seq {
                success = true;
                break;
            }
            // Break the two-initiator deadlock: if a shootdown aimed at us is
            // sitting in our mailbox, execute it now.
            if TLB_REQ[my_cpu].load(Ordering::Acquire) > TLB_DONE[my_cpu].load(Ordering::Acquire) {
                drain_local_queue();
            }
            core::hint::spin_loop();
        }
        if !success {
            panic!(
                "TLB shootdown timeout: cpu={} expected seq={} observed done={}",
                cpu_idx,
                seq,
                TLB_DONE[cpu_idx].load(Ordering::Acquire),
            );
        }
    }
}

/// Current CPU index.
fn current_cpu_index() -> usize {
    crate::arch::x86_64::percpu::current_cpu_index()
}
