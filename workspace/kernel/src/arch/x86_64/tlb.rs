//! TLB (Translation Lookaside Buffer) shootdown for SMP.
//!
//! When a page table entry is modified on one CPU, all other CPUs that might
//! have cached that entry in their TLB must be notified to invalidate it.
//!
//! This implementation uses a per-CPU mailbox system inspired by Asterinas:
//! 1. Each CPU has its own queue of pending TLB operations.
//! 2. The initiator pushes an operation into each target's queue.
//! 3. The initiator sends a TLB shootdown IPI to all targets.
//! 4. The targets process their own queue and set an ACK flag.
//! 5. The initiator waits for all ACK flags to become true.
//!
//! This avoids global lock contention and race conditions on global counters.

use core::sync::atomic::{AtomicBool, Ordering};
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

/// Global array of per-CPU TLB queues.
static TLB_QUEUES: [SpinLock<TlbQueue>; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { SpinLock::new(TlbQueue::new()) }; crate::arch::x86_64::percpu::MAX_CPUS];

/// Global array of per-CPU acknowledgement flags.
static TLB_ACKS: [AtomicBool; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { AtomicBool::new(true) }; crate::arch::x86_64::percpu::MAX_CPUS];

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

/// Invalidate a range of pages on all CPUs.
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
    if page_count > 64 {
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

    // `queued` tracks only the APIC IDs that were successfully pushed to a
    // mailbox queue.  We must not send an IPI to, or wait for an ACK from,
    // an AP whose queue was skipped — doing so would either waste cycles or
    // spin-wait forever on an ACK that was never cleared.
    let mut queued = [0u32; crate::arch::x86_64::percpu::MAX_CPUS];
    let mut queued_count = 0usize;

    // 1. Push op to each target's mailbox and clear their ACK.
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
        let mut queue = TLB_QUEUES[cpu_idx].lock();
        queue.push(op);
        TLB_ACKS[cpu_idx].store(false, Ordering::Release);
        drop(queue);
        // Record as a successfully-queued target.
        queued[queued_count] = apic_id;
        queued_count += 1;
    }

    if queued_count == 0 {
        return;
    }

    // 2. Send IPI only to targets that actually received a queued op.
    for i in 0..queued_count {
        send_tlb_ipi(queued[i]);
    }

    // 3. Wait for ACKs from the same set.
    wait_for_acks(&queued[..queued_count]);
}

/// IPI handler for TLB shootdown (called on receiving CPU).
pub extern "C" fn tlb_shootdown_ipi_handler() {
    let cpu_idx = current_cpu_index();

    // 1. Take all pending ops from our mailbox.
    let mut local_ops = [TlbOp::NONE; 16];
    let mut count = 0;
    {
        let mut queue = TLB_QUEUES[cpu_idx].lock();
        count = queue.count;
        for i in 0..count {
            local_ops[i] = queue.ops[i];
        }
        queue.clear();
    }

    // 2. Perform the operations.
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
                if end > start {
                    let page_count = (end - start) / 4096;
                    for j in 0..page_count {
                        let addr = VirtAddr::new(start + j * 4096);
                        unsafe { invlpg(addr) };
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

    // 3. Signal completion.
    TLB_ACKS[cpu_idx].store(true, Ordering::Release);

    // 4. Send EOI.
    crate::arch::x86_64::apic::eoi();
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
    let icr_low = crate::arch::x86_64::apic::IPI_TLB_SHOOTDOWN_VECTOR as u32 | (1 << 14);
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

/// Wait for ACKs from specific APIC IDs.
fn wait_for_acks(targets: &[u32]) {
    const MAX_WAIT_CYCLES: usize = 10_000_000;
    for &apic_id in targets {
        // Use if-let: if the APIC ID is gone (AP offline after we sent the IPI)
        // there is nothing to wait for — skip rather than panic in kernel context.
        let cpu_idx = match crate::arch::x86_64::percpu::cpu_index_by_apic(apic_id) {
            Some(idx) => idx,
            None => {
                log::warn!("TLB wait_acks: APIC {} disappeared, skipping", apic_id);
                continue;
            }
        };
        let mut success = false;
        for _ in 0..MAX_WAIT_CYCLES {
            if TLB_ACKS[cpu_idx].load(Ordering::Acquire) {
                success = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !success {
            log::warn!("TLB shootdown timeout on CPU {}", cpu_idx);
        }
    }
}

/// Current CPU index.
fn current_cpu_index() -> usize {
    crate::arch::x86_64::percpu::current_cpu_index()
}
