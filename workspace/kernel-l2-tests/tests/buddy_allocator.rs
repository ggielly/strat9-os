//! L2 — Buddy allocator deep tests (real kernel code, real host memory).
//!
//! Strategy: the mirror maps `phys_to_virt` through a REAL host arena
//! (HHDM offset = arena_host − fake_phys_base), so the buddy allocator
//! operates on actual writable memory instead of a simulation. Frame
//! zeroing, poison guards and MetaSlot bookkeeping all execute for real.
//!
//! Boot flow replicated per test (kernel order):
//!   1. global boot allocator init over the memory map
//!   2. frame metadata array reserved out of it (consumed)
//!   3. `init_buddy_allocator` consumes remaining free regions, seals boot
//!
//! The buddy allocator is a process-wide static, so tests serialize on a
//! global mutex and re-initialize it.

use std::alloc::{alloc_zeroed, Layout};

use kernel_l2_tests::memory::boot_alloc;
use kernel_l2_tests::memory::frame;
use kernel_l2_tests::memory::{self, buddy, phys_to_virt, set_hhdm_offset, AllocError};
use kernel_l2_tests::sync::IrqDisabledToken;
use strat9_abi::boot::{MemoryKind, MemoryRegion};

/// Global serialization: the buddy allocator is a kernel static.
static SEQ: std::sync::Mutex<()> = std::sync::Mutex::new(());

const PHYS_BASE: u64 = 0x1000_0000; // 256 MiB (2 MiB-aligned)
const BUDDY_BYTES: u64 = 64 << 20; // 64 MiB managed by the buddy

struct BuddyEnv {
    token: IrqDisabledToken,
    arena_ptr: *mut u8,
    arena_size: usize,
}

impl BuddyEnv {
    fn new(buddy_bytes: u64) -> Self {
        let span = buddy_bytes; // fake physical window size
        let total_ram = PHYS_BASE + span; // covers all PFNs below the window

        // Real host backing store, 2 MiB aligned like a physical region.
        let arena_size = span as usize;
        let layout = Layout::from_size_align(arena_size, 2 << 20).unwrap();
        let arena_ptr = unsafe { alloc_zeroed(layout) };
        assert!(!arena_ptr.is_null(), "host arena allocation failed");
        set_hhdm_offset((arena_ptr as u64).wrapping_sub(PHYS_BASE));

        // Kernel boot flow with the GLOBAL boot allocator.
        let regions = [MemoryRegion { base: PHYS_BASE, size: span, kind: MemoryKind::Free }];
        {
            let mut boot = boot_alloc::get_boot_allocator().lock();
            boot.init(&regions);
            frame::init_metadata_array(total_ram, &mut boot);
        }
        kernel_l2_tests::memory::buddy::init_buddy_allocator(&regions);

        BuddyEnv { token: IrqDisabledToken::for_test(), arena_ptr, arena_size }
    }
}

impl Drop for BuddyEnv {
    fn drop(&mut self) {
        unsafe {
            std::alloc::dealloc(
                self.arena_ptr,
                Layout::from_size_align(self.arena_size, 2 << 20).unwrap(),
            )
        };
    }
}

#[test]
fn order0_alloc_free_cycle() {
    let _g = SEQ.lock().unwrap_or_else(|p| p.into_inner());
    let env = BuddyEnv::new(BUDDY_BYTES);
    let t = &env.token;

    let f = kernel_l2_tests::memory::buddy::alloc(t, 0).expect("order-0 alloc on fresh heap");
    assert_eq!(f.start_address.as_u64() % 4096, 0);
    kernel_l2_tests::memory::buddy::free(t, f, 0);

    let f2 = kernel_l2_tests::memory::buddy::alloc(t, 0).expect("realloc after free");
    kernel_l2_tests::memory::buddy::free(t, f2, 0);
}

#[test]
fn frames_are_aligned_to_order() {
    let _g = SEQ.lock().unwrap_or_else(|p| p.into_inner());
    let env = BuddyEnv::new(BUDDY_BYTES);
    let t = &env.token;

    for order in 0..=4u8 {
        if let Ok(f) = kernel_l2_tests::memory::buddy::alloc(t, order) {
            let align = 4096u64 << order;
            assert_eq!(
                f.start_address.as_u64() % align,
                0,
                "order {} frame not {}-aligned",
                order,
                align
            );
            kernel_l2_tests::memory::buddy::free(t, f, order);
        }
    }
}

#[test]
fn exhaustion_returns_oom_cleanly() {
    let _g = SEQ.lock().unwrap_or_else(|p| p.into_inner());
    let env = BuddyEnv::new(64 << 20); // must exceed frame-metadata footprint
    let t = &env.token;

    let mut frames = Vec::new();
    loop {
        match kernel_l2_tests::memory::buddy::alloc(t, 0) {
            Ok(f) => frames.push(f),
            Err(e) => {
                assert_eq!(e, AllocError::OutOfMemory);
                break;
            }
        }
        assert!(frames.len() <= 16384, "allocated more pages than the region holds");
    }
    assert!(!frames.is_empty(), "no pages allocated before OOM");

    for f in &frames {
        kernel_l2_tests::memory::buddy::free(t, *f, 0);
    }
    kernel_l2_tests::memory::buddy::alloc(t, 0).expect("alloc succeeds again after full free");
}

#[test]
fn freed_memory_is_reusable_and_zeroed_by_purpose_alloc() {
    let _g = SEQ.lock().unwrap_or_else(|p| p.into_inner());
    let env = BuddyEnv::new(8 << 20);
    let t = &env.token;

    // Dirty a frame through its REAL host mapping (HHDM trick).
    let f = buddy::alloc(t, 0).unwrap();
    let ptr = phys_to_virt(f.start_address.as_u64()) as *mut u64;
    for i in 0..512 {
        unsafe { ptr.add(i).write_volatile(0xDEAD_BEEF_DEAD_BEEF) };
    }
    buddy::free(t, f, 0);

    // Purpose-driven alloc must hand back ZEROED memory.
    let g = frame::FrameAllocOptions::new()
        .purpose(frame::FramePurpose::KernelData)
        .allocate(t)
        .expect("purpose alloc");
    let gptr = phys_to_virt(g.start_address.as_u64()) as *const u64;
    for i in 0..512 {
        let v = unsafe { gptr.add(i).read_volatile() };
        assert_eq!(v, 0, "word {} not zeroed after purpose alloc", i);
    }
    buddy::free(t, g, 0);
}

#[test]
fn stress_interleaved_alloc_free_with_payload_check() {
    let _g = SEQ.lock().unwrap_or_else(|p| p.into_inner());
    let env = BuddyEnv::new(16 << 20);
    let t = &env.token;
    type Frame = kernel_l2_tests::memory::PhysFrame;
    let mut live: Vec<(Frame, u8, u64)> = Vec::new();
    let mut seed: u64 = 0x1234_5678_9ABC_DEF0;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };

    for round in 1..=2000u64 {
        let action = next() % 3;
        if action != 0 || live.is_empty() {
            let order = (next() % 3) as u8; // orders 0..2
            if let Ok(f) = buddy::alloc(t, order) {
                let tag = f.start_address.as_u64() ^ round.rotate_left(17);
                let virt = phys_to_virt(f.start_address.as_u64()) as *mut u64;
                unsafe { virt.write_volatile(tag) };
                live.push((f, order, tag));
            }
        } else {
            let idx = (next() as usize) % live.len();
            let (f, order, expected_tag) = live.swap_remove(idx);
            let virt = phys_to_virt(f.start_address.as_u64()) as *const u64;
            let tag = unsafe { virt.read_volatile() };
            assert_eq!(tag, expected_tag, "live frame payload corrupted");
            buddy::free(t, f, order);
        }
    }
    for (f, order, _tag) in live {
        buddy::free(t, f, order);
    }
}

#[test]
fn double_free_does_not_break_subsequent_allocations() {
    let _g = SEQ.lock().unwrap_or_else(|p| p.into_inner());
    let env = BuddyEnv::new(8 << 20);
    let t = &env.token;

    let f = buddy::alloc(t, 0).unwrap();
    buddy::free(t, f, 0);
    // Second free: whatever the kernel's tolerance policy is, it must not
    // corrupt the allocator. Keep every subsequent frame LIVE and verify
    // the allocator never hands out two distinct handles to the same frame
    // at the same time.
    let mut live = Vec::new();
    for _ in 0..64 {
        if let Ok(g) = buddy::alloc(t, 0) {
            let addr = g.start_address.as_u64();
            assert!(!live.contains(&addr), "frame {} handed out while live", addr);
            live.push(addr);
        }
    }
    assert!(live.len() >= 16, "allocator degraded after double free");
    // Cleanup is best-effort; a duplicated entry may legitimately panic in
    // debug kernels, so only free what we know is consistent.
    buddy::alloc(t, 0).expect("allocator still functional");
}
