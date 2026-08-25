//! L1 — `alloc-freelist`: bump+free-list allocator behaviour.
//!
//! The macro generates a static `GlobalAlloc` over a fixed-size heap array,
//! used by every userspace component. Tests exercise the real allocator
//! (single-threaded here; the CAS lock is exercised implicitly).

use alloc_freelist::define_freelist_allocator;
use core::alloc::GlobalAlloc;
use core::alloc::Layout;

#[global_allocator]
static ALLOC: TestAlloc = TestAlloc;

// The macro defines the allocator struct in the consuming crate.
define_freelist_allocator!(pub struct TestAlloc; heap_size = 1 << 20;);

#[test]
fn basic_alloc_write_read_dealloc() {
    unsafe {
        let layout = Layout::from_size_align(128, 8).unwrap();
        let p = ALLOC.alloc(layout);
        assert!(!p.is_null());
        // Memory must be usable: write a pattern and read it back.
        for i in 0..128 {
            *p.add(i) = i as u8;
        }
        for i in 0..128 {
            assert_eq!(*p.add(i), i as u8);
        }
        ALLOC.dealloc(p, layout);
    }
}

#[test]
fn alignment_requests_are_honored() {
    unsafe {
        for align in [16usize, 64, 256, 4096] {
            let layout = Layout::from_size_align(64, align).unwrap();
            let p = ALLOC.alloc(layout);
            assert!(!p.is_null(), "align {} failed", align);
            assert_eq!(p as usize % align, 0, "pointer not {}-aligned", align);
            ALLOC.dealloc(p, layout);
        }
    }
}

#[test]
fn zero_sized_and_min_block_handling() {
    unsafe {
        // Zero-size requests still return a usable unique pointer or null —
        // but must never crash. The freelist enforces MIN_BLOCK_SIZE.
        let layout = Layout::from_size_align(0, 8).unwrap();
        let p = ALLOC.alloc(layout);
        if !p.is_null() {
            ALLOC.dealloc(p, layout);
        }
    }
}

#[test]
fn freed_blocks_are_reused_by_the_free_list() {
    unsafe {
        // Allocate, free, then reallocate same size: with an exhausted
        // bump region this only works via the free list. Use a size big
        // enough to be distinctive but small vs heap.
        let layout = Layout::from_size_align(4096, 8).unwrap();
        let a = ALLOC.alloc(layout);
        assert!(!a.is_null());
        *(a as *mut u64) = 0xAAAA_AAAA_AAAA_AAAA;
        ALLOC.dealloc(a, layout);

        let b = ALLOC.alloc(layout);
        assert!(!b.is_null());
        // First-fit free list should hand back the just-freed block.
        assert_eq!(b, a, "freed block not reused by first-fit search");
        ALLOC.dealloc(b, layout);
    }
}

#[test]
fn many_allocations_do_not_collide() {
    unsafe {
        const N: usize = 200;
        let mut ptrs = [core::ptr::null_mut::<u8>(); N];
        for slot in ptrs.iter_mut() {
            let layout = Layout::from_size_align(96, 8).unwrap();
            *slot = ALLOC.alloc(layout);
            assert!(!slot.is_null());
        }
        // All pointers distinct.
        for i in 0..N {
            for j in (i + 1)..N {
                assert_ne!(ptrs[i], ptrs[j]);
            }
        }
        // Write distinct patterns to prove no aliasing.
        for (i, p) in ptrs.iter().enumerate() {
            let p: *mut u8 = *p;
            unsafe { *p = i as u8 };
            unsafe { *p.add(95) = (i ^ 0xFF) as u8 };
        }
        for (i, p) in ptrs.iter().enumerate() {
            let p: *mut u8 = *p;
            unsafe { assert_eq!(*p, i as u8) };
            unsafe { assert_eq!(*p.add(95), (i ^ 0xFF) as u8) };
        }
        for p in ptrs.iter() {
            ALLOC.dealloc(*p, Layout::from_size_align(96, 8).unwrap());
        }
    }
}

#[test]
fn oversized_allocation_returns_null_not_panics() {
    unsafe {
        // Valid layouts far beyond the 1 MiB heap: must fail cleanly (null),
        // never panic nor wrap around into bumping the small static heap.
        let layout = Layout::from_size_align(4 << 30, 8).unwrap(); // 4 GiB
        let p = ALLOC.alloc(layout);
        assert!(p.is_null(), "absurd allocation must fail cleanly");

        let layout = Layout::from_size_align(1 << 30, 8).unwrap(); // 1 GiB
        let p = ALLOC.alloc(layout);
        assert!(p.is_null());
    }
}
