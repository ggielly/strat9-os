#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::alloc::Layout;
use core::panic::PanicInfo;
use strat9_syscall::call;

// ---------------------------------------------------------------------------
// Point 2 (à venir) : Allocateur de mémoire robuste.
// Pour l'instant on utilise un allocateur statique basique (bump allocator)
// pour que le code compile, mais il sera remplacé à l'étape 2.
// ---------------------------------------------------------------------------

struct DummyAllocator;

const HEAP_SIZE: usize = 1024 * 1024; // 1 MiB heap for now.
static mut HEAP: [u8; HEAP_SIZE] = [0u8; HEAP_SIZE];
static HEAP_OFFSET: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

unsafe impl core::alloc::GlobalAlloc for DummyAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align().max(1);
        let size = layout.size();
        let mut offset = HEAP_OFFSET.load(core::sync::atomic::Ordering::Relaxed);
        loop {
            let aligned = (offset + align - 1) & !(align - 1);
            let new_offset = match aligned.checked_add(size) {
                Some(v) => v,
                None => return core::ptr::null_mut(),
            };
            if new_offset > HEAP_SIZE {
                return core::ptr::null_mut();
            }
            match HEAP_OFFSET.compare_exchange(
                offset,
                new_offset,
                core::sync::atomic::Ordering::SeqCst,
                core::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => {
                    let heap_ptr = core::ptr::addr_of_mut!(HEAP) as *mut u8;
                    return unsafe { heap_ptr.add(aligned) };
                }
                Err(prev) => offset = prev,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static GLOBAL_ALLOCATOR: DummyAllocator = DummyAllocator;

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    let _ = call::write(1, b"[strate-wasm] OOM\n");
    call::exit(12);
}

// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let _ = call::write(1, b"[strate-wasm] PANIC!\n");
    call::exit(255);
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let _ = call::write(1, b"[strate-wasm] Starting WASM strate\n");

    // Pour l'instant on fait juste la preuve que wasmi est correctement importable.
    // L'initialisation du moteur se fera une fois l'allocateur géré (Point 2).
    let _engine = wasmi::Engine::default();

    let _ = call::write(1, b"[strate-wasm] WASMI engine successfully instantiated!\n");
    
    // On quitte proprement pour ce simple test.
    call::exit(0)
}
