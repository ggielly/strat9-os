#![no_std]

#[macro_export]
macro_rules! define_freelist_allocator {
    ($vis:vis struct $name:ident; heap_size = $heap_size:expr;) => {
        $vis struct $name;

        #[repr(C)]
        struct __FreeNode {
            size: usize,
            next: *mut __FreeNode,
        }

        static __ALLOC_LOCK: core::sync::atomic::AtomicUsize =
            core::sync::atomic::AtomicUsize::new(0);
        static __FREE_LIST_HEAD: core::sync::atomic::AtomicUsize =
            core::sync::atomic::AtomicUsize::new(0);
        static __HEAP_OFFSET: core::sync::atomic::AtomicUsize =
            core::sync::atomic::AtomicUsize::new(0);
        static mut __HEAP: [u8; $heap_size] = [0u8; $heap_size];

        const __MIN_ALIGN: usize = core::mem::align_of::<usize>();
        const __MIN_BLOCK_SIZE: usize = core::mem::size_of::<__FreeNode>();

        #[inline]
        fn __align_up(v: usize, align: usize) -> usize {
            (v + align - 1) & !(align - 1)
        }

        #[inline]
        fn __lock_alloc() {
            while __ALLOC_LOCK
                .compare_exchange(
                    0,
                    1,
                    core::sync::atomic::Ordering::Acquire,
                    core::sync::atomic::Ordering::Relaxed,
                )
                .is_err()
            {
                core::hint::spin_loop();
            }
        }

        #[inline]
        fn __unlock_alloc() {
            __ALLOC_LOCK.store(0, core::sync::atomic::Ordering::Release);
        }

        #[inline]
        fn __alloc_size(layout: core::alloc::Layout) -> usize {
            __align_up(layout.size().max(__MIN_BLOCK_SIZE), __MIN_BLOCK_SIZE)
        }

        unsafe impl core::alloc::GlobalAlloc for $name {
            #[allow(unsafe_op_in_unsafe_fn)]
            unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
                let align = layout.align().max(__MIN_ALIGN);
                let size = __alloc_size(layout);

                __lock_alloc();

                let mut prev: *mut __FreeNode = core::ptr::null_mut();
                let mut cur = __FREE_LIST_HEAD.load(core::sync::atomic::Ordering::Relaxed)
                    as *mut __FreeNode;
                while !cur.is_null() {
                    let cur_addr = cur as usize;
                    if cur_addr % align == 0 && (*cur).size >= size {
                        let cur_size = (*cur).size;
                        let next = (*cur).next;
                        let rem = cur_size - size;

                        if rem >= __MIN_BLOCK_SIZE {
                            let rem_ptr = (cur_addr + size) as *mut __FreeNode;
                            (*rem_ptr).size = rem;
                            (*rem_ptr).next = next;
                            if prev.is_null() {
                                __FREE_LIST_HEAD
                                    .store(rem_ptr as usize, core::sync::atomic::Ordering::Relaxed);
                            } else {
                                (*prev).next = rem_ptr;
                            }
                        } else if prev.is_null() {
                            __FREE_LIST_HEAD.store(next as usize, core::sync::atomic::Ordering::Relaxed);
                        } else {
                            (*prev).next = next;
                        }

                        __unlock_alloc();
                        return cur as *mut u8;
                    }
                    prev = cur;
                    cur = (*cur).next;
                }

                let raw_base = core::ptr::addr_of_mut!(__HEAP) as usize;
                let base = __align_up(raw_base, __MIN_ALIGN);
                let usable = ($heap_size as usize).saturating_sub(base - raw_base);

                let mut offset = __HEAP_OFFSET.load(core::sync::atomic::Ordering::Relaxed);
                loop {
                    let aligned = __align_up(base + offset, align) - base;
                    let next = match aligned.checked_add(size) {
                        Some(v) => v,
                        None => {
                            __unlock_alloc();
                            return core::ptr::null_mut();
                        }
                    };
                    if next > usable {
                        __unlock_alloc();
                        return core::ptr::null_mut();
                    }
                    match __HEAP_OFFSET.compare_exchange(
                        offset,
                        next,
                        core::sync::atomic::Ordering::SeqCst,
                        core::sync::atomic::Ordering::Relaxed,
                    ) {
                        Ok(_) => {
                            __unlock_alloc();
                            return (base + aligned) as *mut u8;
                        }
                        Err(prev_off) => offset = prev_off,
                    }
                }
            }

            #[allow(unsafe_op_in_unsafe_fn)]
            unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
                if ptr.is_null() {
                    return;
                }
                let size = __alloc_size(layout);

                __lock_alloc();

                let addr = ptr as usize;
                let node = ptr as *mut __FreeNode;
                (*node).size = size;
                (*node).next = core::ptr::null_mut();

                let mut prev: *mut __FreeNode = core::ptr::null_mut();
                let mut cur = __FREE_LIST_HEAD.load(core::sync::atomic::Ordering::Relaxed)
                    as *mut __FreeNode;
                while !cur.is_null() && (cur as usize) < addr {
                    prev = cur;
                    cur = (*cur).next;
                }

                (*node).next = cur;
                if prev.is_null() {
                    __FREE_LIST_HEAD.store(node as usize, core::sync::atomic::Ordering::Relaxed);
                } else {
                    (*prev).next = node;
                }

                if !cur.is_null() {
                    let node_end = addr + (*node).size;
                    if node_end == cur as usize {
                        (*node).size += (*cur).size;
                        (*node).next = (*cur).next;
                    }
                }

                if !prev.is_null() {
                    let prev_end = (prev as usize) + (*prev).size;
                    if prev_end == addr {
                        (*prev).size += (*node).size;
                        (*prev).next = (*node).next;
                    }
                }

                __unlock_alloc();
            }
        }
    };
}

#[macro_export]
macro_rules! define_freelist_brk_allocator {
    ($vis:vis struct $name:ident; brk = $brk:path; heap_max = $heap_max:expr;) => {
        $vis struct $name;

        #[repr(C)]
        struct __FreeNode {
            size: usize,
            next: *mut __FreeNode,
        }

        static __ALLOC_LOCK: core::sync::atomic::AtomicUsize =
            core::sync::atomic::AtomicUsize::new(0);
        static __FREE_LIST_HEAD: core::sync::atomic::AtomicUsize =
            core::sync::atomic::AtomicUsize::new(0);
        static __HEAP_OFFSET: core::sync::atomic::AtomicUsize =
            core::sync::atomic::AtomicUsize::new(0);
        static __HEAP_START: core::sync::atomic::AtomicUsize =
            core::sync::atomic::AtomicUsize::new(0);

        const __MIN_ALIGN: usize = core::mem::align_of::<usize>();
        const __MIN_BLOCK_SIZE: usize = core::mem::size_of::<__FreeNode>();

        #[inline]
        fn __align_up(v: usize, align: usize) -> usize {
            (v + align - 1) & !(align - 1)
        }

        #[inline]
        fn __lock_alloc() {
            while __ALLOC_LOCK
                .compare_exchange(
                    0,
                    1,
                    core::sync::atomic::Ordering::Acquire,
                    core::sync::atomic::Ordering::Relaxed,
                )
                .is_err()
            {
                core::hint::spin_loop();
            }
        }

        #[inline]
        fn __unlock_alloc() {
            __ALLOC_LOCK.store(0, core::sync::atomic::Ordering::Release);
        }

        #[inline]
        fn __alloc_size(layout: core::alloc::Layout) -> usize {
            __align_up(layout.size().max(__MIN_BLOCK_SIZE), __MIN_BLOCK_SIZE)
        }

        unsafe impl core::alloc::GlobalAlloc for $name {
            #[allow(unsafe_op_in_unsafe_fn)]
            unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
                let align = layout.align().max(__MIN_ALIGN);
                let size = __alloc_size(layout);

                __lock_alloc();

                let mut prev: *mut __FreeNode = core::ptr::null_mut();
                let mut cur = __FREE_LIST_HEAD.load(core::sync::atomic::Ordering::Relaxed)
                    as *mut __FreeNode;
                while !cur.is_null() {
                    let cur_addr = cur as usize;
                    if cur_addr % align == 0 && (*cur).size >= size {
                        let cur_size = (*cur).size;
                        let next = (*cur).next;
                        let rem = cur_size - size;

                        if rem >= __MIN_BLOCK_SIZE {
                            let rem_ptr = (cur_addr + size) as *mut __FreeNode;
                            (*rem_ptr).size = rem;
                            (*rem_ptr).next = next;
                            if prev.is_null() {
                                __FREE_LIST_HEAD
                                    .store(rem_ptr as usize, core::sync::atomic::Ordering::Relaxed);
                            } else {
                                (*prev).next = rem_ptr;
                            }
                        } else if prev.is_null() {
                            __FREE_LIST_HEAD.store(next as usize, core::sync::atomic::Ordering::Relaxed);
                        } else {
                            (*prev).next = next;
                        }

                        __unlock_alloc();
                        return cur as *mut u8;
                    }
                    prev = cur;
                    cur = (*cur).next;
                }

                let mut start = __HEAP_START.load(core::sync::atomic::Ordering::Relaxed);
                if start == 0 {
                    if let Ok(cur) = $brk(0) {
                        if $brk(cur + ($heap_max as usize)).is_ok() {
                            __HEAP_START.store(cur, core::sync::atomic::Ordering::SeqCst);
                            start = cur;
                        } else {
                            __unlock_alloc();
                            return core::ptr::null_mut();
                        }
                    } else {
                        __unlock_alloc();
                        return core::ptr::null_mut();
                    }
                }

                let base = __align_up(start, __MIN_ALIGN);
                let usable = ($heap_max as usize).saturating_sub(base - start);
                let mut offset = __HEAP_OFFSET.load(core::sync::atomic::Ordering::Relaxed);
                loop {
                    let aligned = __align_up(base + offset, align) - base;
                    let next = match aligned.checked_add(size) {
                        Some(v) => v,
                        None => {
                            __unlock_alloc();
                            return core::ptr::null_mut();
                        }
                    };
                    if next > usable {
                        __unlock_alloc();
                        return core::ptr::null_mut();
                    }
                    match __HEAP_OFFSET.compare_exchange(
                        offset,
                        next,
                        core::sync::atomic::Ordering::SeqCst,
                        core::sync::atomic::Ordering::Relaxed,
                    ) {
                        Ok(_) => {
                            __unlock_alloc();
                            return (base + aligned) as *mut u8;
                        }
                        Err(prev_off) => offset = prev_off,
                    }
                }
            }

            #[allow(unsafe_op_in_unsafe_fn)]
            unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
                if ptr.is_null() {
                    return;
                }
                let size = __alloc_size(layout);

                __lock_alloc();

                let addr = ptr as usize;
                let node = ptr as *mut __FreeNode;
                (*node).size = size;
                (*node).next = core::ptr::null_mut();

                let mut prev: *mut __FreeNode = core::ptr::null_mut();
                let mut cur = __FREE_LIST_HEAD.load(core::sync::atomic::Ordering::Relaxed)
                    as *mut __FreeNode;
                while !cur.is_null() && (cur as usize) < addr {
                    prev = cur;
                    cur = (*cur).next;
                }

                (*node).next = cur;
                if prev.is_null() {
                    __FREE_LIST_HEAD.store(node as usize, core::sync::atomic::Ordering::Relaxed);
                } else {
                    (*prev).next = node;
                }

                if !cur.is_null() {
                    let node_end = addr + (*node).size;
                    if node_end == cur as usize {
                        (*node).size += (*cur).size;
                        (*node).next = (*cur).next;
                    }
                }

                if !prev.is_null() {
                    let prev_end = (prev as usize) + (*prev).size;
                    if prev_end == addr {
                        (*prev).size += (*node).size;
                        (*prev).next = (*node).next;
                    }
                }

                __unlock_alloc();
            }
        }
    };
}
