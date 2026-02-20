//! Runtime self-tests for demand paging (lazy VMA reservation + fault mapping).
//!
//! Runs only in test ISO (`feature = "selftest"`).

use alloc::sync::Arc;

use crate::{
    memory::address_space::{AddressSpace, VmaFlags, VmaType},
    process::{add_task, Task, TaskPriority},
};

const DP_ADDR_A: u64 = 0x0000_5100_0000;
const DP_ADDR_B: u64 = 0x0000_5101_0000;
const DP_ADDR_C: u64 = 0x0000_5102_0000;

fn rw_flags() -> VmaFlags {
    VmaFlags {
        readable: true,
        writable: true,
        executable: false,
        user_accessible: true,
    }
}

fn new_user_as() -> Result<Arc<AddressSpace>, &'static str> {
    Ok(Arc::new(AddressSpace::new_user()?))
}

fn test_fault_maps_and_refcount() -> bool {
    let aspace = match new_user_as() {
        Ok(v) => v,
        Err(e) => {
            crate::serial_println!("[dp-test] new_user failed: {}", e);
            return false;
        }
    };
    if aspace
        .reserve_region(
            DP_ADDR_A,
            2,
            rw_flags(),
            VmaType::Anonymous,
            crate::memory::address_space::VmaPageSize::Small,
        )
        .is_err()
    {
        return false;
    }

    if aspace.handle_fault(DP_ADDR_A).is_err() {
        return false;
    }
    let phys = match aspace.translate(x86_64::VirtAddr::new(DP_ADDR_A)) {
        Some(p) => p,
        None => return false,
    };

    unsafe {
        let ptr = crate::memory::phys_to_virt(phys.as_u64()) as *mut u64;
        *ptr = 0x1122_3344_5566_7788;
        if *ptr != 0x1122_3344_5566_7788 {
            return false;
        }
    }

    let frame = crate::memory::PhysFrame {
        start_address: phys,
    };
    if crate::memory::cow::frame_get_refcount(frame) != 1 {
        return false;
    }

    if aspace.unmap_range(DP_ADDR_A, 4096).is_err() {
        return false;
    }
    crate::memory::cow::frame_get_refcount(frame) == 0
}

fn test_repeat_fault_same_page_no_leak() -> bool {
    let aspace = match new_user_as() {
        Ok(v) => v,
        Err(_) => return false,
    };
    if aspace
        .reserve_region(
            DP_ADDR_B,
            1,
            rw_flags(),
            VmaType::Anonymous,
            crate::memory::address_space::VmaPageSize::Small,
        )
        .is_err()
    {
        return false;
    }

    if aspace.handle_fault(DP_ADDR_B).is_err() {
        return false;
    }
    let phys1 = match aspace.translate(x86_64::VirtAddr::new(DP_ADDR_B)) {
        Some(p) => p,
        None => return false,
    };

    if aspace.handle_fault(DP_ADDR_B).is_err() {
        return false;
    }
    let phys2 = match aspace.translate(x86_64::VirtAddr::new(DP_ADDR_B)) {
        Some(p) => p,
        None => return false,
    };
    if phys1 != phys2 {
        return false;
    }

    let frame = crate::memory::PhysFrame {
        start_address: phys1,
    };
    if crate::memory::cow::frame_get_refcount(frame) != 1 {
        return false;
    }
    if aspace.unmap_range(DP_ADDR_B, 4096).is_err() {
        return false;
    }
    crate::memory::cow::frame_get_refcount(frame) == 0
}

fn test_unmap_lazy_unfaulted_region() -> bool {
    let aspace = match new_user_as() {
        Ok(v) => v,
        Err(_) => return false,
    };
    if aspace
        .reserve_region(
            DP_ADDR_C,
            4,
            rw_flags(),
            VmaType::Anonymous,
            crate::memory::address_space::VmaPageSize::Small,
        )
        .is_err()
    {
        return false;
    }
    if aspace.unmap_range(DP_ADDR_C, 4 * 4096).is_err() {
        return false;
    }
    aspace.handle_fault(DP_ADDR_C).is_err()
}

extern "C" fn demand_paging_test_main() -> ! {
    crate::serial_println!("[dp-test] start");

    let t1 = test_fault_maps_and_refcount();
    crate::serial_println!(
        "[dp-test] fault map/refcount: {}",
        if t1 { "ok" } else { "FAIL" }
    );

    let t2 = test_repeat_fault_same_page_no_leak();
    crate::serial_println!(
        "[dp-test] repeat fault no-leak: {}",
        if t2 { "ok" } else { "FAIL" }
    );

    let t3 = test_unmap_lazy_unfaulted_region();
    crate::serial_println!(
        "[dp-test] unmap unfaulted lazy: {}",
        if t3 { "ok" } else { "FAIL" }
    );

    crate::serial_println!(
        "[dp-test] summary: {}",
        if t1 && t2 && t3 { "PASS" } else { "FAIL" }
    );
    crate::process::scheduler::exit_current_task(0);
}

pub fn create_demand_paging_test_task() {
    if let Ok(task) = Task::new_kernel_task(
        demand_paging_test_main,
        "demand-paging-test",
        TaskPriority::Normal,
    ) {
        add_task(task);
    } else {
        crate::serial_println!("[dp-test] failed to create task");
    }
}
