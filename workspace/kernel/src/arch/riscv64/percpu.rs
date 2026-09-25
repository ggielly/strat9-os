use core::{
    ptr,
    sync::atomic::{AtomicU64, Ordering},
};

extern "C" {
    static riscv_kernel_stack_top: u8;
}

pub const MAX_CPUS: usize = 32;

#[repr(C, align(64))]
struct PerCpu {
    cpu_index: AtomicU64,
    kernel_rsp: AtomicU64,
    trap_stack_top: AtomicU64,
    tlb_ready: AtomicU64,
    signal_pending: AtomicU64,
}

impl PerCpu {
    const fn new() -> Self {
        Self {
            cpu_index: AtomicU64::new(0),
            kernel_rsp: AtomicU64::new(0),
            trap_stack_top: AtomicU64::new(0),
            tlb_ready: AtomicU64::new(0),
            signal_pending: AtomicU64::new(0),
        }
    }
}

static PERCPU: [PerCpu; MAX_CPUS] = [const { PerCpu::new() }; MAX_CPUS];

pub fn init_boot_cpu(hart_id: u32) -> usize {
    let stack_top =
        unsafe { ptr::read_volatile(ptr::addr_of!(riscv_kernel_stack_top) as *const u64) };
    init_boot_cpu_with_stack(hart_id, stack_top)
}

pub fn init_boot_cpu_with_stack(hart_id: u32, stack_top: u64) -> usize {
    let index = activate_cpu(hart_id as usize);
    PERCPU[index]
        .trap_stack_top
        .store(stack_top, Ordering::Release);
    index
}

pub fn init_gs_base(cpu_index: usize) {
    activate_cpu(cpu_index);
}

pub fn current_cpu_index() -> usize {
    let pointer = read_scratch();
    if pointer == 0 {
        return 0;
    }
    let cpu_index = unsafe {
        (*(pointer as *const PerCpu))
            .cpu_index
            .load(Ordering::Acquire) as usize
    };
    if cpu_index < MAX_CPUS {
        cpu_index
    } else {
        0
    }
}

pub fn current_cpu_index_fast() -> usize {
    current_cpu_index()
}

pub fn cpu_count() -> usize {
    1
}

pub fn get_cpu_count() -> usize {
    1
}

pub fn set_kernel_rsp_current(rsp: u64) {
    let index = current_cpu_index();
    PERCPU[index].kernel_rsp.store(rsp, Ordering::Release);
}

pub fn kernel_rsp_current() -> Option<u64> {
    let index = current_cpu_index();
    let rsp = PERCPU[index].kernel_rsp.load(Ordering::Acquire);
    (rsp != 0).then_some(rsp)
}

pub fn mark_tlb_ready_current() {
    let index = current_cpu_index();
    PERCPU[index].tlb_ready.store(1, Ordering::Release);
}

pub fn tlb_ready(index: usize) -> bool {
    PERCPU
        .get(index)
        .map_or(false, |slot| slot.tlb_ready.load(Ordering::Acquire) != 0)
}

pub fn set_signal_pending_current() {
    let index = current_cpu_index();
    PERCPU[index].signal_pending.store(1, Ordering::Release);
}

pub fn test_and_clear_signal_pending_current() -> bool {
    let index = current_cpu_index();
    PERCPU[index].signal_pending.swap(0, Ordering::Acquire) != 0
}

fn activate_cpu(cpu_index: usize) -> usize {
    assert!(cpu_index < MAX_CPUS, "RISC-V hart index out of range");
    PERCPU[cpu_index]
        .cpu_index
        .store(cpu_index as u64, Ordering::Release);
    let pointer = &PERCPU[cpu_index] as *const PerCpu as usize;
    unsafe {
        core::arch::asm!("csrw sscratch, {0}", in(reg) pointer, options(nostack));
    }
    cpu_index
}

fn read_scratch() -> usize {
    let mut value = 0usize;
    unsafe {
        core::arch::asm!("csrr {0}, sscratch", out(reg) value, options(nostack, nomem));
    }
    value
}
