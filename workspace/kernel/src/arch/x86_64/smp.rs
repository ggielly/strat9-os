//! SMP (Symmetric Multi-Processing) boot for x86_64.
//!
//! Boots Application Processors (APs) using the legacy INIT+SIPI sequence
//! and parks them in an idle loop. Per-CPU data is initialized but no
//! per-CPU scheduler is active yet.

use core::arch::global_asm;
use core::sync::atomic::{AtomicUsize, Ordering};

use alloc::vec::Vec;
use alloc::vec;
use x86_64::{PhysAddr, VirtAddr};
use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB};

use crate::acpi::madt;
use crate::arch::x86_64::{apic, idt, io::io_wait, percpu, timer};
use crate::memory;
use crate::process::task::KernelStack;
use crate::sync::SpinLock;

/// Physical address where the SMP trampoline is copied.
pub const TRAMPOLINE_PHYS_ADDR: u64 = 0x8000;

/// Number of booted cores (starts at 1 for BSP).
static BOOTED_CORES: AtomicUsize = AtomicUsize::new(1);

/// Keep AP kernel stacks alive.
static AP_KERNEL_STACKS: SpinLock<Vec<KernelStack>> = SpinLock::new(Vec::new());

#[cfg(target_arch = "x86_64")]
global_asm!(
    r#"
.section .text
.code16

.global smp_trampoline
.global smp_trampoline_end

.set SMP_VAR_ADDR, 0x8000 + (smp_trampoline_end - smp_trampoline)

smp_trampoline:
    cli
    cld
    ljmp 0, 0x8040

.align 16
_gdt_table:
    .long 0, 0
    .long 0x0000ffff, 0x00af9a00 # code 64
    .long 0x0000ffff, 0x00cf9200 # data
    .long 0x0000ffff, 0x00cf9a00 # code 32
_gdt:
    .word _gdt - _gdt_table - 1
    .long 0x8010
    .long 0, 0
.align 64

    xor ax, ax
    mov ds, ax
    lgdt [0x8030]
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    ljmp 24, 0x8060

.align 32
.code32
    mov ax, 16
    mov ds, ax
    mov ss, ax

    # Get Local APIC ID
    mov eax, 1
    cpuid
    shr ebx, 24

    # Set PML4 physical address
    mov eax, [SMP_VAR_ADDR]
    mov cr3, eax

    # Enable PSE and PAE
    mov eax, cr4
    or eax, 0x30
    mov cr4, eax

    # Enable LME
    mov ecx, 0xc0000080 # EFER
    xor edx, edx
    rdmsr
    or eax, 0x901
    wrmsr

    # Enable paging and write protect
    mov eax, cr0
    or eax, 0x80010000
    mov cr0, eax

    ljmp 8, 0x80c0

.align 32
.code64
    # Setup local stack
    mov rsp, [SMP_VAR_ADDR + 8]
    shl rbx, 3
    add rsp, rbx
    mov rsp, [rsp]

    push 0
    popfq

    movabs rax, offset smp_main
    jmp rax

.align 8
smp_trampoline_end:
"#
);

unsafe extern "C" {
    fn smp_trampoline();
    fn smp_trampoline_end();
}

/// Busy-wait for the given number of microseconds (very rough).
fn udelay(us: u32) {
    for _ in 0..us {
        io_wait();
    }
}

fn ensure_identity_mapping(phys_start: u64, length: usize) {
    let start = phys_start & !0xFFFu64;
    let end = (phys_start + length as u64 + 0xFFF) & !0xFFFu64;
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

    let mut addr = start;
    while addr < end {
        let virt = VirtAddr::new(addr);
        if let Some(mapped) = crate::memory::paging::translate(virt) {
            if mapped.as_u64() != addr {
                log::warn!(
                    "SMP: identity map collision at {:#x} -> {:#x}",
                    addr,
                    mapped.as_u64()
                );
            }
        } else {
            let page = Page::<Size4KiB>::containing_address(virt);
            let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(addr));
            if let Err(e) = crate::memory::paging::map_page(page, frame, flags) {
                log::error!("SMP: failed to identity map {:#x}: {}", addr, e);
            }
        }
        addr += 0x1000;
    }
}

fn copy_trampoline(cr3_phys: u64, stacks_ptr: *const u64) {
    let tramp_len = (smp_trampoline_end as *const u8 as usize)
        .saturating_sub(smp_trampoline as *const u8 as usize);

    ensure_identity_mapping(TRAMPOLINE_PHYS_ADDR, tramp_len + 16);

    let tramp_virt = memory::phys_to_virt(TRAMPOLINE_PHYS_ADDR) as *mut u8;

    // SAFETY: trampoline destination is mapped and writable in HHDM.
    unsafe {
        core::ptr::copy_nonoverlapping(smp_trampoline as *const u8, tramp_virt, tramp_len);
        let ptrs = tramp_virt.add(tramp_len) as *mut u64;
        core::ptr::write_volatile(ptrs, cr3_phys);
        core::ptr::write_volatile(ptrs.add(1), stacks_ptr as u64);
    }
}

fn wait_delivery() {
    const DELIVERY_STATUS: u32 = 1 << 12;
    for _ in 0..1_000_000 {
        // SAFETY: APIC initialized, ICR low is readable.
        let val = unsafe { apic::read_reg(apic::REG_ICR_LOW) };
        if val & DELIVERY_STATUS == 0 {
            return;
        }
        core::hint::spin_loop();
    }
    log::warn!("SMP: IPI delivery timeout");
}

fn send_ipi(apic_id: u32, value: u32) {
    unsafe {
        apic::write_reg(apic::REG_ESR, 0);
        apic::write_reg(apic::REG_ESR, 0);
        apic::write_reg(apic::REG_ICR_HIGH, apic_id << 24);
        apic::write_reg(apic::REG_ICR_LOW, value);
    }
    wait_delivery();
}

fn send_init_sipi(apic_id: u32) {
    // INIT IPI (assert)
    send_ipi(apic_id, 0x0000_c500);
    udelay(10_000);

    // INIT de-assert
    send_ipi(apic_id, 0x0000_8500);
    udelay(200);

    // SIPI twice, vector = 0x8 (0x8000 >> 12)
    for _ in 0..2 {
        send_ipi(apic_id, 0x0000_0608);
        udelay(200);
    }
}

/// Boot Application Processors.
pub fn init() -> Result<usize, &'static str> {
    if !apic::is_initialized() {
        return Err("APIC not initialized");
    }

    BOOTED_CORES.store(1, Ordering::Release);

    let madt_info = madt::parse_madt().ok_or("MADT not available")?;
    let bsp_apic_id = apic::lapic_id();

    if madt_info.local_apic_count <= 1 {
        log::info!("SMP: single CPU system");
        return Ok(1);
    }

    let mut max_apic_id: usize = 0;
    for i in 0..madt_info.local_apic_count {
        if let Some(ref entry) = madt_info.local_apics[i] {
            max_apic_id = max_apic_id.max(entry.apic_id as usize);
        }
    }

    let mut stacks: Vec<u64> = vec![0; max_apic_id + 1];
    let cr3_phys = crate::memory::paging::kernel_l4_phys().as_u64();
    let mut targets: Vec<u32> = Vec::new();
    let mut expected: usize = 1;

    for i in 0..madt_info.local_apic_count {
        let Some(ref entry) = madt_info.local_apics[i] else {
            continue;
        };

        let apic_id = entry.apic_id as u32;
        if apic_id == bsp_apic_id {
            continue;
        }

        let kernel_stack = KernelStack::allocate(crate::process::task::Task::DEFAULT_STACK_SIZE)?;
        let stack_top = kernel_stack.virt_base.as_u64() + kernel_stack.size as u64;

        if apic_id as usize >= stacks.len() {
            log::warn!("SMP: APIC id {} out of stack array range", apic_id);
            continue;
        }

        stacks[apic_id as usize] = stack_top;

        let cpu_index = percpu::register_cpu(apic_id)
            .ok_or("SMP: exceeded MAX_CPUS for per-CPU data")?;
        percpu::set_kernel_stack_top(cpu_index, stack_top);

        AP_KERNEL_STACKS.lock().push(kernel_stack);
        targets.push(apic_id);
        expected += 1;
    }

    copy_trampoline(cr3_phys, stacks.as_ptr());

    for apic_id in targets {
        send_init_sipi(apic_id);
    }

    while BOOTED_CORES.load(Ordering::Acquire) < expected {
        core::hint::spin_loop();
    }

    log::info!("SMP: {} cores online", expected);
    Ok(expected)
}

/// First Rust function executed on APs after the trampoline.
#[unsafe(no_mangle)]
pub extern "C" fn smp_main() -> ! {
    // Load IDT for this core (shared IDT is fine for now).
    idt::init();

    // Re-initialize Local APIC for this core (per-core registers).
    apic::init_ap();

    let apic_id = apic::lapic_id();
    let cpu_index = percpu::cpu_index_by_apic(apic_id).unwrap_or(0);

    // Initialize per-CPU TSS/GDT.
    crate::arch::x86_64::tss::init_cpu(cpu_index);
    crate::arch::x86_64::gdt::init_cpu(cpu_index);
    crate::arch::x86_64::percpu::init_gs_base(cpu_index);
    crate::arch::x86_64::syscall::init();

    if let Some(stack_top) = percpu::kernel_stack_top(cpu_index) {
        crate::arch::x86_64::tss::set_kernel_stack_for(
            cpu_index,
            x86_64::VirtAddr::new(stack_top),
        );
    }

    let _ = percpu::mark_online_by_apic(apic_id);
    BOOTED_CORES.fetch_add(1, Ordering::Release);

    // Start APIC timer on this CPU (uses cached calibration from BSP).
    timer::start_apic_timer_cached();

    // Start per-CPU scheduler (never returns).
    crate::process::scheduler::schedule_on_cpu(cpu_index);
}
