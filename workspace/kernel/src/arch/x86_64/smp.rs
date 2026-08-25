//! SMP (Symmetric Multi-Processing) boot for x86_64.
//!
//! Boots Application Processors (APs) using the legacy INIT+SIPI sequence.
//! Inspired by Redox-OS's approach: a minimal trampoline does the 16=>64 bit
//! mode switch, then jumps directly to `smp_main` in Rust.
//!
//! Data layout after the trampoline code (written by BSP, read by AP):
//!   offset +0: PML4 physical address (CR3)
//!   offset +8: kernel stack top virtual address (RSP)
//!
//! Synchronization: AP increments `BOOTED_CORES` after finishing per-CPU init.
//! BSP spins until all expected APs are online.

use core::{
    arch::global_asm,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use alloc::{vec, vec::Vec};
use x86_64::{
    structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB},
    PhysAddr, VirtAddr,
};

use crate::{
    acpi::madt,
    arch::x86_64::{apic, idt, io::io_wait, percpu, timer},
    memory,
};

/// Physical address where the SMP trampoline is copied.
pub const TRAMPOLINE_PHYS_ADDR: u64 = 0x8000;

/// Number of booted cores (starts at 1 for BSP).
static BOOTED_CORES: AtomicUsize = AtomicUsize::new(1);
/// Counter for synchronization barriers.
static SYNC_BARRIER: AtomicUsize = AtomicUsize::new(0);
/// Target count for the rendezvous barrier (set by BSP before barrier).
static BARRIER_TARGET: AtomicUsize = AtomicUsize::new(0);
/// Gate used by BSP to release APs into scheduler/timer start.
static AP_SCHED_GATE_OPEN: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Trampoline: 16-bit => 32-bit => 64-bit mode switch.
//
// The AP starts in real mode at the SIPI vector (0x8000).  This stub:
//   1. Loads a GDT embedded at known physical offsets.
//   2. Enables protected mode, then PAE + long mode + paging.
//   3. Loads the kernel PML4 (CR3) and kernel stack (RSP) from the data area.
//   4. Jumps to smp_main (64-bit Rust code).
//
// LAYOUT (physical addresses, copied to 0x8000):
//   0x8000:  cli ; cld ; ljmp 0, 0x8040         (16-bit)
//   0x8010:  _gdt_table  (32 bytes: null, code64, data, code32)
//   0x8030:  _gdt        (GDTR: limit=31, base=0x8010)
//   0x8040:  real-mode setup (xor ax,ax; lgdt; enter PM)
//   0x8060:  32-bit code (enable PAE + LME + paging)
//   0x80C0:  64-bit code (load stack, jump to smp_main)
//
// CRITICAL: The GDT table and descriptor MUST occupy these exact offsets.
// The `lgdt [0x8030]` instruction reads physical 0x8030 which contains the
// GDTR. Without this embedded GDT data, the AP loads garbage and triple-faults.
//
// Data area (at smp_trampoline_end, written by BSP via HHDM):
//   +0 u64: CR3 (PML4 physical address)
//   +8 u64: RSP (kernel stack top virtual address)
// ---------------------------------------------------------------------------
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
    # Jump over the GDT data : code continues at 0x8040.
    ljmp 0, 0x8040

# -------------------------------------------------------------------
# GDT : must be at physical offset 0x10 so that:
#   _gdt_table starts at 0x8010, _gdt (GDTR) is at 0x8030.
# -------------------------------------------------------------------
.align 16
_gdt_table:
    .long 0, 0                       # null  (selector 0)
    .long 0x0000ffff, 0x00af9a00     # code64 (selector 8):  64-bit ring-0
    .long 0x0000ffff, 0x00cf9200     # data   (selector 16): ring-0 rw
    .long 0x0000ffff, 0x00cf9a00     # code32 (selector 24): 32-bit ring-0
_gdt:
    .word _gdt - _gdt_table - 1      # limit = 31 (4 entries × 8 - 1)
    .long 0x8010                     # base  = 0x8010
    .long 0, 0                       # padding
.align 64

# -------------------------------------------------------------------
# Real-mode setup continues at 0x8040.
# -------------------------------------------------------------------
    xor ax, ax
    mov ds, ax
    lgdt [0x8030]                    # loads GDTR from 0x8030

    # Enter protected mode
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    ljmp 24, 0x8060                  # => code32 segment

.align 32
.code32
    mov ax, 16
    mov ds, ax
    mov ss, ax

    # Enable PAE + PSE + OSFXSR + OSXMMEXCPT
    # NOTE: do NOT force SMEP/SMAP (CR4 bits 20/21) here. qemu64 (and many
    # older hosts) lack them: `mov cr4` then raises #GP and the AP dies
    # silently (no IDT yet -> triple fault -> "waiting for APs" hang).
    # Feature-gated bits (OSXSAVE, SMEP, SMAP) are enabled conditionally
    # in Rust once CPUID detection has run.
    mov eax, cr4
    or eax, 0x630
    mov cr4, eax

    # Enable Long Mode (EFER.LME)
    mov ecx, 0xc0000080
    xor edx, edx
    rdmsr
    or eax, 0x901                    # LME + SCE
    wrmsr

    # Load kernel PML4 from data area
    mov eax, [SMP_VAR_ADDR]
    mov cr3, eax

    # Enable paging (activates long mode)
    mov eax, cr0
    and eax, 0xFFFFFFFB              # Clear EM
    or eax, 0x80010002               # PG + WP + MP
    mov cr0, eax

    ljmp 8, 0x80c0                   # => code64 segment

.align 32
.code64
    # Load kernel stack pointer
    mov rsp, [SMP_VAR_ADDR + 8]

    # Clear RFLAGS
    push 0
    popfq

    # Jump to smp_main (Rust)
    # NOTE: must use movabs (64-bit absolute), NOT RIP-relative lea.
    # The trampoline is copied to 0x8000, so RIP-relative would compute
    # an offset based on the wrong base address (the linker's original
    # placement in the kernel .text section, not 0x8000).
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

/// Identity-map the trampoline physical pages so the AP can execute the
/// trampoline code in real mode / protected mode before paging is enabled.
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

/// Copy the trampoline to physical address 0x8000 and write the data area.
///
/// Data area layout (at smp_trampoline_end):
///   +0: CR3 (PML4 physical address)
///   +8: RSP (kernel stack top virtual address)
///
/// After writing, performs WBINVD to flush the cache hierarchy to RAM.
/// This is essential on real hardware: the BSP writes the trampoline via
/// HHDM (WB cacheable), but the AP boots in real mode where the effective
/// memory type is determined by MTRRs. If MTRRs mark the region as UC, or
/// if platform firmware does not guarantee cache coherency, the AP would
/// read stale data from RAM without this flush.
fn copy_trampoline(cr3_phys: u64, stack_top_virt: u64) {
    let tramp_len = (smp_trampoline_end as *const u8 as usize)
        .saturating_sub(smp_trampoline as *const u8 as usize);

    ensure_identity_mapping(TRAMPOLINE_PHYS_ADDR, tramp_len + 16);

    let tramp_virt = memory::phys_to_virt(TRAMPOLINE_PHYS_ADDR) as *mut u8;

    // SAFETY: trampoline destination is mapped and writable in HHDM.
    unsafe {
        core::ptr::copy_nonoverlapping(smp_trampoline as *const u8, tramp_virt, tramp_len);
        let data = tramp_virt.add(tramp_len) as *mut u64;
        // +0: CR3
        core::ptr::write_volatile(data, cr3_phys);
        // +8: RSP (stack top virtual address)
        core::ptr::write_volatile(data.add(1), stack_top_virt);

        // SFENCE + WBINVD: ensure all stores reach RAM before the AP starts.
        core::arch::asm!("sfence");
        core::arch::asm!("wbinvd");
    }
}

/// Wait for ICR delivery to complete.
///
/// In x2APIC mode, the ICR MSR write is synchronous : the CPU blocks until
/// the IPI is dispatched, so there is nothing to wait for.  In xAPIC mode,
/// we poll the delivery-pending bit (ICR_LOW bit 12) until it clears.
fn wait_delivery() {
    // x2APIC: MSR write is synchronous, no pending bit to poll.
    if apic::is_x2apic_enabled() {
        return;
    }

    const DELIVERY_PENDING: u32 = 1 << 12;
    for i in 0..1_000_000 {
        let val = unsafe { apic::read_reg(apic::REG_ICR_LOW) };
        if val & DELIVERY_PENDING == 0 {
            return;
        }
        if i > 0 && i % 200_000 == 0 {
            crate::serial_println!(
                "[smp] wait_delivery: still pending (iter={}, icr={:#x})",
                i,
                val,
            );
        }
        core::hint::spin_loop();
    }
    let final_val = unsafe { apic::read_reg(apic::REG_ICR_LOW) };
    crate::serial_println!("[smp] wait_delivery: TIMEOUT, final icr={:#x}", final_val,);
    log::warn!("SMP: IPI delivery timeout");
}

/// Send an IPI and wait for delivery.
fn send_ipi(apic_id: u32, value: u32) {
    apic::send_ipi_raw(apic_id, value);
    wait_delivery();
}

/// Send INIT + SIPI×2 to an AP per Intel SDM Volume 3, Section 10.6.7.1.
///
/// The Intel SDM recommends sending SIPI twice (200 µs apart) so that if
/// the first SIPI is missed, the second one still catches the AP. Some
/// platforms (Redox-OS) succeed with a single SIPI, but sending two is
/// more robust and matches Linux/FreeBSD behaviour.
///
///   Step 1: INIT level-assert (0xC500) : wait ≥10 ms
///   Step 2: INIT level-de-assert (0x8500) : wait ≥200 µs
///   Step 3: SIPI (0x4608, vector=0x08 => trampoline at 0x8000) : 200 µs
///   Step 4: SIPI again : 200 µs
///
/// ICR values (xAPIC format, delivery-mode bit-fields):
///   INIT:  delivery=INIT(101), level=1(assert), trigger=1(level)
///   Deassert: delivery=INIT(101), level=0(de-assert), trigger=1(level)
///   SIPI:  delivery=STARTUP(110), level=1, vector=0x8
fn send_init_sipi(apic_id: u32) {
    crate::serial_println!("[smp] send_init_sipi: apic_id={}", apic_id);

    // Step 1: INIT level-assert
    crate::serial_println!("[smp]   INIT assert -> {}", apic_id);
    send_ipi(apic_id, 0xC500);
    udelay(10_000);

    // Step 2: INIT level-de-assert
    crate::serial_println!("[smp]   INIT de-assert -> {}", apic_id);
    send_ipi(apic_id, 0x8500);
    udelay(200);

    // Step 3: SIPI #1
    crate::serial_println!("[smp]   SIPI (1/2) -> {} (vector=0x8)", apic_id);
    send_ipi(apic_id, 0x0608);
    udelay(200);

    // Step 4: SIPI #2  (SDM recommends two SIPIs)
    crate::serial_println!("[smp]   SIPI (2/2) -> {} (vector=0x8)", apic_id);
    send_ipi(apic_id, 0x0608);
    udelay(200);

    crate::serial_println!("[smp]   INIT+SIPI complete for {}", apic_id);
}

/// Broadcast a halt command to all other CPUs.
///
/// Used during panic to stop the system and prevent log corruption.
pub fn broadcast_panic_halt() {
    if !apic::is_initialized() {
        return;
    }
    let icr_low = (0b11 << 18) | (0b100 << 8) | (1 << 14);
    apic::send_ipi_raw(0, icr_low);
}

/// Wait at a synchronization barrier until all expected CPUs arrive.
fn rendezvous_barrier() {
    let expected = BARRIER_TARGET.load(Ordering::Acquire);
    SYNC_BARRIER.fetch_add(1, Ordering::AcqRel);
    while SYNC_BARRIER.load(Ordering::Acquire) < expected {
        core::hint::spin_loop();
    }
}

/// Boot Application Processors.
///
/// AP kernel stack frames are allocated from the buddy allocator during this
/// function and intentionally leaked (never freed). The allocation happens
/// once at boot while only the BSP is online, so there is no lock contention
/// and no risk of heap exhaustion under concurrent pressure.
///
/// If CPU hotplug is added in the future, stack allocation must be moved to
/// a sleepable context (e.g. `Mutex`-protected) to avoid heap allocation
/// under any spinlock that could be held during hot-add.
pub fn init() -> Result<usize, &'static str> {
    crate::serial_println!("[smp] init: entering SMP initialization");
    if !apic::is_initialized() {
        crate::serial_println!("[smp] init: ERROR - APIC not initialized");
        return Err("APIC not initialized");
    }

    BOOTED_CORES.store(1, Ordering::Release);
    SYNC_BARRIER.store(0, Ordering::Release);
    BARRIER_TARGET.store(0, Ordering::Release);

    let madt_info = madt::parse_madt().ok_or("MADT not available")?;
    let bsp_apic_id = apic::lapic_id();

    crate::serial_println!(
        "[smp] init: MADT parsed, {} local APICs, BSP apic_id={}",
        madt_info.local_apic_count,
        bsp_apic_id,
    );

    if madt_info.local_apic_count <= 1 {
        crate::serial_println!("[smp] init: single CPU system, returning");
        log::info!("SMP: single CPU system");
        return Ok(1);
    }

    let mut max_apic_id: usize = 0;
    for i in 0..madt_info.local_apic_count {
        if let Some(ref entry) = madt_info.local_apics[i] {
            crate::serial_println!(
                "[smp]   APIC[{}]: id={} proc={} flags={:#x} {}",
                i,
                entry.apic_id,
                entry.processor,
                entry.flags,
                if entry.flags & 1 == 0 {
                    "(DISABLED)"
                } else {
                    ""
                },
            );
            max_apic_id = max_apic_id.max(entry.apic_id as usize);
        }
    }

    let mut stack_tops: Vec<u64> = vec![0; max_apic_id + 1];
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

        // Allocate AP kernel stack from the buddy allocator.
        let stack_size = crate::process::task::Task::DEFAULT_STACK_SIZE;
        let pages = (stack_size + 4095) / 4096;
        let order = pages.next_power_of_two().trailing_zeros() as u8;
        let frame = crate::sync::with_irqs_disabled(|token| {
            crate::memory::allocate_phys_contiguous(token, order)
        })
        .map_err(|_| "SMP: failed to allocate AP stack from buddy")?;
        let stack_phys = frame.start_address.as_u64();
        let stack_virt = crate::memory::phys_to_virt(stack_phys);

        // Zero the stack.
        unsafe { core::ptr::write_bytes(stack_virt as *mut u8, 0, stack_size) };

        // Stack grows downward: top = base_virt + size.
        let stack_top = stack_virt.saturating_add(stack_size as u64);

        if apic_id as usize >= stack_tops.len() {
            log::warn!("SMP: APIC id {} out of stack array range", apic_id);
            continue;
        }

        stack_tops[apic_id as usize] = stack_top;

        let cpu_index =
            percpu::register_cpu(apic_id).ok_or("SMP: exceeded MAX_CPUS for per-CPU data")?;
        percpu::set_kernel_stack_top(cpu_index, stack_top);

        targets.push(apic_id);
        expected += 1;
    }

    // Copy trampoline and write data area (CR3 + first AP's stack top).
    // All APs share the same CR3; each gets its own stack from stack_tops.
    // We write the first target's stack top; subsequent APs will use their
    // own stack (set up in smp_main via percpu::kernel_stack_top).
    let first_stack_top = targets
        .first()
        .and_then(|id| stack_tops.get(*id as usize))
        .copied()
        .unwrap_or(0);
    copy_trampoline(cr3_phys, first_stack_top);
    crate::serial_println!(
        "[smp] init: trampoline at {:#x}, cr3={:#x}, stack={:#x}",
        TRAMPOLINE_PHYS_ADDR,
        cr3_phys,
        first_stack_top,
    );

    // Send INIT + single SIPI to each AP (Redox-OS style, no broadcast INIT).
    crate::serial_println!("[smp] init: sending INIT+SIPI to {} APs", targets.len(),);
    for apic_id in &targets {
        // Each AP needs its own stack. Re-write the data area stack pointer
        // before each SIPI so the AP picks up the correct stack.
        if let Some(stack_top) = stack_tops.get(*apic_id as usize) {
            let tramp_len = (smp_trampoline_end as *const u8 as usize)
                .saturating_sub(smp_trampoline as *const u8 as usize);
            let data = memory::phys_to_virt(TRAMPOLINE_PHYS_ADDR) as *mut u64;
            unsafe {
                // +8: RSP
                core::ptr::write_volatile(data.add(tramp_len / 8 + 1), *stack_top);
            }
        }
        send_init_sipi(*apic_id);
    }

    // Wait for APs to come online (they increment BOOTED_CORES in smp_main).
    let mut spins: u64 = 0;
    const MAX_SPINS: u64 = 200_000_000;
    crate::serial_println!("[smp] init: waiting for APs (expected={})...", expected,);
    while BOOTED_CORES.load(Ordering::Acquire) < expected && spins < MAX_SPINS {
        if spins > 0 && spins % 50_000_000 == 0 {
            crate::serial_println!(
                "[smp] init: waiting... online={} expected={} spins={}",
                BOOTED_CORES.load(Ordering::Acquire),
                expected,
                spins,
            );
        }
        core::hint::spin_loop();
        spins = spins.saturating_add(1);
    }
    let online = BOOTED_CORES.load(Ordering::Acquire);
    crate::serial_println!(
        "[smp] init: AP wait done: online={} expected={} spins={}",
        online,
        expected,
        spins,
    );
    if online < expected {
        crate::serial_println!(
            "[smp] init: WARNING only {}/{} APs online",
            online,
            expected,
        );
        log::warn!(
            "SMP: timeout waiting APs (online={} expected={}), continuing",
            online,
            expected
        );
    }

    log::info!("SMP: {} cores online (expected {})", online, expected);

    // Publish barrier target so APs can proceed.
    BARRIER_TARGET.store(online, Ordering::Release);
    rendezvous_barrier();

    Ok(online)
}

/// First Rust function executed on APs after the trampoline.
///
/// The trampoline enables paging with the kernel's PML4, sets up the stack,
/// and jumps here. All virtual addresses are valid at this point.
#[unsafe(no_mangle)]
pub extern "C" fn smp_main() -> ! {
    // Early serial output : use raw port 0x3F8 directly since the AP
    // hasn't initialized the serial mutex yet.
    {
        use core::fmt::Write;
        let mut port = unsafe { uart_16550::SerialPort::new(0x3F8) };
        port.init();
        let _ = port.write_fmt(format_args!("[smp][ap] entered smp_main\n"));
    }

    idt::load();

    // Re-initialize Local APIC for this core.
    apic::init_ap();

    let apic_id = apic::lapic_id();
    {
        use core::fmt::Write;
        let mut port = unsafe { uart_16550::SerialPort::new(0x3F8) };
        let _ = port.write_fmt(format_args!("[smp][ap] apic_id={}\n", apic_id));
    }

    let cpu_index = match percpu::cpu_index_by_apic(apic_id) {
        Some(idx) => idx,
        None => {
            {
                use core::fmt::Write;
                let mut port = unsafe { uart_16550::SerialPort::new(0x3F8) };
                let _ = port.write_fmt(format_args!(
                    "[smp][ap] ERROR: apic_id={} not registered, halting\n",
                    apic_id
                ));
            }
            loop {
                core::hint::spin_loop();
            }
        }
    };

    // Initialize per-CPU GS base.
    crate::arch::x86_64::percpu::init_gs_base(cpu_index);

    // Initialize per-CPU TSS/GDT.
    crate::arch::x86_64::tss::init_cpu(cpu_index);
    crate::arch::x86_64::gdt::init_cpu(cpu_index);

    crate::arch::x86_64::syscall::init();
    crate::arch::x86_64::init_cpu_extensions();

    if let Some(stack_top) = percpu::kernel_stack_top(cpu_index) {
        crate::arch::x86_64::tss::set_kernel_stack_for(cpu_index, x86_64::VirtAddr::new(stack_top));
    }

    let _ = percpu::mark_online_by_apic(apic_id);
    BOOTED_CORES.fetch_add(1, Ordering::Release);

    {
        use core::fmt::Write;
        let mut port = unsafe { uart_16550::SerialPort::new(0x3F8) };
        let _ = port.write_fmt(format_args!(
            "[smp][ap] cpu_index={} online, waiting for barrier\n",
            cpu_index
        ));
    }

    // AP spins until BSP publishes the barrier target.
    while BARRIER_TARGET.load(Ordering::Acquire) == 0 {
        core::hint::spin_loop();
    }
    rendezvous_barrier();

    crate::serial_println!("[trace][ap] cpu_index={} entering scheduler", cpu_index);

    // Wait until BSP has finished scheduler initialization.
    while !AP_SCHED_GATE_OPEN.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }

    // Start APIC timer on this CPU.
    timer::start_apic_timer_cached();

    // Start per-CPU scheduler (never returns).
    crate::process::scheduler::schedule_on_cpu(cpu_index)
}

/// Return the number of online CPUs.
pub fn cpu_count() -> usize {
    BOOTED_CORES.load(Ordering::Acquire)
}

/// Allow APs to start their local timer and enter the scheduler.
pub fn open_ap_scheduler_gate() {
    AP_SCHED_GATE_OPEN.store(true, Ordering::Release);
}
