//! Interrupt Descriptor Table (IDT) for Strat9-OS
//!
//! Handles CPU exceptions and hardware IRQs.
//! Inspired by MaestroOS `idt.rs` and Redox-OS kernel.

use super::{pic, tss};
use core::sync::atomic::{AtomicU32, Ordering};
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

/// IRQ interrupt vector numbers (PIC1_OFFSET + IRQ number)
#[allow(dead_code)]
pub mod irq {
    pub const TIMER: u8 = super::pic::PIC1_OFFSET; // IRQ0 = 0x20
    pub const KEYBOARD: u8 = super::pic::PIC1_OFFSET + 1; // IRQ1 = 0x21
    pub const CASCADE: u8 = super::pic::PIC1_OFFSET + 2; // IRQ2 = 0x22
    pub const MOUSE: u8 = super::pic::PIC1_OFFSET + 12; // IRQ12 = 0x2C
    pub const COM2: u8 = super::pic::PIC1_OFFSET + 3; // IRQ3 = 0x23
    pub const COM1: u8 = super::pic::PIC1_OFFSET + 4; // IRQ4 = 0x24
    pub const FLOPPY: u8 = super::pic::PIC1_OFFSET + 6; // IRQ6 = 0x26
    pub const ATA_PRIMARY: u8 = super::pic::PIC1_OFFSET + 14; // IRQ14 = 0x2E
    pub const ATA_SECONDARY: u8 = super::pic::PIC1_OFFSET + 15; // IRQ15 = 0x2F
}

/// Static IDT storage (must be 'static for load())
static mut IDT_STORAGE: InterruptDescriptorTable = InterruptDescriptorTable::new();
static USER_PF_TRACE_BUDGET: AtomicU32 = AtomicU32::new(64);

/// Initialize the IDT with exception handlers and IRQ handlers
pub fn init() {
    // SAFETY: Called once during single-threaded kernel init, before interrupts are enabled.
    unsafe {
        let idt = &raw mut IDT_STORAGE;

        // CPU exceptions
        (*idt).breakpoint.set_handler_fn(breakpoint_handler);
        (*idt).page_fault.set_handler_fn(page_fault_handler);
        (*idt)
            .general_protection_fault
            .set_handler_fn(general_protection_fault_handler);
        (*idt).invalid_opcode.set_handler_fn(invalid_opcode_handler);
        (*idt)
            .double_fault
            .set_handler_fn(double_fault_handler)
            .set_stack_index(tss::DOUBLE_FAULT_IST_INDEX);

        // Hardware IRQs (PIC remapped to 0x20+)
        let idt_ref = &mut *idt;
        idt_ref[irq::TIMER as u8].set_handler_fn(legacy_timer_handler);
        idt_ref[irq::KEYBOARD as u8].set_handler_fn(keyboard_handler);
        idt_ref[irq::MOUSE as u8].set_handler_fn(mouse_handler);

        // Spurious interrupt handler at vector 0xFF (APIC spurious vector)
        idt_ref[0xFF_u8].set_handler_fn(spurious_handler);

        // Cross-CPU reschedule IPI (vector 0xE0)
        idt_ref[super::apic::IPI_RESCHED_VECTOR as u8].set_handler_fn(resched_ipi_handler);

        // Cross-CPU TLB shootdown IPI (vector 0xF0)
        idt_ref[super::apic::IPI_TLB_SHOOTDOWN_VECTOR as u8].set_handler_fn(tlb_shootdown_handler);

        (*idt).load_unsafe();
    }

    log::debug!("IDT initialized with {} entries", 256);
}

/// Register the TLB shootdown IPI handler.
///
/// This is called by the TLB system during initialization to provide
/// the architecture-independent handler function.
pub fn register_tlb_shootdown_handler(handler: extern "C" fn()) {
    unsafe {
        let idt = &raw mut IDT_STORAGE;
        (&mut *idt)[super::apic::IPI_TLB_SHOOTDOWN_VECTOR as u8]
            .set_handler_fn(core::mem::transmute(handler));
        (*idt).load_unsafe();
    }
}

/// Register the Local APIC timer IRQ vector to use the timer handler.
pub fn register_lapic_timer_vector(vector: u8) {
    unsafe {
        let idt = &raw mut IDT_STORAGE;
        (&mut *idt)[vector].set_handler_fn(lapic_timer_handler);
        (*idt).load_unsafe();
    }
}

/// Register the AHCI storage controller IRQ handler.
///
/// Called after AHCI initialisation once the PCI interrupt line is known.
pub fn register_ahci_irq(irq: u8) {
    let vector = if irq < 16 {
        super::pic::PIC1_OFFSET + irq
    } else {
        irq
    };

    // SAFETY: called during kernel init, before the scheduler starts
    unsafe {
        let idt = &raw mut IDT_STORAGE;
        (&mut *idt)[vector].set_handler_fn(ahci_handler);
        (*idt).load_unsafe();
    }
    log::info!("AHCI IRQ {} registered on vector {:#x}", irq, vector);
}

/// Register the VirtIO block device IRQ handler
///
/// Called after VirtIO block device initialization to route the device's
/// IRQ to the correct handler.
pub fn register_virtio_block_irq(irq: u8) {
    // PCI INTx gives an IRQ line number (typically 0..15), while IDT expects
    // a vector number. Map legacy IRQ lines to the remapped interrupt vectors.
    let vector = if irq < 16 {
        super::pic::PIC1_OFFSET + irq
    } else {
        irq
    };

    // SAFETY: called during kernel init, before interrupts are fully enabled
    unsafe {
        let idt = &raw mut IDT_STORAGE;
        (&mut *idt)[vector].set_handler_fn(virtio_block_handler);
        (*idt).load_unsafe();
    }
    log::info!("VirtIO-blk IRQ {} registered on vector {:#x}", irq, vector);
}

// =============================================
// CPU Exception Handlers
// =============================================

/// Performs the breakpoint handler operation.
extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    log::warn!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

/// Performs the invalid opcode handler operation.
extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    let is_user = (stack_frame.code_segment.0 & 3) == 3;
    if is_user {
        if let Some(tid) = crate::process::current_task_id() {
            crate::silo::handle_user_fault(
                tid,
                crate::silo::SiloFaultReason::InvalidOpcode,
                stack_frame.instruction_pointer.as_u64(),
                0,
                stack_frame.instruction_pointer.as_u64(),
            );
            return;
        }
    }
    log::error!("EXCEPTION: INVALID OPCODE\n{:#?}", stack_frame);
    panic!("Invalid opcode");
}

/// Performs the page fault handler operation.
extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    use x86_64::registers::control::{Cr2, Cr3};
    let is_user = (stack_frame.code_segment.0 & 3) == 3;

    // Get the faulting address
    let fault_addr = Cr2::read();
    let fault_vaddr = fault_addr.as_ref().map(|v| v.as_u64()).unwrap_or(0);
    let rip = stack_frame.instruction_pointer.as_u64();
    let user_rsp = stack_frame.stack_pointer.as_u64();

    let mut trace_ctx = crate::trace::TraceTaskCtx::empty();
    let task = if is_user {
        crate::process::scheduler::current_task_clone()
    } else {
        crate::process::scheduler::current_task_clone_try()
    };

    if let Some(ref t) = task {
        let as_ref = unsafe { &*t.process.address_space.get() };
        trace_ctx = crate::trace::TraceTaskCtx {
            task_id: t.id.as_u64(),
            pid: t.pid,
            tid: t.tid,
            cr3: as_ref.cr3().as_u64(),
        };
    }

    let do_pf_trace = if is_user {
        USER_PF_TRACE_BUDGET
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                if v > 0 {
                    Some(v - 1)
                } else {
                    None
                }
            })
            .is_ok()
    } else {
        true
    };
    if do_pf_trace {
        crate::trace_mem!(
            crate::trace::category::MEM_PF,
            crate::trace::TraceKind::MemPageFault,
            error_code.bits() as u64,
            trace_ctx,
            rip,
            fault_vaddr,
            user_rsp,
            0
        );
    }

    // Try COW only for write-protection faults on already-present pages.
    // For not-present faults, demand paging should run first.
    if error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION)
        && error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE)
        && is_user
    {
        if let Some(ref t) = task {
            let address_space = unsafe { &*t.process.address_space.get() };
            if let Ok(vaddr) = fault_addr {
                match crate::syscall::fork::handle_cow_fault(vaddr.as_u64(), address_space) {
                    Ok(()) => {
                        crate::trace_mem!(
                            crate::trace::category::MEM_COW,
                            crate::trace::TraceKind::MemCow,
                            1,
                            trace_ctx,
                            rip,
                            vaddr.as_u64(),
                            0,
                            0
                        );
                        return;
                    }
                    Err(reason) => {
                        crate::trace_mem!(
                            crate::trace::category::MEM_COW,
                            crate::trace::TraceKind::MemCow,
                            0,
                            trace_ctx,
                            rip,
                            vaddr.as_u64(),
                            0,
                            0
                        );
                        crate::serial_println!(
                            "\x1b[31m[pagefault] COW resolve failed\x1b[0m: task={} \x1b[36mpid={}\x1b[0m tid={} \x1b[35maddr={:#x}\x1b[0m \x1b[35mrip={:#x}\x1b[0m err={}",
                            t.id.as_u64(),
                            t.pid,
                            t.tid,
                            vaddr.as_u64(),
                            stack_frame.instruction_pointer.as_u64(),
                            reason
                        );
                    }
                }
            }
        }
    }

    // Try Demand Paging (lazy allocation) if page is not present
    if !error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION) && is_user {
        if let Some(ref t) = task {
            let address_space = unsafe { &*t.process.address_space.get() };
            if let Ok(vaddr) = fault_addr {
                match address_space.handle_fault(vaddr.as_u64()) {
                    Ok(()) => return,
                    Err(_) => {
                        dump_user_pf_context(address_space, rip, user_rsp);
                    }
                }
            }
        }
    }

    if is_user {
        if let Some(tid) = crate::process::scheduler::current_task_id_try() {
            crate::silo::handle_user_fault(
                tid,
                crate::silo::SiloFaultReason::PageFault,
                fault_addr.map(|v| v.as_u64()).unwrap_or(0),
                error_code.bits() as u64,
                stack_frame.instruction_pointer.as_u64(),
            );
            return;
        }
    }

    // =========================================================================
    // Comprehensive page fault diagnostics dump
    // Uses serial_println! directly to avoid log framework deadlocks.
    // =========================================================================
    dump_page_fault_full(&stack_frame, error_code, fault_addr, &task);
}

// =============================================================================
// Comprehensive page fault diagnostic dump
// =============================================================================

/// Decode `PageFaultErrorCode` bits into a human-readable string.
fn decode_error_code(ec: PageFaultErrorCode) -> &'static str {
    let p = ec.contains(PageFaultErrorCode::PROTECTION_VIOLATION);
    let w = ec.contains(PageFaultErrorCode::CAUSED_BY_WRITE);
    let u = ec.contains(PageFaultErrorCode::USER_MODE);
    match (p, w, u) {
        (false, false, false) => "kernel read of non-present page",
        (false, true, false) => "kernel write to non-present page",
        (false, false, true) => "user read of non-present page",
        (false, true, true) => "user write to non-present page",
        (true, false, false) => "kernel read protection violation",
        (true, true, false) => "kernel write protection violation (COW / RO page)",
        (true, false, true) => "user read protection violation (NX / supervisor-only)",
        (true, true, true) => "user write protection violation (COW / RO page)",
    }
}

/// Format PTE flags in a human-readable way.
fn format_pte_flags(entry: u64) -> [u8; 32] {
    let mut buf = [b' '; 32];
    let mut pos = 0;
    let flags: &[(&str, u64)] = &[
        ("P", 1 << 0),
        ("RW", 1 << 1),
        ("US", 1 << 2),
        ("PWT", 1 << 3),
        ("PCD", 1 << 4),
        ("A", 1 << 5),
        ("D", 1 << 6),
        ("PS", 1 << 7),
        ("G", 1 << 8),
        ("NX", 1 << 63),
    ];
    for &(name, bit) in flags {
        if entry & bit != 0 {
            for &b in name.as_bytes() {
                if pos < buf.len() {
                    buf[pos] = b;
                    pos += 1;
                }
            }
            if pos < buf.len() {
                buf[pos] = b'|';
                pos += 1;
            }
        }
    }
    if pos > 0 && buf[pos - 1] == b'|' {
        buf[pos - 1] = b' ';
    }
    buf
}

/// Full page fault diagnostic dump — called just before the final `panic!`.
///
/// Prints everything needed to diagnose the fault in a single serial output:
/// error code analysis, control registers, CPU/task context, memory stats,
/// code bytes at RIP, stack dump, and a detailed page table walk.
fn dump_page_fault_full(
    stack_frame: &InterruptStackFrame,
    error_code: PageFaultErrorCode,
    fault_addr: Result<x86_64::VirtAddr, x86_64::addr::VirtAddrNotValid>,
    task: &Option<alloc::sync::Arc<crate::process::task::Task>>,
) {
    use x86_64::registers::control::{Cr0, Cr3, Cr4};

    let rip = stack_frame.instruction_pointer.as_u64();
    let rsp = stack_frame.stack_pointer.as_u64();
    let cs = stack_frame.code_segment.0;
    let ss = stack_frame.stack_segment.0;
    let rflags = stack_frame.cpu_flags.bits();
    let fault_vaddr = fault_addr.as_ref().map(|v| v.as_u64()).unwrap_or(0);
    let is_user = (cs & 3) == 3;
    let ring = cs & 3;

    // ===== Banner =====
    crate::serial_println!("\x1b[1;31m");
    crate::serial_println!("╔══════════════════════════════════════════════════════════════════╗");
    crate::serial_println!("║                  KERNEL PAGE FAULT EXCEPTION                    ║");
    crate::serial_println!(
        "╚══════════════════════════════════════════════════════════════════╝\x1b[0m"
    );

    // ===== Error Code Analysis =====
    crate::serial_println!("\x1b[1;33m--- Error Code Analysis ---\x1b[0m");
    crate::serial_println!(
        "  Raw error code  : {:#06x} ({:#018b})",
        error_code.bits(),
        error_code.bits()
    );
    crate::serial_println!(
        "  PRESENT (P)     : {}  ({})",
        error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION) as u8,
        if error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION) {
            "protection violation on present page"
        } else {
            "page NOT present"
        }
    );
    crate::serial_println!(
        "  WRITE (W)       : {}  ({})",
        error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE) as u8,
        if error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE) {
            "caused by WRITE"
        } else {
            "caused by READ"
        }
    );
    crate::serial_println!(
        "  USER (U)        : {}  ({})",
        error_code.contains(PageFaultErrorCode::USER_MODE) as u8,
        if error_code.contains(PageFaultErrorCode::USER_MODE) {
            "from USER mode (ring 3)"
        } else {
            "from SUPERVISOR mode (ring 0)"
        }
    );
    crate::serial_println!(
        "  RSVD            : {}  ({})",
        (error_code.bits() >> 3) & 1,
        if error_code.bits() & (1 << 3) != 0 {
            "RESERVED BIT set in page table!"
        } else {
            "ok"
        }
    );
    crate::serial_println!(
        "  I/D (fetch)     : {}  ({})",
        (error_code.bits() >> 4) & 1,
        if error_code.bits() & (1 << 4) != 0 {
            "caused by INSTRUCTION FETCH (NX violation)"
        } else {
            "data access"
        }
    );
    crate::serial_println!(
        "  \x1b[1;31mDiagnosis: {}\x1b[0m",
        decode_error_code(error_code)
    );

    // ===== Faulting Context =====
    crate::serial_println!("\x1b[1;33m--- Faulting Context ---\x1b[0m");
    crate::serial_println!(
        "  Faulting Addr (CR2) : \x1b[1;35m{:#018x}\x1b[0m",
        fault_vaddr
    );
    crate::serial_println!("  Instruction (RIP)   : \x1b[1;36m{:#018x}\x1b[0m", rip);
    crate::serial_println!("  Stack Pointer (RSP) : {:#018x}", rsp);
    crate::serial_println!(
        "  Code Segment (CS)   : {:#06x}  (index={}, RPL/ring={}{})",
        cs,
        cs >> 3,
        ring,
        if is_user { " USER" } else { " KERNEL" }
    );
    crate::serial_println!("  Stack Segment (SS)  : {:#06x}", ss);

    // RFLAGS decomposition
    let mut rflags_str = [0u8; 64];
    let mut fpos = 0;
    let rflags_bits: &[(&str, u64)] = &[
        ("CF", 1 << 0),
        ("PF", 1 << 2),
        ("AF", 1 << 4),
        ("ZF", 1 << 6),
        ("SF", 1 << 7),
        ("TF", 1 << 8),
        ("IF", 1 << 9),
        ("DF", 1 << 10),
        ("OF", 1 << 11),
        ("IOPL", 3 << 12),
        ("NT", 1 << 14),
        ("RF", 1 << 16),
        ("VM", 1 << 17),
        ("AC", 1 << 18),
        ("VIF", 1 << 19),
        ("VIP", 1 << 20),
        ("ID", 1 << 21),
    ];
    for &(name, bit) in rflags_bits {
        if rflags & bit != 0 {
            for &b in name.as_bytes() {
                if fpos < rflags_str.len() {
                    rflags_str[fpos] = b;
                    fpos += 1;
                }
            }
            if fpos < rflags_str.len() {
                rflags_str[fpos] = b' ';
                fpos += 1;
            }
        }
    }
    let rflags_s = core::str::from_utf8(&rflags_str[..fpos]).unwrap_or("?");
    crate::serial_println!("  RFLAGS              : {:#018x}  [{}]", rflags, rflags_s);

    // ===== Control Registers =====
    crate::serial_println!("\x1b[1;33m--- Control Registers ---\x1b[0m");
    let cr0 = Cr0::read_raw();
    let (cr3_frame, cr3_flags) = Cr3::read();
    let cr3_phys = cr3_frame.start_address().as_u64();
    let cr4 = Cr4::read_raw();

    // CR0 flags
    let cr0_flags = {
        let mut s = [0u8; 48];
        let mut p = 0;
        let bits: &[(&str, u64)] = &[
            ("PE", 1 << 0),
            ("MP", 1 << 1),
            ("EM", 1 << 2),
            ("TS", 1 << 3),
            ("ET", 1 << 4),
            ("NE", 1 << 5),
            ("WP", 1 << 16),
            ("AM", 1 << 18),
            ("NW", 1 << 29),
            ("CD", 1 << 30),
            ("PG", 1u64 << 31),
        ];
        for &(n, b) in bits {
            if cr0 & b != 0 {
                for &c in n.as_bytes() {
                    if p < s.len() {
                        s[p] = c;
                        p += 1;
                    }
                }
                if p < s.len() {
                    s[p] = b' ';
                    p += 1;
                }
            }
        }
        (s, p)
    };
    crate::serial_println!(
        "  CR0 : {:#018x}  [{}]",
        cr0,
        core::str::from_utf8(&cr0_flags.0[..cr0_flags.1]).unwrap_or("?")
    );
    crate::serial_println!(
        "  CR3 : {:#018x}  (PML4 phys, flags={:#x})",
        cr3_phys,
        cr3_flags.bits()
    );
    // CR4 flags
    let cr4_flags = {
        let mut s = [0u8; 64];
        let mut p = 0;
        let bits: &[(&str, u64)] = &[
            ("VME", 1 << 0),
            ("PVI", 1 << 1),
            ("TSD", 1 << 2),
            ("DE", 1 << 3),
            ("PSE", 1 << 4),
            ("PAE", 1 << 5),
            ("MCE", 1 << 6),
            ("PGE", 1 << 7),
            ("PCE", 1 << 8),
            ("OSFXSR", 1 << 9),
            ("OSXMMEX", 1 << 10),
            ("UMIP", 1 << 11),
            ("VMXE", 1 << 13),
            ("SMXE", 1 << 14),
            ("FSGSBASE", 1 << 16),
            ("PCIDE", 1 << 17),
            ("OSXSAVE", 1 << 18),
            ("SMEP", 1 << 20),
            ("SMAP", 1 << 21),
        ];
        for &(n, b) in bits {
            if cr4 & b != 0 {
                for &c in n.as_bytes() {
                    if p < s.len() {
                        s[p] = c;
                        p += 1;
                    }
                }
                if p < s.len() {
                    s[p] = b' ';
                    p += 1;
                }
            }
        }
        (s, p)
    };
    crate::serial_println!(
        "  CR4 : {:#018x}  [{}]",
        cr4,
        core::str::from_utf8(&cr4_flags.0[..cr4_flags.1]).unwrap_or("?")
    );

    // EFER MSR (IA32_EFER = 0xC0000080)
    let efer: u64 = unsafe { x86_64::registers::model_specific::Efer::read_raw() };
    crate::serial_println!(
        "  EFER: {:#018x}  [{}{}{}]",
        efer,
        if efer & 1 != 0 { "SCE " } else { "" },
        if efer & (1 << 8) != 0 { "LME " } else { "" },
        if efer & (1 << 11) != 0 { "NXE" } else { "" }
    );

    // ===== CPU Context =====
    crate::serial_println!("\x1b[1;33m--- CPU Context ---\x1b[0m");
    let cpu_id = super::apic::lapic_id();
    let apic_timer = crate::arch::x86_64::timer::is_apic_timer_active();
    let sched_ticks = crate::process::scheduler::ticks();
    crate::serial_println!("  CPU / LAPIC ID    : {}", cpu_id);
    crate::serial_println!("  APIC timer active : {}", apic_timer);
    crate::serial_println!("  Scheduler ticks   : {}", sched_ticks);
    crate::serial_println!("  HHDM offset       : {:#x}", crate::memory::hhdm_offset());

    // ===== Task Context =====
    crate::serial_println!("\x1b[1;33m--- Task Context ---\x1b[0m");
    if let Some(ref t) = *task {
        crate::serial_println!("  Task ID    : {}", t.id.as_u64());
        crate::serial_println!("  PID        : {}", t.pid);
        crate::serial_println!("  TID        : {}", t.tid);
        crate::serial_println!("  TGID       : {}", t.tgid);
        crate::serial_println!("  Name       : \"{}\"", t.name);
        crate::serial_println!("  Priority   : {:?}", t.priority);
        crate::serial_println!("  CPU ticks  : {}", t.ticks.load(Ordering::Relaxed));
        // Address space CR3 (may differ from hardware CR3 if preemption occurred)
        let as_ref = unsafe { &*t.process.address_space.get() };
        let task_cr3 = as_ref.cr3().as_u64();
        crate::serial_println!(
            "  Task CR3   : {:#018x}{}",
            task_cr3,
            if task_cr3 != cr3_phys {
                " *** DIFFERS from hardware CR3! ***"
            } else {
                " (matches hardware CR3)"
            }
        );
    } else {
        crate::serial_println!("  (no current task — scheduler unavailable or idle)");
    }

    // ===== Memory Stats =====
    crate::serial_println!("\x1b[1;33m--- Memory Stats ---\x1b[0m");
    if let Some(guard) = crate::memory::get_allocator().try_lock() {
        if let Some(ref alloc) = *guard {
            let (total, allocated) = alloc.page_totals();
            let free = total.saturating_sub(allocated);
            crate::serial_println!(
                "  Total pages : {} ({} KiB = {} MiB)",
                total,
                total * 4,
                total * 4 / 1024
            );
            crate::serial_println!(
                "  Allocated   : {} ({} KiB = {} MiB)",
                allocated,
                allocated * 4,
                allocated * 4 / 1024
            );
            crate::serial_println!(
                "  Free        : {} ({} KiB = {} MiB)",
                free,
                free * 4,
                free * 4 / 1024
            );
            // Per-zone breakdown
            let mut zones = [(0u8, 0u64, 0usize, 0usize); 4];
            let n = alloc.zone_snapshot(&mut zones);
            for i in 0..n {
                let (zt, base, pages, alloc_pg) = zones[i];
                let zone_name = match zt {
                    0 => "DMA",
                    1 => "Normal",
                    2 => "High",
                    _ => "?",
                };
                crate::serial_println!(
                    "    Zone {} ({}): base={:#x} pages={} alloc={} free={}",
                    i,
                    zone_name,
                    base,
                    pages,
                    alloc_pg,
                    pages.saturating_sub(alloc_pg)
                );
            }
        } else {
            crate::serial_println!("  (allocator not initialized)");
        }
    } else {
        crate::serial_println!("  (allocator lock contended — skipping)");
    }

    // ===== Code Bytes at RIP =====
    crate::serial_println!("\x1b[1;33m--- Code at RIP ({:#x}) ---\x1b[0m", rip);
    dump_memory_bytes(rip, cr3_phys, 32, "  ");

    // ===== Stack Dump =====
    crate::serial_println!("\x1b[1;33m--- Stack Dump (RSP={:#x}) ---\x1b[0m", rsp);
    dump_memory_bytes(rsp, cr3_phys, 128, "  ");

    // ===== Detailed Page Table Walk =====
    crate::serial_println!(
        "\x1b[1;33m--- Page Table Walk for {:#x} (CR3={:#x}) ---\x1b[0m",
        fault_vaddr,
        cr3_phys
    );
    if fault_addr.is_ok() {
        dump_page_table_walk(fault_vaddr, cr3_phys);
    } else {
        crate::serial_println!("  (CR2 returned non-canonical address: {:#x})", fault_vaddr);
    }

    // ===== VMA Regions Near Fault =====
    if let Some(ref t) = *task {
        crate::serial_println!("\x1b[1;33m--- VMA Regions Near Fault Address ---\x1b[0m");
        let as_ref = unsafe { &*t.process.address_space.get() };
        dump_nearby_vma_regions(as_ref, fault_vaddr);
    }

    crate::serial_println!(
        "\x1b[1;31m╔══════════════════════════════════════════════════════════════════╗"
    );
    crate::serial_println!("║                     END OF PAGE FAULT DUMP                      ║");
    crate::serial_println!(
        "╚══════════════════════════════════════════════════════════════════╝\x1b[0m"
    );

    panic!(
        "PAGE FAULT: {} at {:#x}, RIP={:#x}, CR3={:#x}, err={:#x}",
        decode_error_code(error_code),
        fault_vaddr,
        rip,
        cr3_phys,
        error_code.bits()
    );
}

/// Dump `count` bytes of memory at virtual address `vaddr` using the given
/// CR3 page tables.  Hex + ASCII output like a mini hexdump.
/// Does a manual translate via page tables to avoid needing an AddressSpace.
fn dump_memory_bytes(vaddr: u64, cr3_phys: u64, count: usize, prefix: &str) {
    let hhdm = crate::memory::hhdm_offset();

    // Try to translate vaddr → phys using the raw page tables
    let phys = translate_via_raw_pt(vaddr, cr3_phys, hhdm);
    let phys = match phys {
        Some(p) => p,
        None => {
            crate::serial_println!(
                "{}(address {:#x} is not mapped — cannot dump)",
                prefix,
                vaddr
            );
            return;
        }
    };

    // Read up to `count` bytes, but don't cross a page boundary without re-translating
    let mut offset = 0usize;
    while offset < count {
        let current_va = vaddr.wrapping_add(offset as u64);
        let page_off = (current_va & 0xFFF) as usize;
        let remain_in_page = 0x1000 - page_off;
        let chunk = core::cmp::min(count - offset, remain_in_page);

        let current_phys = if offset == 0 {
            Some(phys)
        } else {
            translate_via_raw_pt(current_va, cr3_phys, hhdm)
        };

        if let Some(cp) = current_phys {
            // SAFETY: Read-only access to physical memory via HHDM for diagnostics
            let src = (cp + hhdm) as *const u8;
            // Print in lines of 16 bytes
            let mut line_off = 0;
            while line_off < chunk {
                let line_len = core::cmp::min(16, chunk - line_off);
                let line_va = current_va.wrapping_add(line_off as u64);

                // Hex part
                let mut hex_buf = [0u8; 16 * 3];
                let mut ascii_buf = [b'.'; 16];
                for i in 0..line_len {
                    let byte = unsafe { *src.add(page_off + line_off + i) };
                    let hi = byte >> 4;
                    let lo = byte & 0xF;
                    hex_buf[i * 3] = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
                    hex_buf[i * 3 + 1] = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
                    hex_buf[i * 3 + 2] = b' ';
                    if byte >= 0x20 && byte < 0x7F {
                        ascii_buf[i] = byte;
                    }
                }
                // Pad remaining hex positions
                for i in line_len..16 {
                    hex_buf[i * 3] = b' ';
                    hex_buf[i * 3 + 1] = b' ';
                    hex_buf[i * 3 + 2] = b' ';
                }
                let hex_str = core::str::from_utf8(&hex_buf[..48]).unwrap_or("???");
                let ascii_str = core::str::from_utf8(&ascii_buf[..line_len]).unwrap_or("???");
                crate::serial_println!("{}{:#018x}: {} |{}|", prefix, line_va, hex_str, ascii_str);
                line_off += line_len;
            }
        } else {
            crate::serial_println!("{}(page at {:#x} not mapped)", prefix, current_va);
        }
        offset += chunk;
    }
}

/// Translate a virtual address to physical using raw page table walk.
/// Returns `Some(phys_addr)` or `None` if any level is not present.
fn translate_via_raw_pt(vaddr: u64, cr3_phys: u64, hhdm: u64) -> Option<u64> {
    // SAFETY: Read-only access to page tables via HHDM pointers.
    unsafe {
        let l4_ptr = (cr3_phys + hhdm) as *const u64;
        let l4_idx = ((vaddr >> 39) & 0x1FF) as usize;
        let l4_entry = *l4_ptr.add(l4_idx);
        if l4_entry & 1 == 0 {
            return None;
        }

        let l3_phys = l4_entry & 0x000F_FFFF_FFFF_F000;
        let l3_ptr = (l3_phys + hhdm) as *const u64;
        let l3_idx = ((vaddr >> 30) & 0x1FF) as usize;
        let l3_entry = *l3_ptr.add(l3_idx);
        if l3_entry & 1 == 0 {
            return None;
        }
        if l3_entry & 0x80 != 0 {
            // 1 GiB huge page
            let page_phys = l3_entry & 0x000F_FFFF_C000_0000;
            return Some(page_phys + (vaddr & 0x3FFF_FFFF));
        }

        let l2_phys = l3_entry & 0x000F_FFFF_FFFF_F000;
        let l2_ptr = (l2_phys + hhdm) as *const u64;
        let l2_idx = ((vaddr >> 21) & 0x1FF) as usize;
        let l2_entry = *l2_ptr.add(l2_idx);
        if l2_entry & 1 == 0 {
            return None;
        }
        if l2_entry & 0x80 != 0 {
            // 2 MiB huge page
            let page_phys = l2_entry & 0x000F_FFFF_FFE0_0000;
            return Some(page_phys + (vaddr & 0x1F_FFFF));
        }

        let l1_phys = l2_entry & 0x000F_FFFF_FFFF_F000;
        let l1_ptr = (l1_phys + hhdm) as *const u64;
        let l1_idx = ((vaddr >> 12) & 0x1FF) as usize;
        let l1_entry = *l1_ptr.add(l1_idx);
        if l1_entry & 1 == 0 {
            return None;
        }

        let page_phys = l1_entry & 0x000F_FFFF_FFFF_F000;
        Some(page_phys + (vaddr & 0xFFF))
    }
}

/// Detailed page table walk with full flag decoding at each level.
fn dump_page_table_walk(vaddr: u64, cr3_phys: u64) {
    let hhdm = crate::memory::hhdm_offset();

    let l4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let l3_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let l2_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let l1_idx = ((vaddr >> 12) & 0x1FF) as usize;

    // SAFETY: Read-only access to page tables via HHDM for diagnostics.
    unsafe {
        let l4_ptr = (cr3_phys + hhdm) as *const u64;
        let l4_entry = *l4_ptr.add(l4_idx);
        let flags = format_pte_flags(l4_entry);
        let flags_s = core::str::from_utf8(&flags).unwrap_or("?");
        let phys4 = l4_entry & 0x000F_FFFF_FFFF_F000;
        crate::serial_println!(
            "  PML4[{:>3}] = {:#018x}  phys={:#014x}  [{}]",
            l4_idx,
            l4_entry,
            phys4,
            flags_s.trim()
        );
        if l4_entry & 1 == 0 {
            crate::serial_println!("  \x1b[1;31m╰→ STOP: PML4 entry NOT PRESENT\x1b[0m");
            return;
        }

        let l3_phys = l4_entry & 0x000F_FFFF_FFFF_F000;
        let l3_ptr = (l3_phys + hhdm) as *const u64;
        let l3_entry = *l3_ptr.add(l3_idx);
        let flags = format_pte_flags(l3_entry);
        let flags_s = core::str::from_utf8(&flags).unwrap_or("?");
        let phys3 = l3_entry & 0x000F_FFFF_FFFF_F000;
        crate::serial_println!(
            "  PDPT[{:>3}] = {:#018x}  phys={:#014x}  [{}]",
            l3_idx,
            l3_entry,
            phys3,
            flags_s.trim()
        );
        if l3_entry & 1 == 0 {
            crate::serial_println!("  \x1b[1;31m╰→ STOP: PDPT entry NOT PRESENT\x1b[0m");
            return;
        }
        if l3_entry & 0x80 != 0 {
            crate::serial_println!(
                "  ╰→ 1 GiB HUGE PAGE → phys {:#x}",
                l3_entry & 0x000F_FFFF_C000_0000
            );
            return;
        }

        let l2_phys = l3_entry & 0x000F_FFFF_FFFF_F000;
        let l2_ptr = (l2_phys + hhdm) as *const u64;
        let l2_entry = *l2_ptr.add(l2_idx);
        let flags = format_pte_flags(l2_entry);
        let flags_s = core::str::from_utf8(&flags).unwrap_or("?");
        let phys2 = l2_entry & 0x000F_FFFF_FFFF_F000;
        crate::serial_println!(
            "  PD  [{:>3}] = {:#018x}  phys={:#014x}  [{}]",
            l2_idx,
            l2_entry,
            phys2,
            flags_s.trim()
        );
        if l2_entry & 1 == 0 {
            crate::serial_println!("  \x1b[1;31m╰→ STOP: PD entry NOT PRESENT\x1b[0m");
            return;
        }
        if l2_entry & 0x80 != 0 {
            crate::serial_println!(
                "  ╰→ 2 MiB HUGE PAGE → phys {:#x}",
                l2_entry & 0x000F_FFFF_FFE0_0000
            );
            return;
        }

        let l1_phys = l2_entry & 0x000F_FFFF_FFFF_F000;
        let l1_ptr = (l1_phys + hhdm) as *const u64;
        let l1_entry = *l1_ptr.add(l1_idx);
        let flags = format_pte_flags(l1_entry);
        let flags_s = core::str::from_utf8(&flags).unwrap_or("?");
        let phys1 = l1_entry & 0x000F_FFFF_FFFF_F000;
        crate::serial_println!(
            "  PT  [{:>3}] = {:#018x}  phys={:#014x}  [{}]",
            l1_idx,
            l1_entry,
            phys1,
            flags_s.trim()
        );
        if l1_entry & 1 == 0 {
            crate::serial_println!("  \x1b[1;31m╰→ STOP: PT entry NOT PRESENT\x1b[0m");
        } else {
            crate::serial_println!("  \x1b[1;32m╰→ PAGE PRESENT\x1b[0m → phys {:#x} (flags issue? check RW/US/NX above)",
                l1_entry & 0x000F_FFFF_FFFF_F000);
        }

        // Show a few neighbouring PT entries for context
        crate::serial_println!("  --- Neighbouring PT entries ---");
        let start = if l1_idx >= 2 { l1_idx - 2 } else { 0 };
        let end = core::cmp::min(l1_idx + 3, 512);
        for i in start..end {
            let e = *l1_ptr.add(i);
            if e != 0 {
                let f = format_pte_flags(e);
                let fs = core::str::from_utf8(&f).unwrap_or("?");
                let marker = if i == l1_idx { " <<<" } else { "" };
                crate::serial_println!("    PT[{:>3}] = {:#018x}  [{}]{}", i, e, fs.trim(), marker);
            }
        }
    }
}

/// Dump VMA regions near the fault address (±3 closest).
fn dump_nearby_vma_regions(as_ref: &crate::memory::AddressSpace, fault_vaddr: u64) {
    // We need to access the regions BTreeMap. Use the public region_by_start
    // and scan a few pages around the fault address.
    // Check if the exact fault page belongs to any VMA
    let page_start = fault_vaddr & !0xFFF;

    // Simple probe: check a few likely region starts
    let probes = [
        page_start,
        fault_vaddr & !0x1F_FFFF,   // 2MiB aligned down
        fault_vaddr & !0x3FFF_FFFF, // 1GiB aligned down
        0x0000_0001_0000_0000,      // typical ELF base
        0x0000_0000_0040_0000,      // lower ELF base
        0x0000_7FFF_F000_0000,      // typical stack region
    ];

    let mut found_any = false;
    for &p in &probes {
        if let Some(vma) = as_ref.region_by_start(p) {
            let end = vma.start + (vma.page_count as u64) * page_size_bytes(vma.page_size);
            let contains = fault_vaddr >= vma.start && fault_vaddr < end;
            crate::serial_println!(
                "  VMA {:#014x}..{:#014x}  pages={:<5}  type={:?}  flags={:?}  pgsz={:?}{}",
                vma.start,
                end,
                vma.page_count,
                vma.vma_type,
                vma.flags,
                vma.page_size,
                if contains {
                    "  \x1b[1;32m<<< CONTAINS FAULT ADDR\x1b[0m"
                } else {
                    ""
                }
            );
            found_any = true;
        }
    }

    // Also check if address belongs to any mapped range via has_mapping_in_range
    if as_ref.has_mapping_in_range(page_start, 0x1000) {
        crate::serial_println!(
            "  Note: fault page {:#x} IS within a tracked mapping range",
            page_start
        );
    } else {
        crate::serial_println!(
            "  Note: fault page {:#x} is NOT within any tracked mapping range",
            page_start
        );
    }

    if !found_any {
        crate::serial_println!("  (no VMA regions found at probed addresses)");
    }
}

/// Convert VmaPageSize to byte count.
fn page_size_bytes(ps: crate::memory::VmaPageSize) -> u64 {
    ps.bytes()
}

/// Performs the dump user pf context operation.
fn dump_user_pf_context(as_ref: &crate::memory::AddressSpace, rip: u64, rsp: u64) {
    use x86_64::VirtAddr;

    let hhdm = crate::memory::hhdm_offset();

    if let Some(phys) = as_ref.translate(VirtAddr::new(rip)) {
        let off = (rip & 0xfff) as usize;
        let mut bytes = [0u8; 8];
        // SAFETY: We read at most 8 bytes from a mapped user instruction page via HHDM.
        unsafe {
            let src = (phys.as_u64() - (rip & 0xfff) + hhdm + off as u64) as *const u8;
            core::ptr::copy_nonoverlapping(src, bytes.as_mut_ptr(), bytes.len());
        }
        crate::serial_println!(
            "[pagefault] ctx: rsp={:#x} rip-bytes={:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
            rsp,
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
            bytes[4],
            bytes[5],
            bytes[6],
            bytes[7],
        );
    } else {
        crate::serial_println!("[pagefault] ctx: rsp={:#x} rip page unmapped", rsp);
    }

    if let Some(phys) = as_ref.translate(VirtAddr::new(rsp)) {
        crate::serial_println!(
            "[pagefault] stack-top: rsp mapped (phys={:#x})",
            phys.as_u64()
        );
    } else {
        crate::serial_println!("[pagefault] stack-top: rsp unmapped");
    }
}

/// Performs the general protection fault handler operation.
extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    let is_user = (stack_frame.code_segment.0 & 3) == 3;
    if is_user {
        if let Some(tid) = crate::process::current_task_id() {
            crate::silo::handle_user_fault(
                tid,
                crate::silo::SiloFaultReason::GeneralProtection,
                stack_frame.instruction_pointer.as_u64(),
                error_code,
                stack_frame.instruction_pointer.as_u64(),
            );
            return;
        }
    }
    log::error!("EXCEPTION: GENERAL PROTECTION FAULT");
    log::error!("Error code: {:#x}", error_code);
    log::error!("{:#?}", stack_frame);
    panic!("General protection fault");
}

/// Performs the double fault handler operation.
extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) -> ! {
    panic!(
        "EXCEPTION: DOUBLE FAULT (error code: {:#x})\n{:#?}",
        error_code, stack_frame
    );
}

// =============================================
// Hardware IRQ handlers
// =============================================

/// Legacy external timer IRQ handler (PIC/IOAPIC IRQ0 path, vector 0x20).
///
/// When the LAPIC timer is active, we ignore this source to avoid double-ticking.
extern "x86-interrupt" fn legacy_timer_handler(_stack_frame: InterruptStackFrame) {
    if crate::arch::x86_64::timer::is_apic_timer_active() {
        // Ignore legacy timer source once LAPIC timer is running.
        if super::apic::is_initialized() {
            super::apic::eoi();
        } else {
            pic::end_of_interrupt(0);
        }
        return;
    }

    // Increment tick counter
    crate::process::scheduler::timer_tick();
    // NOTE: avoid complex rendering/allocation work in IRQ context.
    // Status bar refresh is currently done from non-IRQ paths.

    // Send EOI first so the timer can fire again on the new task
    if super::apic::is_initialized() {
        super::apic::eoi();
    } else {
        pic::end_of_interrupt(0);
    }

    // Try to preempt the current task (no-op if scheduler lock is held
    // or no task is running yet)
    crate::process::scheduler::maybe_preempt();
}

/// Local APIC timer handler (dedicated vector, e.g. 0x22).
extern "x86-interrupt" fn lapic_timer_handler(_stack_frame: InterruptStackFrame) {
    crate::process::scheduler::timer_tick();
    super::apic::eoi();
    crate::process::scheduler::maybe_preempt();
}

/// PS/2 Mouse IRQ12 handler.
extern "x86-interrupt" fn mouse_handler(_stack_frame: InterruptStackFrame) {
    crate::arch::x86_64::mouse::handle_irq();
    if super::apic::is_initialized() {
        super::apic::eoi();
    } else {
        pic::end_of_interrupt(12);
    }
}

/// Performs the keyboard handler operation.
extern "x86-interrupt" fn keyboard_handler(_stack_frame: InterruptStackFrame) {
    let raw = unsafe { super::io::inb(0x60) };
    // Port 0x60 is consumed on read: feed the raw scancode directly.
    if let Some(ch) = super::keyboard_layout::handle_scancode_raw(raw) {
        crate::arch::x86_64::keyboard::add_to_buffer(ch);
    }

    if super::apic::is_initialized() {
        super::apic::eoi();
    } else {
        pic::end_of_interrupt(1);
    }
}

/// Spurious interrupt handler (APIC vector 0xFF).
/// Per Intel SDM: do NOT send EOI for spurious interrupts.
extern "x86-interrupt" fn spurious_handler(_stack_frame: InterruptStackFrame) {
    // Intentionally empty — no EOI per Intel SDM
}

/// AHCI storage controller IRQ handler.
///
/// Reads `HBA_IS`, processes per-port completions, wakes waiting tasks, then
/// sends EOI.  Must not call any function that may block or allocate.
extern "x86-interrupt" fn ahci_handler(_stack_frame: InterruptStackFrame) {
    crate::hardware::storage::ahci::handle_interrupt();

    if super::apic::is_initialized() {
        super::apic::eoi();
    } else {
        let irq = crate::hardware::storage::ahci::AHCI_IRQ_LINE
            .load(core::sync::atomic::Ordering::Relaxed);
        pic::end_of_interrupt(irq);
    }
}

/// VirtIO Block device IRQ handler
///
/// Handles interrupts from the VirtIO block device.
/// The IRQ line is determined at runtime from PCI config.
extern "x86-interrupt" fn virtio_block_handler(_stack_frame: InterruptStackFrame) {
    // Handle the VirtIO block interrupt
    crate::hardware::storage::virtio_block::handle_interrupt();

    // Send EOI
    if super::apic::is_initialized() {
        super::apic::eoi();
    } else {
        // Get the IRQ number from the device
        let irq = crate::hardware::storage::virtio_block::get_irq();
        pic::end_of_interrupt(irq);
    }
}

/// Cross-CPU reschedule IPI handler (vector 0xF0).
///
/// Sent by another CPU (via `apic::send_resched_ipi`) to request that this
/// CPU preempts its current task immediately rather than waiting for the next
/// timer tick. This is used when a task running on this CPU is killed or
/// suspended by a different CPU.
///
/// EOI is sent ***before*** ` maybe_preempt()` so the APIC can accept further
/// IPIs before the potentially long context-switch path runs.
extern "x86-interrupt" fn resched_ipi_handler(_stack_frame: InterruptStackFrame) {
    super::apic::eoi();
    crate::process::scheduler::maybe_preempt();
}

/// Cross-CPU TLB shootdown IPI handler (vector 0xF0).
extern "x86-interrupt" fn tlb_shootdown_handler(_stack_frame: InterruptStackFrame) {
    // Note: EOI is sent by the architecture-independent handler.
    super::tlb::tlb_shootdown_ipi_handler();
}
