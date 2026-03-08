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
    if is_user {
        if let Some(task) = crate::process::current_task_clone() {
            let as_ref = unsafe { &*task.process.address_space.get() };
            trace_ctx = crate::trace::TraceTaskCtx {
                task_id: task.id.as_u64(),
                pid: task.pid,
                tid: task.tid,
                cr3: as_ref.cr3().as_u64(),
            };
        }
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
        if let Some(task) = crate::process::current_task_clone() {
            let address_space = unsafe { &*task.process.address_space.get() };
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
                            task.id.as_u64(),
                            task.pid,
                            task.tid,
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
        if let Some(task) = crate::process::current_task_clone() {
            let address_space = unsafe { &*task.process.address_space.get() };
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
        if let Some(tid) = crate::process::current_task_id() {
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

    // Capture current task (non-blocking, safe from IRQ context) for the diagnostic dump.
    let task_snap = crate::process::scheduler::current_task_clone_try();
    dump_page_fault_full(&stack_frame, error_code, fault_addr, &task_snap);
}

// =============================================================================
// CRITICAL: Full page fault diagnostic dump
//
// Invoked for every non-recoverable page fault (kernel or unhandled user).
// Designed to be deadlock-safe:
//   - Uses serial_println! (direct UART) instead of the log framework, which
//     may itself allocate or acquire locks.
//   - All memory reads go through translate_via_raw_pt so no unmapped address
//     is ever dereferenced.
//   - The buddy allocator lock is acquired with try_lock (non-blocking) for
//     memory statistics.
//   - Uses current_task_clone_try (non-blocking) instead of current_task_clone.
// =============================================================================

/// Decodes `PageFaultErrorCode` bits into a human-readable string.
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

/// Formats page table entry flags into a short human-readable byte string.
fn format_pte_flags(entry: u64) -> [u8; 32] {
    let mut buf = [b' '; 32];
    let mut pos = 0usize;
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

/// Translates a virtual address to a physical address via a manual 4-level
/// page table walk.  Returns `Some(phys)` or `None` if any level is absent.
///
/// # SAFETY
/// Read-only access to page tables through the HHDM mapping.
/// All intermediate addresses are derived from table entries — no pointer
/// originating from user-controlled data is ever dereferenced.
fn translate_via_raw_pt(vaddr: u64, cr3_phys: u64, hhdm: u64) -> Option<u64> {
    unsafe {
        let l4_ptr = (cr3_phys + hhdm) as *const u64;
        let l4e = *l4_ptr.add(((vaddr >> 39) & 0x1FF) as usize);
        if l4e & 1 == 0 {
            return None;
        }

        let l3_ptr = ((l4e & 0x000F_FFFF_FFFF_F000) + hhdm) as *const u64;
        let l3e = *l3_ptr.add(((vaddr >> 30) & 0x1FF) as usize);
        if l3e & 1 == 0 {
            return None;
        }
        if l3e & 0x80 != 0 {
            return Some((l3e & 0x000F_FFFF_C000_0000) + (vaddr & 0x3FFF_FFFF));
        }

        let l2_ptr = ((l3e & 0x000F_FFFF_FFFF_F000) + hhdm) as *const u64;
        let l2e = *l2_ptr.add(((vaddr >> 21) & 0x1FF) as usize);
        if l2e & 1 == 0 {
            return None;
        }
        if l2e & 0x80 != 0 {
            return Some((l2e & 0x000F_FFFF_FFE0_0000) + (vaddr & 0x1F_FFFF));
        }

        let l1_ptr = ((l2e & 0x000F_FFFF_FFFF_F000) + hhdm) as *const u64;
        let l1e = *l1_ptr.add(((vaddr >> 12) & 0x1FF) as usize);
        if l1e & 1 == 0 {
            return None;
        }
        Some((l1e & 0x000F_FFFF_FFFF_F000) + (vaddr & 0xFFF))
    }
}

/// Hex + ASCII dump of `count` bytes at virtual address `vaddr`.
/// Each page boundary is translated through the raw page tables.
fn dump_memory_bytes(vaddr: u64, cr3_phys: u64, count: usize, prefix: &str) {
    let hhdm = crate::memory::hhdm_offset();
    let mut offset = 0usize;
    while offset < count {
        let cur_va = vaddr.wrapping_add(offset as u64);
        let page_off = (cur_va & 0xFFF) as usize;
        let chunk = core::cmp::min(count - offset, 0x1000 - page_off);
        let Some(phys) = translate_via_raw_pt(cur_va, cr3_phys, hhdm) else {
            crate::serial_println!("{}(page {:#x} not mapped)", prefix, cur_va);
            offset += chunk;
            continue;
        };
        // SAFETY: read-only access to a valid physical page through the HHDM mapping.
        let src = (phys - (cur_va & 0xFFF) + hhdm) as *const u8;
        let mut line_off = 0usize;
        while line_off < chunk {
            let ll = core::cmp::min(16, chunk - line_off);
            let line_va = cur_va.wrapping_add(line_off as u64);
            let mut hex = [0u8; 48];
            let mut asc = [b'.'; 16];
            for i in 0..ll {
                let byte = unsafe { *src.add(page_off + line_off + i) };
                let hi = byte >> 4;
                let lo = byte & 0xF;
                hex[i * 3] = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
                hex[i * 3 + 1] = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
                hex[i * 3 + 2] = b' ';
                if byte >= 0x20 && byte < 0x7F {
                    asc[i] = byte;
                }
            }
            for i in ll..16 {
                hex[i * 3] = b' ';
                hex[i * 3 + 1] = b' ';
                hex[i * 3 + 2] = b' ';
            }
            crate::serial_println!(
                "{}{:#018x}: {} |{}|",
                prefix,
                line_va,
                core::str::from_utf8(&hex[..48]).unwrap_or("???"),
                core::str::from_utf8(&asc[..ll]).unwrap_or("???")
            );
            line_off += ll;
        }
        offset += chunk;
    }
}

/// Detailed page table walk with flag decoding at every level.
fn dump_page_table_walk(vaddr: u64, cr3_phys: u64) {
    let hhdm = crate::memory::hhdm_offset();
    let l4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let l3_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let l2_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let l1_idx = ((vaddr >> 12) & 0x1FF) as usize;

    // SAFETY: read-only access through the HHDM mapping for diagnostic purposes.
    unsafe {
        let l4_ptr = (cr3_phys + hhdm) as *const u64;
        let l4e = *l4_ptr.add(l4_idx);
        let f = format_pte_flags(l4e);
        crate::serial_println!(
            "  PML4[{:>3}] = {:#018x}  phys={:#014x}  [{}]",
            l4_idx,
            l4e,
            l4e & 0x000F_FFFF_FFFF_F000,
            core::str::from_utf8(&f).unwrap_or("?").trim()
        );
        if l4e & 1 == 0 {
            crate::serial_println!("  \x1b[1;31m╰→ STOP: PML4 not present\x1b[0m");
            return;
        }

        let l3_ptr = ((l4e & 0x000F_FFFF_FFFF_F000) + hhdm) as *const u64;
        let l3e = *l3_ptr.add(l3_idx);
        let f = format_pte_flags(l3e);
        crate::serial_println!(
            "  PDPT[{:>3}] = {:#018x}  phys={:#014x}  [{}]",
            l3_idx,
            l3e,
            l3e & 0x000F_FFFF_FFFF_F000,
            core::str::from_utf8(&f).unwrap_or("?").trim()
        );
        if l3e & 1 == 0 {
            crate::serial_println!("  \x1b[1;31m╰→ STOP: PDPT not present\x1b[0m");
            return;
        }
        if l3e & 0x80 != 0 {
            crate::serial_println!(
                "  ╰→ 1 GiB huge page → phys {:#x}",
                l3e & 0x000F_FFFF_C000_0000
            );
            return;
        } // 1 GiB

        let l2_ptr = ((l3e & 0x000F_FFFF_FFFF_F000) + hhdm) as *const u64;
        let l2e = *l2_ptr.add(l2_idx);
        let f = format_pte_flags(l2e);
        crate::serial_println!(
            "  PD  [{:>3}] = {:#018x}  phys={:#014x}  [{}]",
            l2_idx,
            l2e,
            l2e & 0x000F_FFFF_FFFF_F000,
            core::str::from_utf8(&f).unwrap_or("?").trim()
        );
        if l2e & 1 == 0 {
            crate::serial_println!("  \x1b[1;31m╰→ STOP: PD not present\x1b[0m");
            return;
        }
        if l2e & 0x80 != 0 {
            crate::serial_println!(
                "  ╰→ 2 MiB huge page → phys {:#x}",
                l2e & 0x000F_FFFF_FFE0_0000
            );
            return;
        } // 2 MiB

        let l1_ptr = ((l2e & 0x000F_FFFF_FFFF_F000) + hhdm) as *const u64;
        let l1e = *l1_ptr.add(l1_idx);
        let f = format_pte_flags(l1e);
        crate::serial_println!(
            "  PT  [{:>3}] = {:#018x}  phys={:#014x}  [{}]",
            l1_idx,
            l1e,
            l1e & 0x000F_FFFF_FFFF_F000,
            core::str::from_utf8(&f).unwrap_or("?").trim()
        );
        if l1e & 1 == 0 {
            crate::serial_println!("  \x1b[1;31m╰→ STOP: PT not present\x1b[0m");
        } else {
            crate::serial_println!(
                "  \x1b[1;32m╰→ PAGE PRESENT\x1b[0m → phys {:#x} (check RW/US/NX flags)",
                l1e & 0x000F_FFFF_FFFF_F000
            );
        }
        // Neighbouring PT entries for context
        crate::serial_println!("  --- Neighbouring PT entries ---");
        let start = if l1_idx >= 2 { l1_idx - 2 } else { 0 };
        for i in start..core::cmp::min(l1_idx + 3, 512) {
            let e = *l1_ptr.add(i);
            if e != 0 {
                let f = format_pte_flags(e);
                crate::serial_println!(
                    "    PT[{:>3}] = {:#018x}  [{}]{}",
                    i,
                    e,
                    core::str::from_utf8(&f).unwrap_or("?").trim(),
                    if i == l1_idx { " <<<" } else { "" }
                );
            }
        }
    }
}

/// Dumps VMA regions near the faulting address.
fn dump_nearby_vma_regions(as_ref: &crate::memory::AddressSpace, fault_vaddr: u64) {
    let page_start = fault_vaddr & !0xFFF;
    let probes = [
        page_start,
        fault_vaddr & !0x1F_FFFF,
        fault_vaddr & !0x3FFF_FFFF,
        0x0000_0001_0000_0000,
        0x0000_0000_0040_0000,
        0x0000_7FFF_F000_0000,
    ];
    let mut found_any = false;
    for &p in &probes {
        if let Some(vma) = as_ref.region_by_start(p) {
            let end = vma.start + (vma.page_count as u64) * vma.page_size.bytes();
            let hit = fault_vaddr >= vma.start && fault_vaddr < end;
            crate::serial_println!(
                "  VMA {:#014x}..{:#014x}  pages={:<5}  type={:?}  flags={:?}  pgsz={:?}{}",
                vma.start,
                end,
                vma.page_count,
                vma.vma_type,
                vma.flags,
                vma.page_size,
                if hit {
                    "  \x1b[1;32m<<< FAULT\x1b[0m"
                } else {
                    ""
                }
            );
            found_any = true;
        }
    }
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

/// Full diagnostic dump for a non-recoverable page fault.
///
/// Uses `serial_println!` directly (lock-free UART) to avoid any deadlock
/// with the log framework or the heap allocator.
fn dump_page_fault_full(
    stack_frame: &InterruptStackFrame,
    error_code: PageFaultErrorCode,
    fault_addr: Result<x86_64::VirtAddr, x86_64::addr::VirtAddrNotValid>,
    task: &Option<alloc::sync::Arc<crate::process::task::Task>>,
) -> ! {
    use x86_64::registers::control::{Cr0, Cr3, Cr4};

    let rip = stack_frame.instruction_pointer.as_u64();
    let rsp = stack_frame.stack_pointer.as_u64();
    let cs = stack_frame.code_segment.0;
    let ss = stack_frame.stack_segment.0;
    let rflags = stack_frame.cpu_flags.bits();
    let fault_vaddr = fault_addr.as_ref().map(|v| v.as_u64()).unwrap_or(0);
    let is_user = (cs & 3) == 3;

    crate::serial_println!("\x1b[1;31m");
    crate::serial_println!("╔══════════════════════════════════════════════════════════════════╗");
    crate::serial_println!("║                  KERNEL PAGE FAULT EXCEPTION                    ║");
    crate::serial_println!(
        "╚══════════════════════════════════════════════════════════════════╝\x1b[0m"
    );

    // --- Error code ---
    crate::serial_println!("\x1b[1;33m--- Error Code ---\x1b[0m");
    crate::serial_println!("  Raw         : {:#06x}", error_code.bits());
    crate::serial_println!(
        "  Diagnostic  : \x1b[1;31m{}\x1b[0m",
        decode_error_code(error_code)
    );
    crate::serial_println!(
        "  PRESENT     : {} | WRITE : {} | USER : {} | RSVD : {} | FETCH : {}",
        error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION) as u8,
        error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE) as u8,
        error_code.contains(PageFaultErrorCode::USER_MODE) as u8,
        (error_code.bits() >> 3) & 1,
        (error_code.bits() >> 4) & 1
    );

    // --- Faulting context ---
    crate::serial_println!("\x1b[1;33m--- Faulting Context ---\x1b[0m");
    crate::serial_println!("  CR2 (addr)  : \x1b[1;35m{:#018x}\x1b[0m", fault_vaddr);
    crate::serial_println!("  RIP         : \x1b[1;36m{:#018x}\x1b[0m", rip);
    crate::serial_println!("  RSP         : {:#018x}", rsp);
    crate::serial_println!(
        "  CS          : {:#06x}  (ring={}{}) | SS : {:#06x}",
        cs,
        cs & 3,
        if is_user { " USER" } else { " KERNEL" },
        ss
    );

    // RFLAGS décodé
    let mut rf_str = [0u8; 64];
    let mut rfp = 0usize;
    for &(name, bit) in &[
        ("CF", 1u64),
        ("PF", 4),
        ("AF", 16),
        ("ZF", 64),
        ("SF", 128),
        ("TF", 256),
        ("IF", 512),
        ("DF", 1024),
        ("OF", 2048),
    ] {
        if rflags & bit != 0 {
            for &b in name.as_bytes() {
                if rfp < rf_str.len() {
                    rf_str[rfp] = b;
                    rfp += 1;
                }
            }
            if rfp < rf_str.len() {
                rf_str[rfp] = b' ';
                rfp += 1;
            }
        }
    }
    crate::serial_println!(
        "  RFLAGS      : {:#018x}  [{}]",
        rflags,
        core::str::from_utf8(&rf_str[..rfp]).unwrap_or("?")
    );

    // --- Control registers ---
    crate::serial_println!("\x1b[1;33m--- Control Registers ---\x1b[0m");
    let cr0 = Cr0::read_raw();
    let (cr3_frame, cr3_flags) = Cr3::read();
    let cr3_phys = cr3_frame.start_address().as_u64();
    let cr4 = Cr4::read_raw();
    let efer: u64 = unsafe { x86_64::registers::model_specific::Efer::read_raw() };
    crate::serial_println!("  CR0         : {:#018x}", cr0);
    crate::serial_println!(
        "  CR3         : {:#018x}  (flags={:#x})",
        cr3_phys,
        cr3_flags.bits()
    );
    crate::serial_println!("  CR4         : {:#018x}", cr4);
    crate::serial_println!(
        "  EFER        : {:#018x}  [{}{}{}]",
        efer,
        if efer & 1 != 0 { "SCE " } else { "" },
        if efer & (1 << 8) != 0 { "LME " } else { "" },
        if efer & (1 << 11) != 0 { "NXE" } else { "" }
    );

    // --- CPU context ---
    crate::serial_println!("\x1b[1;33m--- CPU Context ---\x1b[0m");
    crate::serial_println!("  LAPIC ID    : {}", super::apic::lapic_id());
    crate::serial_println!("  Ticks sched : {}", crate::process::scheduler::ticks());
    crate::serial_println!("  HHDM offset : {:#x}", crate::memory::hhdm_offset());

    // --- Task context ---
    crate::serial_println!("\x1b[1;33m--- Task Context ---\x1b[0m");
    if let Some(ref t) = *task {
        crate::serial_println!(
            "  ID={} PID={} TID={} TGID={} name=\"{}\" prio={:?} ticks={}",
            t.id.as_u64(),
            t.pid,
            t.tid,
            t.tgid,
            t.name,
            t.priority,
            t.ticks.load(core::sync::atomic::Ordering::Relaxed)
        );
        // SAFETY: Read task CR3 safely using the hardware page-table walker
        // (translate_via_raw_pt) to prevent recursive page faults if the
        // process's Arc<AddressSpace> is partially initialized or corrupted.
        //
        // Chain: &t.process → Arc<Process> data ptr (Arc::as_ptr)
        //      → (*process).address_space.get() → *mut Arc<AddressSpace>
        //      → Arc::as_ptr(arc_as) → *const AddressSpace
        //      → (*addr_space).cr3_phys
        //
        // Each step uses translate_via_raw_pt to verify the pointer is mapped
        // before dereferencing, using the hardware CR3 (cr3_phys) which always
        // maps the kernel's HHDM region.
        let task_cr3: u64 = {
            let hhdm = crate::memory::hhdm_offset();
            // Step 1: Arc<Process> data (Arc::as_ptr is always valid for a live Arc)
            let proc_ptr: u64 = alloc::sync::Arc::as_ptr(&t.process) as u64;
            // Step 2: address_space field in Process = SyncUnsafeCell whose .get()
            // returns a raw ptr into the Process data — always valid for a live Process.
            // However, reading the Arc<AddressSpace> *value* from that pointer may
            // fault if the memory is unmapped, so we use translate_via_raw_pt.
            let as_cell_addr: u64 =
                unsafe { (*alloc::sync::Arc::as_ptr(&t.process)).address_space.get() as u64 };
            // Step 3: read the 8-byte Arc<AddressSpace> inner pointer from as_cell_addr
            // via raw page table walk with current hardware CR3.
            let as_inner_u64: u64 = match translate_via_raw_pt(as_cell_addr, cr3_phys, hhdm) {
                Some(phys) => unsafe { *((phys + hhdm) as *const u64) },
                None => 0,
            };
            if as_inner_u64 == 0 {
                0u64
            } else {
                // as_inner_u64 is the NonNull ptr inside Arc<AddressSpace>
                // = pointer to ArcInner<AddressSpace>.
                // ArcInner = strong(8) + weak(8) + data(AddressSpace).
                // So AddressSpace data is at as_inner_u64 + 16.
                let as_data_ptr: u64 = as_inner_u64 + 2 * core::mem::size_of::<usize>() as u64;
                // cr3_phys is the first field of AddressSpace (PhysAddr = u64, 8 bytes).
                match translate_via_raw_pt(as_data_ptr, cr3_phys, hhdm) {
                    Some(phys) => unsafe { *((phys + hhdm) as *const u64) },
                    None => 0,
                }
            }
        };
        if task_cr3 == 0 {
            crate::serial_println!(
                "  Task CR3    : <unreadable — null/unmapped Arc<AddressSpace>>"
            );
        } else {
            crate::serial_println!(
                "  Task CR3    : {:#018x}{}",
                task_cr3,
                if task_cr3 != cr3_phys {
                    " *** DIFFERS from hardware CR3! ***"
                } else {
                    " (matches hardware CR3)"
                }
            );
        }
    } else {
        crate::serial_println!("  (no current task — scheduler idle or unavailable)");
    }

    // --- Memory statistics ---
    crate::serial_println!("\x1b[1;33m--- Memory Stats ---\x1b[0m");
    if let Some(guard) = crate::memory::get_allocator().try_lock() {
        if let Some(ref alloc) = *guard {
            let (total, allocated) = alloc.page_totals();
            let free = total.saturating_sub(allocated);
            crate::serial_println!(
                "  Total={} pages ({} MiB)  Alloc={} ({} MiB)  Free={} ({} MiB)",
                total,
                total * 4 / 1024,
                allocated,
                allocated * 4 / 1024,
                free,
                free * 4 / 1024
            );
            let mut zones = [(0u8, 0u64, 0usize, 0usize); 4];
            let n = alloc.zone_snapshot(&mut zones);
            for i in 0..n {
                let (zt, base, pages, ap) = zones[i];
                crate::serial_println!(
                    "    Zone {} ({}): base={:#x} pages={} alloc={} free={}",
                    i,
                    match zt {
                        0 => "DMA",
                        1 => "Normal",
                        2 => "High",
                        _ => "?",
                    },
                    base,
                    pages,
                    ap,
                    pages.saturating_sub(ap)
                );
            }
        } else {
            crate::serial_println!("  (allocator not initialized)");
        }
    } else {
        crate::serial_println!("  (allocator lock contended — skipping)");
    }

    // --- Code bytes at RIP ---
    crate::serial_println!("\x1b[1;33m--- Code at RIP ({:#x}) ---\x1b[0m", rip);
    dump_memory_bytes(rip, cr3_phys, 32, "  ");

    // --- Stack dump ---
    crate::serial_println!("\x1b[1;33m--- Stack Dump (RSP={:#x}) ---\x1b[0m", rsp);
    dump_memory_bytes(rsp, cr3_phys, 128, "  ");

    // --- Page table walk ---
    crate::serial_println!(
        "\x1b[1;33m--- Page Table Walk (CR2={:#x}, CR3={:#x}) ---\x1b[0m",
        fault_vaddr,
        cr3_phys
    );
    if fault_addr.is_ok() {
        dump_page_table_walk(fault_vaddr, cr3_phys);
    } else {
        crate::serial_println!("  (CR2 is a non-canonical address: {:#x})", fault_vaddr);
    }

    // --- VMA regions near fault ---
    if let Some(ref t) = *task {
        crate::serial_println!("\x1b[1;33m--- VMA Regions Near Fault ---\x1b[0m");
        // SAFETY: Use the same safe ptr-chain read strategy as the Task CR3 section above:
        // Arc::as_ptr gives a valid *const AddressSpace if the Arc is alive, but the
        // Arc<AddressSpace> stored inside the SyncUnsafeCell might be corrupted.
        // We validate via translate_via_raw_pt before reading the inner ptr.
        let hhdm_vma = crate::memory::hhdm_offset();
        let safe_as: Option<*const crate::memory::AddressSpace> = unsafe {
            let as_cell_addr: u64 =
                (*alloc::sync::Arc::as_ptr(&t.process)).address_space.get() as u64;
            match translate_via_raw_pt(as_cell_addr, cr3_phys, hhdm_vma) {
                Some(phys) => {
                    // Read the Arc<AddressSpace> inner pointer (a NonNull ptr stored at this phys)
                    let as_inner_u64 = *((phys + hhdm_vma) as *const u64);
                    if as_inner_u64 == 0 {
                        None
                    } else {
                        // ArcInner<AddressSpace>.data at +16
                        let as_data_ptr = (as_inner_u64 + 2 * core::mem::size_of::<usize>() as u64)
                            as *const crate::memory::AddressSpace;
                        // Validate the AddressSpace pointer is mapped before returning it
                        if translate_via_raw_pt(as_data_ptr as u64, cr3_phys, hhdm_vma).is_some() {
                            Some(as_data_ptr)
                        } else {
                            None
                        }
                    }
                }
                None => None,
            }
        };
        if let Some(as_ptr) = safe_as {
            // SAFETY: We verified above that as_ptr is mapped and readable.
            let as_ref = unsafe { &*as_ptr };
            dump_nearby_vma_regions(as_ref, fault_vaddr);
        } else {
            crate::serial_println!("  (AddressSpace unreadable — skipping VMA dump)");
        }
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
