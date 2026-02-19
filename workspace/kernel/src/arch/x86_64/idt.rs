//! Interrupt Descriptor Table (IDT) for Strat9-OS
//!
//! Handles CPU exceptions and hardware IRQs.
//! Inspired by MaestroOS `idt.rs` and RedoxOS kernel.

use super::{pic, tss};
use x86_64::{
    structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode},
    VirtAddr,
};

/// IRQ interrupt vector numbers (PIC1_OFFSET + IRQ number)
#[allow(dead_code)]
pub mod irq {
    pub const TIMER: u8 = super::pic::PIC1_OFFSET; // IRQ0 = 0x20
    pub const KEYBOARD: u8 = super::pic::PIC1_OFFSET + 1; // IRQ1 = 0x21
    pub const CASCADE: u8 = super::pic::PIC1_OFFSET + 2; // IRQ2 = 0x22
    pub const COM2: u8 = super::pic::PIC1_OFFSET + 3; // IRQ3 = 0x23
    pub const COM1: u8 = super::pic::PIC1_OFFSET + 4; // IRQ4 = 0x24
    pub const FLOPPY: u8 = super::pic::PIC1_OFFSET + 6; // IRQ6 = 0x26
    pub const ATA_PRIMARY: u8 = super::pic::PIC1_OFFSET + 14; // IRQ14 = 0x2E
    pub const ATA_SECONDARY: u8 = super::pic::PIC1_OFFSET + 15; // IRQ15 = 0x2F
}

/// Static IDT storage (must be 'static for load())
static mut IDT_STORAGE: InterruptDescriptorTable = InterruptDescriptorTable::new();

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
        idt_ref[irq::TIMER as u8].set_handler_fn(timer_handler);
        idt_ref[irq::KEYBOARD as u8].set_handler_fn(keyboard_handler);

        // Spurious interrupt handler at vector 0xFF (APIC spurious vector)
        idt_ref[0xFF_u8].set_handler_fn(spurious_handler);

        // Cross-CPU reschedule IPI (vector 0xF0)
        idt_ref[super::apic::IPI_RESCHED_VECTOR].set_handler_fn(resched_ipi_handler);

        (*idt).load_unsafe();
    }

    log::debug!("IDT initialized with {} entries", 256);
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

    // SAFETY: Called during kernel init, before interrupts are fully enabled
    unsafe {
        let idt = &raw mut IDT_STORAGE;
        (&mut *idt)[vector].set_handler_fn(virtio_block_handler);
        (*idt).load_unsafe();
    }
    log::info!(
        "VirtIO-blk IRQ {} registered on vector {:#x}",
        irq,
        vector
    );
}

// =============================================
// CPU Exception Handlers
// =============================================

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    log::warn!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    let is_user = (stack_frame.code_segment.0 & 3) == 3;
    if is_user {
        if let Some(tid) = crate::process::current_task_id() {
            crate::silo::handle_user_fault(
                tid,
                crate::silo::SiloFaultReason::InvalidOpcode,
                stack_frame.instruction_pointer.as_u64(),
                0,
            );
            return;
        }
    }
    log::error!("EXCEPTION: INVALID OPCODE\n{:#?}", stack_frame);
    panic!("Invalid opcode");
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    use x86_64::registers::control::{Cr2, Cr3};
    let is_user = (stack_frame.code_segment.0 & 3) == 3;
    if is_user {
        if let Some(tid) = crate::process::current_task_id() {
            crate::silo::handle_user_fault(
                tid,
                crate::silo::SiloFaultReason::PageFault,
                Cr2::read().unwrap_or(VirtAddr::new(0)).as_u64(),
                error_code.bits() as u64,
            );
            return;
        }
    }

    log::error!("EXCEPTION: PAGE FAULT");
    let fault_addr = Cr2::read();
    log::error!("Accessed Address: {:?}", fault_addr);
    log::error!("Error Code: {:?}", error_code);
    log::error!("{:#?}", stack_frame);

    // Diagnostic: manual page table walk to show which level fails
    if let Ok(vaddr) = fault_addr {
        let addr = vaddr.as_u64();
        let (cr3_frame, _) = Cr3::read();
        let cr3_phys = cr3_frame.start_address().as_u64();
        let hhdm = crate::memory::hhdm_offset();
        log::error!(
            "=== Page table walk for {:#x} (CR3={:#x}) ===",
            addr,
            cr3_phys
        );

        // SAFETY: Read-only access to page tables via HHDM for diagnostics.
        unsafe {
            let l4_ptr = (cr3_phys + hhdm) as *const u64;
            let l4_idx = ((addr >> 39) & 0x1FF) as usize;
            let l4_entry = *l4_ptr.add(l4_idx);
            log::error!(
                "  PML4[{}] = {:#x} (present={})",
                l4_idx,
                l4_entry,
                l4_entry & 1
            );
            if l4_entry & 1 == 0 {
                log::error!("  -> WALK STOPS: PML4 entry not present");
            } else {
                let l3_phys = l4_entry & 0x000F_FFFF_FFFF_F000;
                let l3_ptr = (l3_phys + hhdm) as *const u64;
                let l3_idx = ((addr >> 30) & 0x1FF) as usize;
                let l3_entry = *l3_ptr.add(l3_idx);
                log::error!(
                    "  PDPT[{}] = {:#x} (present={})",
                    l3_idx,
                    l3_entry,
                    l3_entry & 1
                );
                if l3_entry & 1 == 0 {
                    log::error!("  -> WALK STOPS: PDPT entry not present");
                } else if l3_entry & 0x80 != 0 {
                    log::error!("  -> 1GiB huge page");
                } else {
                    let l2_phys = l3_entry & 0x000F_FFFF_FFFF_F000;
                    let l2_ptr = (l2_phys + hhdm) as *const u64;
                    let l2_idx = ((addr >> 21) & 0x1FF) as usize;
                    let l2_entry = *l2_ptr.add(l2_idx);
                    log::error!(
                        "  PD[{}] = {:#x} (present={})",
                        l2_idx,
                        l2_entry,
                        l2_entry & 1
                    );
                    if l2_entry & 1 == 0 {
                        log::error!("  -> WALK STOPS: PD entry not present");
                    } else if l2_entry & 0x80 != 0 {
                        log::error!("  -> 2MiB huge page");
                    } else {
                        let l1_phys = l2_entry & 0x000F_FFFF_FFFF_F000;
                        let l1_ptr = (l1_phys + hhdm) as *const u64;
                        let l1_idx = ((addr >> 12) & 0x1FF) as usize;
                        let l1_entry = *l1_ptr.add(l1_idx);
                        log::error!(
                            "  PT[{}] = {:#x} (present={})",
                            l1_idx,
                            l1_entry,
                            l1_entry & 1
                        );
                        if l1_entry & 1 == 0 {
                            log::error!("  -> WALK STOPS: PT entry not present");
                        } else {
                            log::error!("  -> page present (flags issue?)");
                        }
                    }
                }
            }
        }
    }

    panic!("Page fault");
}

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
            );
            return;
        }
    }
    log::error!("EXCEPTION: GENERAL PROTECTION FAULT");
    log::error!("Error Code: {:#x}", error_code);
    log::error!("{:#?}", stack_frame);
    panic!("General protection fault");
}

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

extern "x86-interrupt" fn timer_handler(_stack_frame: InterruptStackFrame) {
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

extern "x86-interrupt" fn keyboard_handler(_stack_frame: InterruptStackFrame) {
    // Read scancode and convert to character using the selected layout
    // Store in keyboard buffer for userspace/shell to read
    // Do NOT echo here - let the shell handle display to avoid double-echo
    if let Some(ch) = super::keyboard_layout::handle_scancode() {
        // Store character in keyboard buffer (for future shell input)
        crate::arch::x86_64::keyboard::add_to_buffer(ch);

        // Echo to serial only for debugging (not VGA to avoid double-echo)
        crate::serial_print!("{}", ch as char);
    }

    // Send EOI to the appropriate interrupt controller
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

/// VirtIO Block device IRQ handler
///
/// Handles interrupts from the VirtIO block device.
/// The IRQ line is determined at runtime from PCI config.
extern "x86-interrupt" fn virtio_block_handler(_stack_frame: InterruptStackFrame) {
    // Handle the VirtIO block interrupt
    crate::drivers::virtio::block::handle_interrupt();

    // Send EOI
    if super::apic::is_initialized() {
        super::apic::eoi();
    } else {
        // Get the IRQ number from the device
        let irq = crate::drivers::virtio::block::get_irq();
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
/// EOI is sent **before** `maybe_preempt()` so the APIC can accept further
/// IPIs before the potentially long context-switch path runs.
extern "x86-interrupt" fn resched_ipi_handler(_stack_frame: InterruptStackFrame) {
    super::apic::eoi();
    crate::process::scheduler::maybe_preempt();
}
