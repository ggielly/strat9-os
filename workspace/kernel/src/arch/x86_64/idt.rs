//! Interrupt Descriptor Table (IDT) for Strat9-OS
//!
//! Handles CPU exceptions and hardware IRQs.
//! Inspired by MaestroOS `idt.rs` and Redox-OS kernel.

use super::{pic, tss};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use x86_64::{
    structures::{
        gdt::SegmentSelector,
        idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode},
    },
    VirtAddr,
};

const KERNEL_CODE_SELECTOR: SegmentSelector = SegmentSelector(0x08);

#[repr(C, packed)]
struct Idtr {
    limit: u16,
    base: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct LiveIdtGateInfo {
    pub vector: u8,
    pub selector: u16,
    pub options: u16,
    pub offset: u64,
}

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

/// RAII guard: swap GS to kernel on entry if we came from Ring 3, and restore
/// user GS automatically on drop (covers every exit path including early returns).
///
/// # Why this is needed
/// After `swapgs ; iretq` in the Ring-3 trampoline:
///   - `IA32_GS_BASE`        = 0  (user GS base, inactive)
///   - `IA32_KERNEL_GS_BASE` = kernel per-CPU pointer
/// When an interrupt fires from Ring 3, the CPU does NOT automatically call
/// swapgs.  The first `gs:[0]` access (e.g. in `current_cpu_index`) would
/// dereference virtual address 0 → page fault → double fault → triple fault.
///
/// # Safety
/// Must be constructed **before** any `gs:[…]` access in the handler.
/// `InterruptStackFrame::code_segment` is a plain memory read from the
/// interrupt stack — it does not access GS.
struct SwapGsGuard {
    from_ring3: bool,
}

impl SwapGsGuard {
    /// Construct.  If `from_ring3` is true, executes `swapgs` immediately to
    /// restore the kernel per-CPU GS base.
    #[inline(always)]
    fn new(from_ring3: bool) -> Self {
        if from_ring3 {
            // SAFETY: We are in Ring 0 with interrupts disabled (standard for
            // interrupt handlers).  GS_BASE currently points at user space (0);
            // swapgs gives us the kernel per-CPU block via KERNEL_GS_BASE.
            unsafe { core::arch::asm!("swapgs", options(nostack, preserves_flags)) };
        }
        Self { from_ring3 }
    }
}

impl Drop for SwapGsGuard {
    #[inline(always)]
    fn drop(&mut self) {
        if self.from_ring3 {
            // SAFETY: Symmetric to the constructor.  Restores user GS_BASE so
            // that iretq returns to Ring 3 with the correct GS state.
            unsafe { core::arch::asm!("swapgs", options(nostack, preserves_flags)) };
        }
    }
}

/// Determine whether `swapgs` is needed at interrupt/exception entry.
///
/// In the normal case, `code_segment & 3 == 3` (Ring 3) means we need
/// swapgs.  However, between `swapgs` and `iretq` in
/// `elf_ring3_trampoline`, CS is still Ring 0 but `IA32_GS_BASE` is
/// already the user value (0).  If `iretq` itself faults, the exception
/// handler sees CS=Ring 0 but GS=user — the simple ring check misses
/// this.  Reading `IA32_GS_BASE` via `rdmsr` catches both cases.
///
/// Cost: ~20-30 cycles for the `rdmsr` — acceptable in exception paths
/// (not used for high-frequency IRQ handlers where IF=0 prevents
/// firing in the swapgs→iretq window).
#[inline(always)]
fn needs_swapgs(cs: u16) -> bool {
    // Fast path: Ring 3 → always need swapgs.
    if (cs & 3) == 3 {
        return true;
    }
    // Slow path: check if GS_BASE unexpectedly points to user space.
    // SAFETY: rdmsr is privileged but we are in Ring 0 (exception handler).
    let gs_base: u64 = unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!(
            "rdmsr",
            in("ecx") 0xC000_0101u32,  // IA32_GS_BASE
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags),
        );
        (lo as u64) | ((hi as u64) << 32)
    };
    gs_base < 0xFFFF_8000_0000_0000
}

/// Static IDT storage (must be 'static for load())
static mut IDT_STORAGE: InterruptDescriptorTable = InterruptDescriptorTable::new();
static IDT_STORAGE_LOCK: AtomicBool = AtomicBool::new(false);
static USER_PF_TRACE_BUDGET: AtomicU32 = AtomicU32::new(64);
static RESCHED_IPI_TRACE_BUDGET: AtomicU32 = AtomicU32::new(32);

pub fn live_gate_info(vector: u8) -> Option<LiveIdtGateInfo> {
    let mut idtr = Idtr { limit: 0, base: 0 };
    // SAFETY: `sidt` is a privileged register read with no side effect.
    unsafe {
        core::arch::asm!(
            "sidt [{}]",
            in(reg) &mut idtr,
            options(nostack, preserves_flags),
        );
    }

    let entry_offset = vector as usize * 16;
    if entry_offset + 16 > idtr.limit as usize + 1 {
        return None;
    }

    // SAFETY: The IDTR base/limit were read from the CPU and bounds-checked above.
    let (low, high) = unsafe {
        let entry_ptr = (idtr.base + entry_offset as u64) as *const u64;
        (
            core::ptr::read_unaligned(entry_ptr),
            core::ptr::read_unaligned(entry_ptr.add(1)),
        )
    };

    let offset = (low & 0xFFFF) | (((low >> 48) & 0xFFFF) << 16) | ((high & 0xFFFF_FFFF) << 32);
    let selector = ((low >> 16) & 0xFFFF) as u16;
    let options = ((low >> 32) & 0xFFFF) as u16;

    Some(LiveIdtGateInfo {
        vector,
        selector,
        options,
        offset,
    })
}

/// Decision returned by the raw interrupt trampolines.
///
/// Phase 1 of the preemptive scheduler refactor only wires the raw timer/IPI
/// stubs and returns `next_rsp = 0`, which means "restore the current
/// interrupt frame and return with iretq". The future interrupt-aware scheduler
/// path will return a non-zero `next_rsp` and matching FPU buffers.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct InterruptReturnDecision {
    pub next_rsp: u64,
    pub old_fpu: *mut u8,
    pub new_fpu: *const u8,
}

/// Raw Local APIC timer interrupt entry.
///
/// Saves registers in exactly the same order as `SyscallFrame`, calls the Rust
/// inner handler, then restores the interrupted context and returns with
/// `iretq`. This avoids the `extern "x86-interrupt"` ABI mismatch with the
/// legacy `ret`-based scheduler switch path.
#[unsafe(naked)]
unsafe extern "C" fn lapic_timer_entry() -> ! {
    core::arch::naked_asm!(
        "cld",
        // Hardware IRQ stack frame at entry:
        //   [rsp+0]  = RIP
        //   [rsp+8]  = CS
        //   [rsp+16] = RFLAGS
        //   [rsp+24] = RSP
        //   [rsp+32] = SS
        // If interrupted from Ring 3, restore kernel GS before any percpu use.
        "test qword ptr [rsp + 8], 0x3",
        "jz 2f",
        "swapgs",
        "2:",
        // Save GPRs in reverse order so that final RSP points at a SyscallFrame.
        "push rax",
        "push rcx",
        "push rdx",
        "push rdi",
        "push rsi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        // SysV large-struct return uses an implicit out-pointer in RDI.
        // Reserve 32 bytes to keep 16-byte alignment before `call`.
        "sub rsp, 32",
        "mov rdi, rsp",
        "lea rsi, [rsp + 32]",
        "call {inner}",
        // Load returned InterruptReturnDecision fields.
        "mov rax, [rsp + 0]",
        "mov rdx, [rsp + 8]",
        "mov rcx, [rsp + 16]",
        "add rsp, 32",
        "test rax, rax",
        "jz 3f",
        // Context switch path: save old task's FPU, switch stack, restore new task's FPU.
        "fxsave [rdx]",
        "mov rsp, rax",
        "fxrstor [rcx]",
        "call {switch_finish}",
        "3:",
        // No context switch (rax == 0): skip FPU save/restore entirely.
        // The interrupted task's FPU state remains unchanged.
        // Restore current SyscallFrame.
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rsi",
        "pop rdi",
        "pop rdx",
        "pop rcx",
        "pop rax",
        // Restore user GS iff we are returning to Ring 3.
        "test qword ptr [rsp + 8], 0x3",
        "jz 4f",
        "swapgs",
        "4:",
        "iretq",
        inner = sym lapic_timer_inner,
        switch_finish = sym crate::process::scheduler::finish_interrupt_switch,
    );
}

/// Raw reschedule IPI entry.
///
/// Uses the same `SyscallFrame` layout as the timer entry. Phase 1 only marks
/// a reschedule hint and returns to the interrupted context.
#[unsafe(naked)]
unsafe extern "C" fn resched_ipi_entry() -> ! {
    core::arch::naked_asm!(
        "cld",
        "test qword ptr [rsp + 8], 0x3",
        "jz 2f",
        "swapgs",
        "2:",
        "push rax",
        "mov al, 0x65",
        "out 0xe9, al",
        "push rcx",
        "push rdx",
        "push rdi",
        "push rsi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "sub rsp, 32",
        "mov al, 0x45",
        "out 0xe9, al",
        "mov rdi, rsp",
        "lea rsi, [rsp + 32]",
        "call {inner}",
        "mov rax, [rsp + 0]",
        "mov rdx, [rsp + 8]",
        "mov rcx, [rsp + 16]",
        "add rsp, 32",
        "test rax, rax",
        "jz 3f",
        "ud2",
        "3:",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rsi",
        "pop rdi",
        "pop rdx",
        "pop rcx",
        "pop rax",
        "test qword ptr [rsp + 8], 0x3",
        "jz 4f",
        "swapgs",
        "4:",
        "iretq",
        inner = sym resched_ipi_inner,
    );
}

extern "C" fn lapic_timer_inner(
    frame: &mut crate::syscall::SyscallFrame,
) -> InterruptReturnDecision {
    let cpu = crate::arch::x86_64::percpu::current_cpu_index();
    let ticks = crate::process::scheduler::ticks();
    // Heartbeat: single byte only. e9_println!/format_args in IRQ can cause issues.
    let from_ring3 = (frame.iret_cs & 3) == 3;
    if from_ring3 && (ticks < 5 || ticks % 100 == 0) {
        unsafe { core::arch::asm!("mov al, 0x48; out 0xe9, al", out("al") _) } // 'H'
    }
    crate::process::scheduler::timer_tick();
    super::apic::eoi();
    let _ = frame;

    // Temporarily keep timer IRQs side-effect free with respect to stack
    // switching. The raw `iretq`-based resume path is not yet correct for all
    // contexts:
    // - Ring 3 resumes can return with a shifted IRET frame under SMP load.
    // - Ring 0 resumes are fundamentally different because same-CPL `iretq`
    //   does not restore RSP/SS, so synthetic `SyscallFrame` resumes of kernel
    //   tasks can continue with a bogus stack pointer and RIP=0.
    // Keep only the reschedule hint here and let tasks switch on safer paths
    // (blocking syscalls, explicit yields, future validated return path).
    crate::process::scheduler::request_force_resched_hint(cpu);
    InterruptReturnDecision::default()
}

extern "C" fn resched_ipi_inner(
    frame: &mut crate::syscall::SyscallFrame,
) -> InterruptReturnDecision {
    let cpu = crate::arch::x86_64::percpu::current_cpu_index();
    let should_trace = RESCHED_IPI_TRACE_BUDGET
        .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |budget| {
            budget.checked_sub(1)
        })
        .is_ok();
    if should_trace {
        let rsp0 = crate::arch::x86_64::tss::kernel_stack_for(cpu)
            .map(|addr| addr.as_u64())
            .unwrap_or(0);
        let (slot_rip, slot_cs, slot_rsp, slot_ss) = if rsp0 >= 40 {
            // SAFETY: rsp0 points at the top of the current CPU's kernel stack.
            // During a Ring3->Ring0 interrupt, the CPU-saved IRET frame lives at
            // [rsp0-40 .. rsp0-8]. We only read those 5 u64 words for diagnosis.
            unsafe {
                let frame_base = (rsp0 - 40) as *const u64;
                (
                    *frame_base.add(0),
                    *frame_base.add(1),
                    *frame_base.add(3),
                    *frame_base.add(4),
                )
            }
        } else {
            (0, 0, 0, 0)
        };
        crate::e9_println!(
            "[ipi-rsp0] cpu={} rsp0={:#x} slot_rip={:#x} slot_cs={:#x} slot_rsp={:#x} slot_ss={:#x} frame_rip={:#x} frame_cs={:#x} frame_rsp={:#x} frame_ss={:#x}",
            cpu,
            rsp0,
            slot_rip,
            slot_cs,
            slot_rsp,
            slot_ss,
            frame.iret_rip,
            frame.iret_cs,
            frame.iret_rsp,
            frame.iret_ss,
        );
    }
    super::apic::eoi();
    crate::process::scheduler::request_force_resched_hint(cpu);
    InterruptReturnDecision::default()
}

#[inline]
fn lock_idt_storage() {
    while IDT_STORAGE_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

#[inline]
fn unlock_idt_storage() {
    IDT_STORAGE_LOCK.store(false, Ordering::Release);
}

pub fn init() {
    lock_idt_storage();
    unsafe {
        let idt = &raw mut IDT_STORAGE;

        // CPU exceptions
        (*idt)
            .breakpoint
            .set_handler_fn(breakpoint_handler)
            .set_code_selector(KERNEL_CODE_SELECTOR);
        (*idt)
            .page_fault
            .set_handler_fn(page_fault_handler)
            .set_code_selector(KERNEL_CODE_SELECTOR);
        (*idt)
            .general_protection_fault
            .set_handler_fn(general_protection_fault_handler)
            .set_code_selector(KERNEL_CODE_SELECTOR);
        (*idt)
            .stack_segment_fault
            .set_handler_fn(stack_segment_fault_handler)
            .set_code_selector(KERNEL_CODE_SELECTOR);
        (*idt)
            .non_maskable_interrupt
            .set_handler_fn(non_maskable_interrupt_handler)
            .set_code_selector(KERNEL_CODE_SELECTOR);
        (*idt)
            .invalid_opcode
            .set_handler_fn(invalid_opcode_handler)
            .set_code_selector(KERNEL_CODE_SELECTOR);
        (*idt)
            .double_fault
            .set_handler_fn(double_fault_handler)
            .set_code_selector(KERNEL_CODE_SELECTOR)
            .set_stack_index(tss::DOUBLE_FAULT_IST_INDEX);

        // Hardware IRQs (PIC remapped to 0x20+)
        let idt_ref = &mut *idt;
        idt_ref[irq::TIMER as u8]
            .set_handler_fn(legacy_timer_handler)
            .set_code_selector(KERNEL_CODE_SELECTOR);
        idt_ref[irq::KEYBOARD as u8]
            .set_handler_fn(keyboard_handler)
            .set_code_selector(KERNEL_CODE_SELECTOR);
        idt_ref[irq::MOUSE as u8]
            .set_handler_fn(mouse_handler)
            .set_code_selector(KERNEL_CODE_SELECTOR);

        // Spurious interrupt handler at vector 0xFF (APIC spurious vector)
        idt_ref[0xFF_u8]
            .set_handler_fn(spurious_handler)
            .set_code_selector(KERNEL_CODE_SELECTOR);

        // Cross-CPU reschedule IPI (vector 0xE0)

        idt_ref[super::apic::IPI_RESCHED_VECTOR as u8]
            .set_handler_addr(VirtAddr::from_ptr(resched_ipi_entry as *const ()))
            .set_code_selector(KERNEL_CODE_SELECTOR);

        // Cross-CPU TLB shootdown IPI (vector 0xF0)
        idt_ref[super::apic::IPI_TLB_SHOOTDOWN_VECTOR as u8]
            .set_handler_fn(tlb_shootdown_handler)
            .set_code_selector(KERNEL_CODE_SELECTOR);

        (*idt).load_unsafe();
    }
    unlock_idt_storage();

    log::debug!("IDT initialized with {} entries", 256);
}

pub fn load() {
    lock_idt_storage();
    unsafe {
        let idt = &raw const IDT_STORAGE;
        (*idt).load_unsafe();
    }
    unlock_idt_storage();
}

/// Register the Local APIC timer IRQ vector to use the timer handler.
pub fn register_lapic_timer_vector(vector: u8) {
    lock_idt_storage();
    unsafe {
        let idt = &raw mut IDT_STORAGE;
        (&mut *idt)[vector]
            .set_handler_addr(VirtAddr::from_ptr(lapic_timer_entry as *const ()))
            .set_code_selector(KERNEL_CODE_SELECTOR);
        (*idt).load_unsafe();
    }
    unlock_idt_storage();
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

    lock_idt_storage();
    unsafe {
        let idt = &raw mut IDT_STORAGE;
        (&mut *idt)[vector]
            .set_handler_fn(ahci_handler)
            .set_code_selector(KERNEL_CODE_SELECTOR);
        (*idt).load_unsafe();
    }
    unlock_idt_storage();
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

    lock_idt_storage();
    unsafe {
        let idt = &raw mut IDT_STORAGE;
        (&mut *idt)[vector]
            .set_handler_fn(virtio_block_handler)
            .set_code_selector(KERNEL_CODE_SELECTOR);
        (*idt).load_unsafe();
    }
    unlock_idt_storage();
    log::info!("VirtIO-blk IRQ {} registered on vector {:#x}", irq, vector);
}

/// Register the xHCI USB controller IRQ handler.
///
/// Called after xHCI initialization once the PCI interrupt line is known.
pub fn register_xhci_irq(irq: u8) {
    let vector = if irq < 16 {
        super::pic::PIC1_OFFSET + irq
    } else {
        irq
    };

    lock_idt_storage();
    unsafe {
        let idt = &raw mut IDT_STORAGE;
        (&mut *idt)[vector]
            .set_handler_fn(xhci_handler)
            .set_code_selector(KERNEL_CODE_SELECTOR);
        (*idt).load_unsafe();
    }
    unlock_idt_storage();
    log::info!("xHCI IRQ {} registered on vector {:#x}", irq, vector);
}

// =============================================
// CPU Exception Handlers
// =============================================

/// Performs the breakpoint handler operation.
extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    let _gs = SwapGsGuard::new(needs_swapgs(stack_frame.code_segment.0));
    log::warn!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

/// Performs the invalid opcode handler operation.
extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    let cs = stack_frame.code_segment.0;
    let is_user = (cs & 3) == 3;
    let _gs = SwapGsGuard::new(needs_swapgs(cs));
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

extern "x86-interrupt" fn non_maskable_interrupt_handler(stack_frame: InterruptStackFrame) {
    // NMI can fire at any point — including the swapgs→iretq window.
    // Use rdmsr to safely restore kernel GS if needed.
    let _gs = SwapGsGuard::new(needs_swapgs(stack_frame.code_segment.0));
    crate::serial_force_println!(
        "[NMI] rip={:#x} cs={:#x}",
        stack_frame.instruction_pointer.as_u64(),
        stack_frame.code_segment.0
    );
    crate::arch::x86_64::cli();
    loop {
        crate::arch::x86_64::hlt();
    }
}

/// Performs the page fault handler operation.
extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    use x86_64::registers::control::Cr2;
    let cs = stack_frame.code_segment.0;
    let is_user = (cs & 3) == 3;
    // SAFETY: must be before any gs:[...] access – GS may point to user memory
    // if the fault fired from Ring 3 (after swapgs in elf_ring3_trampoline),
    // OR during the swapgs→iretq window (CS=Ring0 but GS=user).
    // needs_swapgs() uses rdmsr to catch both cases.
    let swapgs_needed = needs_swapgs(cs);
    let _gs = SwapGsGuard::new(swapgs_needed);

    // Detect the swapgs→iretq window: CS=Ring0 but GS was user (0).
    if swapgs_needed && !is_user {
        let fault_addr = x86_64::registers::control::Cr2::read()
            .as_ref()
            .map(|v| v.as_u64())
            .unwrap_or(0);
        crate::serial_force_println!(
            "\x1b[31;1m[pagefault]\x1b[0m SWAPGS-WINDOW: CS={:#x} (Ring0) but GS was user! rip={:#x} addr={:#x} err={:#x}",
            cs,
            stack_frame.instruction_pointer.as_u64(),
            fault_addr,
            error_code.bits()
        );
        panic!("#PF in swapgs→iretq window");
    }

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

    if is_user {
        if let Some(task) = crate::process::current_task_clone() {
            let address_space = unsafe { &*task.process.address_space.get() };
            if let Ok(vaddr) = fault_addr {
                if do_pf_trace {
                    // FORCE OUTPUT for the first user faults only; lazy demand paging can
                    // legitimately fault thousands of times during boot and flood serial.
                    crate::serial_force_println!(
                        "\x1b[33m[pagefault] USER fault\x1b[0m: tid={} rip={:#x} addr={:#x} err={:#x}",
                        task.tid,
                        rip,
                        vaddr.as_u64(),
                        error_code.bits()
                    );
                    // Mirror to e9 so the first handled faults stay visible in e9_debug.log.
                    crate::e9_println!(
                        "[PF] tid={} rip={:#x} addr={:#x} err={:#x}",
                        task.tid,
                        rip,
                        vaddr.as_u64(),
                        error_code.bits()
                    );
                }

                match address_space.handle_fault(vaddr.as_u64()) {
                    Ok(()) => {
                        if do_pf_trace {
                            crate::serial_force_println!(
                                "\x1b[32m[pagefault] USER fault resolved\x1b[0m: tid={} addr={:#x}",
                                task.tid,
                                vaddr.as_u64()
                            );
                        }
                        return;
                    }
                    Err(e) => {
                        crate::serial_force_println!(
                            "\x1b[31m[pagefault] USER fault resolution FAILED\x1b[0m: tid={} addr={:#x} err={:?}",
                            task.tid,
                            vaddr.as_u64(),
                            e
                        );
                        crate::e9_println!(
                            "[PF-FAIL] tid={} rip={:#x} addr={:#x}",
                            task.tid,
                            rip,
                            vaddr.as_u64()
                        );
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
                fault_addr.as_ref().map(|v| v.as_u64()).unwrap_or(0),
                error_code.bits() as u64,
                stack_frame.instruction_pointer.as_u64(),
            );
            return;
        }
    } else {
        // FORCE OUTPUT for kernel fault
        crate::serial_force_println!(
            "\x1b[31;1m[pagefault] KERNEL fault\x1b[0m: rip={:#x} addr={:#x} err={:#x}",
            rip,
            fault_addr.as_ref().map(|v| v.as_u64()).unwrap_or(0),
            error_code.bits()
        );
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
    let cs = stack_frame.code_segment.0;
    let is_user = (cs & 3) == 3;
    // Use rdmsr-based check: catches the swapgs→iretq window where
    // CS=Ring0 but GS=user (0).  Without this, #GP from a bad iretq
    // would escalate to double fault → triple fault.
    let swapgs_needed = needs_swapgs(cs);
    let _gs = SwapGsGuard::new(swapgs_needed);
    // Detect the swapgs→iretq window case: CS says Ring 0 but GS was user.
    if swapgs_needed && !is_user {
        crate::serial_force_println!(
            "\x1b[31;1m[GPF]\x1b[0m SWAPGS-WINDOW: CS={:#x} (Ring0) but GS was user! rip={:#x} err={:#x} rsp={:#x}",
            cs,
            stack_frame.instruction_pointer.as_u64(),
            error_code,
            stack_frame.stack_pointer.as_u64()
        );
        panic!("#GP in swapgs→iretq window (iretq frame invalid?)");
    }
    if is_user {
        if let Some(tid) = crate::process::current_task_id() {
            crate::serial_force_println!(
                "\x1b[31;1m[GPF]\x1b[0m USER tid={} rip={:#x} err={:#x}",
                tid,
                stack_frame.instruction_pointer.as_u64(),
                error_code
            );
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
    crate::serial_force_println!(
        "\x1b[31;1m[GPF]\x1b[0m KERNEL rip={:#x} err={:#x} cs={:#x} rsp={:#x}",
        stack_frame.instruction_pointer.as_u64(),
        error_code,
        stack_frame.code_segment.0,
        stack_frame.stack_pointer.as_u64()
    );
    panic!("General protection fault");
}

/// Performs the stack segment fault handler operation.
extern "x86-interrupt" fn stack_segment_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    // Use rdmsr-based check: iretq can trigger #SS if the user SS is bad,
    // and at that point GS is already swapped to user.
    let _gs = SwapGsGuard::new(needs_swapgs(stack_frame.code_segment.0));
    crate::serial_force_println!(
        "\x1b[31;1m[STACK_FAULT]\x1b[0m rip={:#x} err={:#x} cs={:#x} rsp={:#x}",
        stack_frame.instruction_pointer.as_u64(),
        error_code,
        stack_frame.code_segment.0,
        stack_frame.stack_pointer.as_u64()
    );
    panic!("Stack segment fault");
}

/// Performs the double fault handler operation.
///
/// Uses IST stack so the handler always runs on a known-good stack, even
/// when RSP0 is corrupt.  We must still do `swapgs` if the fault originated
/// from Ring 3 (or from Ring 0 code that already did `swapgs`, e.g. the
/// `iretq` path in `elf_ring3_trampoline`).
///
/// # Note on divergent handler
/// This handler is `-> !`, so `SwapGsGuard::drop` will never run.  That is
/// fine because we never return to the interrupted context.
extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) -> ! {
    // Best-effort swapgs: if GS currently points at user space (address 0)
    // we need to swap to kernel GS so that any code below that touches
    // `gs:[0]` (e.g. via `current_cpu_index`) does not page-fault again.
    // We use a raw read of IA32_GS_BASE via rdmsr to decide.
    //
    // During `elf_ring3_trampoline`, `swapgs` is executed *before* `iretq`.
    // If `iretq` itself faults, `code_segment` is still Ring 0 (0x08) but
    // GS_BASE is already the user value (0).  The normal `cs & 3 == 3` test
    // would miss this case.  Reading the MSR catches it.
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!(
            "rdmsr",
            in("ecx") 0xC000_0101u32,  // IA32_GS_BASE
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags),
        );
        let gs_base = (lo as u64) | ((hi as u64) << 32);
        // If GS_BASE is in the low half (user space) or zero, swap to kernel.
        if gs_base < 0xFFFF_8000_0000_0000 {
            core::arch::asm!("swapgs", options(nostack, preserves_flags));
        }
    }
    crate::serial_force_println!(
        "\x1b[31;1m[DOUBLE_FAULT]\x1b[0m rip={:#x} err={:#x} cs={:#x} rsp={:#x}",
        stack_frame.instruction_pointer.as_u64(),
        error_code,
        stack_frame.code_segment.0,
        stack_frame.stack_pointer.as_u64()
    );
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
extern "x86-interrupt" fn legacy_timer_handler(stack_frame: InterruptStackFrame) {
    // Restore kernel GS if the timer fired while Ring 3 was running.
    let _gs = SwapGsGuard::new((stack_frame.code_segment.0 & 3) == 3);
    if crate::arch::x86_64::timer::is_apic_timer_active() {
        // Ignore legacy timer source once LAPIC timer is running.
        if super::apic::is_initialized() {
            super::apic::eoi();
        } else {
            pic::end_of_interrupt(0);
        }
        return;
    }

    // FORCE OUTPUT for heartbeat (every 100 ticks to avoid flooding,
    // plus first 10 ticks to confirm timer fires after Ring-3 entry)
    let ticks = crate::process::scheduler::ticks();
    if ticks < 10 || ticks % 100 == 0 {
        crate::serial_force_println!("[heartbeat] PIC timer tick={}", ticks);
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
    if ticks < 10 {
        crate::serial_force_println!("[heartbeat] PIC timer tick={} preempt_done", ticks);
    }
}

/// Local APIC timer handler (dedicated vector, e.g. 0xD2).
extern "x86-interrupt" fn lapic_timer_handler(stack_frame: InterruptStackFrame) {
    // Restore kernel GS if the timer fired while Ring 3 was running.
    let cs = stack_frame.code_segment.0;
    let _gs = SwapGsGuard::new((cs & 3) == 3);
    let cpu = crate::arch::x86_64::percpu::current_cpu_index();
    let ticks = crate::process::scheduler::ticks();
    // Trace first 10 ticks per CPU unconditionally to confirm timer fires
    // after Ring-3 entry, then one-per-100 heartbeat to avoid flooding.
    if ticks < 10 || ticks % 100 == 0 {
        crate::serial_force_println!(
            "[heartbeat] APIC timer tick={} cpu={} cs={:#x} rip={:#x}",
            ticks,
            cpu,
            cs,
            stack_frame.instruction_pointer.as_u64()
        );
    }

    // serial_force_println holds FORCE_LOCK (IRQ-disabled spinlock) while writing
    // to the UART. At 115200 baud each byte takes ~87 µs; a 60-char message is
    // ~5 ms of IRQs-off time — long enough to miss ticks and corrupt scheduling.
    // Keep serial output out of the hot IRQ path; use e9 port (µs-range) instead.
    unsafe { core::arch::asm!("mov al, '0'; out 0xe9, al", out("al") _) };
    crate::process::scheduler::timer_tick();
    unsafe { core::arch::asm!("mov al, '1'; out 0xe9, al", out("al") _) };
    super::apic::eoi();
    // IMPORTANT:
    // Do not run `maybe_preempt()` directly from a Ring-3-origin timer IRQ.
    //
    // Current scheduler switch path (`do_switch_context` + `ret`) is built for
    // task context frames, while this function is an `extern "x86-interrupt"`
    // frame that the compiler expects to unwind with iretq.
    //
    // On first user-mode preemption (CPU1), switching away from this frame can
    // corrupt the interrupt return state and trigger #DF/#TF. Instead, mark a
    // lock-free resched hint and return through the normal interrupt epilogue.
    // The scheduler will consume the hint on a safe path.
    if (cs & 3) == 3 {
        crate::process::scheduler::request_force_resched_hint(cpu);
        unsafe { core::arch::asm!("mov al, 'P'; out 0xe9, al", out("al") _) };
    } else {
        crate::process::scheduler::maybe_preempt();
    }
}

/// PS/2 Mouse IRQ12 handler.
extern "x86-interrupt" fn mouse_handler(_stack_frame: InterruptStackFrame) {
    crate::arch::x86_64::mouse::handle_irq();
    // PS/2 mouse IRQ12 is intentionally kept on the remapped legacy PIC path.
    // Even when LAPIC/IOAPIC are active for timer/IPI traffic, this source must
    // still be acknowledged via the 8259 PIC.
    pic::end_of_interrupt(12);
}

/// Performs the keyboard handler operation.
extern "x86-interrupt" fn keyboard_handler(_stack_frame: InterruptStackFrame) {
    let raw = unsafe { super::io::inb(0x60) };
    // Port 0x60 is consumed on read: feed the raw scancode directly.
    if let Some(ch) = super::keyboard_layout::handle_scancode_raw(raw) {
        crate::arch::x86_64::keyboard::add_to_buffer(ch);
    }

    // PS/2 keyboard IRQ1 is intentionally kept on the remapped legacy PIC path.
    // A LAPIC EOI here leaves the PIC request in service and stalls keyboard
    // delivery after the first edge.
    pic::end_of_interrupt(1);
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

/// xHCI USB controller IRQ handler
///
/// Handles interrupts from the xHCI host controller.
/// Processes event ring completions for control transfers and HID reports.
extern "x86-interrupt" fn xhci_handler(_stack_frame: InterruptStackFrame) {
    crate::hardware::usb::xhci::handle_interrupt();

    if super::apic::is_initialized() {
        super::apic::eoi();
    } else {
        let irq =
            crate::hardware::usb::xhci::XHCI_IRQ_LINE.load(core::sync::atomic::Ordering::Relaxed);
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
extern "x86-interrupt" fn resched_ipi_handler(stack_frame: InterruptStackFrame) {
    // Restore kernel GS if the IPI arrived while Ring 3 was running.
    let _gs = SwapGsGuard::new((stack_frame.code_segment.0 & 3) == 3);
    super::apic::eoi();
    crate::process::scheduler::maybe_preempt();
}

/// Cross-CPU TLB shootdown IPI handler (vector 0xF0).
extern "x86-interrupt" fn tlb_shootdown_handler(stack_frame: InterruptStackFrame) {
    // Restore kernel GS if the IPI arrived while Ring 3 was running.
    let _gs = SwapGsGuard::new((stack_frame.code_segment.0 & 3) == 3);
    // Note: EOI is sent by the architecture-independent handler.
    super::tlb::tlb_shootdown_ipi_handler();
}
