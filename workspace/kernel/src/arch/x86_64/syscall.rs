//! SYSCALL/SYSRET interface for Strat9-OS
//!
//! Configures the x86_64 SYSCALL/SYSRET MSRs and provides the naked
//! assembly entry point that bridges Ring 3 → Ring 0 → Rust dispatcher.
//!
//! ## Per-CPU design (SWAPGS + GS-base)
//!
//! SYSCALL entry uses SWAPGS to switch GS base to a per-CPU block
//! that stores the kernel RSP and temporary user RSP. This enables
//! SMP-safe SYSCALL entry without a global KERNEL_RSP.
//!
//! ## Register convention on SYSCALL entry
//!
//! CPU sets: RCX = user RIP, R11 = user RFLAGS, IF cleared via FMASK.
//! Userspace passes: RAX = syscall number, RDI/RSI/RDX/R10/R8/R9 = args 1-6.

/// MSR addresses
const IA32_EFER: u32 = 0xC000_0080;
const IA32_STAR: u32 = 0xC000_0081;
const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_FMASK: u32 = 0xC000_0084;

/// EFER bit: System Call Extensions
const EFER_SCE: u64 = 1 << 0;

/// FMASK: Clear IF (0x200), DF (0x400), TF (0x100) on SYSCALL entry.
/// This ensures interrupts are disabled and direction flag is clear.
const FMASK_VALUE: u64 = 0x200 | 0x400 | 0x100;

/// Update the kernel RSP used by the SYSCALL entry point.
///
/// Called by the scheduler on every context switch to point to the
/// top of the new task's kernel stack.
pub fn set_kernel_rsp(rsp: u64) {
    // SAFETY: Called with interrupts disabled from the scheduler.
    crate::arch::x86_64::percpu::set_kernel_rsp_current(rsp);
}

/// Initialize the SYSCALL/SYSRET MSRs.
///
/// Must be called after GDT init (needs segment selectors).
pub fn init() {
    use super::{rdmsr, wrmsr};

    // Enable System Call Extensions in EFER
    let efer = rdmsr(IA32_EFER);
    wrmsr(IA32_EFER, efer | EFER_SCE);

    // STAR: kernel CS/SS in [47:32], user CS/SS base in [63:48]
    let star = super::gdt::star_msr_value();
    wrmsr(IA32_STAR, star);

    // LSTAR: RIP loaded on SYSCALL
    let entry_addr = syscall_entry as *const () as u64;
    wrmsr(IA32_LSTAR, entry_addr);

    // FMASK: bits to clear in RFLAGS on SYSCALL
    wrmsr(IA32_FMASK, FMASK_VALUE);

    log::info!(
        "SYSCALL/SYSRET initialized: LSTAR={:#x}, STAR={:#x}, FMASK={:#x}",
        entry_addr,
        star,
        FMASK_VALUE,
    );
}

/// The SYSCALL entry point (naked function).
///
/// On entry from userspace:
/// - RCX = user RIP (saved by CPU)
/// - R11 = user RFLAGS (saved by CPU)
/// - RSP = user stack pointer (NOT saved by CPU — we must save it)
/// - IF = 0 (cleared by FMASK)
/// - RAX = syscall number
/// - RDI, RSI, RDX, R10, R8, R9 = arguments 1-6
///
/// We build a `SyscallFrame` on the kernel stack and call the Rust dispatcher.
#[unsafe(naked)]
unsafe extern "C" fn syscall_entry() {
    core::arch::naked_asm!(
        // Swap GS to kernel base (per-CPU)
        "swapgs",

        // Save user RSP and switch to kernel stack (per-CPU via GS)
        "mov gs:[{user_rsp_off}], rsp",
        "mov rsp, gs:[{kernel_rsp_off}]",

        // Build IRET-compatible frame on kernel stack (for potential IRET exit)
        // Push order: SS, RSP, RFLAGS, CS, RIP (reverse of IRET pop order)
        "push 0x23",               // User SS (user_data | RPL3)
        "push gs:[{user_rsp_off}]",// User RSP
        "push r11",                // User RFLAGS (saved by CPU in R11)
        "push 0x2B",               // User CS (user_code64 | RPL3)
        "push rcx",                // User RIP (saved by CPU in RCX)

        // Save all general-purpose registers (SyscallFrame layout)
        "push rax",                // Syscall number
        "push rcx",                // (user RIP, saved again for frame access)
        "push rdx",
        "push rdi",
        "push rsi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",                // (user RFLAGS, saved again)
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",

        // Call Rust dispatcher: rdi = pointer to SyscallFrame
        "mov rdi, rsp",
        "call {dispatch}",

        // Return value is in RAX — write it into the frame's rax slot
        // SyscallFrame layout: r15 is at RSP+0, ..., rax is at RSP+14*8 = RSP+112
        "mov [rsp + 14*8], rax",

        // Restore general-purpose registers
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
        "pop rax",                 // Restored return value

        // Peek at user RIP without consuming it from the IRET frame.
        // RSP stays pointing at [RIP | CS | RFLAGS | RSP_user | SS], so:
        //   - the IRET path needs zero stack adjustment (just swapgs + iretq), and
        //   - the SYSRETQ path skips RIP+CS in one add rsp, 16.
        "mov rcx, [rsp]",

        // Canonical address check: SYSRETQ with a non-canonical RCX executes the
        // target in Ring 0 on some Intel CPUs (AMD64 erratum).  Fall back to IRETQ
        // which faults cleanly instead.  Sign-extend bit 47 to bits 48-63:
        "mov r11, rcx",
        "sar r11, 47",
        "cmp r11, 0",
        "je 2f",
        "cmp r11, -1",
        "je 2f",
        "jmp 3f",

        "2:",
        // SYSRETQ fast path — skip RIP and CS in one step.
        "add rsp, 16",             // Skip RIP + CS
        "pop r11",                 // User RFLAGS into R11
        "pop rsp",                 // User RSP
        "swapgs",
        "sysretq",                 // RCX→RIP, R11→RFLAGS, CS/SS from STAR MSR

        "3:",
        // IRET slow path — RSP already points at the complete [RIP, CS, RFLAGS, RSP, SS]
        // frame; no stack fixup needed.
        "swapgs",
        "iretq",

        user_rsp_off = const crate::arch::x86_64::percpu::USER_RSP_OFFSET,
        kernel_rsp_off = const crate::arch::x86_64::percpu::KERNEL_RSP_OFFSET,
        dispatch = sym crate::syscall::dispatch,
    );
}
