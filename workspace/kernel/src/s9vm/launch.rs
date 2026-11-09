//! s9vm — guest entry/exit trampoline.
//!
//! The only reliable way to enter the guest is an assembly routine
//! that honors the hardware contract:
//!
//! 1. save the host callee-saved registers;
//! 2. load the guest general-purpose registers from [`EnterFrame`];
//! 3. execute `vmlaunch` (first entry) or `vmresume` (subsequent
//!    entries);
//! 4. on exit, the hardware loads `HOST_RSP`/`HOST_RIP`: control arrives at the
//!    `s9vm_guest_exit` label, which saves the guest registers and restores
//!    the host.
//!
//! # Contract
//!
//! `s9vm_enter_guest(frame, host_stack_top) -> u64`
//! - `frame`: `*mut EnterFrame`, live for the whole call;
//! - `host_stack_top`: top (16-byte aligned) of a dedicated host stack,
//!    written into `HOST_RSP` before entry;
//! - return: `0` = normal guest exit (read the reason from the control
//!   block), `1` = entry failure (`VMfail`, read the status).
//!
//! The frame is referenced by a pointer stored on the host stack
//! (`[host_stack_top - 8]`), which makes it possible to find it again on return
//! without depending on a register (all GPRs belong to the guest).
//!
//! The `S9VM_F_*` offsets are shared between the assembler and the Rust
//! structure; a host test verifies that they match (`offset_of!`).

use core::arch::global_asm;

/// Guest general-purpose registers, in save order.
pub const S9VM_F_RAX: usize = 0;
pub const S9VM_F_RBX: usize = 8;
pub const S9VM_F_RCX: usize = 16;
pub const S9VM_F_RDX: usize = 24;
pub const S9VM_F_RSI: usize = 32;
pub const S9VM_F_RDI: usize = 40;
pub const S9VM_F_RBP: usize = 48;
pub const S9VM_F_RSP: usize = 56;
pub const S9VM_F_R8: usize = 64;
pub const S9VM_F_R9: usize = 72;
pub const S9VM_F_R10: usize = 80;
pub const S9VM_F_R11: usize = 88;
pub const S9VM_F_R12: usize = 96;
pub const S9VM_F_R13: usize = 104;
pub const S9VM_F_R14: usize = 112;
pub const S9VM_F_R15: usize = 120;
pub const S9VM_F_RIP: usize = 128;
pub const S9VM_F_RFLAGS: usize = 136;
pub const S9VM_F_HOST_RSP: usize = 144;
pub const S9VM_F_HOST_RBX: usize = 152;
pub const S9VM_F_HOST_RBP: usize = 160;
pub const S9VM_F_HOST_R12: usize = 168;
pub const S9VM_F_HOST_R13: usize = 176;
pub const S9VM_F_HOST_R14: usize = 184;
pub const S9VM_F_HOST_R15: usize = 192;
pub const S9VM_F_STATUS: usize = 200;
pub const S9VM_F_LAUNCHED: usize = 208;
/// Total size of the frame.
pub const S9VM_ENTER_FRAME_SIZE: usize = 216;

/// Exchange area between the kernel and the trampoline for one guest entry.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EnterFrame {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    /// Guest RSP (informational: the hardware uses `GUEST_RSP`).
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    /// Guest RIP (informational: the hardware uses `GUEST_RIP`).
    pub rip: u64,
    /// Guest RFLAGS (informational).
    pub rflags: u64,
    /// Host RSP saved by the trampoline.
    pub host_rsp: u64,
    pub host_rbx: u64,
    pub host_rbp: u64,
    pub host_r12: u64,
    pub host_r13: u64,
    pub host_r14: u64,
    pub host_r15: u64,
    /// Failure status: CPU flags at the time of the `VMfail`.
    pub status: u64,
    /// 1 if the guest has already been launched (`vmresume`), 0 otherwise (`vmlaunch`).
    pub launched: u64,
}

impl EnterFrame {
    /// Zeroed frame.
    pub const fn zeroed() -> Self {
        Self {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rflags: 0,
            host_rsp: 0,
            host_rbx: 0,
            host_rbp: 0,
            host_r12: 0,
            host_r13: 0,
            host_r14: 0,
            host_r15: 0,
            status: 0,
            launched: 0,
        }
    }
}

/// Compile-time checks: the offsets shared with the assembler
/// must match the fields of [`EnterFrame`] exactly. A
/// regression here would silently corrupt the host state.
const _: () = {
    assert!(core::mem::offset_of!(EnterFrame, rax) == S9VM_F_RAX);
    assert!(core::mem::offset_of!(EnterFrame, rbx) == S9VM_F_RBX);
    assert!(core::mem::offset_of!(EnterFrame, rcx) == S9VM_F_RCX);
    assert!(core::mem::offset_of!(EnterFrame, rdx) == S9VM_F_RDX);
    assert!(core::mem::offset_of!(EnterFrame, rsi) == S9VM_F_RSI);
    assert!(core::mem::offset_of!(EnterFrame, rdi) == S9VM_F_RDI);
    assert!(core::mem::offset_of!(EnterFrame, rbp) == S9VM_F_RBP);
    assert!(core::mem::offset_of!(EnterFrame, rsp) == S9VM_F_RSP);
    assert!(core::mem::offset_of!(EnterFrame, r8) == S9VM_F_R8);
    assert!(core::mem::offset_of!(EnterFrame, r9) == S9VM_F_R9);
    assert!(core::mem::offset_of!(EnterFrame, r10) == S9VM_F_R10);
    assert!(core::mem::offset_of!(EnterFrame, r11) == S9VM_F_R11);
    assert!(core::mem::offset_of!(EnterFrame, r12) == S9VM_F_R12);
    assert!(core::mem::offset_of!(EnterFrame, r13) == S9VM_F_R13);
    assert!(core::mem::offset_of!(EnterFrame, r14) == S9VM_F_R14);
    assert!(core::mem::offset_of!(EnterFrame, r15) == S9VM_F_R15);
    assert!(core::mem::offset_of!(EnterFrame, rip) == S9VM_F_RIP);
    assert!(core::mem::offset_of!(EnterFrame, rflags) == S9VM_F_RFLAGS);
    assert!(core::mem::offset_of!(EnterFrame, host_rsp) == S9VM_F_HOST_RSP);
    assert!(core::mem::offset_of!(EnterFrame, host_rbx) == S9VM_F_HOST_RBX);
    assert!(core::mem::offset_of!(EnterFrame, host_rbp) == S9VM_F_HOST_RBP);
    assert!(core::mem::offset_of!(EnterFrame, host_r12) == S9VM_F_HOST_R12);
    assert!(core::mem::offset_of!(EnterFrame, host_r13) == S9VM_F_HOST_R13);
    assert!(core::mem::offset_of!(EnterFrame, host_r14) == S9VM_F_HOST_R14);
    assert!(core::mem::offset_of!(EnterFrame, host_r15) == S9VM_F_HOST_R15);
    assert!(core::mem::offset_of!(EnterFrame, status) == S9VM_F_STATUS);
    assert!(core::mem::offset_of!(EnterFrame, launched) == S9VM_F_LAUNCHED);
    assert!(core::mem::size_of::<EnterFrame>() == S9VM_ENTER_FRAME_SIZE);
};

extern "C" {
    /// Assembly entry point (defined by [`S9VM_TRAMPOLINE`]).
    ///
    /// # Safety
    /// See the module contract; never call when VT-x is not active
    /// on the current CPU, or when the control block is not loaded.
    pub fn s9vm_enter_guest(frame: *mut EnterFrame, host_stack_top: u64) -> u64;

    /// Resume label after a guest exit (address placed in `HOST_RIP`).
    /// This is not a callable function: only its address is taken.
    pub fn s9vm_guest_exit();

    /// Assembly guest entry (address used for `HOST_RIP`).
    pub fn s9vm_guest_entry();
}

// Trampoline code. The `S9VM_F_*` offsets must stay in sync with
// [`EnterFrame`]; a host test verifies it.
global_asm!(
    r#"
    .set S9VM_F_RAX,        0
    .set S9VM_F_RBX,        8
    .set S9VM_F_RCX,       16
    .set S9VM_F_RDX,       24
    .set S9VM_F_RSI,       32
    .set S9VM_F_RDI,       40
    .set S9VM_F_RBP,       48
    .set S9VM_F_R8,        64
    .set S9VM_F_R9,        72
    .set S9VM_F_R10,       80
    .set S9VM_F_R11,       88
    .set S9VM_F_R12,       96
    .set S9VM_F_R13,      104
    .set S9VM_F_R14,      112
    .set S9VM_F_R15,      120
    .set S9VM_F_HOST_RSP, 144
    .set S9VM_F_HOST_RBX, 152
    .set S9VM_F_HOST_RBP, 160
    .set S9VM_F_HOST_R12, 168
    .set S9VM_F_HOST_R13, 176
    .set S9VM_F_HOST_R14, 184
    .set S9VM_F_HOST_R15, 192
    .set S9VM_F_STATUS,   200
    .set S9VM_F_LAUNCHED, 208

    .text
    .global s9vm_enter_guest
    .type s9vm_enter_guest, @function
s9vm_enter_guest:
    /* rdi = frame, rsi = host_stack_top */
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rdi                        /* recovery slot on failure */
    mov [rdi + S9VM_F_HOST_RSP], rsp
    mov [rdi + S9VM_F_HOST_RBX], rbx
    mov [rdi + S9VM_F_HOST_RBP], rbp
    mov [rdi + S9VM_F_HOST_R12], r12
    mov [rdi + S9VM_F_HOST_R13], r13
    mov [rdi + S9VM_F_HOST_R14], r14
    mov [rdi + S9VM_F_HOST_R15], r15

    /* Frame pointer reachable from the host stack on return. */
    mov [rsi - 8], rdi
    mov rax, [rdi + S9VM_F_LAUNCHED]
    mov [rsi - 16], rax

    /* The vmlaunch/vmresume choice is fixed here; the following movs
       do not modify the flags. */
    cmp qword ptr [rsi - 16], 0

    mov rax, [rdi + S9VM_F_RAX]
    mov rbx, [rdi + S9VM_F_RBX]
    mov rcx, [rdi + S9VM_F_RCX]
    mov rdx, [rdi + S9VM_F_RDX]
    mov rsi, [rdi + S9VM_F_RSI]
    mov rbp, [rdi + S9VM_F_RBP]
    mov r8,  [rdi + S9VM_F_R8]
    mov r9,  [rdi + S9VM_F_R9]
    mov r10, [rdi + S9VM_F_R10]
    mov r11, [rdi + S9VM_F_R11]
    mov r12, [rdi + S9VM_F_R12]
    mov r13, [rdi + S9VM_F_R13]
    mov r14, [rdi + S9VM_F_R14]
    mov r15, [rdi + S9VM_F_R15]
    mov rdi, [rdi + S9VM_F_RDI]
    je .Ls9vm_launch
    vmresume
    jmp .Ls9vm_fail
.Ls9vm_launch:
    vmlaunch
    jmp .Ls9vm_fail

.Ls9vm_fail:
    /* Still on the kernel stack: the frame is in the pushed slot. */
    pop rdi
    pushfq
    pop rax
    mov [rdi + S9VM_F_STATUS], rax
    mov rsp, [rdi + S9VM_F_HOST_RSP]
    mov rbx, [rdi + S9VM_F_HOST_RBX]
    mov rbp, [rdi + S9VM_F_HOST_RBP]
    mov r12, [rdi + S9VM_F_HOST_R12]
    mov r13, [rdi + S9VM_F_HOST_R13]
    mov r14, [rdi + S9VM_F_HOST_R14]
    mov r15, [rdi + S9VM_F_HOST_R15]
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    mov eax, 1
    ret

    .global s9vm_guest_entry
    .type s9vm_guest_entry, @function
s9vm_guest_entry:
    /* Never executed directly: informational address. */
    ud2

    .global s9vm_guest_exit
    .type s9vm_guest_exit, @function
s9vm_guest_exit:
    /* The hardware loaded HOST_RSP = host_stack_top; [rsp-8] = frame. */
    mov [rsp - 16], rdi             /* saves the guest rdi */
    mov rdi, [rsp - 8]              /* frame */
    mov [rdi + S9VM_F_RAX], rax
    mov [rdi + S9VM_F_RBX], rbx
    mov [rdi + S9VM_F_RCX], rcx
    mov [rdi + S9VM_F_RDX], rdx
    mov [rdi + S9VM_F_RSI], rsi
    mov [rdi + S9VM_F_R8],  r8
    mov [rdi + S9VM_F_R9],  r9
    mov [rdi + S9VM_F_R10], r10
    mov [rdi + S9VM_F_R11], r11
    mov [rdi + S9VM_F_R12], r12
    mov [rdi + S9VM_F_R13], r13
    mov [rdi + S9VM_F_R14], r14
    mov [rdi + S9VM_F_R15], r15
    mov rax, [rsp - 16]
    mov [rdi + S9VM_F_RDI], rax
    mov qword ptr [rdi + S9VM_F_STATUS], 0

    /* Restores the host and returns to the Rust caller. */
    mov rsp, [rdi + S9VM_F_HOST_RSP]
    mov rbx, [rdi + S9VM_F_HOST_RBX]
    mov rbp, [rdi + S9VM_F_HOST_RBP]
    mov r12, [rdi + S9VM_F_HOST_R12]
    mov r13, [rdi + S9VM_F_HOST_R13]
    mov r14, [rdi + S9VM_F_HOST_R14]
    mov r15, [rdi + S9VM_F_HOST_R15]
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    xor eax, eax
    ret
    "#
);
