//! Minimal Ring 3 test task for Strat9-OS.
//!
//! Creates a user address space with a tiny machine code blob that:
//! 1. Calls SYS_DEBUG_LOG to print "Hello Ring 3!" to serial
//! 2. Calls SYS_PROC_EXIT to cleanly exit
//!
//! This tests the full SYSCALL/SYSRET pipeline without needing an ELF loader.

use alloc::sync::Arc;
use x86_64::VirtAddr;

use crate::{
    capability::CapabilityTable,
    memory::address_space::{AddressSpace, VmaFlags, VmaType},
    process::{
        task::{CpuContext, KernelStack, SyncUnsafeCell, Task, TaskPriority},
        TaskState,
    },
};

/// User code virtual address (must be in lower half, page-aligned).
const USER_CODE_ADDR: u64 = 0x40_0000;

/// User stack virtual address (page-aligned).
const USER_STACK_ADDR: u64 = 0x80_0000;

/// User stack top (stack grows down, so this is base + 4096).
const USER_STACK_TOP: u64 = USER_STACK_ADDR + 0x1000;

/// Create and schedule a minimal Ring 3 test task.
///
/// This function:
/// 1. Creates a user address space (PML4 with kernel half cloned)
/// 2. Maps a code page at USER_CODE_ADDR (RX, user-accessible)
/// 3. Maps a stack page at USER_STACK_ADDR (RW, user-accessible)
/// 4. Writes a small machine code blob into the code page
/// 5. Creates a kernel task whose entry point does IRETQ to Ring 3
pub fn create_user_test_task() {
    log::info!("Creating Ring 3 test task...");

    // Step 1: Create user address space
    let user_as = match AddressSpace::new_user() {
        Ok(a) => Arc::new(a),
        Err(e) => {
            log::error!("Failed to create user address space: {}", e);
            return;
        }
    };

    // Step 2: Map code page (USER_ACCESSIBLE | RX)
    let code_flags = VmaFlags {
        readable: true,
        writable: false,
        executable: true,
        user_accessible: true,
    };
    if let Err(e) = user_as.map_region(
        USER_CODE_ADDR,
        1,
        code_flags,
        VmaType::Code,
        crate::memory::address_space::VmaPageSize::Small,
    ) {
        log::error!("Failed to map user code page: {}", e);
        return;
    }

    // Step 3: Map stack page (USER_ACCESSIBLE | RW)
    let stack_flags = VmaFlags {
        readable: true,
        writable: true,
        executable: false,
        user_accessible: true,
    };
    if let Err(e) = user_as.map_region(
        USER_STACK_ADDR,
        1,
        stack_flags,
        VmaType::Stack,
        crate::memory::address_space::VmaPageSize::Small,
    ) {
        log::error!("Failed to map user stack page: {}", e);
        return;
    }

    // Step 4: Write machine code into the code page.
    // We need to write via the HHDM mapping since the user AS isn't active.
    // Translate user vaddr → phys → HHDM virt for writing.
    let code_phys = user_as.translate(VirtAddr::new(USER_CODE_ADDR));
    let code_phys = match code_phys {
        Some(p) => p,
        None => {
            log::error!("Failed to translate user code page");
            return;
        }
    };
    let code_virt = crate::memory::phys_to_virt(code_phys.as_u64());

    // Write the user code blob
    write_user_code(code_virt as *mut u8);

    // Step 5: Create a kernel task that will IRETQ to Ring 3.
    // We store the user_as Arc and entry parameters in statics since the
    // trampoline is a simple extern "C" fn.
    // SAFETY: Single-threaded setup, task not yet scheduled.
    unsafe {
        let ptr = &raw mut USER_TASK_AS;
        *ptr = Some(user_as.clone());
    }

    // Create a kernel task with the IRETQ trampoline as entry point
    let kernel_stack = match KernelStack::allocate(Task::DEFAULT_STACK_SIZE) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to allocate kernel stack for user task: {}", e);
            return;
        }
    };

    let context = CpuContext::new(ring3_trampoline as *const () as u64, &kernel_stack);
    let (pid, tid, tgid) = Task::allocate_process_ids();

    let task = Arc::new(Task {
        id: crate::process::TaskId::new(),
        pid,
        tid,
        tgid,
        pgid: core::sync::atomic::AtomicU32::new(pid),
        sid: core::sync::atomic::AtomicU32::new(pid),
        uid: core::sync::atomic::AtomicU32::new(0),
        euid: core::sync::atomic::AtomicU32::new(0),
        gid: core::sync::atomic::AtomicU32::new(0),
        egid: core::sync::atomic::AtomicU32::new(0),
        state: SyncUnsafeCell::new(TaskState::Ready),
        priority: TaskPriority::Normal,
        context: SyncUnsafeCell::new(context),
        kernel_stack,
        user_stack: None,
        name: "test-user-ring3",
        capabilities: SyncUnsafeCell::new(CapabilityTable::new()),
        address_space: SyncUnsafeCell::new(user_as),
        fd_table: SyncUnsafeCell::new(crate::vfs::FileDescriptorTable::new()),
        pending_signals: SyncUnsafeCell::new(super::signal::SignalSet::new()),
        blocked_signals: SyncUnsafeCell::new(super::signal::SignalSet::new()),
        signal_actions: SyncUnsafeCell::new([super::signal::SigAction::Default; 64]),
        signal_stack: SyncUnsafeCell::new(None),
        itimers: super::timer::ITimers::new(),
        wake_pending: core::sync::atomic::AtomicBool::new(false),
        wake_deadline_ns: core::sync::atomic::AtomicU64::new(0),
        brk: core::sync::atomic::AtomicU64::new(0),
        mmap_hint: core::sync::atomic::AtomicU64::new(0x0000_0000_6000_0000),
        trampoline_entry: core::sync::atomic::AtomicU64::new(0),
        trampoline_stack_top: core::sync::atomic::AtomicU64::new(0),
        trampoline_arg0: core::sync::atomic::AtomicU64::new(0),
        ticks: core::sync::atomic::AtomicU64::new(0),
        sched_policy: crate::process::task::SyncUnsafeCell::new(Task::default_sched_policy(
            TaskPriority::Normal,
        )),
        vruntime: core::sync::atomic::AtomicU64::new(0),
        clear_child_tid: core::sync::atomic::AtomicU64::new(0),
        cwd: crate::process::task::SyncUnsafeCell::new(alloc::string::String::from("/")),
        umask: core::sync::atomic::AtomicU32::new(0o022),
        user_fs_base: core::sync::atomic::AtomicU64::new(0),
        fpu_state: crate::process::task::SyncUnsafeCell::new(crate::process::task::FpuState::new()),
    });

    crate::process::add_task(task);
    log::info!(
        "Ring 3 test task created: code@{:#x}, stack@{:#x}",
        USER_CODE_ADDR,
        USER_STACK_TOP,
    );
}

/// Static storage for the user address space (accessed by the trampoline).
static mut USER_TASK_AS: Option<Arc<AddressSpace>> = None;

/// Trampoline that switches to user address space and does IRETQ to Ring 3.
///
/// This runs as a kernel task entry point. It:
/// 1. Switches CR3 to the user address space
/// 2. Pushes an IRET frame (SS, RSP, RFLAGS, CS, RIP)
/// 3. Executes IRETQ to jump to Ring 3 code
extern "C" fn ring3_trampoline() -> ! {
    use crate::arch::x86_64::gdt;

    // Switch to user address space
    // SAFETY: The user AS was set up with the kernel half cloned.
    unsafe {
        let user_as = &*(&raw const USER_TASK_AS);
        if let Some(ref as_ref) = user_as {
            as_ref.switch_to();

            // Diagnostic: verify the code page is mapped before IRETQ
            let phys = as_ref.translate(x86_64::VirtAddr::new(USER_CODE_ADDR));
            crate::serial_println!(
                "[ring3-tramp] CR3={:#x}, translate({:#x})={:?}",
                as_ref.cr3().as_u64(),
                USER_CODE_ADDR,
                phys,
            );

            // Also verify via a direct CR3 read + manual walk
            let (cr3_frame, _) = x86_64::registers::control::Cr3::read();
            let cr3_phys = cr3_frame.start_address().as_u64();
            let hhdm = crate::memory::hhdm_offset();
            crate::serial_println!(
                "[ring3-tramp] Active CR3={:#x} (expected {:#x})",
                cr3_phys,
                as_ref.cr3().as_u64(),
            );

            // Manual PML4[0] check
            let l4_ptr = (cr3_phys + hhdm) as *const u64;
            let l4_entry = *l4_ptr; // PML4[0]
            crate::serial_println!(
                "[ring3-tramp] PML4[0]={:#x} (present={})",
                l4_entry,
                l4_entry & 1,
            );
        } else {
            crate::serial_println!("[ring3-tramp] ERROR: USER_TASK_AS is None!");
        }
    }

    let user_cs = gdt::user_code_selector().0 as u64;
    let user_ss = gdt::user_data_selector().0 as u64;
    let user_rip = USER_CODE_ADDR;
    let user_rsp = USER_STACK_TOP;
    let user_rflags: u64 = 0x202; // IF=1, reserved bit 1 = 1

    crate::serial_println!(
        "[ring3-tramp] IRETQ: CS={:#x} RIP={:#x} SS={:#x} RSP={:#x} RFLAGS={:#x}",
        user_cs,
        user_rip,
        user_ss,
        user_rsp,
        user_rflags,
    );

    // SAFETY: We've set up valid user mappings. IRETQ will switch to Ring 3.
    unsafe {
        core::arch::asm!(
            "push {ss}",       // SS
            "push {rsp}",      // RSP
            "push {rflags}",   // RFLAGS
            "push {cs}",       // CS
            "push {rip}",      // RIP
            "iretq",
            ss = in(reg) user_ss,
            rsp = in(reg) user_rsp,
            rflags = in(reg) user_rflags,
            cs = in(reg) user_cs,
            rip = in(reg) user_rip,
            options(noreturn),
        );
    }
}

/// Write the user-mode test program into the code page.
///
/// The program:
/// ```asm
/// ; SYS_DEBUG_LOG(buf_ptr, buf_len)
/// mov rax, 600           ; SYS_DEBUG_LOG
/// lea rdi, [rip + msg]   ; buffer pointer (rdi = arg1)
/// mov rsi, 13            ; length (rsi = arg2)
/// syscall
///
/// ; SYS_PROC_EXIT(0)
/// mov rax, 300           ; SYS_PROC_EXIT
/// xor rdi, rdi           ; exit code 0
/// syscall
///
/// ; Safety: should never reach here
/// hlt
/// jmp $-1
///
/// msg: db "Hello Ring 3!"
/// ```
fn write_user_code(dest: *mut u8) {
    // Hand-assembled x86_64 machine code
    let code: &[u8] = &[
        // mov rax, 600 (SYS_DEBUG_LOG)
        0x48, 0xC7, 0xC0, 0x58, 0x02, 0x00, 0x00, // mov rax, 0x258 (600)
        // lea rdi, [rip + offset_to_msg]
        // This instruction is at offset 7, length 7, so next IP at offset 14.
        // msg is at offset 38 (after hlt+jmp = 35+1+2 = 38).
        // disp32 = 38 - 14 = 24 = 0x18
        0x48, 0x8D, 0x3D, 0x18, 0x00, 0x00, 0x00, // lea rdi, [rip+0x18]
        // mov rsi, 13
        0x48, 0xC7, 0xC6, 0x0D, 0x00, 0x00, 0x00, // mov rsi, 13
        // syscall
        0x0F, 0x05, // syscall
        // mov rax, 300 (SYS_PROC_EXIT)
        0x48, 0xC7, 0xC0, 0x2C, 0x01, 0x00, 0x00, // mov rax, 0x12C (300)
        // xor rdi, rdi
        0x48, 0x31, 0xFF, // xor rdi, rdi
        // syscall
        0x0F, 0x05, // syscall
        // hlt + infinite loop (safety)
        0xF4, // hlt
        0xEB, 0xFD, // jmp $-1 (back to hlt)
        // "Hello Ring 3!" (13 bytes)
        b'H', b'e', b'l', b'l', b'o', b' ', b'R', b'i', b'n', b'g', b' ', b'3', b'!',
    ];

    // SAFETY: dest points to a freshly allocated and zeroed page.
    unsafe {
        core::ptr::copy_nonoverlapping(code.as_ptr(), dest, code.len());
    }
}
