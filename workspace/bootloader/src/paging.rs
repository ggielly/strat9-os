pub use crate::{
    boot_plan::INITIAL_ALLOCATION_LIMIT as INITIAL_PHYS_LIMIT,
    page_tables::{create_page_tables, FRAMEBUFFER_BASE, HHDM_OFFSET},
};

/// Enter with validated CPU features and a mapped EFI image. There are no stack
/// accesses or calls after CR3 changes; the last jump enters the kernel stub.
#[inline(never)]
pub unsafe fn context_switch(pml4_phys: u64, stack_top: u64, entry: u64, args: u64) -> ! {
    unsafe {
        core::arch::asm!(
            "cli",
            "cld",
            // Force each input into a distinct register that does NOT overlap
            // with our destination scratch registers (rbx, r8, r9, r10).
            // Using in("reg") ties the operand to a specific register; the
            // asm body must reference that register directly, not via {name}.
            "mov rbx, rax",
            "mov r8,  rdx",
            "mov r9,  rcx",
            "mov r10, rsi",
            "xor rbp, rbp",
            // Clear EM/TS, set MP/NE/WP; paging and protected mode stay enabled.
            "mov rax, cr0",
            "and rax, -13",
            "or rax, 0x10022",
            "mov cr0, rax",
            // Change memory types only with caching disabled and dirty lines
            // drained. Preserve PAT; the new tables use verified WB/UC entries.
            "mov r11, rax",
            "bts rax, 30", // CD = 1
            "btr rax, 29", // NW = 0
            "mov cr0, rax",
            "wbinvd",
            // Select PCID zero before disabling PCIDE, and invalidate inherited
            // global translations by clearing PGE. LA57/CET were rejected earlier.
            "mov rax, cr4",
            "bt rax, 17",
            "jnc 2f",
            "mov rdx, cr3",
            "and rdx, -4096",
            "mov cr3, rdx",
            "2:",
            "and rax, -131201", // ~(PCIDE | PGE)
            "or rax, 0x600", // OSFXSR | OSXMMEXCPT
            "mov cr4, rax",
            // Enable IA32_EFER.NXE (bit 11) so NX page bits are enforced.
            "mov ecx, 0xC0000080",          // IA32_EFER
            "rdmsr",
            "or eax, 1 << 11",              // NXE (LME already set: we run in long mode)
            "wrmsr",
            // Now use the scratch registers (safe from rdmsr/wrmsr clobbers).
            "mov rsp, r8",
            "and rsp, -16",
            "mov rdi, r10",
            "mov cr3, rbx",
            "wbinvd",
            "btr r11, 30", // Enable normal caching with the new attributes.
            "btr r11, 29",
            "mov cr0, r11",
            "jmp r9",
            in("rax") pml4_phys,
            in("rdx") stack_top,
            in("rcx") entry,
            in("rsi") args,
            options(noreturn)
        );
    }
}
