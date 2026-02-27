# strat9 simple boot stub for QEMU -kernel (Linux boot protocol style)
# This removes Multiboot and uses Linux 64-bit boot protocol instead

.section .boot.text, "ax"
.code64
.global _start
_start:
    cli

    # Save RDI (KernelArgs pointer passed by bootloader)
    movq %rdi, %r15

    # Setup stack
    leaq boot_stack_top(%rip), %rsp
    
    # Enable SSE (Required for Rust 2024 / SIMD)
    # 1. Enable SSE/AVX in CR4
    movq %cr4, %rax
    orq $0x620, %rax # OSFXSR (9), OSXMMEXCPT (10), PAE (5)
    movq %rax, %cr4
    
    # 2. Enable SSE in CR0
    movq %cr0, %rax
    andl $0xFFFFFFFB, %eax # Clear EM (2) - using 32-bit register for the constant
    orl $0x2, %eax        # Set MP (1)
    movq %rax, %cr0

    # Clear BSS
    leaq __bss_start(%rip), %rdi
    leaq __bss_end(%rip), %rcx
    subq %rdi, %rcx
    xorl %eax, %eax
    rep stosb
    
    # Restore KernelArgs to RDI (System V ABI first arg)
    movq %r15, %rdi

    # Call kernel_main
    call kernel_main
    
.halt_loop:
    cli
    hlt
    jmp .halt_loop

# Boot stack (64KB)
.section .bss
.align 16
boot_stack_bottom:
    .space 65536
boot_stack_top:
