# strat9 multiboot1 boot stub
# 32-bit protected mode -> 64-bit long mode -> kernel_main

# Multiboot1 Header
.section .multiboot_header, "a"
.align 4
multiboot_header:
    .long   0x1BADB002
    .long   0x00000003
    .long   -(0x1BADB002 + 0x00000003)

# Page Tables (BSS)
.section .bss
.align 4096
boot_pml4:      .space 4096
boot_pdpt:      .space 4096
boot_pd:        .space 4096

# Boot stack (64KB)
.align 16
boot_stack_bottom:
    .space 65536
.global boot_stack_top
boot_stack_top:

# 64-bit GDT
.section .rodata
.align 16
gdt64:
    .quad   0x0000000000000000
    .quad   0x00AF9A000000FFFF
    .quad   0x00CF92000000FFFF
gdt64_end:

gdt64_ptr:
    .word   gdt64_end - gdt64 - 1
    .long   gdt64

# 32-bit boot entry (Multiboot gives us control here)
.section ".boot.text", "ax"
.code32
.global _start
_start:
    cli
    movl    $boot_stack_top, %esp
    movl    %ebx, %esi

    # PML4[0] -> PDPT
    movl    $boot_pdpt, %eax
    orl     $0x03, %eax
    movl    %eax, boot_pml4

    # PDPT[0] -> PD
    movl    $boot_pd, %eax
    orl     $0x03, %eax
    movl    %eax, boot_pdpt

    # PD: 512 x 2MB huge pages = 1GB identity map
    movl    $boot_pd, %edi
    movl    $0x00000083, %eax
    movl    $512, %ecx
.fill_pd:
    movl    %eax, 0(%edi)
    movl    $0, 4(%edi)
    addl    $0x00200000, %eax
    addl    $8, %edi
    decl    %ecx
    jnz     .fill_pd

    # CR3 = PML4
    movl    $boot_pml4, %eax
    movl    %eax, %cr3

    # Enable PAE and SSE (accumulate bits in EAX)
    movl    %cr4, %eax
    orl     $0x620, %eax    # Set PAE (5), OSFXSR (9), OSXMMEXCPT (10)
    movl    %eax, %cr4

    # Enable SSE in CR0
    movl    %cr0, %eax
    andl    $0xFFFFFFFB, %eax # Clear EM (2)
    movl    %eax, %cr0
    
    movl    %cr0, %eax
    orl     $0x2, %eax        # Set MP (1)
    movl    %eax, %cr0

    # Enable Long Mode (EFER.LME)
    movl    $0xC0000080, %ecx
    rdmsr
    orl     $0x100, %eax
    wrmsr

    # Enable Paging
    movl    %cr0, %eax
    orl     $0x80000000, %eax
    movl    %eax, %cr0

    # Load 64-bit GDT
    lgdt    gdt64_ptr

    # Far jump to 64-bit code
    ljmp    $0x08, $long_mode_entry

# 64-bit entry
.code64
.global long_mode_entry
long_mode_entry:
    movw    $0x10, %ax
    movw    %ax, %ds
    movw    %ax, %es
    movw    %ax, %fs
    movw    %ax, %gs
    movw    %ax, %ss

    movabs  $boot_stack_top, %rsp

    # RDI = multiboot info (System V ABI first arg)
    movl    %esi, %edi
    
    # DEBUG: Write 'L' to top-left of VGA buffer to indicate Long Mode entry
    movq    $0xB8000, %rax
    movw    $0x2F4C, (%rax)  # 'L' with white on green
    
    call    kernel_main

.halt_loop:
    cli
    hlt
    jmp     .halt_loop
