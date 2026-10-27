# x86-64 kernel entry. RDI holds the physical KernelArgs pointer.
# The loader maps the complete PT_LOAD memory extents, including pure BSS.
# IF stays clear until the kernel's normal interrupt initialization is complete.
.section .boot.text, "ax"
.code64
.global _start
_start:
    cli
    cld
    movq %rdi, %r15
    xorq %rbp, %rbp

    # All early vectors halt locally. No allocation, formatting, firmware call,
    # TSS or IST is needed. The full GDT/TSS/IDT replace these during kernel_main.
    # Prepare the IDT before changing the GDT to keep their replacement adjacent.
    leaq early_fault_halt(%rip), %rax
    leaq early_idt(%rip), %rdi
    movl $256, %ecx
.Lfill_idt:
    movw %ax, 0(%rdi)
    movw $0x08, 2(%rdi)
    movb $0, 4(%rdi)
    movb $0x8e, 5(%rdi)
    movq %rax, %rdx
    shrq $16, %rdx
    movw %dx, 6(%rdi)
    shrq $16, %rdx
    movl %edx, 8(%rdi)
    movl $0, 12(%rdi)
    addq $16, %rdi
    loop .Lfill_idt

    # A private early GDT removes the dependency on firmware selectors. Use the
    # loader's mapped transition stack until the BSS/bootstrap stack is cleared.
    lgdt early_gdt_ptr(%rip)
    lidt early_idt_ptr(%rip)
    pushq $0x08
    leaq .Lkernel_cs(%rip), %rax
    pushq %rax
    lretq
.Lkernel_cs:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss

    movw $0xe9, %dx
    movb $'A', %al
    outb %al, %dx

    # Clear every byte, including a final non-qword tail. The active stack and
    # early IDT are outside BSS, so neither is erased by this loop.
    leaq __bss_start(%rip), %rdi
    leaq __bss_end(%rip), %rcx
    subq %rdi, %rcx
    xorl %eax, %eax
    rep stosb

    movw $0xe9, %dx
    movb $'B', %al
    outb %al, %dx
    leaq boot_stack_top(%rip), %rsp
    andq $-16, %rsp
    movq %r15, %rdi
    movb $'C', %al
    outb %al, %dx
    call kmain

early_fault_halt:
    cli
    movw $0xe9, %dx
    movb $'!', %al
    outb %al, %dx
.Lhalt:
    hlt
    jmp .Lhalt

# Accessed bits are preset, so loading a selector never needs to write the GDT.
.balign 8
early_gdt:
    .quad 0
    .quad 0x00af9b000000ffff
    .quad 0x00cf93000000ffff
early_gdt_end:
early_gdt_ptr:
    .word early_gdt_end - early_gdt - 1
    .quad early_gdt
early_idt_ptr:
    .word 256 * 16 - 1
    .quad early_idt

# Caller supplies a mapped stack and a noreturn SysV entry.
.global switch_stack
switch_stack:
    movq %rdi, %rsp
    andq $-16, %rsp
    xorq %rbp, %rbp
    cld
    callq *%rsi
    jmp early_fault_halt

# PROGBITS, deliberately outside BSS: early exceptions can use it during clearing.
.section .data.boot_idt, "aw", @progbits
.balign 16
early_idt:
    .zero 256 * 16

.section .bss.stack, "aw", @nobits
.balign 16
boot_stack_bottom:
    .skip 65536
boot_stack_top:
