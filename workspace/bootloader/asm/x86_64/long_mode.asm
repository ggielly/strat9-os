; =====================================================================
; Long Mode Transition
; =====================================================================

SECTION .text
USE32

long_mode:
.func: dq 0
.page_table: dd 0

.entry:
    ; Disable interrupts
    cli

    ; Disable paging
    mov eax, cr0
    and eax, 0x7FFFFFFF
    mov cr0, eax

    ; Enable FXSAVE/FXRSTOR, Page Global, PAE, and Page Size Extension
    mov eax, cr4
    or eax, 1 << 9 | 1 << 7 | 1 << 5 | 1 << 4
    mov cr4, eax

    ; Load long mode GDT
    lgdt [gdtr]

    ; Enable long mode in EFER MSR
    mov ecx, 0xC0000080                 ; EFER MSR
    rdmsr
    or eax, 1 << 11 | 1 << 8           ; NXE + LME
    wrmsr

    ; Set page table
    mov eax, [.page_table]
    mov cr3, eax

    ; Enable paging and protection simultaneously
    mov eax, cr0
    or eax, 1 << 31 | 1 << 16 | 1      ; PG + WP + PE
    mov cr0, eax

    ; Far jump to enable Long Mode and load CS with 64-bit segment
    jmp gdt.lm64_code:.inner

USE64

.inner:
    ; Load all other segments with 64-bit data segments
    mov rax, gdt.lm64_data
    mov ds, rax
    mov es, rax
    mov fs, rax
    mov gs, rax
    mov ss, rax

    ; Jump to specified function
    mov rax, [.func]
    jmp rax
