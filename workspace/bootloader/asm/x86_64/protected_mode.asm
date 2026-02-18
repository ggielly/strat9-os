; =====================================================================
; Protected Mode Transition
; =====================================================================

SECTION .text
USE16

protected_mode:

.func: dd 0

.entry:
    ; Disable interrupts
    cli

    ; Load protected mode GDT
    lgdt [gdtr]

    ; Set protected mode bit of CR0
    mov eax, cr0
    or eax, 1
    mov cr0, eax

    ; Far jump to load CS with 32-bit segment
    jmp gdt.pm32_code:.inner

USE32

.inner:
    ; Load all other segments with 32-bit data segments
    mov eax, gdt.pm32_data
    mov ds, eax
    mov es, eax
    mov fs, eax
    mov gs, eax
    mov ss, eax

    ; Jump to specified function
    mov eax, [.func]
    jmp eax
