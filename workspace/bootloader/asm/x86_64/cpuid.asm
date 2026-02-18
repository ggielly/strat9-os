; =====================================================================
; CPUID Feature Detection
; =====================================================================

SECTION .text
USE16

cpuid_check:
    pusha
    pushf

    ; Test if CPUID is supported
    pushfd
    pop eax
    mov ebx, eax
    xor eax, 1 << 21
    push eax
    popfd
    pushfd
    pop eax
    push ebx
    popfd
    xor eax, ebx
    and eax, 1 << 21
    jz .no_cpuid

    ; Check for long mode support
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb .no_long_mode

    mov eax, 0x80000001
    cpuid
    test edx, 1 << 29                   ; Long Mode bit
    jz .no_long_mode

    popf
    popa
    ret

.no_cpuid:
    mov si, .msg_no_cpuid
    call print
    jmp .halt

.no_long_mode:
    mov si, .msg_no_lm
    call print
    jmp .halt

.halt:
    call print_line
    cli
    hlt
    jmp .halt

.msg_no_cpuid:  db 'ERROR: CPUID not supported', 0
.msg_no_lm:     db 'ERROR: 64-bit not supported', 0
