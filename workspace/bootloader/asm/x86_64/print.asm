; =====================================================================
; Real Mode Print Utilities (BIOS INT 10h)
; =====================================================================

SECTION .text
USE16

; Print newline (CR + LF)
print_line:
    pusha
    pushf
    mov al, 13
    call print_char
    mov al, 10
    call print_char
    popf
    popa
    ret

; Print null-terminated string from SI
print:
    pusha
    pushf
.loop:
    lodsb
    or al, al
    jz .done
    call print_char
    jmp .loop
.done:
    popf
    popa
    ret

; Print single character in AL
print_char:
    pusha
    pushf
    mov ah, 0x0E                        ; BIOS teletype output
    mov bh, 0
    mov bl, 0x07                        ; Light gray on black
    int 0x10
    popf
    popa
    ret

; Print 16-bit hex number in BX
print_hex:
    pusha
    pushf
    mov cx, 4
.loop:
    rol bx, 4
    mov al, bl
    and al, 0x0F
    cmp al, 10
    jl .decimal
    add al, 'A' - 10
    jmp .print
.decimal:
    add al, '0'
.print:
    call print_char
    loop .loop
    popf
    popa
    ret
