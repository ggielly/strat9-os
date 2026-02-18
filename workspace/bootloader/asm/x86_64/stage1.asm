; =====================================================================
; Strat9-OS Stage 1 Bootloader (MBR)
; Loaded by BIOS at 0x7C00
; Loads Stage 2 from disk and jumps to it
; Inspired by RedoxOS bootloader architecture
; =====================================================================

ORG 0x7C00
SECTION .text
USE16

stage1:
    ; Initialize segment registers
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax

    ; Initialize stack below MBR
    mov sp, 0x7C00

    ; Initialize CS properly (like RedoxOS)
    push ax
    push word .set_cs
    retf

.set_cs:
    ; Save boot drive number (BIOS passes it in DL)
    mov [disk], dl

    mov si, msg_stage
    call print
    mov al, '1'
    call print_char
    call print_line

    ; =============================================
    ; Load Stage 2 from disk (sectors 1-8 -> 4KB)
    ; =============================================
    mov eax, (stage2 - stage1) / 512
    mov bx, stage2
    mov cx, (stage2_end - stage2) / 512
    mov dx, 0
    call load

    mov si, msg_stage
    call print
    mov al, '2'
    call print_char
    call print_line

    jmp stage2_entry

; =============================================
; Disk read function (from RedoxOS)
; IN:  eax = start sector LBA
;      bx  = offset of buffer
;      cx  = number of sectors
;      dx  = segment of buffer
; =============================================
load:
    cmp cx, 127
    jbe .good_size
    pusha
    mov cx, 127
    call load
    popa
    add eax, 127
    add dx, 127 * 512 / 16
    sub cx, 127
    jmp load

.good_size:
    mov [DAPACK.addr], eax
    mov [DAPACK.buf], bx
    mov [DAPACK.count], cx
    mov [DAPACK.seg], dx

    mov dl, [disk]
    mov si, DAPACK
    mov ah, 0x42                        ; Extended read
    int 0x13
    jc error
    ret

error:
    call print_line
    mov bh, 0
    mov bl, ah
    call print_hex
    mov al, ' '
    call print_char
    mov si, msg_error
    call print
    call print_line
.halt:
    cli
    hlt
    jmp .halt

%include "print.asm"

; =============================================
; Data
; =============================================
msg_stage:  db "Strat9-OS Stage ", 0
msg_error:  db "DISK ERROR", 0

disk: db 0

DAPACK:
    db 0x10                             ; Size of packet
    db 0                                ; Reserved
.count: dw 0                            ; Number of sectors
.buf:   dw 0                            ; Buffer offset
.seg:   dw 0                            ; Buffer segment
.addr:  dq 0                            ; LBA address

times 446-($-$$) db 0                   ; Pad to partition table
partitions: times 4 * 16 db 0           ; Empty partition table
dw 0xAA55                               ; Boot signature

; =====================================================================
; Stage 2 starts here - immediately after MBR (sector 1)
; No ORG directive - addresses are relative to stage1 base
; This is the key insight from RedoxOS: stage2 is assembled
; as part of the same binary, so all labels resolve correctly
; =====================================================================

stage2:

%include "stage2.asm"

stage2_end:
