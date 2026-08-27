; =====================================================================
; CPUID Feature Detection
; =====================================================================
;
; Hard requirements (halt on failure):
;   - CPUID instruction (EFLAGS.ID toggleable)
;   - Long Mode (CPUID.80000001h:EDX bit 29)
;
; Optional features (stored in [cpuid_features]):
;   Bit 0 (0x01) — NX (No Execute, EFER.NXE)
;   Bit 1 (0x02) — PAT (Page Attribute Table)
;   Bit 2 (0x04) — 1 GiB pages (Page1GB)
;
; The 64-bit code must check [cpuid_features] before using NX, PAT,
; or 1 GiB pages. On CPUs without these features, the identity map
; must use 2 MiB pages and context_switch must not program EFER.NXE
; or IA32_PAT.

SECTION .text
USE16

cpuid_check:
    pusha
    pushf

    ; --- Step 1: test if CPUID is supported (EFLAGS bit 21) ---
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

    ; --- Step 2: leaf 0x80000000 — max extended leaf ---
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb .no_long_mode

    ; --- Step 3: leaf 0x80000001 — long mode + NX + 1 GiB pages ---
    mov eax, 0x80000001
    cpuid

    ; Long mode (bit 29) — hard requirement
    test edx, 1 << 29
    jz .no_long_mode

    ; NX / No-Execute (bit 20) — optional, store in flags
    xor bx, bx
    test edx, 1 << 20
    jz .check_1g
    or bl, 0x01                        ; bit 0 = NX

.check_1g:
    ; 1 GiB pages / Page1GB (bit 26) — optional, store in flags
    test edx, 1 << 26
    jz .check_pat
    or bl, 0x04                        ; bit 2 = 1GB pages

.check_pat:
    ; --- Step 4: leaf 1 — PAT (EDX bit 16) ---
    mov eax, 1
    cpuid
    test edx, 1 << 16
    jz .store_features
    or bl, 0x02                        ; bit 1 = PAT

.store_features:
    ; Export detected optional features for 64-bit code.
    ; The linker places this in .bss; the64-bit code reads it via
    ; an extern symbol (cpuid_features).
    mov [cpuid_features], bl

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

; =====================================================================
; Data
; =====================================================================
SECTION .bss

; Bitmask of optional CPU features detected above.
; Read by 64-bit Rust code as `extern "C" { static cpuid_features: u8; }`
global cpuid_features
cpuid_features: resb 1
