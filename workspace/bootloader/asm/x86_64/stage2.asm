; =====================================================================
; Strat9-OS Stage 2 Bootloader
; Included from stage1.asm - NO ORG directive
; Transitions: Real Mode -> Protected Mode -> Long Mode
; Architecture inspired by RedoxOS bootloader
; =====================================================================

USE16

stage2_entry:
    ; Setup segments for flat memory model
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov sp, 0x7C00

    ; Print banner
    mov si, s2_msg_banner
    call print
    call print_line

    ; =============================================
    ; Step 1: Enable A20 Line
    ; =============================================
    mov si, s2_msg_a20
    call print

    ; Method: Fast A20 via port 0x92 (like RedoxOS)
    in al, 0x92
    or al, 2
    out 0x92, al

    mov si, s2_msg_ok
    call print
    call print_line

    ; =============================================
    ; Step 2: Check CPU features
    ; =============================================
    mov si, s2_msg_cpuid
    call print

    call cpuid_check

    mov si, s2_msg_ok
    call print
    call print_line

    ; =============================================
    ; Step 3: Load Kernel from disk (multi-pass)
    ; =============================================
    mov si, s2_msg_kernel
    call print

    ; Strategy: Load kernel in multiple chunks to avoid 16-bit segment overflow
    ; Chunk 1: sectors 17-1800 (896KB) -> 0x10000-0xEFFFF
    ; Chunk 2: sectors 1801-3584 (896KB) -> 0x20000-0xFFFFFF (in protected mode)

    ; Load first chunk (896KB) to 0x10000
    mov eax, 17             ; Start at sector 17
    mov bx, 0               ; offset 0
    mov cx, 1792            ; 1792 sectors = 896KB (safe: 1792*512 = 917504 bytes)
    mov dx, 0x1000          ; segment 0x1000 => physical 0x10000
    call load

    ; Store info about first chunk for later use in protected mode
    mov dword [kernel_chunk1_sectors], 1792

    mov si, s2_msg_ok
    call print
    call print_line

    ; =============================================
    ; Step 4: Setup Page Tables
    ; =============================================
    mov si, s2_msg_paging
    call print

    call setup_page_tables

    mov si, s2_msg_ok
    call print
    call print_line

    ; =============================================
    ; Step 5: Enter Protected Mode -> Long Mode
    ; =============================================
    mov si, s2_msg_enter_pm
    call print
    call print_line

    ; Set the function to call after entering protected mode
    ; This is the RedoxOS pattern: store target in a variable
    mov dword [protected_mode.func], s2_pm32_entry
    jmp protected_mode.entry

; =============================================
; Setup Page Tables for Long Mode
; =============================================
; Identity maps first 1GB using 2MB pages
; PML4 at 0x1000, PDPT at 0x2000, PD at 0x3000

setup_page_tables:
    push es
    push di
    push cx
    push ax

    ; Clear page table area (16KB at 0x1000)
    xor ax, ax
    mov es, ax
    mov di, 0x1000
    mov cx, 8192                        ; 16KB = 8192 words
    rep stosw

    ; PML4[0] -> PDPT at 0x2000
    mov dword [es:0x1000], 0x2003       ; Present + RW

    ; PDPT[0] -> PD at 0x3000
    mov dword [es:0x2000], 0x3003       ; Present + RW

    ; PD: 512 entries of 2MB pages (identity map first 1GB)
    mov di, 0x3000
    mov cx, 512
    mov eax, 0x00000083                 ; Present + RW + PS (2MB page)
.loop_pd:
    mov [es:di], eax
    mov dword [es:di+4], 0              ; High 32 bits = 0
    add eax, 0x200000                   ; Next 2MB
    add di, 8
    dec cx
    jnz .loop_pd

    pop ax
    pop cx
    pop di
    pop es
    ret

; =============================================
; Include sub-modules
; =============================================
%include "cpuid.asm"
%include "gdt.asm"
%include "protected_mode.asm"
%include "long_mode.asm"

; =============================================
; Protected Mode Entry (32-bit)
; Parse ELF at 0x10000, copy segments, setup KernelArgs
; =============================================
USE32

s2_pm32_entry:
    ; Stack in protected mode
    mov esp, 0x90000

    ; ----- Parse ELF64 at 0x10000 -----
    ; Verify ELF magic: 0x7F 'E' 'L' 'F'
    cmp dword [0x10000], 0x464C457F
    jne .elf_error

    ; Get entry point (low 32 bits of e_entry at offset 0x18)
    mov eax, [0x10018]
    mov [kernel_entry_addr], eax
    mov eax, [0x1001C]
    mov [kernel_entry_addr + 4], eax

    ; Get program header table offset (low 32 bits at offset 0x20)
    mov ebx, [0x10020]
    add ebx, 0x10000                    ; Absolute address in buffer

    ; Get number of program headers (at offset 0x38)
    movzx ecx, word [0x10038]

    ; Process each program header (ELF64 Phdr = 0x38 bytes each)
.parse_phdr:
    test ecx, ecx
    jz .elf_done

    ; Check p_type == PT_LOAD (1)
    cmp dword [ebx], 1
    jne .next_phdr

    ; Copy segment: src = buffer + p_offset, dst = p_paddr, len = p_filesz
    push ecx
    push ebx

    mov esi, [ebx + 0x08]               ; p_offset (low 32)
    add esi, 0x10000                     ; Source = ELF buffer + offset
    mov edi, [ebx + 0x18]               ; p_paddr (low 32) = destination
    mov ecx, [ebx + 0x20]               ; p_filesz (low 32)

    ; Copy p_filesz bytes
    cld
    rep movsb

    ; Zero remaining bytes (p_memsz - p_filesz = BSS)
    pop ebx
    push ebx
    mov eax, [ebx + 0x28]               ; p_memsz (low 32)
    sub eax, [ebx + 0x20]               ; - p_filesz
    jz .no_bss
    mov ecx, eax
    xor al, al
    rep stosb
.no_bss:

    pop ebx
    pop ecx

.next_phdr:
    add ebx, 0x38                        ; sizeof(Elf64_Phdr)
    dec ecx
    jmp .parse_phdr

.elf_error:
    ; Show 'E' 'R' in red on VGA if ELF is invalid
    mov word [0xB8000], 0x4F45
    mov word [0xB8002], 0x4F52
    jmp $

.elf_done:
    ; ----- Setup KernelArgs at 0x60000 -----
    ; First: create a minimal memory map at 0x60100
    ; MemoryRegion { base: u64, size: u64, kind: u64 }
    ; Entry 0: Free memory from 2MB to 254MB
    mov dword [0x60100], 0x00200000      ; base low = 2MB
    mov dword [0x60104], 0               ; base high
    mov dword [0x60108], 0x0FE00000      ; size low = 254MB
    mov dword [0x6010C], 0               ; size high
    mov dword [0x60110], 1               ; kind = Free
    mov dword [0x60114], 0               ; kind high

    ; KernelArgs struct at 0x60000 (packed(8), all u64 then u32s)
    ; kernel_base (u64)
    mov dword [0x60000], 0x00100000      ; 1MB
    mov dword [0x60004], 0
    ; kernel_size (u64)
    mov dword [0x60008], 0x00040000      ; 256KB approx
    mov dword [0x6000C], 0
    ; stack_base (u64)
    mov dword [0x60010], 0x00080000
    mov dword [0x60014], 0
    ; stack_size (u64)
    mov dword [0x60018], 0x00010000      ; 64KB
    mov dword [0x6001C], 0
    ; env_base (u64)
    mov dword [0x60020], 0
    mov dword [0x60024], 0
    ; env_size (u64)
    mov dword [0x60028], 0
    mov dword [0x6002C], 0
    ; acpi_rsdp_base (u64)
    mov dword [0x60030], 0
    mov dword [0x60034], 0
    ; acpi_rsdp_size (u64)
    mov dword [0x60038], 0
    mov dword [0x6003C], 0
    ; memory_map_base (u64)
    mov dword [0x60040], 0x00060100      ; -> 0x60100
    mov dword [0x60044], 0
    ; memory_map_size (u64) = 24 bytes (one MemoryRegion)
    mov dword [0x60048], 24
    mov dword [0x6004C], 0
    ; initfs_base (u64)
    mov dword [0x60050], 0
    mov dword [0x60054], 0
    ; initfs_size (u64)
    mov dword [0x60058], 0
    mov dword [0x6005C], 0
    ; framebuffer_addr (u64)
    mov dword [0x60060], 0x000B8000      ; VGA text buffer
    mov dword [0x60064], 0
    ; framebuffer_width (u32)
    mov dword [0x60068], 80
    ; framebuffer_height (u32)
    mov dword [0x6006C], 25
    ; framebuffer_stride (u32)
    mov dword [0x60070], 80

    ; ----- Transition to Long Mode -----
    mov dword [long_mode.page_table], 0x1000
    mov dword [long_mode.func], s2_lm64_entry
    mov dword [long_mode.func + 4], 0
    jmp long_mode.entry

; =============================================
; Long Mode Entry (64-bit)
; Jump to the kernel entry point
; =============================================
USE64

s2_lm64_entry:
    ; Stack in long mode
    mov rsp, 0x90000

    ; RDI = pointer to KernelArgs (System V ABI first arg)
    mov rdi, 0x60000

    ; Jump to kernel entry point
    mov rax, [kernel_entry_addr]
    jmp rax

    ; Fallback halt (should never reach here)
.halt:
    cli
    hlt
    jmp .halt

; =============================================
; Data Section
; =============================================
USE16

s2_msg_banner:    db 'Strat9-OS stage 2 bootloader :', 0
s2_msg_a20:       db '  A20 line........... ', 0
s2_msg_cpuid:     db '  CPU features....... ', 0
s2_msg_kernel:    db '  Kernel loading..... ', 0
s2_msg_paging:    db '  Page tables........ ', 0
s2_msg_enter_pm:  db '  Entering long mode...', 0
s2_msg_ok:        db '[OK]', 0

; Kernel entry point (filled by ELF parser in PM)
kernel_entry_addr: dq 0

; Padding to 8KB (16 sectors) to fit the extra code
times 8192-($-stage2) db 0
