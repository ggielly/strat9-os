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
    ; Step 4: Detect physical memory (INT 15h E820)
    ; =============================================
    mov si, s2_msg_memmap
    call print

    call e820_detect

    mov si, s2_msg_ok
    call print
    call print_line

    ; =============================================
    ; Step 5: Setup Page Tables
    ; =============================================
    mov si, s2_msg_paging
    call print

    call setup_page_tables

    mov si, s2_msg_ok
    call print
    call print_line

    ; =============================================
    ; Step 6: Enter Protected Mode -> Long Mode
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
; E820 Memory Detection (INT 15h, EAX=0xE820)
; Stores MemoryRegion entries at physical 0x8000
; Fills [e820_entry_count] with number of entries
; =============================================
e820_detect:
    pusha
    pushf
    push es

    ; Setup buffer at physical 0x8000
    mov ax, 0
    mov es, ax
    mov di, 0x8000

    xor ebx, ebx            ; Continuation = 0 (first call)
    xor bp, bp              ; Entry counter

.e820_loop:
    mov eax, 0xE820
    mov ecx, 24             ; Our MemoryRegion size
    mov edx, 0x534D4150     ; 'SMAP'
    int 0x15

    jc .e820_done           ; CF set = error or end of list

    cmp eax, 0x534D4150     ; Verify 'SMAP' returned
    jne .e820_done

    cmp ecx, 24             ; Did we get a full entry?
    jb .e820_check_more

    ; Map E820 type to MemoryKind
    ; E820 type at offset 16 (dword): 1=usable, 2=reserved, 3=ACPI reclaim, 4=ACPI NVS, 5=bad
    cmp dword [es:di + 16], 1
    je .e820_type_free
    cmp dword [es:di + 16], 3
    je .e820_type_reclaim
    ; Everything else (2, 4, 5, ...) -> Reserved
    mov dword [es:di + 16], 3       ; MemoryKind::Reserved (3)
    mov dword [es:di + 20], 0
    jmp .e820_type_done

.e820_type_free:
    mov dword [es:di + 16], 1       ; MemoryKind::Free (1)
    mov dword [es:di + 20], 0
    jmp .e820_type_done

.e820_type_reclaim:
    mov dword [es:di + 16], 2       ; MemoryKind::Reclaim (2)
    mov dword [es:di + 20], 0

.e820_type_done:
    inc bp
    cmp bp, 512                     ; Max entries
    jae .e820_done
    add di, 24                      ; Advance to next entry slot

.e820_check_more:
    test ebx, ebx                   ; EBX=0 means last entry
    jz .e820_done
    jmp .e820_loop

.e820_done:
    mov [e820_entry_count], bp

    pop es
    popf
    popa
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
    ; KernelArgs struct at 0x60000 (repr(C, packed(8)))
    ; Zero-fill first 144 bytes (struct size) to clear padding + trailing fields
    mov edi, 0x60000
    mov ecx, 36                          ; 144 / 4 = 36 dwords
    xor eax, eax
    rep stosd
    ; magic (u32) = 0x53543942 "ST9B"
    mov dword [0x60000], 0x53543942
    ; abi_version (u32) = 1
    mov dword [0x60004], 1
    ; kernel_base (u64)
    mov dword [0x60008], 0x00100000      ; 1MB
    ; kernel_size (u64)
    mov dword [0x60010], 0x00040000      ; 256KB approx
    ; stack_base (u64)
    mov dword [0x60018], 0x00080000
    ; stack_size (u64)
    mov dword [0x60020], 0x00010000      ; 64KB
    ; acpi_rsdp_base (u64) = 0
    ; memory_map_base (u64) = 0x8000 (E820 map)
    mov dword [0x60048], 0x00008000
    mov dword [0x6004C], 0
    ; memory_map_size (u64) = entry_count * 24
    mov eax, [e820_entry_count]
    mov ecx, eax
    shl eax, 3                           ; count * 8
    shl ecx, 4                           ; count * 16
    add eax, ecx                         ; count * 24
    mov [0x60050], eax
    mov dword [0x60054], 0
    ; framebuffer_addr (u64)
    mov dword [0x60068], 0x000B8000      ; VGA text buffer
    ; framebuffer_width (u32)
    mov dword [0x60070], 80
    ; framebuffer_height (u32)
    mov dword [0x60074], 25
    ; framebuffer_stride (u32)
    mov dword [0x60078], 80
    ; framebuffer_bpp..hhdm_offset = 0 (already zeroed)

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
s2_msg_memmap:    db '  Memory map........ ', 0
s2_msg_paging:    db '  Page tables........ ', 0
s2_msg_enter_pm:  db '  Entering long mode...', 0
s2_msg_ok:        db '[OK]', 0

; Kernel entry point (filled by ELF parser in PM)
kernel_entry_addr: dq 0

; Number of sectors loaded in the first chunk.
kernel_chunk1_sectors: dd 0

; Number of E820 memory map entries (filled by e820_detect)
e820_entry_count: dd 0

; Padding to 8KB (16 sectors) to fit the extra code
times 8192-($-stage2) db 0
