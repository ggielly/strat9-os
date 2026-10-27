/* Strat9-OS Kernel linker script */
/* x86_64 higher-half kernel */

OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS(5);   /* R X */
    rodata PT_LOAD FLAGS(4);   /* R   */
    data   PT_LOAD FLAGS(6);   /* RW  */
    bss    PT_LOAD FLAGS(6);   /* RW  */
}

SECTIONS
{
    /* Kernel loaded at -2GB (0xFFFFFFFF80000000) by default */
    . = 0xFFFFFFFF80000000;

    /* Read-only code */
    .text : ALIGN(4K) { *(.boot.text) *(.text .text.*) } :text

    /* Read-only data */
    .rodata : ALIGN(4K) { *(.rodata .rodata.*) } :rodata

    /* Initialized data */
    .data : ALIGN(4K) { *(.data .data.*) __start_component_entries = .; KEEP(*(.component_entries)) __stop_component_entries = .; } :data

    /* Global Offset Table: the compiler emits `call *sym@GOTPCREL(%rip)` for
     * some indirect calls (format_args/panic machinery). If .got is discarded
     * lld resolves those slots against address 0 -> calls read garbage from
     * low RAM (IVT/BDA) and #UD. Keep it mapped at its higher-half VMA. */
    .got : ALIGN(4K) { *(.got .got.*) } :data

    /* Uninitialized data (zero-filled) */
    .bss : ALIGN(4K)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        *(.bss.stack)
        __bss_end = .;
    } :bss

    /* Section header string table - NOT in a PT_LOAD PHDR.
     * Placing PROGBITS (.shstrtab) in the :bss PHDR inflates p_filesz
     * to ~2 GB because lld covers the entire segment range. */
    .shstrtab : { *(.shstrtab) }

    /* .got is discarded below; with relocation-model=static no GOT entries
     * are emitted, so RIP-relative calls resolve to higher-half addresses. */

    /* Discard unneeded sections */
    /DISCARD/ :
    {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.note .note.*)
        *(.comment)
        *(.plt)
        *(.plt.*)
        *(.debug*)
        *(.zdebug*)
        *(.ARM.exidx)
        *(.ARM.extab)
        *(.symtab)
        *(.strtab)
    }
}
