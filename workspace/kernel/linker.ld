/* Strat9-OS Kernel linker script */
/* x86_64 higher-half kernel */

OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

PHDRS
{
    text   PT_LOAD;
    rodata PT_LOAD;
    data   PT_LOAD;
    bss    PT_LOAD;
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

    /* Bootstrap stack — placed before .bss so BSS clear doesn't touch it */
    .boot.stack : ALIGN(4K) { *(.boot.stack) } :data

    /* Uninitialized data (zero-filled) */
    .bss : ALIGN(4K)
    {
        *(.bss .bss.*)
        *(COMMON)
    } :bss

    /* BSS bounds via ADDR/SIZEOF — works reliably in all code models */
    __bss_start = ADDR(.bss);
    __bss_end = ADDR(.bss) + SIZEOF(.bss);

    /* Section header string table - NOT in a PT_LOAD PHDR.
     * Placing PROGBITS (.shstrtab) in the :bss PHDR inflates p_filesz
     * to ~2 GB because lld covers the entire segment range. */
    .shstrtab : { *(.shstrtab) }

    /* Discard unneeded sections */
    /DISCARD/ :
    {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.note .note.*)
        *(.comment)
        *(.got)
        *(.got.*)
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
