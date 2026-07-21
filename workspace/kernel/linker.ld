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

    /* Uninitialized data (zero-filled) */
    .bss : ALIGN(4K)
    {
        *(.bss .bss.*)
        *(COMMON)
        *(.bss.stack)
    } :bss

    /* Section header string table - placed last, forced ALLOC to close BSS segment */
    .shstrtab : ALIGN(4K) { *(.shstrtab) } :bss

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
