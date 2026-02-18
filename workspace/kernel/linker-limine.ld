/* strat9-os kernel linker script for Limine */
/* x86_64 higher-half kernel with Limine boot protocol */

OUTPUT_FORMAT(elf64-x86-64)
ENTRY(kmain)

PHDRS
{
    text    PT_LOAD;
    rodata  PT_LOAD;
    data    PT_LOAD;
}

SECTIONS
{
    /* Limine loads us at -2GB (0xFFFFFFFF80000000) by default */
    . = 0xFFFFFFFF80000000;

    /* Read-only code */
    .text : ALIGN(4K)
    {
        *(.text .text.*)
    } :text

    /* Read-only data */
    .rodata : ALIGN(4K)
    {
        *(.rodata .rodata.*)
    } :rodata

    /* Initialized data, including Limine request sections */
    .data : ALIGN(4K)
    {
        *(.data .data.*)

        /* Limine requests - markers must bracket the requests */
        KEEP(*(.requests_start_marker))
        KEEP(*(.requests))
        KEEP(*(.requests_end_marker))

        /* Component initialization entries */
        __start_component_entries = .;
        KEEP(*(.component_entries))
        __stop_component_entries = .;
    } :data

    /* Uninitialized data (zero-filled) */
    .bss : ALIGN(4K)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } :data

    /* Discard unneeded sections */
    /DISCARD/ :
    {
        *(.eh_frame)
        *(.note .note.*)
        *(.comment)
    }
}
