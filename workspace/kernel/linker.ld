/* Strat9-OS Kernel Linker Script */
/* x86_64 higher-half kernel with U-Boot boot protocol support */

ENTRY(_start)

SECTIONS
{
    /* Kernel loaded at -2GB (higher half) */
    . = 0xFFFFFFFF80000000;

    /* 64-bit boot code */
    .boot.text : ALIGN(4K)
    {
        *(.boot.text)
    }

    /* 64-bit kernel code */
    .text : ALIGN(4K)
    {
        *(.text .text.*)
    }

    /* Read-only data (GDT, strings, etc.) */
    .rodata : ALIGN(4K)
    {
        *(.rodata .rodata.*)
    }

    /* Initialized data */
    .data : ALIGN(4K)
    {
        *(.data .data.*)

        /* Component initialization entries */
        __start_component_entries = .;
        KEEP(*(.component_entries))
        __stop_component_entries = .;
    }

    /* Uninitialized data (zero-filled) */
    .bss : ALIGN(4K)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    /* Discard unneeded sections */
    /DISCARD/ :
    {
        *(.eh_frame)
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
