/* Strat9-OS Kernel Linker Script */
/* x86_64 higher-half kernel with Limine boot protocol support */

ENTRY(kmain)

SECTIONS
{
    /* Kernel loaded at 1 MiB by bootloader */
    . = 1M;

    /* Limine requests (must be in writable section) */
    .requests : ALIGN(8)
    {
        KEEP(*(.requests_start_marker))
        KEEP(*(.requests))
        KEEP(*(.requests_end_marker))
    }

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
        *(.multiboot_header)
    }
}
