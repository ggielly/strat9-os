/*
 * Linker script of the s9vm bare-metal guest kernel.
 *
 * The image is a fixed-address ET_EXEC loaded at guest-physical 0x0010_0000 by
 * SYS_VMM_LOAD_IMAGE. The policy installs an identity mapping of the first
 * 4 MiB before entry, so the linked virtual addresses are also the physical
 * addresses the guest executes from.
 *
 * Every allocatable output section starts on its own 4 KiB page: the kernel
 * image loader rejects loadable segments whose page-aligned spans overlap, so
 * `.text` occupies the first page and `.bss` (the guest stack) starts at
 * 0x0010_1000. `.rodata` and `.data` are page-aligned too for the same reason
 * (they are empty today, but a future constant or static must not share a page
 * with the executable segment).
 */

OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

SECTIONS
{
    . = 0x00100000;

    .text : ALIGN(16)
    {
        /* `_start` first: the entry point is the first instruction page. */
        *(.text.entry)
        *(.text .text.*)
    }

    . = ALIGN(4096);
    .rodata : ALIGN(16)
    {
        *(.rodata .rodata.*)
    }

    . = ALIGN(4096);
    .data : ALIGN(16)
    {
        *(.data .data.*)
        *(.got .got.*)
    }

    . = ALIGN(4096);
    .bss : ALIGN(16)
    {
        *(.bss .bss.*)
        *(COMMON)
    }

    /* The guest never returns, so unwinding metadata is not needed. */
    /DISCARD/ :
    {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame .eh_frame_hdr)
    }
}
