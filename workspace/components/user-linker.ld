/* Strat9-OS userspace component linker script.
 *
 * User binaries live in the dedicated LOW-HALF window at base 0x400000
 * (PML4[0]) — canonical, Ring-3 accessible, and completely disjoint from
 * the kernel image (higher half 0xFFFFFFFF80000000).
 *
 * Why NOT 0xFFFFFFFF80000000 (the higher half)?  That window is the kernel
 * image's own. AddressSpace::new_user() gives every process a private copy
 * of the PML4[511] PDP with the kernel-image slot removed so user mappings
 * cannot clobber kernel pages — but that also means the kernel text is NOT
 * addressable while a user CR3 is active. A user binary linked in the
 * same window would therefore fight the kernel for the same virtual
 * addresses (see the #PF at 0xffffffff800c76e9 with the user CR3 active:
 * the scheduler jumped to the first task and faulted fetching kernel code
 * under the private user page tables).
 *
 * Lower half keeps the classic split: kernel text stays mapped (shared
 * PML4[511] subtree), user pages are private, and RIP-relative references
 * in the binary stay within ±2 GiB of its load base.
 *
 * Usage (component build, overrides the kernel linker script):
 *   rustflags = ["-C", "link-arg=-T", "-C", "link-arg=<this file>",
 *                "-C", "link-arg=-no-pie", "-C", "relocation-model=static"]
 */

ENTRY(_start)

SECTIONS
{
    . = 0x400000;

    __user_base = .;

    .text : ALIGN(4096)
    {
        KEEP(*(.text.boot))
        *(.text .text.*)
    }

    .rodata : ALIGN(4096)
    {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4096)
    {
        *(.data .data.*)
        *(.got .got.*)
    }

    .bss : ALIGN(4096)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    __user_end = .;

    /* Debug sections: keep the data (debuggers use it) but out of the loaded
     * image; NOLOAD-ish placement at the end avoids overlap with .text. */
    .debug_info  0 : { *(.debug_info .debug_info.*) }
    .debug_loc   0 : { *(.debug_loc .debug_loc.*) }
    .debug_abbrev 0 : { *(.debug_abbrev .debug_abbrev.*) }
    .debug_line  0 : { *(.debug_line .debug_line.*) }
    .debug_str   0 : { *(.debug_str .debug_str.*) }
    .debug_ranges 0 : { *(.debug_ranges .debug_ranges.*) }
    .debug_frame 0 : { *(.debug_frame .debug_frame.*) }
    .debug_loclists 0 : { *(.debug_loclists*) }
    .debug_rnglists 0 : { *(.debug_rnglists*) }
    .debug_str_offsets 0 : { *(.debug_str_offsets*) }
    .debug_addr  0 : { *(.debug_addr*) }
    .debug_2_line 0 : { *(.debug_line_str) }

    /DISCARD/ :
    {
        *(.eh_frame .eh_frame_hdr)
        *(.note .note.*)
        *(.comment)
    }
}
