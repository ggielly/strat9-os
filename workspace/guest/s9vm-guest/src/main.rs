/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! s9vm — bare-metal guest kernel image.
//!
//! This is the smallest real "guest OS" that runs under s9vm: a fixed-address
//! x86-64 ELF image loaded by `SYS_VMM_LOAD_IMAGE` and entered in 64-bit long
//! mode by the machine policy. It validates the boot hand-off a real kernel
//! needs and brings up its own processor state before reporting that the
//! kernel is ready:
//!
//! 1. the boot-parameter block (`S9VMBP`), its command line, memory map bounds
//!    and the ACPI RSDP;
//! 2. a private GDT (flat code/data descriptors) installed with `lgdt` and a
//!    far return that reloads `CS`, followed by `SS`/`DS`/`ES`/`FS`/`GS`;
//! 3. a private IDT (128 gates) whose exception stubs reach a common handler;
//! 4. private 4-level page tables with 2 MiB identity leaves over the first
//!    4 MiB, activated by switching `CR3`;
//! 5. a local APIC timer count probe and a bounded interrupt-delivery probe
//!    (private IDT gate, assembly ISR, EOI and `iretq`);
//! 6. the boot-parameter-driven device drivers: virtio-console text output,
//!    virtio-block label read and virtio-network frame transmit.
//!
//! # Boot contract
//!
//! The policy enters the image with:
//!
//! - 64-bit long mode, paging enabled with an identity mapping of
//!   `0x0000_0000..0x0040_0000` (`CR3 = 0`, 2 MiB page-directory leaves);
//! - no IDT: the guest installs its own; interrupts are enabled only for the
//!   bounded timer-interrupt probe and disabled again afterwards;
//! - `RDI` = guest-physical address of the `S9VMBP` boot-parameter block
//!   (`workspace/kernel/src/s9vm/bootparams.rs`);
//! - the ACPI RSDP table at guest-physical `0x000E_0000`;
//! - the image linked at [`LINK_ADDRESS`] with entry symbol `_start`.
//!
//! `_start` installs a 16-byte aligned stack from `.bss`, clears the direction
//! flag and calls [`guest_main`]. The policy-provided page tables are only
//! used until the guest switches to its own tables; both map the same low
//! 4 MiB identity window, so the switch is transparent to code and stack.
//!
//! The code only relies on the image itself and on the contract above: no
//! kernel dependency, no allocator, no external crate.
//!
//! # Debug protocol (port `0xE9`)
//!
//! One byte per `out 0xE9, al`. Port `0xE9` is **not** part of the engine's
//! in-kernel fast path: each write is a policy exit whose
//! `VmmExitEvent.instruction_length` and `value` fields carry the instruction
//! length and the byte written (ABI v7), and the policy completes the exit
//! with the matching RIP advance.
//!
//! | Byte | Meaning |
//! |---|---|
//! | `b'G'` | boot-parameter magic `S9VMBP` validated |
//! | `b'M'` | memory-map count is non-zero |
//! | `b'A'` | RSDP found, `rsdp_gpa` coherent and ACPI 1.0 checksum valid |
//! | `b'R'` | initrd module (entry #1) starts with a cpio `newc` archive |
//! | `b'r'` | no initrd module (absent, out of the identity window or not cpio) |
//! | `b'K'` | command line parsed, private GDT/IDT and page tables active |
//! | `b'T'` | local APIC timer probe observed a count tick |
//! | `b't'` | no coherent local APIC timer (non-fatal) |
//! | `b'N'` | initrd `init` entry extracted and queued for console output |
//! | `b'n'` | no initrd `init` entry extracted (non-fatal) |
//! | `b'S'` | ACPI RSDP -> XSDT/RSDT -> MADT walked and validated |
//! | `b's'` | ACPI root table or MADT invalid (non-fatal) |
//! | `b'C'` | virtio-console accepted and consumed the greeting message |
//! | `b'c'` | no console device, or it did not acknowledge (non-fatal) |
//! | `b'D'` | virtio-block read sector 0 and validated the `S9VMDISK` label |
//! | `b'd'` | no block device, or the request/label failed (non-fatal) |
//! | `b'V'` | local APIC timer interrupt delivered through the private IDT |
//! | `b'v'` | no timer interrupt observed (non-fatal) |
//! | `b'X'` | virtio-net transmit queue consumed the Ethernet frame |
//! | `b'x'` | no network device, or the transmit failed (non-fatal) |
//! | `b'E'` + vector | CPU exception caught by the private IDT; then halt |
//! | `b'F'` + code | failure; the next byte is a [`failure`] code |
//! | `b'P'` | Rust panic (the next byte is not emitted; the guest halts) |
//!
//! Success sequence: `G`, `M`, `A`, `R`/`r` (initrd), `K` (kernel tables up),
//! `T`/`t` (timer probe), `N`/`n` (initrd `init` extracted), `S`/`s` (ACPI
//! tables), `C`/`c` (virtio-console text output), `D`/`d` (virtio-block read),
//! `V`/`v` (timer interrupt) and `X`/`x` (virtio-net transmit), then one `hlt`
//! at a time forever. A failure emits `F`, its code, then halts; an exception
//! after the IDT is installed emits `E`, the vector, then halts.

#![no_std]
#![no_main]

use core::{
    arch::{asm, global_asm},
    panic::PanicInfo,
    ptr::{addr_of, addr_of_mut, read_volatile, write_volatile},
    sync::atomic::{AtomicU32, Ordering},
};

mod guest_acpi;
mod virtio;
mod virtio_blk;
mod virtio_console;
mod virtio_net;

/// Guest-physical address the image is linked and loaded at.
pub const LINK_ADDRESS: u64 = 0x0010_0000;

/// Debug port emulated by the engine.
const DEBUG_PORT: u16 = 0xE9;

// Boot-parameter block offsets (little-endian, frozen ABI of
// `workspace/kernel/src/s9vm/bootparams.rs`).
/// `S9VMBP` magic, `u64`.
const BP_OFF_MAGIC: u64 = 0x000;
/// Layout version, `u32`.
const BP_OFF_VERSION: u64 = 0x008;
/// Block size, `u32`.
const BP_OFF_SIZE: u64 = 0x00C;
/// Boot flags, `u32` (which devices the world exposes).
const BP_OFF_FLAGS: u64 = 0x010;
/// Memory-map entry count, `u32` (max 32).
const BP_OFF_MEMORY_COUNT: u64 = 0x014;
/// Initrd/module entry count, `u32` (max 4).
const BP_OFF_MODULE_COUNT: u64 = 0x018;
/// Command-line length, `u32` (max 256).
const BP_OFF_CMDLINE_LEN: u64 = 0x01C;
/// ACPI RSDP guest-physical address, `u64`.
const BP_OFF_RSDP_GPA: u64 = 0x020;
/// Console virtio-mmio transport base, `u64`.
const BP_OFF_CONSOLE_MMIO: u64 = 0x028;
/// Console I/O APIC line, `u32`.
const BP_OFF_CONSOLE_IRQ: u64 = 0x030;
/// Checksum byte of the whole block, `u8` (the block sums to zero mod 256).
const BP_OFF_CHECKSUM: u64 = 0x034;

/// Boot flag: a virtio-console device is present on this world.
const BP_FLAG_CONSOLE: u32 = 1;
/// Boot flag: a virtio-block device is present on this world.
const BP_FLAG_BLOCK: u32 = 2;
/// Boot flag: a virtio-network device is present on this world.
const BP_FLAG_NETWORK: u32 = 4;

/// Total size of the boot-parameter block.
const BP_SIZE: u64 = 1024;
/// Layout version this kernel understands.
const BP_VERSION: u32 = 1;
/// Maximum number of memory-map entries.
const MAX_MEMORY_ENTRIES: u64 = 32;
/// Wire size of one memory-map entry (`base: u64`, `len: u64`, `kind: u32`).
const MEMORY_ENTRY_SIZE: u64 = 20;
/// Offset of the packed memory-map array in the block.
const MEMORY_OFFSET: u64 = 0x038;
/// Maximum number of module entries.
const MAX_MODULE_ENTRIES: u64 = 4;
/// Wire size of one module entry (`base: u64`, `len: u64`).
const MODULE_ENTRY_SIZE: u64 = 16;
/// Offset of the packed module array in the block.
const MODULE_OFFSET: u64 = 0x2B8;
/// Maximum length of the inline command line.
const CMDLINE_MAX: u64 = 256;
/// Offset of the inline command line in the block.
const CMDLINE_OFFSET: u64 = 0x2F8;

/// `S9VMBP` followed by two NUL bytes, read as a little-endian `u64`.
const BP_MAGIC: u64 = 0x0000_5042_4D56_3953;
/// End (exclusive) of the identity mapping shared by the policy and the
/// private page tables: the only window a guest pointer may be read from.
const IDENTITY_WINDOW: u64 = 0x0040_0000;
/// `cpio` "newc" ASCII magic, first bytes of an initrd archive.
const CPIO_NEWC_MAGIC: [u8; 6] = *b"070701";
/// Size of a `newc` cpio header: six magic bytes and thirteen 8-digit
/// hexadecimal fields.
const CPIO_HEADER_LEN: u64 = 110;
/// Offset of the `namesize` field inside a `newc` cpio header.
const CPIO_OFF_NAMESIZE: u64 = 94;
/// Offset of the `filesize` field inside a `newc` cpio header.
const CPIO_OFF_FILESIZE: u64 = 54;
/// Maximum number of archive entries walked (safety bound).
const CPIO_MAX_ENTRIES: u32 = 16;

// Global descriptor table.
/// Selector of the flat 64-bit code descriptor.
const GDT_CODE_SELECTOR: u16 = 0x08;
/// Selector of the flat data descriptor.
const GDT_DATA_SELECTOR: u16 = 0x10;
/// Number of entries of the private GDT.
const GDT_ENTRIES: usize = 3;
/// Null descriptor (entry 0).
const GDT_NULL: u64 = 0;
/// Flat 64-bit code descriptor (entry 1, selector `0x08`): present, DPL 0,
/// type `0xA`, `L = 1`, `D = 0`, `G = 1`.
const GDT_CODE: u64 = 0x00AF_9A00_0000_FFFF;
/// Flat data descriptor (entry 2, selector `0x10`): present, DPL 0, type `0x2`,
/// `D/B = 1` (ignored in 64-bit mode), `G = 1`.
const GDT_DATA: u64 = 0x00CF_9200_0000_FFFF;

/// Private GDT storage.
///
/// It **must be writable**: loading a segment descriptor makes the processor
/// set that descriptor's *accessed* bit, which is a memory write. A GDT placed
/// in a read-only segment makes `lretq`/`mov ss` fault on the descriptor
/// address (observed as an EPT violation on write, not a guest page fault).
/// The table therefore lives in `.bss` and is filled at boot.
#[repr(C, align(16))]
struct Gdt([u64; GDT_ENTRIES]);
/// The private GDT itself.
static mut GDT: Gdt = Gdt([GDT_NULL; GDT_ENTRIES]);

// Interrupt descriptor table.
/// Number of gates of the private IDT (exceptions plus the legacy IRQ range).
const IDT_ENTRIES: usize = 128;
/// Number of CPU exception vectors with a dedicated stub.
const EXCEPTION_VECTORS: usize = 32;
/// 64-bit interrupt gate: present, DPL 0, type `0xE`.
const IDT_TYPE_ATTRIBUTE: u64 = 0x8E;

// Page tables.
/// Number of entries per page table.
const PAGE_TABLE_ENTRIES: usize = 512;
/// Present leaf/table bit.
const PAGE_PRESENT: u64 = 1 << 0;
/// Writable leaf/table bit.
const PAGE_WRITE: u64 = 1 << 1;
/// 2 MiB page leaf bit.
const PAGE_LARGE: u64 = 1 << 7;
/// Size of a 2 MiB identity leaf.
const LARGE_PAGE_SIZE: u64 = 0x0020_0000;
/// Page-directory-pointer-table index of the 3..4 GiB window.
const APIC_PDPT_INDEX: usize = 3;
/// Page-directory index of the virtio-mmio device pages (`0xFE B0_0000`:
/// console `0xFEB0_0000`, block `0xFEB0_1000`, network `0xFEB0_2000`) inside
/// the 3..4 GiB window. The leaf starts at `0xFEA0_0000`.
const VIRTIO_PD_INDEX: usize = 0x1F5;
/// Page-directory index of the I/O APIC page (`0xFEC0_0000`); the leaf starts
/// at `0xFEC0_0000`.
const IOAPIC_PD_INDEX: usize = 0x1F6;
/// Page-directory index of the local APIC page (`0xFEE0_0000`).
const APIC_PD_INDEX: usize = 0x1F7;

// Local APIC.
/// Base of the local APIC MMIO page in the conventional x86 memory map.
const APIC_BASE: u64 = 0xFEE0_0000;
/// `APIC_ID` register offset.
const APIC_ID: u64 = 0x020;
/// `APIC_VERSION` register offset.
const APIC_VERSION: u64 = 0x030;
/// Spurious-interrupt vector register offset.
const APIC_SVR: u64 = 0x0F0;
/// LVT timer register offset.
const APIC_LVT_TIMER: u64 = 0x320;
/// Initial-count register offset.
const APIC_INITIAL_COUNT: u64 = 0x380;
/// Current-count register offset (read-only).
const APIC_CURRENT_COUNT: u64 = 0x390;
/// Divide-configuration register offset.
const APIC_DIVIDE_CONFIG: u64 = 0x3E0;
/// Spurious register: APIC software-enable bit.
const APIC_SVR_ENABLE: u32 = 1 << 8;
/// LVT timer mask bit (bit 16); the probe must not raise an interrupt.
const APIC_LVT_MASKED: u32 = 1 << 16;
/// LVT timer vector used while masked (any non-reserved vector).
const APIC_LVT_VECTOR: u32 = 0x20;
/// Divide-configuration encoding `0b1011` = divide by 1.
const APIC_DIVIDE_BY_1: u32 = 0xB;
/// End-of-interrupt register offset.
const APIC_EOI: u64 = 0x0B0;
/// In-request register block: first offset of the eight 32-bit words.
const APIC_IRR_FIRST: u64 = 0x200;
/// Number of 32-bit words in the in-request register block.
const APIC_IRR_WORDS: u64 = 8;
/// Vector delivered by the local APIC timer (legacy IRQ0 remap).
const TIMER_VECTOR: u8 = 0x20;
/// Initial one-shot count of the interrupt probe: one bus tick expires it.
const TIMER_IRQ_INITIAL: u32 = 1;
/// Maximum number of current-count polls while waiting for the interrupt.
///
/// Each poll is one replayed device exit that advances the emulated timer; the
/// bound also keeps the probe well below the engine's `MAX_RESUMED_EXITS`.
const TIMER_IRQ_POLLS: u32 = 32;
/// Initial one-shot count.
///
/// Small on purpose: the engine converts host TSC cycles to APIC bus ticks, so
/// a small count moves after a single replayed device exit and the probe can
/// observe a tick within its bounded poll budget.
const APIC_TIMER_INITIAL: u32 = 2_000;
/// Maximum number of current-count polls before declaring the timer silent.
///
/// Kept well below the engine's per-`RUN` budget of replayed device exits (64)
/// so a silent timer reports `t` instead of exhausting the exit budget.
const APIC_TIMER_POLLS: u32 = 32;

/// Failure code published after a non-fatal device marker (`c`, `d`, `x`) when
/// the boot-parameter block does not advertise the device at all.
const DEVICE_NOT_ADVERTISED: u8 = 0;

/// Failure codes published after `b'F'`.
mod failure {
    /// The boot-parameter block does not start with `S9VMBP`.
    pub const MAGIC: u8 = 1;
    /// The memory-map entry count is zero.
    pub const MEMORY_COUNT: u8 = 2;
    /// The `rsdp_gpa` field is not the address the firmware image lives at.
    pub const RSDP_FIELD: u8 = 3;
    /// The `RSD PTR ` signature was not found where the block advertises it.
    pub const RSDP_SCAN: u8 = 4;
    /// The ACPI 1.0 checksum of the RSDP is invalid.
    pub const CHECKSUM: u8 = 5;
    /// A fixed-capacity array of the block does not fit its field.
    pub const LAYOUT: u8 = 6;
    /// The inline command line is out of bounds or not printable ASCII.
    pub const CMDLINE: u8 = 7;
    /// A private page table is not page aligned.
    pub const PAGE_TABLES: u8 = 8;
    /// The block header (version, size or checksum) is inconsistent.
    pub const BLOCK: u8 = 9;
}

/// Pointer to a descriptor table (`GDTR`/`IDTR` operand).
#[repr(C, packed)]
struct DescriptorTablePointer {
    /// Table size in bytes, minus one.
    limit: u16,
    /// Linear address of the table.
    base: u64,
}

extern "C" {
    /// Addresses of the exception stubs, indexed by vector.
    static s9vm_guest_exception_table: [u64; EXCEPTION_VECTORS];
    /// Common stub used for vectors without a dedicated handler.
    fn s9vm_exception_spurious();
    /// Local APIC timer interrupt stub (vector `0x20`).
    fn s9vm_timer_isr();
    /// Loads `GDTR` and reloads `CS`/`SS`/`DS`/`ES`/`FS`/`GS`.
    fn s9vm_load_gdt(gdtr: *const DescriptorTablePointer);
    /// Page-table root built in `.bss`.
    static mut __s9vm_guest_pml4: [u64; PAGE_TABLE_ENTRIES];
    /// Page-directory-pointer table built in `.bss`.
    static mut __s9vm_guest_pdpt: [u64; PAGE_TABLE_ENTRIES];
    /// Low page directory (identity 0..4 MiB) built in `.bss`.
    static mut __s9vm_guest_pd_low: [u64; PAGE_TABLE_ENTRIES];
    /// High page directory (local APIC window) built in `.bss`.
    static mut __s9vm_guest_pd_high: [u64; PAGE_TABLE_ENTRIES];
    /// Interrupt descriptor table built in `.bss`.
    static mut __s9vm_guest_idt: [u64; IDT_ENTRIES * 2];
}

global_asm!(
    r#"
    .section .text.entry, "ax"
    .globl _start
    .type _start, @function
_start:
    /* Stack: a 16-byte aligned region reserved in .bss. */
    lea rsp, [rip + __s9vm_guest_stack_top]
    and rsp, -16
    /* SysV ABI: RDI already carries the boot-parameter GPA. */
    cld
    call guest_main
1:
    /* `guest_main` never returns; this is a safety net. */
    hlt
    jmp 1b
    .size _start, . - _start

    .section .text, "ax"
    .type s9vm_load_gdt, @function
    .globl s9vm_load_gdt
s9vm_load_gdt:
    /* RDI points to the 10-byte GDTR operand. */
    lgdt [rdi]
    /* Far return through the code selector reloads CS from the new GDT. */
    push {code_selector}
    lea rax, [rip + 2f]
    push rax
    retfq
2:
    mov ax, {data_selector}
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    ret
    .size s9vm_load_gdt, . - s9vm_load_gdt

    /* Exception stubs: every stub pushes its vector and reaches the common
       handler. Exceptions with a hardware error code keep it below the pushed
       vector; the handler only reads the vector. */
    .type s9vm_exception_common, @function
    .globl s9vm_exception_common
s9vm_exception_common:
    mov rdi, [rsp]
    and rsp, -16
    call s9vm_exception_handler
3:
    hlt
    jmp 3b
    .size s9vm_exception_common, . - s9vm_exception_common

    .macro S9VM_EXCEPTION_STUB vector
    .type s9vm_exception_\vector, @function
    .globl s9vm_exception_\vector
s9vm_exception_\vector:
    push \vector
    jmp s9vm_exception_common
    .size s9vm_exception_\vector, . - s9vm_exception_\vector
    .endm

    S9VM_EXCEPTION_STUB 0
    S9VM_EXCEPTION_STUB 1
    S9VM_EXCEPTION_STUB 2
    S9VM_EXCEPTION_STUB 3
    S9VM_EXCEPTION_STUB 4
    S9VM_EXCEPTION_STUB 5
    S9VM_EXCEPTION_STUB 6
    S9VM_EXCEPTION_STUB 7
    S9VM_EXCEPTION_STUB 8
    S9VM_EXCEPTION_STUB 9
    S9VM_EXCEPTION_STUB 10
    S9VM_EXCEPTION_STUB 11
    S9VM_EXCEPTION_STUB 12
    S9VM_EXCEPTION_STUB 13
    S9VM_EXCEPTION_STUB 14
    S9VM_EXCEPTION_STUB 15
    S9VM_EXCEPTION_STUB 16
    S9VM_EXCEPTION_STUB 17
    S9VM_EXCEPTION_STUB 18
    S9VM_EXCEPTION_STUB 19
    S9VM_EXCEPTION_STUB 20
    S9VM_EXCEPTION_STUB 21
    S9VM_EXCEPTION_STUB 22
    S9VM_EXCEPTION_STUB 23
    S9VM_EXCEPTION_STUB 24
    S9VM_EXCEPTION_STUB 25
    S9VM_EXCEPTION_STUB 26
    S9VM_EXCEPTION_STUB 27
    S9VM_EXCEPTION_STUB 28
    S9VM_EXCEPTION_STUB 29
    S9VM_EXCEPTION_STUB 30
    S9VM_EXCEPTION_STUB 31

    /* Vectors without a dedicated handler: report vector 0xFF. */
    .type s9vm_exception_spurious, @function
    .globl s9vm_exception_spurious
s9vm_exception_spurious:
    push 0xFF
    jmp s9vm_exception_common
    .size s9vm_exception_spurious, . - s9vm_exception_spurious

    /* Local APIC timer interrupt stub (vector 0x20). The interrupt gate
       cleared IF; save all 15 general-purpose registers, call the Rust
       handler and resume the interrupted context with iretq. RBX keeps the
       saved frame pointer while the stack is aligned for the Rust call. */
    .type s9vm_timer_isr, @function
    .globl s9vm_timer_isr
s9vm_timer_isr:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rbx, rsp
    and rsp, -16
    call s9vm_timer_handler
    mov rsp, rbx
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    iretq
    .size s9vm_timer_isr, . - s9vm_timer_isr

    .section .rodata, "a"
    .balign 16
    .globl s9vm_guest_exception_table
s9vm_guest_exception_table:
    .quad s9vm_exception_0
    .quad s9vm_exception_1
    .quad s9vm_exception_2
    .quad s9vm_exception_3
    .quad s9vm_exception_4
    .quad s9vm_exception_5
    .quad s9vm_exception_6
    .quad s9vm_exception_7
    .quad s9vm_exception_8
    .quad s9vm_exception_9
    .quad s9vm_exception_10
    .quad s9vm_exception_11
    .quad s9vm_exception_12
    .quad s9vm_exception_13
    .quad s9vm_exception_14
    .quad s9vm_exception_15
    .quad s9vm_exception_16
    .quad s9vm_exception_17
    .quad s9vm_exception_18
    .quad s9vm_exception_19
    .quad s9vm_exception_20
    .quad s9vm_exception_21
    .quad s9vm_exception_22
    .quad s9vm_exception_23
    .quad s9vm_exception_24
    .quad s9vm_exception_25
    .quad s9vm_exception_26
    .quad s9vm_exception_27
    .quad s9vm_exception_28
    .quad s9vm_exception_29
    .quad s9vm_exception_30
    .quad s9vm_exception_31

    .section .bss, "aw", @nobits
    .balign 16
__s9vm_guest_stack_bottom:
    /* 16 KiB minus a 16-byte alignment gap: the stack top stays strictly
       below the page-aligned tables that follow. */
    .skip 16368
    .balign 16
__s9vm_guest_stack_top:

    /* Private page tables, one 4 KiB page each, page aligned so they can be
       loaded into CR3. */
    .balign 4096
    .globl __s9vm_guest_pml4
__s9vm_guest_pml4:
    .skip 4096
    .globl __s9vm_guest_pdpt
__s9vm_guest_pdpt:
    .skip 4096
    .globl __s9vm_guest_pd_low
__s9vm_guest_pd_low:
    .skip 4096
    .globl __s9vm_guest_pd_high
__s9vm_guest_pd_high:
    .skip 4096

    /* Private IDT: 128 gates of 16 bytes, 16-byte aligned. */
    .balign 16
    .globl __s9vm_guest_idt
__s9vm_guest_idt:
    .skip 2048
"#,
    code_selector = const GDT_CODE_SELECTOR,
    data_selector = const GDT_DATA_SELECTOR,
);

/// Guest kernel entry point called by `_start`.
///
/// Validates the hand-off block, the command line and the ACPI tables, then
/// installs the private GDT, IDT and page tables before probing the local
/// APIC timer. Publishes one progress byte per stage on the debug port.
/// Never returns.
///
/// # Safety
///
/// Called exactly once from `_start` with the boot contract satisfied: long
/// mode, identity paging over the low 4 MiB, `boot_params_gpa` a readable
/// `S9VMBP` block and the RSDP at [`RSDP_GPA`].
#[no_mangle]
pub unsafe extern "C" fn guest_main(boot_params_gpa: u64) -> ! {
    // 1. The block is really the s9vm hand-off structure.
    if read_u64(boot_params_gpa, BP_OFF_MAGIC) != BP_MAGIC {
        fail(failure::MAGIC);
    }
    debug_write(b'G');

    // 2. The block header is consistent: known version, encoded size and the
    //    byte checksum that seals the whole 1024-byte block.
    if !block_header_ok(boot_params_gpa) {
        fail(failure::BLOCK);
    }

    // 3. The memory map is populated: a kernel has at least one region.
    if read_u32(boot_params_gpa, BP_OFF_MEMORY_COUNT) == 0 {
        fail(failure::MEMORY_COUNT);
    }
    debug_write(b'M');

    // 4. The fixed-capacity arrays of the block fit their fields, not only
    //    their counts (packed entry sizes are part of the frozen ABI).
    if !memory_layout_ok(boot_params_gpa) {
        fail(failure::LAYOUT);
    }

    // 5. The advertised RSDP pointer is the address the firmware image lives
    //    at, the signature is really there and its ACPI 1.0 checksum is valid.
    //    The whole firmware window is exposed as a slice so the exact
    //    discovery algorithm is shared with the host tests (`guest_acpi`).
    let rsdp_gpa = read_u64(boot_params_gpa, BP_OFF_RSDP_GPA);
    if rsdp_gpa != guest_acpi::WINDOW_BASE {
        fail(failure::RSDP_FIELD);
    }
    // SAFETY: the policy maps the whole ACPI window read-only for the guest.
    let acpi_window: &'static [u8] = unsafe {
        core::slice::from_raw_parts(guest_acpi::WINDOW_BASE as *const u8, guest_acpi::WINDOW_LEN)
    };
    let Some(found) = guest_acpi::find_rsdp(acpi_window) else {
        fail(failure::RSDP_SCAN);
    };
    if guest_acpi::WINDOW_BASE + found as u64 != rsdp_gpa {
        fail(failure::CHECKSUM);
    }
    debug_write(b'A');

    // 6. Kernel command line: bounds and byte set. The parsed word count is
    //    kept for later stages (initrd selection, console speed, ...).
    let cmdline_len = read_u32(boot_params_gpa, BP_OFF_CMDLINE_LEN);
    let Some(_argc) = parse_cmdline(boot_params_gpa, cmdline_len) else {
        fail(failure::CMDLINE);
    };

    // 7. Private processor tables: GDT first (it is needed by the exception
    //    gates' selector), then the IDT.
    install_gdt();
    install_idt();

    // 8. Private page tables: identity over the low 4 MiB with 2 MiB leaves,
    //    plus the local APIC window used by the timer probe.
    let page_table_root = build_page_tables();
    if page_table_root % 4096 != 0 {
        fail(failure::PAGE_TABLES);
    }
    switch_page_tables(page_table_root);

    // 9. Initrd module (entry #1): report `R` when the block advertises a
    //    cpio `newc` archive where it says it is, then `I` when the complete
    //    archive can be walked (headers, names and data ranges all in bounds,
    //    at least one entry and the `TRAILER!!!` record). An absent or
    //    malformed archive reports the non-fatal lowercase `r` instead.
    if initrd_present(boot_params_gpa) {
        debug_write(b'R');
        if cpio_archive_ok(boot_params_gpa) {
            debug_write(b'I');
        }
    } else {
        debug_write(b'r');
    }
    debug_write(b'K');

    // 10. Non-fatal local APIC timer probe: program a one-shot count and wait
    //     for the model to show progress. Interrupts stay disabled.
    match probe_apic_timer() {
        Ok(()) => debug_write(b'T'),
        Err(code) => {
            debug_write(b't');
            debug_write(code);
        }
    }

    // 11. Initrd consumption: extract the `init` entry of the `newc` archive
    //     the policy staged and append it to the console message, proving the
    //     guest can actually read the initrd payload (not only validate its
    //     framing). `N` on success, non-fatal `n` otherwise.
    let mut message = [0u8; CONSOLE_MESSAGE_MAX];
    let mut message_len = 0usize;
    while message_len < CONSOLE_GREETING.len() {
        message[message_len] = CONSOLE_GREETING[message_len];
        message_len += 1;
    }
    let mut initrd_init = 0usize;
    if initrd_present(boot_params_gpa) {
        let prefix = CONSOLE_INITRD_PREFIX;
        let payload_start = message_len + prefix.len();
        // SAFETY: the boot block and the module range were validated above;
        // `cpio_init_payload` revalidates every archive bound before reading,
        // and the destination slice is inside `message`.
        let found = unsafe {
            cpio_init_payload(
                boot_params_gpa,
                &mut message[payload_start..payload_start + CONSOLE_INIT_MAX],
            )
        };
        if let Some(size) = found {
            let mut index = 0usize;
            while index < prefix.len() {
                message[message_len + index] = prefix[index];
                index += 1;
            }
            message_len += prefix.len() + size;
            initrd_init = size;
        }
    }
    debug_write(if initrd_init > 0 { b'N' } else { b'n' });

    // 12. ACPI discovery: walk the RSDP -> XSDT/RSDT -> tables the policy
    //     wrote (validating every header and checksum inside the mapped
    //     window) and summarise the result. `S` when the root table and the
    //     MADT are valid, non-fatal `s` otherwise. The summary is echoed on
    //     the console below.
    let mut acpi_message = [0u8; CONSOLE_MESSAGE_MAX];
    let mut acpi_message_len = 0usize;
    let mut acpi_found = false;
    match guest_acpi::scan(acpi_window) {
        Ok(info) => {
            push_bytes(&mut acpi_message, &mut acpi_message_len, b"acpi: ");
            push_bytes(
                &mut acpi_message,
                &mut acpi_message_len,
                if info.xsdt { b"XSDT " } else { b"RSDT " },
            );
            push_decimal(&mut acpi_message, &mut acpi_message_len, info.tables);
            push_bytes(&mut acpi_message, &mut acpi_message_len, b" tables madt=");
            push_decimal(
                &mut acpi_message,
                &mut acpi_message_len,
                u32::from(info.madt),
            );
            push_bytes(&mut acpi_message, &mut acpi_message_len, b" facp=");
            push_decimal(
                &mut acpi_message,
                &mut acpi_message_len,
                u32::from(info.fadt),
            );
            push_bytes(&mut acpi_message, &mut acpi_message_len, b"\n");
            acpi_found = info.madt;
            debug_write(b'S');
        }
        Err(error) => {
            // `s` followed by the typed failure code, so a hardware run is
            // diagnosable without a rebuild.
            debug_write(b's');
            debug_write(error.code());
        }
    }
    let _ = acpi_found;

    // 13. Real text output: drive the virtio-console transmit queue published
    //     in the boot block. Two messages are sent through the same queue: the
    //     greeting (with the initrd `init` content when available) and the ACPI
    //     summary. Proves the full path guest -> split queue -> device model ->
    //     kernel console log. `C` when the device consumed every message, `c`
    //     followed by a failure code otherwise (non-fatal).
    let flags = read_u32(boot_params_gpa, BP_OFF_FLAGS);
    let console_base = read_u64(boot_params_gpa, BP_OFF_CONSOLE_MMIO);
    let mut console_error = None;
    if flags & BP_FLAG_CONSOLE != 0 {
        // The device IRQ line is published too, but this driver polls the used
        // ring: the guest has no ISR and never enables interrupts.
        let _console_irq = read_u32(boot_params_gpa, BP_OFF_CONSOLE_IRQ);
        // SAFETY: the console transport page is part of the device window
        // mapped by the private page tables; the driver validates the device
        // identity before touching any queue.
        match unsafe { virtio_console::Console::init(console_base) } {
            Ok(mut console) => {
                match console.send(&message[..message_len]) {
                    Ok(()) => {
                        if acpi_message_len > 0 {
                            if let Err(code) = console.send(&acpi_message[..acpi_message_len]) {
                                console_error = Some(code);
                            }
                        }
                    }
                    Err(code) => console_error = Some(code),
                }
            }
            Err(code) => console_error = Some(code),
        }
    } else {
        console_error = Some(DEVICE_NOT_ADVERTISED);
    }
    match console_error {
        None => debug_write(b'C'),
        Some(code) => {
            debug_write(b'c');
            debug_write(code);
        }
    }

    // 14. Block device: read sector 0 and verify the `S9VMDISK` label the
    //     userspace policy provisioned. Proves the full request path guest ->
    //     split queue -> device model -> backing image. Non-fatal: `D` on
    //     success, otherwise `d` followed by the failure code.
    if flags & BP_FLAG_BLOCK != 0 {
        // Transport pages are consecutive: console base + one 4 KiB page is
        // the block device (engine device-model convention).
        let block_base = console_base + virtio_blk::BASE_OFFSET_FROM_CONSOLE;
        // SAFETY: the block transport page is part of the device window mapped
        // by the private page tables; the driver validates the device identity
        // and the request status.
        match unsafe { virtio_blk::read_disk_label(block_base) } {
            Ok(()) => debug_write(b'D'),
            Err(code) => {
                debug_write(b'd');
                debug_write(code);
            }
        }
    } else {
        debug_write(b'd');
        debug_write(DEVICE_NOT_ADVERTISED);
    }

    // 15. Interrupt delivery: program the local APIC timer one-shot with the
    //     timer vector, enable interrupts for a bounded wait, and let the
    //     private IDT gate and its assembly stub run the Rust handler. This
    //     proves the full path kernel injection -> IDT -> ISR -> EOI -> iretq.
    //     `V` when the handler observed a tick, otherwise `v` followed by the
    //     failure code (non-fatal).
    match probe_timer_interrupt() {
        Ok(()) => debug_write(b'V'),
        Err(code) => {
            debug_write(b'v');
            debug_write(code);
        }
    }

    // 16. Network device: transmit one Ethernet frame through the virtio-net
    //     transmit queue (device id 1 at console base + two 4 KiB pages, by
    //     engine device-model convention). `X` when the device consumed the
    //     frame, otherwise `x` followed by the failure code (non-fatal).
    let net_error = if flags & BP_FLAG_NETWORK != 0 {
        let net_base = console_base + virtio_net::BASE_OFFSET_FROM_CONSOLE;
        // SAFETY: the network transport page is part of the device window
        // mapped by the private page tables; the driver probes the device
        // identity before touching any queue.
        unsafe { virtio_net::transmit(net_base) }.err()
    } else {
        Some(DEVICE_NOT_ADVERTISED)
    };
    match net_error {
        None => debug_write(b'X'),
        Some(code) => {
            debug_write(b'x');
            debug_write(code);
        }
    }

    // 17. Legacy serial console: emit one line on the in-kernel 16550 model
    //     (COM1) and verify the transmitter reports ready through the line
    //     status register. This is the console path a stock x86 kernel uses
    //     before any PCI/virtio driver loads: `W` on success, `w` + code
    //     otherwise (non-fatal).
    let uart_error = unsafe { serial_probe() }.err();
    match uart_error {
        None => debug_write(b'W'),
        Some(code) => {
            debug_write(b'w');
            debug_write(code);
        }
    }

    // 18. CMOS clock: read the seconds register through the index/data ports
    //     and check it decodes as a BCD or binary second. Proves the in-kernel
    //     MC146818 model answers a guest: `Z` on success, `z` + code otherwise.
    let rtc_error = unsafe { rtc_probe() }.err();
    match rtc_error {
        None => debug_write(b'Z'),
        Some(code) => {
            debug_write(b'z');
            debug_write(code);
        }
    }

    halt_forever()
}

/// COM1 data port (the UART's register file starts here).
const UART_DATA_PORT: u16 = 0x3F8;
/// COM1 line-status register offset from the data port.
const UART_LSR_OFFSET: u16 = 5;
/// LSR bit: transmit holding register empty.
const UART_LSR_THRE: u8 = 1 << 5;
/// Line written to the legacy serial console.
const UART_MESSAGE: &[u8] = b"s9vm-guest: legacy uart online\n";
/// CMOS index/data ports.
const CMOS_INDEX_PORT: u16 = 0x70;
const CMOS_DATA_PORT: u16 = 0x71;
/// CMOS seconds register.
const CMOS_SECONDS: u8 = 0x00;

/// Failure codes published after the non-fatal serial/clock markers.
mod platform_failure {
    /// A transmitted byte was not accepted (transmitter never became ready).
    pub const UART_STATUS: u8 = 1;
    /// The CMOS seconds register did not decode as a valid second.
    pub const RTC_SECONDS: u8 = 2;
}

/// Writes one line on the legacy COM1 UART and checks the transmitter status.
///
/// # Safety
///
/// Port I/O only: the engine replays `out`/`in` against the kernel's 16550
/// model, no memory is touched.
unsafe fn serial_probe() -> Result<(), u8> {
    let mut index = 0usize;
    while index < UART_MESSAGE.len() {
        // SAFETY: port I/O, replayed by the engine.
        unsafe {
            asm!(
                "out dx, al",
                in("dx") UART_DATA_PORT,
                in("al") UART_MESSAGE[index],
                options(nomem, nostack, preserves_flags)
            );
        }
        index += 1;
    }
    let mut status: u8;
    // SAFETY: port I/O, replayed by the engine; the LSR is read-only.
    unsafe {
        asm!(
            "in al, dx",
            in("dx") UART_DATA_PORT + UART_LSR_OFFSET,
            out("al") status,
            options(nomem, nostack, preserves_flags)
        );
    }
    if status & UART_LSR_THRE == 0 {
        return Err(platform_failure::UART_STATUS);
    }
    Ok(())
}

/// Reads the CMOS seconds register and validates its encoding.
///
/// # Safety
///
/// Port I/O only: the engine replays `out`/`in` against the kernel's CMOS
/// model, no memory is touched.
unsafe fn rtc_probe() -> Result<(), u8> {
    // SAFETY: port I/O, replayed by the engine (index port then data port).
    unsafe {
        asm!(
            "out dx, al",
            in("dx") CMOS_INDEX_PORT,
            in("al") CMOS_SECONDS,
            options(nomem, nostack, preserves_flags)
        );
    }
    let mut raw: u8;
    // SAFETY: port I/O, replayed by the engine; the data port is read-only here.
    unsafe {
        asm!(
            "in al, dx",
            in("dx") CMOS_DATA_PORT,
            out("al") raw,
            options(nomem, nostack, preserves_flags)
        );
    }
    // The model is in BCD/24h mode by default: high nibble is the tens digit
    // (0..=5), low nibble the ones digit (0..=9).
    let tens = raw >> 4;
    let ones = raw & 0x0F;
    if tens > 5 || ones > 9 {
        return Err(platform_failure::RTC_SECONDS);
    }
    Ok(())
}

/// Message prefix the guest kernel sends once the console is up (followed by
/// the initrd `init` content when available).
const CONSOLE_GREETING: &[u8] = b"s9vm-guest: virtio-console online\n";
/// Prefix prepended to the initrd `init` content in the console message.
const CONSOLE_INITRD_PREFIX: &[u8] = b"initrd init: ";
/// Maximum size of the console message the guest builds.
const CONSOLE_MESSAGE_MAX: usize = 128;
/// Maximum number of initrd `init` bytes echoed on the console.
const CONSOLE_INIT_MAX: usize = 64;

/// Reports a failure step then halts forever.
fn fail(code: u8) -> ! {
    debug_write(b'F');
    debug_write(code);
    halt_forever()
}

/// Writes one byte on the s9vm debug port.
fn debug_write(byte: u8) {
    // SAFETY: port 0xE9 is the s9vm debug port, always replayed by the engine;
    // `out` does not touch memory and the engine models it as a debug console.
    unsafe {
        asm!(
            "out dx, al",
            in("dx") DEBUG_PORT,
            in("al") byte,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Halts forever: every `hlt` is a policy exit the policy completes.
fn halt_forever() -> ! {
    loop {
        // SAFETY: `hlt` only stops the vCPU until the next exit; the engine
        // reports it as a halt exit and never injects an interrupt here.
        unsafe {
            asm!("hlt", options(nomem, nostack));
        }
    }
}

/// Common exception handler reached by every stub of the private IDT.
///
/// Publishes `b'E'` followed by the vector and halts: an exception means the
/// kernel state is not trustworthy, so this is a diagnosable stop rather than
/// a recovery path.
#[no_mangle]
pub extern "C" fn s9vm_exception_handler(vector: u64) -> ! {
    debug_write(b'E');
    debug_write(vector as u8);
    halt_forever()
}

/// Validates the bounds of every fixed-capacity array of the boot block.
///
/// The counts alone are not enough: each packed array must also stay inside
/// its reserved field, so a malformed count can never make the guest read
/// another field as an entry.
///
/// # Safety
///
/// The 1024 bytes at `boot_params_gpa` must be mapped and readable.
unsafe fn memory_layout_ok(boot_params_gpa: u64) -> bool {
    let memory_count = u64::from(read_u32(boot_params_gpa, BP_OFF_MEMORY_COUNT));
    let module_count = u64::from(read_u32(boot_params_gpa, BP_OFF_MODULE_COUNT));
    let cmdline_len = u64::from(read_u32(boot_params_gpa, BP_OFF_CMDLINE_LEN));
    if memory_count > MAX_MEMORY_ENTRIES
        || module_count > MAX_MODULE_ENTRIES
        || cmdline_len > CMDLINE_MAX
    {
        return false;
    }
    // Entry counts are bounded above, so these products cannot overflow.
    let memory_end = MEMORY_OFFSET + memory_count * MEMORY_ENTRY_SIZE;
    let module_end = MODULE_OFFSET + module_count * MODULE_ENTRY_SIZE;
    let cmdline_end = CMDLINE_OFFSET + cmdline_len;
    memory_end <= MODULE_OFFSET && module_end <= CMDLINE_OFFSET && cmdline_end <= BP_SIZE
}

/// Parses the inline command line and returns its argument count.
///
/// The command line is not NUL-terminated: its length is authoritative. The
/// bytes must be printable ASCII separated by spaces; anything else is
/// rejected instead of being interpreted. Returns `None` when the field is
/// out of bounds or contains a non-printable byte (the caller takes the `F`
/// path).
///
/// # Safety
///
/// The 1024 bytes at `boot_params_gpa` must be mapped and readable.
unsafe fn parse_cmdline(boot_params_gpa: u64, cmdline_len: u32) -> Option<u32> {
    let length = u64::from(cmdline_len);
    if length > CMDLINE_MAX || CMDLINE_OFFSET + length > BP_SIZE {
        return None;
    }
    let mut arguments = 0u32;
    let mut in_argument = false;
    let mut index = 0u64;
    while index < length {
        let byte = read_u8(boot_params_gpa, CMDLINE_OFFSET + index);
        if byte == b' ' {
            in_argument = false;
        } else if (0x21..=0x7E).contains(&byte) {
            if !in_argument {
                in_argument = true;
                arguments = arguments.saturating_add(1);
            }
        } else {
            // Control bytes and non-ASCII are not part of a kernel command
            // line; treat them as malformed input.
            return None;
        }
        index += 1;
    }
    Some(arguments)
}

/// Validates the boot-block header: layout version, encoded size and checksum.
///
/// The checksum is a System V-style byte sum over the whole 1024-byte block:
/// the stored checksum byte is the value that makes the total zero modulo 256.
///
/// # Safety
///
/// The 1024 bytes at `boot_params_gpa` must be mapped and readable.
unsafe fn block_header_ok(boot_params_gpa: u64) -> bool {
    if read_u32(boot_params_gpa, BP_OFF_VERSION) != BP_VERSION
        || u64::from(read_u32(boot_params_gpa, BP_OFF_SIZE)) != BP_SIZE
    {
        return false;
    }
    let mut sum = 0u8;
    let mut offset = 0u64;
    while offset < BP_SIZE {
        if offset != BP_OFF_CHECKSUM {
            sum = sum.wrapping_add(read_u8(boot_params_gpa, offset));
        }
        offset += 1;
    }
    read_u8(boot_params_gpa, BP_OFF_CHECKSUM) == 0u8.wrapping_sub(sum)
}

/// Reports whether the initrd module (module entry #1) starts with a cpio
/// `newc` archive.
///
/// Only the identity window is dereferenced: a module entry pointing outside
/// it, a too-short entry or an absent module is reported as "no initrd" (the
/// caller publishes the non-fatal `r` marker) instead of faulting.
///
/// # Safety
///
/// The 1024 bytes at `boot_params_gpa` must be mapped and readable.
unsafe fn initrd_present(boot_params_gpa: u64) -> bool {
    if read_u32(boot_params_gpa, BP_OFF_MODULE_COUNT) < 2 {
        return false;
    }
    let entry = MODULE_OFFSET + MODULE_ENTRY_SIZE;
    let base = read_u64(boot_params_gpa, entry);
    let len = read_u64(boot_params_gpa, entry + 8);
    let magic_len = CPIO_NEWC_MAGIC.len() as u64;
    if len < magic_len {
        return false;
    }
    let Some(end) = base.checked_add(magic_len) else {
        return false;
    };
    if base >= IDENTITY_WINDOW || end > IDENTITY_WINDOW {
        return false;
    }
    let mut index = 0u64;
    while index < magic_len {
        // SAFETY: `base..base + magic_len` is inside the mapped window.
        if read_u8(base, index) != CPIO_NEWC_MAGIC[index as usize] {
            return false;
        }
        index += 1;
    }
    true
}

/// Walks the whole initrd archive and validates its framing.
///
/// Every offset is checked against the module length before it is dereferenced,
/// so a truncated or hostile archive takes the non-fatal `r` path instead of
/// faulting. Returns `true` only for an archive with at least one entry, valid
/// name/data ranges and the `TRAILER!!!` record.
///
/// # Safety
///
/// The 1024 bytes at `boot_params_gpa` must be mapped and readable.
unsafe fn cpio_archive_ok(boot_params_gpa: u64) -> bool {
    // SAFETY: caller contract.
    let Some((base, len)) = (unsafe { initrd_module(boot_params_gpa) }) else {
        return false;
    };
    // SAFETY: `base..base + len` is inside the identity window (validated by
    // `initrd_module`).
    unsafe { cpio_walk(base, len) }
}

/// One validated `newc` archive entry.
struct CpioEntry {
    /// Offset of the NUL-terminated name inside the archive.
    name_offset: u64,
    /// Size of the name field, including its NUL terminator.
    name_size: u64,
    /// Offset of the file data inside the archive.
    data_offset: u64,
    /// Size of the file data in bytes.
    data_size: u64,
    /// Offset of the next entry (after alignment padding).
    next: u64,
}

/// Reads and validates one `newc` entry at `cursor`.
///
/// Returns `None` for a malformed or out-of-bounds entry; the caller decides
/// whether that is fatal (whole-archive walk) or simply "not found".
///
/// # Safety
///
/// `cursor..` must be inside the mapped archive of `len` bytes.
unsafe fn cpio_read_entry(base: u64, cursor: u64, len: u64) -> Option<CpioEntry> {
    let header_end = match cursor.checked_add(CPIO_HEADER_LEN) {
        Some(end) if end <= len => end,
        _ => return None,
    };
    // SAFETY: the caller guarantees the archive range is mapped.
    if !unsafe { cpio_magic_at(base, cursor) } {
        return None;
    }
    // SAFETY: the header range was validated above.
    let namesize = unsafe { cpio_field(base, cursor + CPIO_OFF_NAMESIZE) }?;
    let filesize = unsafe { cpio_field(base, cursor + CPIO_OFF_FILESIZE) }?;
    if namesize == 0 || namesize > len {
        return None;
    }
    let name_end = match header_end.checked_add(namesize) {
        Some(end) if end <= len => end,
        _ => return None,
    };
    // The name field is NUL-terminated inside `namesize`.
    // SAFETY: the name range was validated above.
    if unsafe { read_u8(base, name_end - 1) } != 0 {
        return None;
    }
    let data_offset = align4(name_end);
    let data_end = match data_offset.checked_add(filesize) {
        Some(end) if end <= len => end,
        _ => return None,
    };
    Some(CpioEntry {
        name_offset: header_end,
        name_size: namesize,
        data_offset,
        data_size: filesize,
        next: align4(data_end),
    })
}

/// Returns the guest-physical range of the initrd module (module entry #1).
///
/// # Safety
///
/// The 1024 bytes at `boot_params_gpa` must be mapped and readable.
unsafe fn initrd_module(boot_params_gpa: u64) -> Option<(u64, u64)> {
    if read_u32(boot_params_gpa, BP_OFF_MODULE_COUNT) < 2 {
        return None;
    }
    let entry = MODULE_OFFSET + MODULE_ENTRY_SIZE;
    let base = read_u64(boot_params_gpa, entry);
    let len = read_u64(boot_params_gpa, entry + 8);
    if base >= IDENTITY_WINDOW || len > IDENTITY_WINDOW - base {
        return None;
    }
    Some((base, len))
}

/// Copies the data of the `init` entry of the initrd archive into `out`.
///
/// Returns the number of bytes copied, or `None` when the archive is absent,
/// malformed, has no regular `init` entry or the entry does not fit in `out`.
///
/// # Safety
///
/// The 1024 bytes at `boot_params_gpa` and the module range must be mapped.
unsafe fn cpio_init_payload(boot_params_gpa: u64, out: &mut [u8]) -> Option<usize> {
    let (base, len) = unsafe { initrd_module(boot_params_gpa) }?;
    let mut cursor = 0u64;
    let mut entries = 0u32;
    while entries < CPIO_MAX_ENTRIES {
        // SAFETY: the module range was validated against the identity window.
        let entry = unsafe { cpio_read_entry(base, cursor, len) }?;
        // SAFETY: the name range was validated by `cpio_read_entry`.
        if unsafe { cpio_name_eq(base, entry.name_offset, entry.name_size, b"init") } {
            if entry.data_size == 0 || entry.data_size > out.len() as u64 {
                return None;
            }
            let mut index = 0u64;
            while index < entry.data_size {
                // SAFETY: the data range was validated by `cpio_read_entry`.
                out[index as usize] = unsafe { read_u8(base, entry.data_offset + index) };
                index += 1;
            }
            return Some(entry.data_size as usize);
        }
        // SAFETY: the name range was validated by `cpio_read_entry`.
        if unsafe { cpio_name_eq(base, entry.name_offset, entry.name_size, b"TRAILER!!!") } {
            return None;
        }
        entries += 1;
        cursor = entry.next;
    }
    None
}

/// Walks one `newc` archive at `base..base + len`.
///
/// # Safety
///
/// The range must be mapped and readable.
unsafe fn cpio_walk(base: u64, len: u64) -> bool {
    let mut cursor = 0u64;
    let mut entries = 0u32;
    while entries < CPIO_MAX_ENTRIES {
        // SAFETY: the caller guarantees the archive range is mapped.
        let Some(entry) = (unsafe { cpio_read_entry(base, cursor, len) }) else {
            return false;
        };
        // SAFETY: the name range was validated by `cpio_read_entry`.
        if unsafe { cpio_name_eq(base, entry.name_offset, entry.name_size, b"TRAILER!!!") } {
            return entries > 0;
        }
        entries += 1;
        cursor = entry.next;
    }
    false
}

/// Checks that a `newc` magic starts at `offset`.
///
/// # Safety
///
/// `offset..offset + 6` must be inside the mapped archive.
unsafe fn cpio_magic_at(base: u64, offset: u64) -> bool {
    let mut index = 0u64;
    while index < CPIO_NEWC_MAGIC.len() as u64 {
        // SAFETY: the caller validated the header range before this call.
        if read_u8(base, offset + index) != CPIO_NEWC_MAGIC[index as usize] {
            return false;
        }
        index += 1;
    }
    true
}

/// Parses one 8-digit hexadecimal `newc` header field.
///
/// # Safety
///
/// `offset..offset + 8` must be inside the mapped archive.
unsafe fn cpio_field(base: u64, offset: u64) -> Option<u64> {
    let mut value = 0u64;
    let mut index = 0u64;
    while index < 8 {
        // SAFETY: the caller validated the header range before this call.
        let byte = read_u8(base, offset + index);
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'a'..=b'f' => u64::from(byte - b'a') + 10,
            b'A'..=b'F' => u64::from(byte - b'A') + 10,
            _ => return None,
        };
        value = value.checked_mul(16)?.checked_add(digit)?;
        index += 1;
    }
    Some(value)
}

/// Compares a `newc` name field, including its NUL terminator, with `expected`.
///
/// # Safety
///
/// `offset..offset + namesize` must be inside the mapped archive.
unsafe fn cpio_name_eq(base: u64, offset: u64, namesize: u64, expected: &[u8]) -> bool {
    let wanted = expected.len() as u64 + 1;
    if namesize != wanted {
        return false;
    }
    let mut index = 0u64;
    while index < expected.len() as u64 {
        // SAFETY: the caller validated the name range before this call.
        if read_u8(base, offset + index) != expected[index as usize] {
            return false;
        }
        index += 1;
    }
    // The final byte is the NUL terminator checked by the caller.
    true
}

/// Rounds `value` up to a four-byte boundary.
const fn align4(value: u64) -> u64 {
    (value + 3) & !3
}

/// Installs the private GDT and reloads every segment register.
///
/// The table is filled here (it lives in `.bss`, not in `.rodata`, because a
/// descriptor load writes the accessed bit into the entry), then loaded with
/// `lgdt` and a far return that reloads `CS`.
///
/// # Safety
///
/// Called once, before any segment is loaded from the private GDT; the
/// selectors `0x08` and `0x10` must be the code and data descriptors written
/// below.
unsafe fn install_gdt() {
    let gdt = addr_of_mut!(GDT).cast::<u64>();
    // SAFETY: the `.bss` GDT has GDT_ENTRIES slots and the descriptors are the
    // canonical flat 64-bit code/data pair named by the selectors.
    unsafe {
        write_volatile(gdt.add(1), GDT_CODE);
        write_volatile(gdt.add(2), GDT_DATA);
    }
    let pointer = DescriptorTablePointer {
        limit: (GDT_ENTRIES * 8 - 1) as u16,
        base: gdt as u64,
    };
    // SAFETY: `pointer` describes the GDT just filled; the far return lands on
    // the next instruction with CS/SS/DS/ES/FS/GS reloaded from it.
    unsafe {
        s9vm_load_gdt(&pointer);
    }
}

/// Installs the private IDT with one gate per vector.
///
/// Vectors `0..=31` use their exception stub, vector `0x20` (local APIC timer)
/// has a dedicated interrupt stub and the remaining vectors use the spurious
/// stub. Interrupts are only enabled for the bounded timer-interrupt probe, so
/// the polling drivers never take a device IRQ.
///
/// # Safety
///
/// Called once; the stubs and the `.bss` IDT must be linked and the code
/// selector must match the private GDT.
unsafe fn install_idt() {
    let idt = addr_of_mut!(__s9vm_guest_idt).cast::<u64>();
    for index in 0..IDT_ENTRIES * 2 {
        // SAFETY: the IDT is a writable `.bss` array of `IDT_ENTRIES` gates.
        unsafe {
            write_volatile(idt.add(index), 0);
        }
    }
    let stubs = addr_of!(s9vm_guest_exception_table);
    for vector in 0..EXCEPTION_VECTORS {
        // SAFETY: the stub table has one entry per exception vector.
        let handler = unsafe { read_volatile(stubs.cast::<u64>().add(vector)) };
        write_idt_entry(idt, vector, handler);
    }
    let spurious = s9vm_exception_spurious as *const () as usize as u64;
    for vector in EXCEPTION_VECTORS..IDT_ENTRIES {
        write_idt_entry(idt, vector, spurious);
    }
    // Dedicated gate for the timer interrupt: the exception range stays
    // unchanged and the remaining vectors keep the spurious stub.
    let timer = s9vm_timer_isr as *const () as usize as u64;
    write_idt_entry(idt, usize::from(TIMER_VECTOR), timer);
    let pointer = DescriptorTablePointer {
        limit: (IDT_ENTRIES * 16 - 1) as u16,
        base: idt as u64,
    };
    // SAFETY: `pointer` describes the IDT just built; `lidt` only loads it.
    unsafe {
        asm!(
            "lidt [{}]",
            in(reg) &pointer,
            options(readonly, nostack, preserves_flags)
        );
    }
}

/// Writes one 64-bit interrupt gate at `vector` in `idt`.
fn write_idt_entry(idt: *mut u64, vector: usize, handler: u64) {
    let low = (handler & 0xFFFF)
        | (u64::from(GDT_CODE_SELECTOR) << 16)
        | (IDT_TYPE_ATTRIBUTE << 40)
        | (((handler >> 16) & 0xFFFF) << 48);
    let high = handler >> 32;
    // SAFETY: the caller passes a `.bss` IDT and `vector < IDT_ENTRIES`.
    unsafe {
        write_volatile(idt.add(vector * 2), low);
        write_volatile(idt.add(vector * 2 + 1), high);
    }
}

/// Builds the private page tables and returns the value to load in `CR3`.
///
/// Layout: `PML4[0] -> PDPT`, `PDPT[0] -> low PD` with two 2 MiB identity
/// leaves (`0..4 MiB`), and `PDPT[3] -> high PD` with one 2 MiB leaf for the
/// local APIC page. Every table lives in `.bss`, page aligned, so its virtual
/// address (identity mapping) is also its physical address.
///
/// # Safety
///
/// Called once, after the GDT/IDT are installed; the `.bss` tables must be
/// writable and identity mapped by the policy-provided tables.
unsafe fn build_page_tables() -> u64 {
    let pml4 = addr_of_mut!(__s9vm_guest_pml4).cast::<u64>();
    let pdpt = addr_of_mut!(__s9vm_guest_pdpt).cast::<u64>();
    let pd_low = addr_of_mut!(__s9vm_guest_pd_low).cast::<u64>();
    let pd_high = addr_of_mut!(__s9vm_guest_pd_high).cast::<u64>();
    for index in 0..PAGE_TABLE_ENTRIES {
        // SAFETY: the four tables are `.bss` arrays of `PAGE_TABLE_ENTRIES`.
        unsafe {
            write_volatile(pml4.add(index), 0);
            write_volatile(pdpt.add(index), 0);
            write_volatile(pd_low.add(index), 0);
            write_volatile(pd_high.add(index), 0);
        }
    }
    let pml4_address = pml4 as u64;
    let pdpt_address = pdpt as u64;
    let pd_low_address = pd_low as u64;
    let pd_high_address = pd_high as u64;
    // SAFETY: every index used below is inside a 4 KiB table.
    unsafe {
        write_volatile(pml4, pdpt_address | PAGE_PRESENT | PAGE_WRITE);
        write_volatile(pdpt, pd_low_address | PAGE_PRESENT | PAGE_WRITE);
        write_volatile(pd_low, PAGE_PRESENT | PAGE_WRITE | PAGE_LARGE);
        write_volatile(
            pd_low.add(1),
            LARGE_PAGE_SIZE | PAGE_PRESENT | PAGE_WRITE | PAGE_LARGE,
        );
        // Device pages (virtio-mmio, I/O APIC and local APIC): the engine
        // models them and serves every access through a second-level
        // violation, so the guest only needs the guest page tables to accept
        // the 3..4 GiB window.
        write_volatile(
            pdpt.add(APIC_PDPT_INDEX),
            pd_high_address | PAGE_PRESENT | PAGE_WRITE,
        );
        write_volatile(
            pd_high.add(VIRTIO_PD_INDEX),
            0xFEA0_0000 | PAGE_PRESENT | PAGE_WRITE | PAGE_LARGE,
        );
        write_volatile(
            pd_high.add(IOAPIC_PD_INDEX),
            0xFEC0_0000 | PAGE_PRESENT | PAGE_WRITE | PAGE_LARGE,
        );
        write_volatile(
            pd_high.add(APIC_PD_INDEX),
            APIC_BASE | PAGE_PRESENT | PAGE_WRITE | PAGE_LARGE,
        );
    }
    pml4_address
}

/// Switches `CR3` to the private page tables.
///
/// # Safety
///
/// `root` must be a page-aligned 4-level root whose tables identity-map the
/// code, stack and data currently in use.
unsafe fn switch_page_tables(root: u64) {
    // SAFETY: the new root maps the currently executing code and the stack;
    // a non-global CR3 write also flushes the TLB for the old tables.
    unsafe {
        asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags));
    }
}

/// Probes the local APIC timer and reports whether it observed a tick.
///
/// Reads the `APIC_ID` and `APIC_VERSION` registers first: an absent or
/// incoherent window (zero or all-ones version, no LVT) makes the probe fail
/// without any side effect. Otherwise it software-enables the APIC, programs
/// the timer in one-shot mode with a fixed divide, then polls the read-only
/// current count until it moves, bounded by [`APIC_TIMER_POLLS`]. The timer is
/// masked and interrupts stay disabled: no ISR is required.
///
/// Returns `Ok(())` when the count moved, otherwise the [`apic_failure`] code
/// of the check that failed (published after the non-fatal `t` marker).
///
/// # Safety
///
/// The local APIC page must be mapped by the active page tables (the private
/// tables map it); no other CPU state is modified.
unsafe fn probe_apic_timer() -> Result<(), u8> {
    let apic_id = mmio_read32(APIC_BASE + APIC_ID);
    let version = mmio_read32(APIC_BASE + APIC_VERSION);
    // Integrated xAPIC: non-zero version, non-zero "max LVT entry" field.
    // A window backed by plain RAM or an absent model reads 0/all ones.
    if version == 0 || version == u32::MAX || (version >> 16) & 0xFF == 0 {
        return Err(apic_failure::VERSION);
    }
    let _ = apic_id;
    // Software-enable the local APIC before programming the timer.
    let svr = mmio_read32(APIC_BASE + APIC_SVR);
    mmio_write32(APIC_BASE + APIC_SVR, svr | APIC_SVR_ENABLE);
    // One-shot mode (mode bits 18:17 = 0), masked (bit 16): no interrupt.
    mmio_write32(
        APIC_BASE + APIC_LVT_TIMER,
        APIC_LVT_MASKED | APIC_LVT_VECTOR,
    );
    mmio_write32(APIC_BASE + APIC_DIVIDE_CONFIG, APIC_DIVIDE_BY_1);
    mmio_write32(APIC_BASE + APIC_INITIAL_COUNT, APIC_TIMER_INITIAL);
    let tsc_start = read_tsc();
    let mut poll = 0u32;
    while poll < APIC_TIMER_POLLS {
        let current = mmio_read32(APIC_BASE + APIC_CURRENT_COUNT);
        if current != APIC_TIMER_INITIAL {
            // The count moved: the first tick was observed. Stop the timer and
            // report success; the TSC is read to show that time really passed.
            let _elapsed = read_tsc().wrapping_sub(tsc_start);
            mmio_write32(APIC_BASE + APIC_INITIAL_COUNT, 0);
            return Ok(());
        }
        poll += 1;
    }
    mmio_write32(APIC_BASE + APIC_INITIAL_COUNT, 0);
    Err(apic_failure::COUNT)
}

/// Failure reasons of the local-APIC probes, published on the debug port right
/// after the non-fatal `t`/`v` markers (small binary codes, never an ASCII
/// marker, so the marker stream stays unambiguous).
mod apic_failure {
    /// The APIC version register is absent or incoherent.
    pub const VERSION: u8 = 1;
    /// The one-shot count never moved (polling timer probe).
    pub const COUNT: u8 = 2;
    /// The interrupt-request block was not empty before enabling interrupts.
    pub const IRR: u8 = 3;
    /// No timer interrupt was observed (interrupt-delivery probe).
    pub const TICK: u8 = 4;
}

/// Number of local APIC timer interrupts delivered to the private ISR.
static TIMER_TICKS: AtomicU32 = AtomicU32::new(0);

/// Local APIC timer interrupt handler (vector [`TIMER_VECTOR`]).
///
/// Called by the assembly stub, which saved all general-purpose registers and
/// aligned the stack. The handler counts the tick and acknowledges the
/// interrupt through the local APIC end-of-interrupt register; the stub then
/// restores the registers and resumes the interrupted context with `iretq`.
/// Kept minimal and panic-free: it must not touch anything the interrupted
/// code owns beyond the atomic counter.
#[no_mangle]
pub extern "C" fn s9vm_timer_handler() {
    TIMER_TICKS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the local APIC page is mapped by the private page tables; the EOI
    // write clears the in-service bit of the delivered vector.
    unsafe {
        mmio_write32(APIC_BASE + APIC_EOI, 0);
    }
}

/// True when the local APIC in-request register block is empty.
///
/// The eight IRR words are read through the modeled device window, so the
/// check also proves the APIC page is reachable. Used before enabling
/// interrupts: a foreign pending vector must not be delivered through the
/// exception stubs.
///
/// # Safety
///
/// The local APIC page must be mapped by the active page tables.
unsafe fn apic_irr_empty() -> bool {
    let mut index = 0u64;
    while index < APIC_IRR_WORDS {
        // SAFETY: the local APIC page is mapped; the IRR block is 0x200..0x280.
        let word = unsafe { mmio_read32(APIC_BASE + APIC_IRR_FIRST + index * 0x10) };
        if word != 0 {
            return false;
        }
        index += 1;
    }
    true
}

/// Probes interrupt delivery through the private IDT and page tables.
///
/// Programs the local APIC timer as an unmasked one-shot with vector
/// [`TIMER_VECTOR`], enables interrupts for a bounded wait, and expects the
/// assembly stub to run the Rust handler (which counts the tick and writes
/// EOI). The timer model only advances when the guest exits to the kernel, so
/// the wait loop reads the read-only current count: each read is a replayed
/// device access (one exit) that advances the timer. With a one-tick initial
/// count the first such advance expires the timer; the kernel then injects the
/// vector because `IF` is set. Interrupts are disabled again before returning.
///
/// Returns `Ok(())` when the handler observed a tick, otherwise the
/// [`apic_failure`] code of the check that failed (published after `v`).
///
/// # Safety
///
/// The APIC page, the private IDT gate and the interrupt stack must be ready;
/// called once, from the boot thread.
unsafe fn probe_timer_interrupt() -> Result<(), u8> {
    let version = mmio_read32(APIC_BASE + APIC_VERSION);
    if version == 0 || version == u32::MAX || (version >> 16) & 0xFF == 0 {
        return Err(apic_failure::VERSION);
    }
    if !unsafe { apic_irr_empty() } {
        return Err(apic_failure::IRR);
    }
    let svr = mmio_read32(APIC_BASE + APIC_SVR);
    mmio_write32(APIC_BASE + APIC_SVR, svr | APIC_SVR_ENABLE);
    // One-shot mode (mode bits 18:17 = 0), unmasked: the expiry raises
    // TIMER_VECTOR. The divide by 1 keeps the conversion to one bus tick.
    mmio_write32(APIC_BASE + APIC_LVT_TIMER, u32::from(TIMER_VECTOR));
    mmio_write32(APIC_BASE + APIC_DIVIDE_CONFIG, APIC_DIVIDE_BY_1);
    mmio_write32(APIC_BASE + APIC_INITIAL_COUNT, TIMER_IRQ_INITIAL);
    // SAFETY: the timer gate is installed in the IDT and the current stack is
    // the kernel stack; interrupts stay enabled only for the bounded wait.
    unsafe {
        asm!("sti", options(nostack));
    }
    let mut polls = 0u32;
    while polls < TIMER_IRQ_POLLS {
        // One emulated device exit per iteration: this is what advances the
        // APIC timer model and eventually lets the kernel inject the vector.
        let _ = mmio_read32(APIC_BASE + APIC_CURRENT_COUNT);
        if TIMER_TICKS.load(Ordering::Relaxed) != 0 {
            break;
        }
        core::hint::spin_loop();
        polls += 1;
    }
    // SAFETY: interrupts are masked again before returning to the caller.
    unsafe {
        asm!("cli", options(nostack));
    }
    mmio_write32(APIC_BASE + APIC_INITIAL_COUNT, 0);
    if TIMER_TICKS.load(Ordering::Relaxed) != 0 {
        Ok(())
    } else {
        Err(apic_failure::TICK)
    }
}

/// Reads one 32-bit MMIO register at `address`.
///
/// Emitted as a plain 32-bit `mov` so the engine's instruction replay and the
/// device model see exactly one access; volatile semantics are provided by the
/// assembly itself.
///
/// # Safety
///
/// `address` must point to a mapped device register.
unsafe fn mmio_read32(address: u64) -> u32 {
    let value: u32;
    // SAFETY: the caller guarantees the address is mapped; the instruction has
    // no side effect other than the device read.
    unsafe {
        asm!(
            "mov {value:e}, dword ptr [{address}]",
            address = in(reg) address,
            value = out(reg) value,
            options(nostack)
        );
    }
    value
}

/// Writes one 32-bit MMIO register at `address`.
///
/// # Safety
///
/// `address` must point to a mapped device register.
unsafe fn mmio_write32(address: u64, value: u32) {
    // SAFETY: the caller guarantees the address is mapped; the instruction has
    // no side effect other than the device write.
    unsafe {
        asm!(
            "mov dword ptr [{address}], {value:e}",
            address = in(reg) address,
            value = in(reg) value,
            options(nostack)
        );
    }
}

/// Reads the time-stamp counter.
fn read_tsc() -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: `rdtsc` is always available in 64-bit mode and only reads a
    // counter; both output registers are declared.
    unsafe {
        asm!(
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// Reads a little-endian `u8` from guest memory.
///
/// # Safety
///
/// `base + offset` must be inside a guest page mapped by the policy.
unsafe fn read_u8(base: u64, offset: u64) -> u8 {
    // SAFETY: caller guarantees the address is mapped and readable.
    unsafe { read_volatile((base + offset) as *const u8) }
}

/// Reads a little-endian `u32` from guest memory.
///
/// # Safety
///
/// `base + offset` must be inside a guest page mapped by the policy.
unsafe fn read_u32(base: u64, offset: u64) -> u32 {
    // SAFETY: caller guarantees the address is mapped and readable.
    unsafe { read_volatile((base + offset) as *const u32) }
}

/// Reads a little-endian `u64` from guest memory.
///
/// # Safety
///
/// `base + offset` must be inside a guest page mapped by the policy.
unsafe fn read_u64(base: u64, offset: u64) -> u64 {
    // SAFETY: caller guarantees the address is mapped and readable.
    unsafe { read_volatile((base + offset) as *const u64) }
}

/// Appends `bytes` to a fixed message buffer, refusing to overflow.
fn push_bytes(buffer: &mut [u8], length: &mut usize, bytes: &[u8]) -> bool {
    let Some(end) = length.checked_add(bytes.len()) else {
        return false;
    };
    if end > buffer.len() {
        return false;
    }
    buffer[*length..end].copy_from_slice(bytes);
    *length = end;
    true
}

/// Appends an unsigned decimal number to a fixed message buffer.
fn push_decimal(buffer: &mut [u8], length: &mut usize, mut value: u32) -> bool {
    let mut digits = [0u8; 10];
    let mut count = 0usize;
    if value == 0 {
        digits[0] = b'0';
        count = 1;
    } else {
        while value > 0 && count < digits.len() {
            digits[count] = b'0' + (value % 10) as u8;
            value /= 10;
            count += 1;
        }
    }
    let Some(end) = length.checked_add(count) else {
        return false;
    };
    if end > buffer.len() {
        return false;
    }
    let mut index = 0usize;
    while index < count {
        buffer[*length + index] = digits[count - 1 - index];
        index += 1;
    }
    *length = end;
    true
}

/// Panic handler: publish `b'P'` on the debug port, then halt forever.
///
/// The guest is expected to be panic-free; this handler exists so a bug turns
/// into a diagnosable marker instead of an undefined behaviour.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    debug_write(b'P');
    halt_forever()
}
