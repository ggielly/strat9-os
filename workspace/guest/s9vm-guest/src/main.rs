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
//! mode by the machine policy. It proves the boot hand-off a real kernel needs:
//! a boot-parameter block address in `RDI`, an identity-mapped low window and an
//! ACPI RSDP the guest can discover on its own.
//!
//! # Boot contract
//!
//! The policy enters the image with:
//!
//! - 64-bit long mode, paging enabled with an identity mapping of
//!   `0x0000_0000..0x0040_0000` (`CR3 = 0`, 2 MiB page-directory leaves);
//! - no IDT: interrupts are not expected and the guest never executes `sti`;
//! - `RDI` = guest-physical address of the `S9VMBP` boot-parameter block
//!   (`workspace/kernel/src/s9vm/bootparams.rs`);
//! - the ACPI RSDP table at guest-physical `0x000E_0000`;
//! - the image linked at [`LINK_ADDRESS`] with entry symbol `_start`.
//!
//! `_start` installs a 16-byte aligned stack from `.bss`, clears the direction
//! flag and calls [`guest_main`]. The code only relies on the image itself and
//! on the contract above: no kernel dependency, no allocator, no external
//! crate.
//!
//! # Debug protocol (port `0xE9`)
//!
//! One byte per `out 0xE9, al`. The engine replays those exits in the kernel
//! (the debug port is part of the fast-path device model), so the policy only
//! sees the guest `hlt`.
//!
//! | Byte | Meaning |
//! |---|---|
//! | `b'G'` | boot-parameter magic `S9VMBP` validated |
//! | `b'M'` | memory-map count is non-zero |
//! | `b'A'` | RSDP found, `rsdp_gpa` coherent and ACPI 1.0 checksum valid |
//! | `b'F'` | failure; the next byte is a [`failure`] code |
//! | `b'P'` | Rust panic (the next byte is not emitted; the guest halts) |
//!
//! After the success marker the guest halts forever, one `hlt` at a time.

#![no_std]
#![no_main]

use core::{
    arch::{asm, global_asm},
    panic::PanicInfo,
};

/// Guest-physical address the image is linked and loaded at.
pub const LINK_ADDRESS: u64 = 0x0010_0000;

/// Debug port emulated by the engine.
const DEBUG_PORT: u16 = 0xE9;

// Boot-parameter block offsets (little-endian, frozen ABI of
// `workspace/kernel/src/s9vm/bootparams.rs`).
/// `S9VMBP` magic, `u64`.
const BP_OFF_MAGIC: u64 = 0x000;
/// Memory-map entry count, `u32` (max 32).
const BP_OFF_MEMORY_COUNT: u64 = 0x014;
/// Initrd/module entry count, `u32` (max 4).
const BP_OFF_MODULE_COUNT: u64 = 0x018;
/// Command-line length, `u32` (max 256).
const BP_OFF_CMDLINE_LEN: u64 = 0x01C;
/// ACPI RSDP guest-physical address, `u64`.
const BP_OFF_RSDP_GPA: u64 = 0x020;

/// `S9VMBP` followed by two NUL bytes, read as a little-endian `u64`.
const BP_MAGIC: u64 = 0x0000_5042_4D56_3953;
/// Expected guest-physical address of the ACPI RSDP.
const RSDP_GPA: u64 = 0x000E_0000;
/// End (exclusive) of the legacy BIOS window scanned for the RSDP.
const RSDP_SCAN_END: u64 = 0x0010_0000;
/// RSDP candidates are 16-byte aligned.
const RSDP_ALIGN: u64 = 16;
/// ACPI 1.0 checksum covers the first 20 bytes of the RSDP.
const RSDP_CHECKSUM_LEN: u64 = 20;
/// `"RSD PTR "` read as a little-endian `u64`.
const RSDP_SIGNATURE: u64 = u64::from_le_bytes(*b"RSD PTR ");

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
    /// A bookkeeping field is outside the maximum of its fixed-capacity array.
    pub const LAYOUT: u8 = 6;
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

    .section .bss, "aw", @nobits
    .balign 16
__s9vm_guest_stack_bottom:
    .skip 16384
__s9vm_guest_stack_top:
"#
);

/// Guest kernel entry point called by `_start`.
///
/// Validates the hand-off block, then the ACPI tables, publishing one progress
/// byte per stage on the debug port. Never returns.
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

    // 2. The memory map is populated: a kernel has at least one region.
    if read_u32(boot_params_gpa, BP_OFF_MEMORY_COUNT) == 0 {
        fail(failure::MEMORY_COUNT);
    }
    debug_write(b'M');

    // 3. The bookkeeping fields fit the fixed-capacity arrays of the block: a
    //    kernel receives four module entries and a 256-byte command line at
    //    most (the lengths themselves may be zero).
    if read_u32(boot_params_gpa, BP_OFF_MODULE_COUNT) > 4
        || read_u32(boot_params_gpa, BP_OFF_CMDLINE_LEN) > 256
    {
        fail(failure::LAYOUT);
    }

    // 4. The advertised RSDP pointer is the address the firmware image lives
    //    at, the signature is really there and its ACPI 1.0 checksum is valid.
    let rsdp_gpa = read_u64(boot_params_gpa, BP_OFF_RSDP_GPA);
    if rsdp_gpa != RSDP_GPA {
        fail(failure::RSDP_FIELD);
    }
    let Some(found) = find_rsdp() else {
        fail(failure::RSDP_SCAN);
    };
    if found != rsdp_gpa || !acpi_checksum_ok(found) {
        fail(failure::CHECKSUM);
    }
    debug_write(b'A');

    halt_forever()
}

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

/// Reads a little-endian `u32` from guest memory.
///
/// # Safety
///
/// `base + offset` must be inside a guest page mapped by the policy.
unsafe fn read_u32(base: u64, offset: u64) -> u32 {
    // SAFETY: caller guarantees the address is mapped and readable.
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}

/// Reads a little-endian `u64` from guest memory.
///
/// # Safety
///
/// `base + offset` must be inside a guest page mapped by the policy.
unsafe fn read_u64(base: u64, offset: u64) -> u64 {
    // SAFETY: caller guarantees the address is mapped and readable.
    unsafe { core::ptr::read_volatile((base + offset) as *const u64) }
}

/// Scans the legacy BIOS window for the `RSD PTR ` signature.
///
/// # Safety
///
/// The policy maps `RSDP_GPA..RSDP_SCAN_END` read-only for the guest.
unsafe fn find_rsdp() -> Option<u64> {
    let mut address = RSDP_GPA;
    while address < RSDP_SCAN_END {
        // SAFETY: every candidate is 8-byte aligned and inside the window.
        let word = unsafe { core::ptr::read_volatile(address as *const u64) };
        if word == RSDP_SIGNATURE {
            return Some(address);
        }
        address += RSDP_ALIGN;
    }
    None
}

/// Checks the ACPI 1.0 byte checksum of the RSDP at `rsdp`.
///
/// # Safety
///
/// The 20 bytes at `rsdp` must be mapped and readable.
unsafe fn acpi_checksum_ok(rsdp: u64) -> bool {
    let mut sum = 0u8;
    let mut index = 0u64;
    while index < RSDP_CHECKSUM_LEN {
        // SAFETY: the checksum range is inside the mapped RSDP page.
        let byte = unsafe { core::ptr::read_volatile((rsdp + index) as *const u8) };
        sum = sum.wrapping_add(byte);
        index += 1;
    }
    sum == 0
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
