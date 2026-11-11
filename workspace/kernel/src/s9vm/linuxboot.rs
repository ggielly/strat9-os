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

//! s9vm — guest-physical layout of a 64-bit boot-protocol guest.
//!
//! Loading a 64-bit kernel is not only a parser problem: the boot loader must
//! place several objects at addresses the kernel will find, keep them from
//! overlapping, and hand over an identity mapping that covers exactly those
//! objects. This module owns that decision:
//!
//! | Object | Guest-physical address | Why |
//! |---|---|---|
//! | boot parameter page | `0x1_0000` | fixed by the boot protocol |
//! | command line | `0x2_0000` | low memory, after the parameter page |
//! | guest page tables | `0x3_0000` | low memory, writable by the loader |
//! | boot stack | top of the low range | the entry code needs a valid `%rsp` |
//! | kernel image | `pref_address` or `0x10_0000` | `init_size` window |
//! | initial ramdisk | 2 MiB aligned, above the image | must not overlap it |
//!
//! The low range is the conventional first 640 KiB (`0..=0x9_FFFF`). Everything
//! the loader writes below the first megabyte therefore lives in a range the
//! guest kernel is told is usable memory, and the identity mapping given to the
//! kernel covers it.
//!
//! # Sub-architecture
//!
//! The layout assumes the x86 PC sub-architecture (`hardware_subarch = 0`):
//! the kernel image is loaded high, the real-mode setup block of the image is
//! not executed (a 64-bit loader enters the image directly), and the boot
//! parameter page carries the memory map built by the firmware layer
//! ([`super::zeropage`]).
//!
//! # Limits
//!
//! The initial implementation keeps the kernel and the ramdisk below 4 GiB:
//! the size of the guest is measured in 4 KiB pages and the second-level
//! translation of this engine is compact below 4 GiB. Loading above 4 GiB is a
//! layout extension, not an architectural limit of the boot protocol.
//!
//! Testable on the host (L2 tests).

use alloc::vec::Vec;

use super::guestpt::{IdentityRange, PtPerms};

/// Guest-physical address of the boot parameter page (the "zero page").
pub const BOOT_PARAMS_GPA: u64 = 0x0001_0000;
/// Size of the boot parameter page.
pub const BOOT_PARAMS_SIZE: u64 = 0x1000;
/// End of the conventional low range (first 640 KiB usable).
pub const LOW_MEMORY_END: u64 = 0x0009_FC00;
/// End of the identity-mapped low range (page aligned, covers the EBDA hole).
pub const LOW_IDENTITY_END: u64 = 0x000A_0000;
/// Guest-physical address of the kernel command line.
pub const CMDLINE_GPA: u64 = 0x0002_0000;
/// Maximum length of the kernel command line the loader accepts.
pub const CMDLINE_MAX: usize = 2048;
/// Guest-physical address of the guest page tables.
pub const PAGE_TABLES_GPA: u64 = 0x0003_0000;
/// First address above the page tables the loader may use for the stack.
pub const STACK_GUARD_END: u64 = 0x0009_F000;
/// Top of the boot stack (`%rsp` at entry, stack grows down).
pub const STACK_TOP: u64 = 0x0009_F000;
/// Default load address of the protected-mode kernel (1 MiB).
pub const HIGH_LOAD_BASE: u64 = 0x0010_0000;
/// Alignment of the initial ramdisk placement.
pub const INITRD_ALIGN: u64 = 2 * 1024 * 1024;
/// Highest guest-physical address the layout may use (below 4 GiB).
pub const MAX_GPA: u64 = 0xFFFF_F000;

/// Inputs of the layout decision.
///
/// The fields are plain numbers so the planner stays independent from the
/// image parser; the caller copies them from the validated image plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutRequest {
    /// Usable guest memory, in bytes, starting at guest-physical 0.
    pub ram_bytes: u64,
    /// Preferred kernel load address (`pref_address`, 0 when absent).
    pub pref_address: u64,
    /// Kernel alignment requirement in bytes (power of two, 0 means 4 KiB).
    pub kernel_alignment: u64,
    /// `init_size`: contiguous memory the kernel needs from its load address.
    pub init_size: u64,
    /// True when the image may be placed at a loader-chosen address.
    pub relocatable: bool,
    /// Size of the initial ramdisk, 0 when none is loaded.
    pub initrd_bytes: u64,
    /// Length of the command line, including its terminating NUL.
    pub cmdline_len: u64,
}

/// Where every boot object goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootLayout {
    /// Guest-physical address of the protected-mode kernel image.
    pub kernel_base: u64,
    /// End of the `init_size` window the kernel needs.
    pub kernel_end: u64,
    /// Guest-physical address of the boot parameter page.
    pub boot_params_gpa: u64,
    /// Guest-physical address of the command line string.
    pub cmdline_gpa: u64,
    /// Length of the command line, including the terminating NUL.
    pub cmdline_len: u64,
    /// Guest-physical address of the guest page tables.
    pub page_tables_gpa: u64,
    /// Number of 4 KiB frames reserved for the page tables.
    pub page_table_pages: u64,
    /// Initial `%rsp` value at guest entry.
    pub stack_top: u64,
    /// Guest-physical address of the initial ramdisk, 0 when none.
    pub initrd_gpa: u64,
    /// End of the initial ramdisk, 0 when none.
    pub initrd_end: u64,
    /// End of usable guest memory.
    pub ram_top: u64,
    /// Identity mapping the guest is entered with.
    pub identity: Vec<IdentityRange>,
}

impl BootLayout {
    /// Guest-physical address of the 64-bit entry point.
    ///
    /// The boot protocol enters a 64-bit kernel at the load address plus
    /// `0x200`: the first 512 bytes are the legacy real-mode header.
    pub const fn entry_gpa(&self) -> u64 {
        self.kernel_base + 0x200
    }

    /// True when the layout places an initial ramdisk.
    pub const fn has_initrd(&self) -> bool {
        self.initrd_gpa != 0
    }

    /// Checks that the identity mapping covers `address` for `len` bytes.
    pub fn covers(&self, address: u64, len: u64) -> bool {
        let end = address.saturating_add(len);
        self.identity
            .iter()
            .any(|range| address >= range.start && end <= range.end())
    }
}

/// Layout errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
    /// Not enough guest memory for the kernel window and the low objects.
    RamTooSmall,
    /// The command line is longer than [`CMDLINE_MAX`] or does not fit in the
    /// low range.
    CmdlineTooLong,
    /// The kernel alignment is not a power of two or is smaller than a page.
    BadAlignment,
    /// A non-relocatable image does not fit at its preferred address.
    NotRelocatable,
    /// The ramdisk would not fit below 4 GiB.
    RamdiskTooBig,
    /// Two objects overlap; this is a planner bug, never a guest input.
    Overlap,
    /// The address arithmetic overflowed.
    Overflow,
}

/// Computes where every boot object goes.
///
/// The function is total: on success the layout is self-consistent (objects do
/// not overlap, the identity mapping covers them, the kernel window fits in
/// guest memory); on failure it returns a typed [`LayoutError`].
pub fn plan(request: &LayoutRequest) -> Result<BootLayout, LayoutError> {
    if request.ram_bytes < HIGH_LOAD_BASE + request.init_size {
        return Err(LayoutError::RamTooSmall);
    }
    let align = if request.kernel_alignment == 0 {
        0x1000
    } else {
        request.kernel_alignment
    };
    if align < 0x1000 || !align.is_power_of_two() {
        return Err(LayoutError::BadAlignment);
    }
    if request.cmdline_len > CMDLINE_MAX as u64
        || request.cmdline_len == 0
        || CMDLINE_GPA
            .checked_add(request.cmdline_len)
            .map_or(true, |end| end > PAGE_TABLES_GPA)
    {
        return Err(LayoutError::CmdlineTooLong);
    }

    let ram_top = request.ram_bytes;
    let kernel_base = kernel_base(request, align, ram_top)?;
    let kernel_end = kernel_base
        .checked_add(request.init_size)
        .ok_or(LayoutError::Overflow)?;
    if kernel_end > ram_top || kernel_end > MAX_GPA {
        return Err(LayoutError::RamTooSmall);
    }

    // The page tables live in low memory and must not reach the boot stack.
    let page_table_pages = page_table_budget(kernel_end.max(LOW_IDENTITY_END)).max(16);
    let page_tables_end = PAGE_TABLES_GPA + page_table_pages * 0x1000;
    if page_tables_end > STACK_GUARD_END {
        return Err(LayoutError::Overlap);
    }

    let (initrd_gpa, initrd_end) = if request.initrd_bytes == 0 {
        (0, 0)
    } else {
        let start = align_up(kernel_end, INITRD_ALIGN)?;
        let end = start
            .checked_add(request.initrd_bytes)
            .ok_or(LayoutError::Overflow)?;
        if end > ram_top || end > MAX_GPA {
            return Err(LayoutError::RamdiskTooBig);
        }
        (start, end)
    };

    // The identity mapping handed to the kernel: the low range that holds the
    // boot objects, and the kernel window the protocol requires.
    let kernel_window = align_up(request.init_size, 0x1000)?;
    let identity = alloc::vec![
        IdentityRange::new(0, LOW_IDENTITY_END, PtPerms::KERNEL_RWX),
        IdentityRange::new(kernel_base, kernel_window, PtPerms::KERNEL_RWX),
    ];

    let layout = BootLayout {
        kernel_base,
        kernel_end,
        boot_params_gpa: BOOT_PARAMS_GPA,
        cmdline_gpa: CMDLINE_GPA,
        cmdline_len: request.cmdline_len,
        page_tables_gpa: PAGE_TABLES_GPA,
        page_table_pages,
        stack_top: STACK_TOP,
        initrd_gpa,
        initrd_end,
        ram_top,
        identity,
    };
    debug_assert!(layout.covers(BOOT_PARAMS_GPA, BOOT_PARAMS_SIZE));
    debug_assert!(layout.covers(CMDLINE_GPA, request.cmdline_len));
    debug_assert!(layout.covers(PAGE_TABLES_GPA, page_table_pages * 0x1000));
    Ok(layout)
}

/// Chooses the kernel load address.
fn kernel_base(
    request: &LayoutRequest,
    align: u64,
    ram_top: u64,
) -> Result<u64, LayoutError> {
    let preferred = if request.pref_address == 0 {
        HIGH_LOAD_BASE
    } else {
        request.pref_address
    };
    if !request.relocatable {
        // The image runs at its preferred address, unconditionally.
        if preferred < HIGH_LOAD_BASE
            || preferred
                .checked_add(request.init_size)
                .map_or(true, |end| end > ram_top)
        {
            return Err(LayoutError::NotRelocatable);
        }
        return Ok(preferred);
    }
    let base = align_up(preferred.max(HIGH_LOAD_BASE), align)?;
    if base
        .checked_add(request.init_size)
        .map_or(true, |end| end > ram_top)
    {
        return Err(LayoutError::RamTooSmall);
    }
    Ok(base)
}

/// Number of 4 KiB frames to reserve for the guest page tables.
///
/// `mapped_top` is the highest address the identity mapping must cover. The
/// builder maps 2 MiB pages wherever it can and 4 KiB pages only for a prefix
/// and a tail, so the worst case is one page directory per 1 GiB of mapped
/// space, one 2 MiB-granular page table per range boundary, a PDPT per 512 GiB
/// and the PML4. The reservation is rounded up by the caller to leave headroom
/// for a future mapping of the ramdisk.
pub const fn page_table_budget(mapped_top: u64) -> u64 {
    let pds = (mapped_top >> 30) + 1;
    let pdpts = (mapped_top >> 39) + 1;
    1 + pdpts + pds + 4
}

/// Rounds `value` up to the next multiple of `align`.
pub const fn align_up(value: u64, align: u64) -> Result<u64, LayoutError> {
    if align == 0 || !align.is_power_of_two() {
        return Err(LayoutError::BadAlignment);
    }
    match value.checked_add(align - 1) {
        Some(sum) => Ok(sum & !(align - 1)),
        None => Err(LayoutError::Overflow),
    }
}
