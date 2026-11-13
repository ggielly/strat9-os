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

//! s9vm-vmm: first userspace policy for the s9vm virtualization subsystem.
//!
//! The component is auto-started as the primary strate of its SYS silo (that
//! silo holds the SILO_ADMIN capability required by `SYS_VMM_CREATE`). It
//! drives a complete world lifecycle through the syscall surface, without any
//! kernel-side helper:
//!
//! 1. `SYS_VMM_CREATE` — a world named `demo` owned by silo id 0;
//! 2. `SYS_VMM_LIST` — enumerate worlds and find `demo`;
//! 3. `SYS_VMM_MAP_MEM` — two scratch guest pages (RAM, R/W) at GPA
//!    `0x0000_6000`;
//! 4. `SYS_VMM_CREATE_VCPU` — one vCPU (APIC id 0);
//! 5. `SYS_VMM_LOAD_IMAGE` — a self-contained ELF64 image built in this
//!    component (see [`build_guest_image`]) at GPA 0: identity page tables in
//!    guest memory (PML4/PDPT/PD, 2 MiB page), one RX/RW segment holding the
//!    guest code, one BSS stack page. Nothing is executed by the loader;
//! 6. `SYS_VMM_SET_REGS` / `SYS_VMM_VCPU_REGS` — 64-bit flat long mode
//!    (`CR0`, `CR3 = 0`, `CR4`, `EFER`), `RIP = 0x3000`, `RSP = 0x4800`;
//! 7. `SYS_VMM_BOOT_INFO` — the guest boot-information page (best effort);
//! 8. `SYS_VMM_INFO` / `SYS_VMM_STATS` / `SYS_VMM_VCPU_LIST` — introspection;
//! 9. `SYS_VMM_PAUSE` / `SYS_VMM_RUN` (expects `EAGAIN` while paused) /
//!    `SYS_VMM_RESUME`;
//! 10. `SYS_VMM_RUN` + `SYS_VMM_EXIT_HANDLER` / `SYS_VMM_EXIT_COMPLETE` — the
//!     policy loop answers the guest `out 0xE9` I/O exit (the kernel device
//!     model does not model port 0xE9, so it reaches the policy) and the final
//!     `hlt` exit;
//! 11. `SYS_VMM_DESTROY_VCPU` / `SYS_VMM_DESTROY` — clean teardown.
//!
//! The guest payload is:
//!
//! ```text
//! mov al, 'K'
//! out 0xE9, al      ; -> IO_PORT policy exit (port 0xE9, byte 'K')
//! hlt               ; -> HALT policy exit
//! jmp $             ; never reached
//! ```
//!
//! # Real guest kernel mode (`/initfs/s9vm-guest`)
//!
//! When the image builder stages `/initfs/s9vm-guest`, the component boots it
//! instead of the demo. The guest kernel is an `ET_EXEC` image linked at guest
//! physical `0x0010_0000`; it expects to be entered in 64-bit long mode with
//! `RDI` = guest-physical address of the boot-parameter block, identity-mapped
//! memory for the first 4 MiB, `CR3 = 0`, and the debug-port protocol `G`,
//! `M`, `A` followed by `hlt`.
//!
//! Boot sequence (all through the syscall surface):
//!
//! 1. read `/initfs/s9vm-guest` (≤ 1 MiB) into a static buffer; if the file is
//!    missing the built-in demo above runs instead (logged explicitly);
//! 2. `SYS_VMM_CREATE "guest"` then `SYS_VMM_CREATE_VCPU` (APIC id 0);
//! 3. `SYS_VMM_SET_CMDLINE` with the command line
//!    `console=ttyS0 root=/dev/vda rw init=/init s9vm.guest=1 s9vm.initrd=1
//!    initrd=s9vm-initrd`;
//! 4. `SYS_VMM_LOAD_IMAGE` at `0x0010_0000` (the linked base, so no
//!    relocation: `VmmImageInfo.entry` is used as `RIP`);
//! 5. identity page tables loaded as a **raw blob** with
//!    `SYS_VMM_LOAD_MODULE` at GPA 0 — this is the documented use of
//!    `LOAD_MODULE` (verbatim bytes, not parsed as ELF):
//!
//!    ```text
//!    0x0000  PML4[0] = 0x1000 | P|RW          -> PDPT
//!    0x1000  PDPT[0] = 0x2000 | P|RW          -> PD
//!    0x2000  PD[0]   = 0x0000_0000 | P|RW|PS  -> identity 0..2 MiB
//!    0x2008  PD[1]   = 0x0020_0000 | P|RW|PS  -> identity 2..4 MiB
//!    ```
//!
//!    (`CR3 = 0` makes the guest read the PML4 from GPA 0.)
//! 6. initrd archive loaded as a **second raw module** at GPA `0x0020_0000`:
//!    `/initfs/s9vm-initrd` when the image builder staged one, otherwise a
//!    built-in `newc` cpio archive (one placeholder `init` file). Both modules
//!    are published to the guest by the boot-parameter block;
//! 7. `SYS_VMM_MAP_MEM` one page at GPA `0x8000` for the boot parameters and
//!    `SYS_VMM_ACPI` at `0x000E_0000` (needs the vCPU and mapped memory);
//! 8. `SYS_VMM_LOAD_DISK` provisions the world virtio-blk device with
//!    `/initfs/s9vm-disk` when staged, otherwise a 4 KiB built-in image whose
//!    first sector carries the `S9VMDISK` label contract (magic at offset 0,
//!    version, sector size, sector count, image length, `0x55AA` signature);
//! 9. `SYS_VMM_BOOT_PARAMS` at `0x8000` (published after
//!    ACPI/cmdline/modules/disk, so the RSDP, command line, module ranges and
//!    block-device content are final);
//! 10. `SYS_VMM_SET_REGS`: `RIP = entry`, `RSP = 0` (the guest sets its stack),
//!     `RDI = 0x8000`, `RFLAGS = 2`, `CR0 = 0x8001_0023`, `CR3 = 0`,
//!     `CR4 = 0x26A0`, `EFER = 0xD01`;
//! 11. `SYS_VMM_RUN` + `SYS_VMM_EXIT_HANDLER`/`SYS_VMM_EXIT_COMPLETE` loop,
//!     bounded to 64 exits plus a 30 s watchdog. PASS requires the ordered
//!     `G`, `M`, `A` bytes on debug port `0xE9` and a `HALT` exit (extra bytes
//!     emitted by newer guest kernels are ignored). Completion policy: I/O and
//!     HLT exits are completed with value 0 and RIP advance 0 (hardware already
//!     advanced RIP); any other exit class is logged and completed as a no-op,
//!     so an unexpected exit only consumes the bounded budget instead of
//!     wedging the policy;
//! 12. teardown on every path: `SYS_VMM_DESTROY_VCPU` then `SYS_VMM_DESTROY`.
//!
//! Expected serial output on a VT-x host (Linux/KVM or nested VT-x):
//!
//! ```text
//! [s9vm-vmm] found /initfs/s9vm-guest (N bytes): real guest mode
//! [s9vm-vmm] ===== s9vm userspace policy (real guest, N bytes) =====
//! [s9vm-vmm] guest 1/10: SYS_VMM_SET_CMDLINE (87 bytes)
//! [s9vm-vmm] guest 2/10: SYS_VMM_LOAD_IMAGE (N bytes at gpa=0x100000)
//! [s9vm-vmm] guest 3/10: SYS_VMM_LOAD_MODULE page tables (12288 bytes at gpa=0x0)
//! [s9vm-vmm] page tables: PML4@0x0 -> PDPT@0x1000 -> PD@0x2000, identity leaves 0..0x400000 (2 MiB pages)
//! [s9vm-vmm] guest 4/10: SYS_VMM_LOAD_MODULE initrd (M bytes, built-in)
//! [s9vm-vmm] initrd: M bytes at gpa=0x200000
//! [s9vm-vmm] guest 5/10: SYS_VMM_MAP_MEM boot params gpa=0x8000 len=0x1000
//! [s9vm-vmm] guest 6/10: SYS_VMM_ACPI gpa=0xe0000
//! [s9vm-vmm] guest 7/10: SYS_VMM_LOAD_DISK (4096 bytes, built-in)
//! [s9vm-vmm] disk: 4096 bytes (8 sectors), world device content provisioned
//! [s9vm-vmm] guest 8/10: SYS_VMM_BOOT_PARAMS gpa=0x8000
//! [s9vm-vmm] guest 9/10: SYS_VMM_SET_REGS rip=0x100000 rsp=0 rdi=0x8000
//! [s9vm-vmm] guest 10/10: SYS_VMM_RUN + policy loop
//! [s9vm-vmm] guest debug byte 0x47   (G)
//! [s9vm-vmm] guest debug byte 0x4d   (M)
//! [s9vm-vmm] guest debug byte 0x41   (A)
//! [s9vm-vmm] guest halted (HLT policy exit)
//! [s9vm-vmm] guest summary: exits=4 markers=3/3 halt=true last_exit=4 (halt)
//! [s9vm-vmm] teardown: DESTROY_VCPU=ok DESTROY=ok
//! [s9vm-vmm] RESULT: PASS (real guest: G/M/A + HLT)
//! ```
//!
//! Without VT-x (TCG) `SYS_VMM_CREATE` returns `ENOTSUP` and the component
//! reports `RESULT: SKIP`; without the SILO_ADMIN capability it reports
//! `RESULT: BLOCKED`.
//!
//! # Expected serial output
//!
//! ```text
//! [s9vm-vmm] ===== s9vm userspace policy (demo) =====
//! [s9vm-vmm] step 1/11: SYS_VMM_CREATE 'demo'
//! [s9vm-vmm] world handle=1
//! ...
//! [s9vm-vmm] policy exit kind=3 (io_port) port=0xe9 size=1 value=0x4b
//! [s9vm-vmm] policy: completing the 0xE9 I/O exit
//! [s9vm-vmm] policy exit kind=4 (halt)
//! [s9vm-vmm] policy: guest halted, completing the exit
//! ...
//! [s9vm-vmm] RESULT: PASS (full userspace policy cycle)
//! ```
//!
//! When the engine is inactive (QEMU TCG, no VT-x) the same boot logs
//! `RESULT: SKIP` after the enumeration fallback. When the boot silo does not
//! hold the SILO_ADMIN capability, `SYS_VMM_CREATE` fails with `EPERM` and the
//! component logs `RESULT: BLOCKED` (see the exit-code table below).
//!
//! # Exit codes
//!
//! | Code | Meaning                                                        |
//! |------|----------------------------------------------------------------|
//! | 0    | PASS: the full world/vCPU policy cycle completed               |
//! | 1    | FAIL: a required syscall failed (list/stats/run/teardown)      |
//! | 2    | SKIP: VT-x is not detected (TCG/no nested virt), no world kept |
//! | 3    | BLOCKED: SYS_VMM_CREATE denied (no SILO_ADMIN capability)      |
//!
//! A failed step is logged with its `errno` name; the component never panics.

#![no_std]
#![no_main]

use core::{
    fmt::{self, Write as _},
    panic::PanicInfo,
};
use strat9_abi::vmm::{
    exit_kind, VmmExitEvent, VmmImageInfo, VmmInfo, VmmRegs, VmmVcpuInfo, VmmWorldEntry,
    VmmWorldStats, VMM_ABI_VERSION, VMM_DISK_SECTOR_SIZE,
};
use strat9_syscall::{call, data::TimeSpec, error::Error, flag, number, CLOCK_MONOTONIC};
use strat9_elf_core::build::ImageWriter;
use strat9_elf_core::{ET_EXEC, PF_R, PF_W, PF_X};

/// Clean PASS: the full policy cycle ran.
const EXIT_PASS: usize = 0;
/// A required syscall failed.
const EXIT_FAIL: usize = 1;
/// The platform has no VT-x (TCG): the engine cannot create a world.
const EXIT_SKIP: usize = 2;
/// SYS_VMM_CREATE was denied: the silo does not hold the SILO_ADMIN capability.
const EXIT_BLOCKED: usize = 3;

/// World name required by the demo.
const WORLD_NAME: &[u8] = b"demo";

// ---------------------------------------------------------------------------
// Real guest kernel mode (`/initfs/s9vm-guest`)
// ---------------------------------------------------------------------------

/// Guest kernel image written to the initfs by the image builder.
const PATH_GUEST_IMAGE: &str = "/initfs/s9vm-guest";
/// Optional initrd archive staged by the image builder (`newc` cpio format).
const PATH_INITRD: &str = "/initfs/s9vm-initrd";
/// Optional boot disk image staged by the image builder (`S9VMDISK` label).
const PATH_DISK_IMAGE: &str = "/initfs/s9vm-disk";
/// Hard cap on the guest image size (1 MiB).
const GUEST_IMAGE_MAX: usize = 1024 * 1024;
/// Hard cap on the initrd archive size (64 KiB).
const INITRD_MAX_BYTES: usize = 64 * 1024;
/// Guest-physical address the initrd module is loaded at (inside the identity
/// window, above the kernel image: `0x100000..0x103000`).
const INITRD_GPA: u64 = 0x0020_0000;
/// Size of the generated boot disk image: one sector for the label plus seven
/// zero sectors, a valid sector-multiple content for the virtio-blk device.
const DISK_IMAGE_LEN: usize = 4096;
/// World name used by the real-guest mode.
const GUEST_WORLD_NAME: &[u8] = b"guest";
/// The guest kernel is an ET_EXEC image linked at 0x0010_0000; loading it at
/// that guest-physical base keeps every linked address unchanged.
const GUEST_IMAGE_GPA: u64 = 0x10_0000;
/// Command line published to the guest (at most 256 bytes).
const GUEST_CMDLINE: &[u8] =
    b"console=ttyS0 root=/dev/vda rw init=/init s9vm.guest=1 s9vm.initrd=1 initrd=s9vm-initrd";
/// Raw identity page-table blob: PML4@0x0000, PDPT@0x1000, PD@0x2000.
const PAGE_TABLE_BLOB_GPA: u64 = 0x0;
const PAGE_TABLE_BLOB_LEN: usize = 0x3000;
/// Identity-mapped window covered by the blob (0..4 MiB, 2 MiB leaves).
const IDENTITY_WINDOW: u64 = 0x40_0000;
/// Guest boot-parameter block (one page) and the ACPI window.
const BOOT_PARAMS_GPA: u64 = 0x8000;
const BOOT_PARAMS_LEN: u64 = 0x1000;
const ACPI_WINDOW_GPA: u64 = 0x000E_0000;
/// Policy loop bounds for the real guest.
const MAX_GUEST_EXITS: u32 = 64;
const MAX_EMPTY_POLLS: u32 = 32;
const GUEST_WATCHDOG_MS: u64 = 30_000;
/// Debug-port protocol bytes the guest kernel must emit before halting.
const GUEST_MARKERS: [u8; 3] = [b'G', b'M', b'A'];
/// Bound on `EAGAIN` retries while reading a scheme file.
const MAX_READ_RETRIES: u32 = 4096;
/// Scratch guest RAM mapped through `SYS_VMM_MAP_MEM` (2 pages).
const SCRATCH_GPA: u64 = 0x6000;
const SCRATCH_LEN: u64 = 0x2000;
/// Guest image load base (guest-physical).
const IMAGE_GPA: u64 = 0x0;
/// Guest entry point inside the image.
const GUEST_ENTRY: u64 = 0x3000;
/// Guest stack top (inside the BSS stack page of the image).
const GUEST_STACK_TOP: u64 = 0x4800;
/// Size of the generated guest image (ELF header, tables, code page).
const IMAGE_LEN: usize = 0x5000;
/// Page-table page addresses inside the image (identity mapped 0..2 MiB).
const GPA_PML4: u64 = 0x0;
const GPA_PDPT: u64 = 0x1000;
const GPA_PD: u64 = 0x2000;
/// Maximum number of policy exits handled before giving up.
const MAX_POLICY_EXITS: usize = 8;
/// I/O port used by the guest to reach the policy.
const POLICY_PORT: u32 = 0xE9;

// Canonical 64-bit flat long-mode values, same shape as the kernel selftest
// (`GuestState::long_mode_64`): PE|MP|NE|PG|WP, PAE|PGE|OSFXSR|OSXMMEXCPT|VMXE,
// SCE|LME|LMA|NXE.
const CR0_LONG_MODE: u64 = 0x8001_0023;
const CR4_LONG_MODE: u64 = 0x26A0;
const EFER_LONG_MODE: u64 = 0xD01;
const RFLAGS_RESERVED: u64 = 0x2;
/// `SYS_VMM_MAP_MEM` permission bits: read + write.
const PERM_READ_WRITE: u64 = 0b011;
/// Memory type write-back.
const MEMTYPE_WRITEBACK: u64 = 0;

// ---------------------------------------------------------------------------
// Logging (no allocation)
// ---------------------------------------------------------------------------

/// Fixed-size line buffer flushed to the kernel log.
struct LogBuf {
    buf: [u8; 224],
    len: usize,
}

impl LogBuf {
    /// Creates an empty buffer.
    const fn new() -> Self {
        Self {
            buf: [0u8; 224],
            len: 0,
        }
    }
}

impl fmt::Write for LogBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        if self.len + bytes.len() > self.buf.len() {
            return Err(fmt::Error);
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}

/// Formats one line and sends it to the kernel log (`SYS_DEBUG_LOG`).
fn log_fmt(args: fmt::Arguments<'_>) {
    let mut line = LogBuf::new();
    let _ = line.write_fmt(args);
    let _ = call::debug_log(&line.buf[..line.len]);
}

/// Logs one line, prefixed with the component name.
macro_rules! log {
    ($($arg:tt)*) => {
        log_fmt(format_args!($($arg)*))
    };
}

// ---------------------------------------------------------------------------
// SYS_VMM_* syscall wrappers
// ---------------------------------------------------------------------------

/// `SYS_VMM_CREATE`: create a world, returns a VMM capability handle.
fn vmm_create(name: &[u8], silo_id: u64) -> Result<u64, Error> {
    // SAFETY: the buffer and its length are a valid userspace read range; the
    // kernel copies the name before returning.
    unsafe {
        strat9_syscall::syscall3(
            number::SYS_VMM_CREATE,
            name.as_ptr() as usize,
            name.len(),
            silo_id as usize,
        )
    }
    .map(|value| value as u64)
}

/// `SYS_VMM_DESTROY`: destroy a world and its vCPUs.
fn vmm_destroy(world: u64) -> Result<(), Error> {
    // SAFETY: plain integer argument.
    unsafe { strat9_syscall::syscall1(number::SYS_VMM_DESTROY, world as usize) }.map(|_| ())
}

/// `SYS_VMM_MAP_MEM`: map guest RAM into a world.
fn vmm_map_mem(world: u64, gpa: u64, len: u64, perms: u64, memtype: u64) -> Result<(), Error> {
    // SAFETY: plain integer arguments.
    unsafe {
        strat9_syscall::syscall5(
            number::SYS_VMM_MAP_MEM,
            world as usize,
            gpa as usize,
            len as usize,
            perms as usize,
            memtype as usize,
        )
    }
    .map(|_| ())
}

/// `SYS_VMM_CREATE_VCPU`: create one vCPU, returns a vCPU capability handle.
fn vmm_create_vcpu(world: u64, apic_id: u64) -> Result<u64, Error> {
    // SAFETY: plain integer arguments.
    unsafe {
        strat9_syscall::syscall2(
            number::SYS_VMM_CREATE_VCPU,
            world as usize,
            apic_id as usize,
        )
    }
    .map(|value| value as u64)
}

/// `SYS_VMM_DESTROY_VCPU`: destroy one vCPU.
fn vmm_destroy_vcpu(vcpu: u64) -> Result<(), Error> {
    // SAFETY: plain integer argument.
    unsafe { strat9_syscall::syscall1(number::SYS_VMM_DESTROY_VCPU, vcpu as usize) }.map(|_| ())
}

/// `SYS_VMM_LOAD_IMAGE`: load an ELF64 image at a guest-physical base.
fn vmm_load_image(
    world: u64,
    gpa: u64,
    image: &[u8],
    info: &mut VmmImageInfo,
) -> Result<(), Error> {
    // SAFETY: both pointers reference live userspace buffers for the duration
    // of the call; the kernel copies the image and writes the result struct.
    unsafe {
        strat9_syscall::syscall5(
            number::SYS_VMM_LOAD_IMAGE,
            world as usize,
            gpa as usize,
            image.as_ptr() as usize,
            image.len(),
            info as *mut VmmImageInfo as usize,
        )
    }
    .map(|_| ())
}

/// `SYS_VMM_LOAD_MODULE`: copy a raw blob into guest memory at `gpa`.
///
/// This is the intended way to seed data the loader must not parse as ELF: the
/// identity page-table blob is written this way (the kernel maps the range
/// read/write and records it as a module, published by `SYS_VMM_BOOT_PARAMS`).
fn vmm_load_module(world: u64, gpa: u64, bytes: &[u8]) -> Result<(), Error> {
    // SAFETY: `bytes` is a live userspace buffer; the kernel copies it before
    // returning.
    unsafe {
        strat9_syscall::syscall4(
            number::SYS_VMM_LOAD_MODULE,
            world as usize,
            gpa as usize,
            bytes.as_ptr() as usize,
            bytes.len(),
        )
    }
    .map(|_| ())
}

/// `SYS_VMM_LOAD_DISK`: replace the world block-device image.
fn vmm_load_disk(world: u64, image: &[u8]) -> Result<(), Error> {
    // SAFETY: `image` is a live userspace buffer; the kernel copies it before
    // returning.
    unsafe {
        strat9_syscall::syscall3(
            number::SYS_VMM_LOAD_DISK,
            world as usize,
            image.as_ptr() as usize,
            image.len(),
        )
    }
    .map(|_| ())
}

/// `SYS_VMM_SET_CMDLINE`: store the guest kernel command line.
fn vmm_set_cmdline(world: u64, bytes: &[u8]) -> Result<u64, Error> {
    // SAFETY: `bytes` is a live userspace buffer read by the kernel.
    unsafe {
        strat9_syscall::syscall3(
            number::SYS_VMM_SET_CMDLINE,
            world as usize,
            bytes.as_ptr() as usize,
            bytes.len(),
        )
    }
    .map(|stored| stored as u64)
}

/// `SYS_VMM_ACPI`: write the guest firmware description tables.
fn vmm_acpi(world: u64, gpa: u64) -> Result<(), Error> {
    // SAFETY: plain integer arguments.
    unsafe { strat9_syscall::syscall2(number::SYS_VMM_ACPI, world as usize, gpa as usize) }
        .map(|_| ())
}

/// `SYS_VMM_BOOT_PARAMS`: write the guest boot-parameter block.
fn vmm_boot_params(world: u64, gpa: u64) -> Result<(), Error> {
    // SAFETY: plain integer arguments.
    unsafe { strat9_syscall::syscall2(number::SYS_VMM_BOOT_PARAMS, world as usize, gpa as usize) }
        .map(|_| ())
}

/// `SYS_VMM_SET_REGS`: write the vCPU register block.
fn vmm_set_regs(vcpu: u64, regs: &VmmRegs) -> Result<(), Error> {
    // SAFETY: `regs` is a live userspace buffer read by the kernel.
    unsafe {
        strat9_syscall::syscall2(
            number::SYS_VMM_SET_REGS,
            vcpu as usize,
            regs as *const VmmRegs as usize,
        )
    }
    .map(|_| ())
}

/// `SYS_VMM_VCPU_REGS`: read the current register block of a vCPU.
fn vmm_vcpu_regs(vcpu: u64, regs: &mut VmmRegs) -> Result<(), Error> {
    // SAFETY: `regs` is a live userspace buffer written by the kernel.
    unsafe {
        strat9_syscall::syscall2(
            number::SYS_VMM_VCPU_REGS,
            vcpu as usize,
            regs as *mut VmmRegs as usize,
        )
    }
    .map(|_| ())
}

/// `SYS_VMM_BOOT_INFO`: write the guest boot-information page.
fn vmm_boot_info(world: u64, gpa: u64) -> Result<(), Error> {
    // SAFETY: plain integer arguments.
    unsafe { strat9_syscall::syscall2(number::SYS_VMM_BOOT_INFO, world as usize, gpa as usize) }
        .map(|_| ())
}

/// `SYS_VMM_INFO`: read a world snapshot.
fn vmm_info(world: u64, info: &mut VmmInfo) -> Result<(), Error> {
    // SAFETY: `info` is a live userspace buffer written by the kernel.
    unsafe {
        strat9_syscall::syscall2(
            number::SYS_VMM_INFO,
            world as usize,
            info as *mut VmmInfo as usize,
        )
    }
    .map(|_| ())
}

/// `SYS_VMM_STATS`: read the cumulative counters of a world.
fn vmm_stats(world: u64, stats: &mut VmmWorldStats) -> Result<(), Error> {
    // SAFETY: `stats` is a live userspace buffer written by the kernel.
    unsafe {
        strat9_syscall::syscall2(
            number::SYS_VMM_STATS,
            world as usize,
            stats as *mut VmmWorldStats as usize,
        )
    }
    .map(|_| ())
}

/// `SYS_VMM_LIST`: enumerate worlds, returns the total count.
fn vmm_list(world: u64, entries: &mut [VmmWorldEntry]) -> Result<u64, Error> {
    // SAFETY: `entries` is a live userspace buffer, capacity matches its length.
    unsafe {
        strat9_syscall::syscall3(
            number::SYS_VMM_LIST,
            world as usize,
            entries.as_mut_ptr() as usize,
            entries.len(),
        )
    }
    .map(|value| value as u64)
}

/// `SYS_VMM_VCPU_LIST`: enumerate vCPUs, returns the total count.
fn vmm_vcpu_list(world: u64, entries: &mut [VmmVcpuInfo]) -> Result<u64, Error> {
    // SAFETY: `entries` is a live userspace buffer, capacity matches its length.
    unsafe {
        strat9_syscall::syscall3(
            number::SYS_VMM_VCPU_LIST,
            world as usize,
            entries.as_mut_ptr() as usize,
            entries.len(),
        )
    }
    .map(|value| value as u64)
}

/// `SYS_VMM_PAUSE`: pause a world (`RUN` then reports `EAGAIN`).
fn vmm_pause(world: u64) -> Result<(), Error> {
    // SAFETY: plain integer argument.
    unsafe { strat9_syscall::syscall1(number::SYS_VMM_PAUSE, world as usize) }.map(|_| ())
}

/// `SYS_VMM_RESUME`: resume a paused world.
fn vmm_resume(world: u64) -> Result<(), Error> {
    // SAFETY: plain integer argument.
    unsafe { strat9_syscall::syscall1(number::SYS_VMM_RESUME, world as usize) }.map(|_| ())
}

/// `SYS_VMM_RUN`: block until the vCPU queues one policy exit.
fn vmm_run(vcpu: u64) -> Result<(), Error> {
    // SAFETY: plain integer argument.
    unsafe { strat9_syscall::syscall1(number::SYS_VMM_RUN, vcpu as usize) }.map(|_| ())
}

/// `SYS_VMM_EXIT_HANDLER`: pop one exit event (returns 1 when written, 0 when
/// the queue is empty).
fn vmm_exit_handler(world: u64, event: &mut VmmExitEvent) -> Result<u64, Error> {
    // SAFETY: `event` is a live userspace buffer written by the kernel.
    unsafe {
        strat9_syscall::syscall2(
            number::SYS_VMM_EXIT_HANDLER,
            world as usize,
            event as *mut VmmExitEvent as usize,
        )
    }
    .map(|value| value as u64)
}

/// `SYS_VMM_EXIT_COMPLETE`: complete a policy exit (RAX value, RIP advance).
fn vmm_exit_complete(vcpu: u64, value: u64, advance: u64) -> Result<(), Error> {
    // SAFETY: plain integer arguments.
    unsafe {
        strat9_syscall::syscall3(
            number::SYS_VMM_EXIT_COMPLETE,
            vcpu as usize,
            value as usize,
            advance as usize,
        )
    }
    .map(|_| ())
}

// ---------------------------------------------------------------------------
// Guest image (ELF64 with identity page tables)
// ---------------------------------------------------------------------------

/// Storage for the generated demo guest image (kept out of the task stack).
static mut GUEST_IMAGE: [u8; IMAGE_LEN] = [0u8; IMAGE_LEN];
/// Storage for the edited guest kernel image read from `/initfs/s9vm-guest`.
static mut GUEST_ELF: [u8; GUEST_IMAGE_MAX] = [0u8; GUEST_IMAGE_MAX];
/// Raw identity page-table blob loaded at GPA 0 through `SYS_VMM_LOAD_MODULE`.
static mut PAGE_TABLE_BLOB: [u8; PAGE_TABLE_BLOB_LEN] = [0u8; PAGE_TABLE_BLOB_LEN];
/// Storage for the initrd archive loaded through `SYS_VMM_LOAD_MODULE`.
static mut INITRD: [u8; INITRD_MAX_BYTES] = [0u8; INITRD_MAX_BYTES];
/// Storage for the boot disk image loaded through `SYS_VMM_LOAD_DISK`.
static mut DISK_IMAGE: [u8; DISK_IMAGE_LEN] = [0u8; DISK_IMAGE_LEN];

/// Returns the writable guest-image buffer.
fn guest_image_buffer() -> &'static mut [u8] {
    // SAFETY: the component is single-threaded and the buffer is used before
    // any concurrent access; `addr_of_mut!` avoids creating a `static mut`
    // reference.
    unsafe {
        core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(GUEST_IMAGE) as *mut u8, IMAGE_LEN)
    }
}

/// Returns the writable buffer that receives `/initfs/s9vm-guest`.
fn guest_elf_buffer() -> &'static mut [u8] {
    // SAFETY: same single-threaded contract as `guest_image_buffer`.
    unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(GUEST_ELF) as *mut u8,
            GUEST_IMAGE_MAX,
        )
    }
}

/// Returns the writable identity page-table blob.
fn page_table_blob_buffer() -> &'static mut [u8] {
    // SAFETY: same single-threaded contract as `guest_image_buffer`.
    unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(PAGE_TABLE_BLOB) as *mut u8,
            PAGE_TABLE_BLOB_LEN,
        )
    }
}

/// Returns the writable initrd buffer.
fn initrd_buffer() -> &'static mut [u8] {
    // SAFETY: same single-threaded contract as `guest_image_buffer`.
    unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(INITRD) as *mut u8,
            INITRD_MAX_BYTES,
        )
    }
}

/// Returns the writable boot disk image buffer.
fn disk_image_buffer() -> &'static mut [u8] {
    // SAFETY: same single-threaded contract as `guest_image_buffer`.
    unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(DISK_IMAGE) as *mut u8,
            DISK_IMAGE_LEN,
        )
    }
}

/// Builds the raw identity page-table blob for the guest kernel.
///
/// Layout (guest-physical, loaded verbatim at [`PAGE_TABLE_BLOB_GPA`] by
/// `SYS_VMM_LOAD_MODULE`):
///
/// ```text
/// 0x0000  PML4[0] = 0x1000 | P|RW          -> PDPT
/// 0x1000  PDPT[0] = 0x2000 | P|RW          -> PD
/// 0x2000  PD[0]   = 0x0000_0000 | P|RW|PS  -> identity 0..2 MiB
/// 0x2008  PD[1]   = 0x0020_0000 | P|RW|PS  -> identity 2..4 MiB
/// ```
///
/// The guest kernel is entered with `CR3 = 0`, so its first PML4 entry is read
/// from GPA 0. The guest image itself lives at GPA 0x0010_0000 (inside the
/// second 2 MiB leaf), while the blob, boot parameters (0x8000) and ACPI
/// (0xE0000) all fall inside the first leaf.
fn build_page_table_blob() -> &'static [u8] {
    let blob = page_table_blob_buffer();
    for byte in blob.iter_mut() {
        *byte = 0;
    }
    put_u64(blob, 0x0000, GPA_PDPT | 0b11);
    put_u64(blob, 0x1000, GPA_PD | 0b11);
    put_u64(blob, 0x2000, 0x0 | 0b1000_0011);
    put_u64(blob, 0x2008, 0x20_0000 | 0b1000_0011);
    &page_table_blob_buffer()[..PAGE_TABLE_BLOB_LEN]
}

/// Writes a little-endian `u64` at `offset`.
fn put_u64(buffer: &mut [u8], offset: usize, value: u64) {
    buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// Builds the complete guest ELF image in the static buffer.
///
/// Layout (guest-physical addresses, loaded at [`IMAGE_GPA`]):
///
/// ```text
/// 0x0000  PML4   entry[0] = 0x1000 | P|RW
/// 0x1000  PDPT   entry[0] = 0x2000 | P|RW
/// 0x2000  PD     entry[0] = 0x0000 | P|RW|PS   (identity 0..2 MiB)
/// 0x3000  code   mov al,'K'; out 0xE9,al; hlt; jmp $
/// 0x4000  stack  BSS page (zeroed by the loader)
/// ```
///
/// File offsets mirror the virtual addresses with a one-page shift for the
/// page-table segment (ELF requires `p_vaddr % page == p_offset % page`).
fn build_guest_image() -> &'static [u8] {
    let image = guest_image_buffer();
    for byte in image.iter_mut() {
        *byte = 0;
    }

    // ELF64 file header and program header table (shared writer).
    {
        let mut builder = ImageWriter::new(&mut image[..], ET_EXEC, GUEST_ENTRY)
            .expect("demo guest image: header fits");
        // Segment 1: page tables (file 0x1000 -> GPA 0x0000, 3 pages, RW).
        builder
            .add_load(PF_R | PF_W, 0x1000, 0x0000, 0x3000, 0x3000, 0x1000)
            .expect("demo guest image: page-table segment fits");
        // Segment 2: code page + BSS stack page (file 0x4000 -> GPA 0x3000,
        // 1 page file-backed, 2 pages of memory, RWX).
        builder
            .add_load(
                PF_R | PF_W | PF_X,
                0x4000,
                0x3000,
                0x1000,
                0x2000,
                0x1000,
            )
            .expect("demo guest image: code segment fits");
        let _ = builder.finish();
    }

    // Identity page tables: PML4[0] -> PDPT, PDPT[0] -> PD, PD[0] -> 2 MiB page.
    let table = 0x1000usize;
    put_u64(image, table + 0x000, GPA_PDPT | 0b11);
    put_u64(image, table + 0x1000, GPA_PD | 0b11);
    put_u64(image, table + 0x2000, 0x0000 | 0b1000_0011);

    // Guest code at GPA 0x3000 (file offset 0x4000).
    let code = 0x4000usize;
    image[code] = 0xB0; // mov al, imm8
    image[code + 1] = b'K';
    image[code + 2] = 0xE6; // out imm8, al
    image[code + 3] = 0xE9;
    image[code + 4] = 0xF4; // hlt
    image[code + 5] = 0xEB; // jmp $
    image[code + 6] = 0xFE;

    &guest_image_buffer()[..IMAGE_LEN]
}

/// Builds the canonical initial register block of the guest.
fn guest_registers() -> VmmRegs {
    VmmRegs {
        abi_version: VMM_ABI_VERSION,
        flags: 0,
        rax: 0,
        rbx: 0,
        rcx: 0,
        rdx: 0,
        rsi: 0,
        rdi: 0,
        rbp: 0,
        rsp: GUEST_STACK_TOP,
        r8: 0,
        r9: 0,
        r10: 0,
        r11: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rip: GUEST_ENTRY,
        rflags: RFLAGS_RESERVED,
        cr0: CR0_LONG_MODE,
        cr3: GPA_PML4,
        cr4: CR4_LONG_MODE,
        efer: EFER_LONG_MODE,
    }
}

// ---------------------------------------------------------------------------
// Boot assets: initrd archive and boot disk image
// ---------------------------------------------------------------------------

/// Length of a `newc` cpio header: six magic bytes and thirteen 8-digit
/// hexadecimal fields.
const CPIO_HEADER_LEN: usize = 110;

/// Writes `value` as eight uppercase hexadecimal ASCII digits.
fn write_hex8(out: &mut [u8], value: u32) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for (index, byte) in out.iter_mut().enumerate().take(8) {
        *byte = HEX[((value >> (4 * (7 - index))) & 0xF) as usize];
    }
}

/// Appends `bytes` at `offset`, NUL-terminated when `with_nul`, padded to a
/// four-byte boundary. Returns the number of bytes written.
fn append_padded(
    out: &mut [u8],
    offset: usize,
    bytes: &[u8],
    with_nul: bool,
) -> Option<usize> {
    let payload = bytes.len() + usize::from(with_nul);
    let padded = payload.checked_add((4 - payload % 4) % 4)?;
    let slice = out.get_mut(offset..offset.checked_add(padded)?)?;
    slice[..bytes.len()].copy_from_slice(bytes);
    Some(padded)
}

/// Writes one `newc` cpio entry (header, name, data) at the start of `out`.
///
/// Returns the number of bytes written, or `None` if `out` is too small.
fn cpio_entry(out: &mut [u8], name: &[u8], data: &[u8], inode: u32) -> Option<usize> {
    if out.len() < CPIO_HEADER_LEN {
        return None;
    }
    out[..6].copy_from_slice(b"070701");
    write_hex8(&mut out[6..14], inode);
    write_hex8(&mut out[14..22], 0o100644); // mode: regular file, 0644
    write_hex8(&mut out[22..30], 0); // uid
    write_hex8(&mut out[30..38], 0); // gid
    write_hex8(&mut out[38..46], 1); // nlink
    write_hex8(&mut out[46..54], 0); // mtime
    write_hex8(&mut out[54..62], data.len() as u32);
    write_hex8(&mut out[62..70], 0); // devmajor
    write_hex8(&mut out[70..78], 0); // devminor
    write_hex8(&mut out[78..86], 0); // rdevmajor
    write_hex8(&mut out[86..94], 0); // rdevminor
    write_hex8(&mut out[94..102], (name.len() + 1) as u32);
    write_hex8(&mut out[102..110], 0); // check

    let mut cursor = CPIO_HEADER_LEN;
    cursor = cursor.checked_add(append_padded(out, cursor, name, true)?)?;
    cursor = cursor.checked_add(append_padded(out, cursor, data, false)?)?;
    Some(cursor)
}

/// Builds the minimal initrd archive (`newc` cpio containing `init`).
///
/// A real archive format is used so the guest kernel can mount or extract it
/// with a normal cpio reader; the payload is a placeholder script until the
/// guest has an actual userland. Returns an empty slice if the static buffer
/// cannot hold the archive (impossible with the current sizes, handled without
/// panicking).
fn build_initrd_archive() -> &'static [u8] {
    let buffer = initrd_buffer();
    for byte in buffer.iter_mut() {
        *byte = 0;
    }
    let init_script: &[u8] = b"#!/bin/sh\nexit 0\n";
    let entries: [(&[u8], &[u8], u32); 2] = [
        (b"init", init_script, 1),
        (b"TRAILER!!!", &[], 0),
    ];
    let mut cursor = 0usize;
    for (name, data, inode) in entries {
        let Some(written) = cpio_entry(&mut buffer[cursor..], name, data, inode) else {
            return &initrd_buffer()[..0];
        };
        cursor += written;
    }
    &initrd_buffer()[..cursor]
}

/// Builds the boot disk image: one labeled sector followed by zero sectors.
///
/// The label documents the on-disk contract the guest block driver can rely on
/// before it has a filesystem parser: magic, version, sector size, sector count
/// and image length, with the classic `0x55AA` signature in the boot sector.
fn build_disk_image() -> &'static [u8] {
    let image = disk_image_buffer();
    for byte in image.iter_mut() {
        *byte = 0;
    }
    image[0..8].copy_from_slice(b"S9VMDISK");
    put_u32(image, 8, 1); // label version
    put_u32(image, 12, VMM_DISK_SECTOR_SIZE as u32);
    put_u64(image, 16, (DISK_IMAGE_LEN / VMM_DISK_SECTOR_SIZE as usize) as u64);
    put_u64(image, 24, DISK_IMAGE_LEN as u64);
    let note: &[u8] = b"s9vm boot disk: label sector only (no filesystem yet)";
    image[64..64 + note.len()].copy_from_slice(note);
    image[510] = 0x55;
    image[511] = 0xAA;
    &disk_image_buffer()[..DISK_IMAGE_LEN]
}

/// Writes a little-endian `u32` at `offset`.
fn put_u32(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

// ---------------------------------------------------------------------------
// Real guest kernel mode (helpers)
// ---------------------------------------------------------------------------

/// Returns a monotonic timestamp in milliseconds, or 0 when the clock is not
/// available (the exit-count bound keeps the watchdog effective in that case).
fn monotonic_ms() -> u64 {
    let mut ts = TimeSpec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    match call::clock_gettime(CLOCK_MONOTONIC, &mut ts) {
        Ok(_) => (ts.tv_sec.max(0) as u64)
            .saturating_mul(1000)
            .saturating_add((ts.tv_nsec.max(0) as u64) / 1_000_000),
        Err(_) => 0,
    }
}

/// State of the optional real-guest image file.
enum GuestImageState {
    /// File present, `n` bytes copied into the static buffer.
    Present(usize),
    /// File absent: the built-in demo is used.
    Absent,
}

/// Failure while reading `/initfs/s9vm-guest`.
enum GuestLoadError {
    /// The file could not be opened for a reason other than absence.
    Open(Error),
    /// A read failed after the bounded retry budget.
    Read(Error),
    /// The image is larger than [`GUEST_IMAGE_MAX`].
    TooLarge,
}

impl GuestLoadError {
    /// Short reason used in logs.
    fn name(&self) -> &'static str {
        match self {
            Self::Open(_) => "open-failed",
            Self::Read(_) => "read-failed",
            Self::TooLarge => "image-too-large",
        }
    }

    /// Underlying `errno` name when the failure came from a syscall.
    fn errno(&self) -> &'static str {
        match self {
            Self::Open(error) | Self::Read(error) => error.name(),
            Self::TooLarge => "E2BIG",
        }
    }
}

/// Reads one small `/initfs` file into `buffer` (single bounded pass).
///
/// Returns `Ok(None)` when the entry is not staged: the kernel-backed
/// `/initfs` scheme reports a missing entry as `BadHandle` (EBADF) instead of
/// `NotFound`, and both mean "not staged". A file larger than `buffer` is
/// rejected rather than silently truncated.
fn read_initfs_file(path: &str, buffer: &mut [u8]) -> Result<Option<usize>, GuestLoadError> {
    let fd = match call::open(path, flag::O_RDONLY) {
        Ok(fd) => fd,
        Err(Error::NotFound) | Err(Error::BadHandle) => return Ok(None),
        Err(error) => return Err(GuestLoadError::Open(error)),
    };
    let mut total = 0usize;
    let mut retries = 0u32;
    let result = loop {
        if total == buffer.len() {
            // Buffer full: prove there is no extra byte, otherwise reject.
            let mut probe = [0u8; 1];
            match call::read(fd, &mut probe) {
                Ok(0) => break Ok(Some(total)),
                Ok(_) => break Err(GuestLoadError::TooLarge),
                Err(error) if error.is_retryable() => {
                    retries += 1;
                    if retries > MAX_READ_RETRIES {
                        break Err(GuestLoadError::Read(error));
                    }
                    let _ = call::sched_yield();
                }
                Err(error) => break Err(GuestLoadError::Read(error)),
            }
        }
        match call::read(fd, &mut buffer[total..]) {
            Ok(0) => break Ok(Some(total)),
            Ok(count) => {
                total += count;
                retries = 0;
            }
            Err(error) if error.is_retryable() => {
                retries += 1;
                if retries > MAX_READ_RETRIES {
                    break Err(GuestLoadError::Read(error));
                }
                let _ = call::sched_yield();
            }
            Err(error) => break Err(GuestLoadError::Read(error)),
        }
    };
    let _ = call::close(fd);
    result
}

/// Reads `/initfs/s9vm-guest` into the static buffer (bounded to 1 MiB).
///
/// A truncated ELF would be rejected later with a useless error, so an
/// oversized file is rejected here.
fn load_guest_image() -> Result<GuestImageState, GuestLoadError> {
    match read_initfs_file(PATH_GUEST_IMAGE, guest_elf_buffer())? {
        Some(len) => Ok(GuestImageState::Present(len)),
        None => Ok(GuestImageState::Absent),
    }
}

/// Logs the read-only enumeration fallback used when `SYS_VMM_CREATE` cannot
/// succeed (engine inactive or missing SILO_ADMIN capability).
fn log_enumerate_fallback() {
    let mut entries: [VmmWorldEntry; 4] = [VmmWorldEntry::default(); 4];
    match vmm_list(0, &mut entries) {
        Ok(total) => log!("[s9vm-vmm] LIST total={}", total),
        Err(error) => log!("[s9vm-vmm] LIST failed: {}", log_errno(error)),
    }
    let mut vcpus: [VmmVcpuInfo; 4] = [VmmVcpuInfo::default(); 4];
    match vmm_vcpu_list(0, &mut vcpus) {
        Ok(total) => log!("[s9vm-vmm] VCPU_LIST total={}", total),
        Err(error) => log!("[s9vm-vmm] VCPU_LIST failed: {}", log_errno(error)),
    }
}

/// Creates a world, mapping the three documented creation outcomes to a stable
/// exit code instead of a capability handle.
fn create_world(name: &[u8]) -> Result<u64, usize> {
    match vmm_create(name, 0) {
        Ok(handle) => Ok(handle),
        Err(Error::NotSupported) => {
            log!("[s9vm-vmm] SYS_VMM_CREATE: ENOTSUP (VT-x not detected: engine inactive)");
            log_enumerate_fallback();
            log!("[s9vm-vmm] RESULT: SKIP (s9vm engine inactive: VT-x absent)");
            Err(EXIT_SKIP)
        }
        Err(Error::PermissionDenied) => {
            // `CREATE` calls `require_silo_admin()` first: a boot silo only
            // receives SILO_ADMIN through the SILO_FLAG_ADMIN silo flag, which
            // the boot chain does not set today. Report the access-control gap
            // instead of a generic failure.
            log!("[s9vm-vmm] SYS_VMM_CREATE: EPERM (SILO_ADMIN capability required)");
            log_enumerate_fallback();
            log!(
                "[s9vm-vmm] RESULT: BLOCKED (boot silo lacks SILO_ADMIN; \
                 see tools/scripts/ for the silo flags contract)"
            );
            Err(EXIT_BLOCKED)
        }
        Err(error) => {
            log!(
                "[s9vm-vmm] RESULT: FAIL (SYS_VMM_CREATE: {})",
                log_errno(error)
            );
            Err(EXIT_FAIL)
        }
    }
}

/// Guest run report collected from the debug-port protocol.
struct GuestRunReport {
    /// `true` when the full `G`,`M`,`A` sequence was seen before a `HALT`.
    pass: bool,
    /// A `HALT` policy exit was handled.
    halt: bool,
    /// Number of policy exits handled.
    exits: u32,
    /// Last decoded exit kind.
    last_kind: u32,
    /// Guest-physical address of the last exit that reported one (0 otherwise).
    last_gpa: u64,
    /// Debug bytes seen on port 0xE9 (first 16).
    seen: [u8; 16],
    /// Number of valid entries in `seen`.
    seen_len: usize,
    /// Number of expected markers matched in order.
    matched: usize,
}

/// Completes one policy exit, applying the guest RIP advance the hardware did
/// not perform.
///
/// For an `OUT` I/O-port exit the engine leaves `GUEST_RIP` at the faulting
/// instruction, so the policy must advance it by the reported instruction
/// length; an `IN` exit additionally needs a value (there is no device behind
/// the policy port, so read back `0xFF`). Every other exit is completed as a
/// no-op.
fn complete_policy_exit(vcpu: u64, event: &VmmExitEvent) -> Result<(), Error> {
    match event.kind {
        exit_kind::IO_PORT => {
            let direction_in = event.flags & 1 != 0;
            let value = if direction_in { 0xFF } else { 0 };
            let advance = u64::from(event.instruction_length).max(1);
            vmm_exit_complete(vcpu, value, advance)
        }
        _ => vmm_exit_complete(vcpu, 0, 0),
    }
}

/// Runs the guest and drains its policy exits until it halts or a bound trips.
///
/// Completion policy:
/// * `IO_PORT` (including the 0xE9 debug byte) → completed with value 0 and
///   RIP advance 0: the hardware already advanced RIP for `OUT`/`IN`, and the
///   policy only consumes the side effect;
/// * `HALT` → completed with value 0 / advance 0, then the loop stops;
/// * `TRANSLATION` (guest touched a guest-physical address the world does not
///   map) → the address and access type are logged, the exit is completed and
///   the run aborts: a policy cannot create EPT mappings, so re-entering would
///   only replay the fault;
/// * any other exit (MMIO, MSR, exception, timer) → completed as a no-op
///   (value 0, advance 0). The real guest kernel only needs the debug port and
///   HLT; an unexpected exit class is logged and bounded by [`MAX_GUEST_EXITS`]
///   and the wall-clock watchdog instead of being emulated.
fn run_guest_policy_loop(world: u64, vcpu: u64) -> Result<GuestRunReport, Error> {
    let mut report = GuestRunReport {
        pass: false,
        halt: false,
        exits: 0,
        last_kind: 0,
        last_gpa: 0,
        seen: [0u8; 16],
        seen_len: 0,
        matched: 0,
    };
    let started = monotonic_ms();
    let mut empty_polls = 0u32;
    // Last printable marker published by the guest: a small binary code that
    // follows one names the optional step that failed, in the guest's own
    // vocabulary (the codes are listed in the guest README).
    let mut last_marker = 0u8;

    while report.exits < MAX_GUEST_EXITS && !report.halt {
        if started != 0 && monotonic_ms().saturating_sub(started) > GUEST_WATCHDOG_MS {
            log!(
                "[s9vm-vmm] guest: watchdog timeout after {} ms",
                GUEST_WATCHDOG_MS
            );
            break;
        }
        match vmm_run(vcpu) {
            Ok(()) => {}
            Err(Error::Again) => {
                empty_polls += 1;
                if empty_polls > MAX_EMPTY_POLLS {
                    log!("[s9vm-vmm] guest: watchdog (no exit after RUN)");
                    break;
                }
                let _ = call::sched_yield();
                continue;
            }
            Err(error) => return Err(error),
        }
        empty_polls = 0;

        // Drain every queued exit before re-entering the guest.
        loop {
            let mut event = VmmExitEvent::default();
            if vmm_exit_handler(world, &mut event)? == 0 {
                break;
            }
            report.exits += 1;
            report.last_kind = event.kind;
            report.last_gpa = event.gpa;
            log!(
                "[s9vm-vmm] guest exit kind={} ({}) port={:#x} size={} value={:#x} gpa={:#x} flags={:#x}",
                event.kind,
                exit_kind_name(event.kind),
                event.port,
                event.size,
                event.value,
                event.gpa,
                event.flags
            );
            if event.kind == exit_kind::IO_PORT && event.port == POLICY_PORT {
                let byte = (event.value & 0xFF) as u8;
                if byte < 0x20 {
                    log!(
                        "[s9vm-vmm] guest failure marker={} code={}",
                        if last_marker == 0 {
                            '?'
                        } else {
                            last_marker as char
                        },
                        byte
                    );
                } else {
                    log!(
                        "[s9vm-vmm] guest debug byte 0x{:02x} ({})",
                        byte,
                        guest_marker_name(byte)
                    );
                    last_marker = byte;
                }
                if report.seen_len < report.seen.len() {
                    report.seen[report.seen_len] = byte;
                    report.seen_len += 1;
                }
                if report.matched < GUEST_MARKERS.len() && byte == GUEST_MARKERS[report.matched] {
                    report.matched += 1;
                }
            }
            if event.kind == exit_kind::HALT {
                report.halt = true;
                log!("[s9vm-vmm] guest halted (HLT policy exit)");
            }
            if event.kind == exit_kind::TRANSLATION {
                // The guest used a guest-physical address the world does not
                // map (and no device model claims). A policy cannot create EPT
                // mappings, so re-entering would only replay the fault: report
                // the address and abort cleanly.
                log!(
                    "[s9vm-vmm] guest accessed an unmapped guest-physical address {:#x} \
                     (access flags={}), aborting the guest run",
                    event.gpa,
                    event.flags
                );
                // The faulting address alone does not say whether the guest
                // used a bad pointer or its page tables were corrupted; the
                // register block does. `rip`/`cr3`/`r12` are the most useful
                // when the fault happens inside a table walk.
                let mut regs = VmmRegs::default();
                if vmm_vcpu_regs(vcpu, &mut regs).is_ok() {
                    log!(
                        "[s9vm-vmm] guest regs on abort: rip={:#x} rsp={:#x} cr3={:#x} \
                         r12={:#x} r13={:#x} r14={:#x} r15={:#x} rsi={:#x} rdi={:#x}",
                        regs.rip,
                        regs.rsp,
                        regs.cr3,
                        regs.r12,
                        regs.r13,
                        regs.r14,
                        regs.r15,
                        regs.rsi,
                        regs.rdi
                    );
                }
                complete_policy_exit(vcpu, &event)?;
                report.pass = false;
                log!(
                    "[s9vm-vmm] run guest summary: exits={} markers={}/{} halted={} last_exit={} ({}) last_gpa={:#x}",
                    report.exits,
                    report.matched,
                    GUEST_MARKERS.len(),
                    report.halt,
                    report.last_kind,
                    exit_kind_name(report.last_kind),
                    report.last_gpa
                );
                return Ok(report);
            }
            complete_policy_exit(vcpu, &event)?;
            if report.halt || report.exits >= MAX_GUEST_EXITS {
                break;
            }
        }
    }

    report.pass = report.halt && report.matched == GUEST_MARKERS.len();
    log!(
        "[s9vm-vmm] guest summary: exits={} markers={}/{} halt={} last_exit={} ({}) last_gpa={:#x}",
        report.exits,
        report.matched,
        GUEST_MARKERS.len(),
        report.halt,
        report.last_kind,
        exit_kind_name(report.last_kind),
        report.last_gpa
    );
    if report.seen_len > 0 {
        let mut seen = LogBuf::new();
        let _ = seen.write_str("[s9vm-vmm] guest bytes seen:");
        for index in 0..report.seen_len {
            let _ = seen.write_fmt(format_args!(" 0x{:02x}", report.seen[index]));
        }
        let _ = call::debug_log(&seen.buf[..seen.len]);
    }
    Ok(report)
}

/// Boots the real guest image: boot sequence, registers and run loop.
///
/// Ordering matters on the kernel side:
/// * `LOAD_IMAGE`/`LOAD_MODULE`/`MAP_MEM` must run before `ACPI` and
///   `BOOT_PARAMS` (both need a mapped guest memory);
/// * `ACPI` needs the vCPU (the MADT describes its APIC ids) and must run
///   before `BOOT_PARAMS` (the boot block publishes the RSDP address);
/// * `SET_CMDLINE`/`LOAD_MODULE` must run before `BOOT_PARAMS` (it publishes
///   the command line and module ranges);
/// * `LOAD_DISK` only needs the world, but is issued before `BOOT_PARAMS` so
///   the guest boots with its final block-device content.
fn boot_real_guest(world: u64, vcpu: u64, image_len: usize) -> Result<bool, Error> {
    // 1. Kernel command line (published by BOOT_PARAMS).
    log!(
        "[s9vm-vmm] guest 1/10: SYS_VMM_SET_CMDLINE ({} bytes)",
        GUEST_CMDLINE.len()
    );
    let stored = vmm_set_cmdline(world, GUEST_CMDLINE)?;
    log!("[s9vm-vmm] SET_CMDLINE stored={}", stored);
    if stored as usize != GUEST_CMDLINE.len() {
        log!("[s9vm-vmm] WARNING: command line was not stored completely");
    }

    // 2. Guest ELF at its linked guest-physical base (0x0010_0000).
    log!(
        "[s9vm-vmm] guest 2/10: SYS_VMM_LOAD_IMAGE ({} bytes at gpa={:#x})",
        image_len,
        GUEST_IMAGE_GPA
    );
    let image = &guest_elf_buffer()[..image_len];
    let mut image_info = VmmImageInfo::default();
    vmm_load_image(world, GUEST_IMAGE_GPA, image, &mut image_info)?;
    log!(
        "[s9vm-vmm] LOAD_IMAGE entry={:#x} base={:#x} span={:#x}..{:#x}",
        image_info.entry,
        image_info.image_base,
        image_info.span_min,
        image_info.span_max
    );
    if image_info.entry == 0 {
        log!("[s9vm-vmm] WARNING: image entry is 0 (unexpected for an ET_EXEC kernel)");
    }

    // 3. Identity page tables as a raw blob through LOAD_MODULE.
    log!(
        "[s9vm-vmm] guest 3/10: SYS_VMM_LOAD_MODULE page tables ({} bytes at gpa={:#x})",
        PAGE_TABLE_BLOB_LEN,
        PAGE_TABLE_BLOB_GPA
    );
    let blob = build_page_table_blob();
    vmm_load_module(world, PAGE_TABLE_BLOB_GPA, blob)?;
    log!(
        "[s9vm-vmm] page tables: PML4@0x0 -> PDPT@0x1000 -> PD@0x2000, \
         identity leaves 0..{:#x} (2 MiB pages)",
        IDENTITY_WINDOW
    );

    // 4. Initrd archive as a second raw module, published in the boot block.
    let initrd = match read_initfs_file(PATH_INITRD, initrd_buffer()) {
        Ok(Some(len)) => {
            log!(
                "[s9vm-vmm] guest 4/10: SYS_VMM_LOAD_MODULE initrd ({} bytes from {})",
                len,
                PATH_INITRD
            );
            &initrd_buffer()[..len]
        }
        Ok(None) => {
            let built = build_initrd_archive();
            log!(
                "[s9vm-vmm] guest 4/10: SYS_VMM_LOAD_MODULE initrd ({} bytes, built-in)",
                built.len()
            );
            built
        }
        Err(error) => {
            // The archive is optional: a read failure must not prevent the
            // guest from booting, so fall back to the built-in archive.
            log!(
                "[s9vm-vmm] WARNING: reading {} failed ({}: {}), using the built-in initrd",
                PATH_INITRD,
                error.name(),
                error.errno()
            );
            build_initrd_archive()
        }
    };
    if !initrd.is_empty() {
        vmm_load_module(world, INITRD_GPA, initrd)?;
        log!(
            "[s9vm-vmm] initrd: {} bytes at gpa={:#x}",
            initrd.len(),
            INITRD_GPA
        );
    } else {
        log!("[s9vm-vmm] WARNING: initrd archive could not be built, booting without it");
    }

    // 5. Guest boot-parameter page (mapped before BOOT_PARAMS writes it).
    log!(
        "[s9vm-vmm] guest 5/10: SYS_VMM_MAP_MEM boot params gpa={:#x} len={:#x}",
        BOOT_PARAMS_GPA,
        BOOT_PARAMS_LEN
    );
    vmm_map_mem(
        world,
        BOOT_PARAMS_GPA,
        BOOT_PARAMS_LEN,
        PERM_READ_WRITE,
        MEMTYPE_WRITEBACK,
    )?;

    // 6. ACPI tables (needs the vCPU and a mapped world memory).
    log!(
        "[s9vm-vmm] guest 6/10: SYS_VMM_ACPI gpa={:#x}",
        ACPI_WINDOW_GPA
    );
    vmm_acpi(world, ACPI_WINDOW_GPA)?;

    // 7. Block-device content: a staged image when the builder provided one,
    //    otherwise the built-in labelled disk.
    let disk = match read_initfs_file(PATH_DISK_IMAGE, disk_image_buffer()) {
        Ok(Some(len)) => {
            log!(
                "[s9vm-vmm] guest 7/10: SYS_VMM_LOAD_DISK ({} bytes from {})",
                len,
                PATH_DISK_IMAGE
            );
            &disk_image_buffer()[..len]
        }
        Ok(None) => {
            let built = build_disk_image();
            log!(
                "[s9vm-vmm] guest 7/10: SYS_VMM_LOAD_DISK ({} bytes, built-in)",
                built.len()
            );
            built
        }
        Err(error) => {
            log!(
                "[s9vm-vmm] WARNING: reading {} failed ({}: {}), using the built-in disk",
                PATH_DISK_IMAGE,
                error.name(),
                error.errno()
            );
            build_disk_image()
        }
    };
    vmm_load_disk(world, disk)?;
    log!(
        "[s9vm-vmm] disk: {} bytes ({} sectors), world device content provisioned",
        disk.len(),
        disk.len() / VMM_DISK_SECTOR_SIZE as usize
    );

    // 8. Boot parameters (after ACPI, cmdline, modules and disk).
    log!(
        "[s9vm-vmm] guest 8/10: SYS_VMM_BOOT_PARAMS gpa={:#x}",
        BOOT_PARAMS_GPA
    );
    vmm_boot_params(world, BOOT_PARAMS_GPA)?;

    // 9. Initial registers: long mode, identity tables at CR3=0, RSP=0 (the
    //    guest sets up its own stack in _start), RDI = guest-physical address of
    //    the boot-parameter block (the guest kernel ABI passes it in RDI).
    log!(
        "[s9vm-vmm] guest 9/10: SYS_VMM_SET_REGS rip={:#x} rsp=0 rdi={:#x}",
        image_info.entry,
        BOOT_PARAMS_GPA
    );
    let mut regs = guest_registers();
    regs.rip = image_info.entry;
    regs.rsp = 0;
    regs.rdi = BOOT_PARAMS_GPA;
    vmm_set_regs(vcpu, &regs)?;

    // 10. Run and drain policy exits.
    log!("[s9vm-vmm] guest 10/10: SYS_VMM_RUN + policy loop");
    let report = run_guest_policy_loop(world, vcpu)?;
    Ok(report.pass)
}

/// Runs the real guest path and always tears the world down.
///
/// On every path the vCPU is destroyed first and the world second; teardown
/// failures are logged but do not mask the boot result.
fn run_guest_cycle(world: u64, image_len: usize) -> Result<bool, Error> {
    let vcpu = match vmm_create_vcpu(world, 0) {
        Ok(vcpu) => vcpu,
        Err(error) => {
            let _ = vmm_destroy(world);
            log!("[s9vm-vmm] teardown: world destroyed (no vCPU)");
            return Err(error);
        }
    };
    log!("[s9vm-vmm] vcpu handle={}", vcpu);

    let boot = boot_real_guest(world, vcpu, image_len);

    let vcpu_destroy = vmm_destroy_vcpu(vcpu);
    let world_destroy = vmm_destroy(world);
    log!(
        "[s9vm-vmm] teardown: DESTROY_VCPU={} DESTROY={}",
        if vcpu_destroy.is_ok() { "ok" } else { "failed" },
        if world_destroy.is_ok() {
            "ok"
        } else {
            "failed"
        }
    );

    match (boot, vcpu_destroy, world_destroy) {
        (Err(error), _, _) => Err(error),
        (Ok(_), Err(error), _) => Err(error),
        (Ok(_), Ok(()), Err(error)) => Err(error),
        (Ok(pass), Ok(()), Ok(())) => Ok(pass),
    }
}

/// Real-guest mode entry point.
fn run_guest_mode(image_len: usize) -> usize {
    log!(
        "[s9vm-vmm] ===== s9vm userspace policy (real guest, {} bytes) =====",
        image_len
    );
    let world = match create_world(GUEST_WORLD_NAME) {
        Ok(world) => world,
        Err(code) => return code,
    };
    log!("[s9vm-vmm] world handle={} name='guest'", world);

    match run_guest_cycle(world, image_len) {
        Ok(true) => {
            log!("[s9vm-vmm] RESULT: PASS (real guest: G/M/A + HLT)");
            EXIT_PASS
        }
        Ok(false) => {
            log!("[s9vm-vmm] RESULT: FAIL (real guest did not complete G/M/A + HLT)");
            EXIT_FAIL
        }
        Err(error) => {
            log!(
                "[s9vm-vmm] RESULT: FAIL (real guest boot: {})",
                log_errno(error)
            );
            EXIT_FAIL
        }
    }
}

// ---------------------------------------------------------------------------
// Policy helpers
// ---------------------------------------------------------------------------

/// Parses a 1- or 2-digit value from the `versions` field of a struct.
fn log_errno(error: Error) -> &'static str {
    error.name()
}

/// Returns the exit-kind name used in the logs.
fn exit_kind_name(kind: u32) -> &'static str {
    match kind {
        exit_kind::MMIO_READ => "mmio_read",
        exit_kind::MMIO_WRITE => "mmio_write",
        exit_kind::IO_PORT => "io_port",
        exit_kind::HALT => "halt",
        exit_kind::TRANSLATION => "translation",
        exit_kind::EXCEPTION => "exception",
        exit_kind::PREEMPTION_TIMER => "preemption_timer",
        _ => "other",
    }
}

/// Returns the meaning of a guest debug-port byte.
///
/// Bytes `G`, `M`, `A` are the mandatory boot markers; the others are the
/// optional progress markers newer guest kernels emit (private GDT/IDT,
/// paging, APIC probe, initrd, failure and panic paths). Unknown bytes are
/// reported as `unknown` so a protocol mismatch is visible in the log.
fn guest_marker_name(byte: u8) -> &'static str {
    match byte {
        b'G' => "boot params magic ok",
        b'M' => "memory map ok",
        b'A' => "ACPI RSDP ok",
        b'K' => "GDT/IDT/paging/cmdline ok",
        b'R' => "initrd module ok",
        b'I' => "initrd archive ok",
        b'r' => "initrd not present",
        b'N' => "initrd init content extracted",
        b'n' => "initrd init content absent",
        b'S' => "ACPI tables ok",
        b's' => "ACPI tables unavailable",
        b'T' => "APIC timer ok",
        b't' => "APIC timer unavailable",
        b'C' => "virtio-console output ok",
        b'c' => "virtio-console unavailable",
        b'D' => "virtio-block label ok",
        b'd' => "virtio-block unavailable",
        b'V' => "timer interrupt observed",
        b'v' => "timer interrupt not observed",
        b'X' => "virtio-net frame transmitted",
        b'x' => "virtio-net unavailable",
        b'W' => "legacy UART online",
        b'w' => "legacy UART unavailable",
        b'Z' => "CMOS clock read",
        b'z' => "CMOS clock unavailable",
        b'F' => "failure (next byte is the code)",
        b'E' => "exception (next byte is the vector)",
        b'P' => "panic",
        _ => "unknown",
    }
}

/// Runs the policy loop after the guest was started.
///
/// Returns `(policy_exits, debug_port_seen, halt_seen)`.
fn run_policy_loop(world: u64, vcpu: u64) -> Result<(u32, bool, bool), Error> {
    let mut policy_exits = 0u32;
    let mut debug_port_seen = false;
    let mut halt_seen = false;

    for _ in 0..MAX_POLICY_EXITS {
        vmm_run(vcpu)?;
        let mut event = VmmExitEvent::default();
        match vmm_exit_handler(world, &mut event)? {
            0 => {
                log!("[s9vm-vmm] no exit queued after RUN");
                break;
            }
            _ => {
                policy_exits += 1;
                log!(
                    "[s9vm-vmm] policy exit kind={} ({}) port={:#x} size={} value={:#x}",
                    event.kind,
                    exit_kind_name(event.kind),
                    event.port,
                    event.size,
                    event.value
                );
                if event.kind == exit_kind::IO_PORT && event.port == POLICY_PORT {
                    debug_port_seen = true;
                    log!("[s9vm-vmm] policy: completing the 0xE9 I/O exit");
                }
                if event.kind == exit_kind::HALT {
                    halt_seen = true;
                    log!("[s9vm-vmm] policy: guest halted, completing the exit");
                }
                // I/O instructions already advanced RIP in hardware; other
                // exits are completed without advancing (the guest enters at a
                // fresh instruction after this demo).
            complete_policy_exit(vcpu, &event)?;
                if halt_seen {
                    break;
                }
            }
        }
    }
    Ok((policy_exits, debug_port_seen, halt_seen))
}

/// Component entry: real guest kernel when `/initfs/s9vm-guest` is staged,
/// built-in demo otherwise.
fn run() -> usize {
    match load_guest_image() {
        Ok(GuestImageState::Present(len)) => {
            log!(
                "[s9vm-vmm] found {} guest image ({} bytes): real guest mode",
                PATH_GUEST_IMAGE,
                len
            );
            run_guest_mode(len)
        }
        Ok(GuestImageState::Absent) => {
            log!(
                "[s9vm-vmm] {} not found: using the built-in demo guest",
                PATH_GUEST_IMAGE
            );
            run_demo()
        }
        Err(error) => {
            // Defensive: a read failure must not prevent the policy demo from
            // running. Report the reason and fall back to the built-in guest.
            log!(
                "[s9vm-vmm] cannot read {} ({} / {}): using the built-in demo guest",
                PATH_GUEST_IMAGE,
                error.name(),
                error.errno()
            );
            run_demo()
        }
    }
}

/// Runs the built-in demo guest and returns the documented exit code.
fn run_demo() -> usize {
    log!("[s9vm-vmm] ===== s9vm userspace policy (demo) =====");

    // Step 1: create the world. `CREATE` is a silo-administration operation.
    log!("[s9vm-vmm] step 1/11: SYS_VMM_CREATE 'demo'");
    let world = match create_world(WORLD_NAME) {
        Ok(world) => world,
        Err(code) => return code,
    };
    log!("[s9vm-vmm] world handle={}", world);

    // Every later failure must destroy the world before returning.
    let outcome = run_world_cycle(world);
    match outcome {
        Ok(()) => {
            log!("[s9vm-vmm] RESULT: PASS (full userspace policy cycle)");
            EXIT_PASS
        }
        Err(error) => {
            log!("[s9vm-vmm] RESULT: FAIL ({})", log_errno(error));
            let _ = vmm_destroy(world);
            EXIT_FAIL
        }
    }
}

/// Drives the world lifecycle once `SYS_VMM_CREATE` succeeded.
fn run_world_cycle(world: u64) -> Result<(), Error> {
    // Step 2: enumerate worlds and check the new one is visible.
    log!("[s9vm-vmm] step 2/11: SYS_VMM_LIST");
    let mut entries: [VmmWorldEntry; 4] = [VmmWorldEntry::default(); 4];
    let total = vmm_list(world, &mut entries)?;
    let mut found = false;
    for entry in entries
        .iter()
        .take(core::cmp::min(total as usize, entries.len()))
    {
        let name = core::str::from_utf8(entry.name_slice()).unwrap_or("<non-utf8>");
        log!(
            "[s9vm-vmm] LIST world id={} name={} state={} vcpus={} pages={}",
            entry.vmm_id,
            name,
            entry.state,
            entry.vcpu_count,
            entry.mapped_pages
        );
        if entry.name_slice() == WORLD_NAME {
            found = true;
        }
    }
    log!("[s9vm-vmm] LIST total={} found_demo={}", total, found);
    if !found {
        log!("[s9vm-vmm] WARNING: the new world is not visible in LIST");
    }

    // Step 3: map two scratch guest pages.
    log!(
        "[s9vm-vmm] step 3/11: SYS_VMM_MAP_MEM gpa={:#x} len={:#x}",
        SCRATCH_GPA,
        SCRATCH_LEN
    );
    vmm_map_mem(
        world,
        SCRATCH_GPA,
        SCRATCH_LEN,
        PERM_READ_WRITE,
        MEMTYPE_WRITEBACK,
    )?;
    log!("[s9vm-vmm] MAP_MEM ok (2 pages of guest RAM)");

    // Step 4: create one vCPU.
    log!("[s9vm-vmm] step 4/11: SYS_VMM_CREATE_VCPU apic_id=0");
    let vcpu = vmm_create_vcpu(world, 0)?;
    log!("[s9vm-vmm] vcpu handle={}", vcpu);

    // Step 5: load the generated ELF64 guest image at GPA 0.
    log!(
        "[s9vm-vmm] step 5/11: SYS_VMM_LOAD_IMAGE ({} bytes at gpa={:#x})",
        IMAGE_LEN,
        IMAGE_GPA
    );
    let image = build_guest_image();
    let mut image_info = VmmImageInfo::default();
    vmm_load_image(world, IMAGE_GPA, image, &mut image_info)?;
    log!(
        "[s9vm-vmm] LOAD_IMAGE entry={:#x} base={:#x} span={:#x}..{:#x}",
        image_info.entry,
        image_info.image_base,
        image_info.span_min,
        image_info.span_max
    );

    // Step 6: install the initial guest registers.
    log!(
        "[s9vm-vmm] step 6/11: SYS_VMM_SET_REGS rip={:#x} rsp={:#x}",
        GUEST_ENTRY,
        GUEST_STACK_TOP
    );
    let regs = guest_registers();
    vmm_set_regs(vcpu, &regs)?;
    let mut readback = VmmRegs::default();
    vmm_vcpu_regs(vcpu, &mut readback)?;
    log!(
        "[s9vm-vmm] VCPU_REGS rip={:#x} rsp={:#x} cr0={:#x} cr3={:#x} cr4={:#x} efer={:#x}",
        readback.rip,
        readback.rsp,
        readback.cr0,
        readback.cr3,
        readback.cr4,
        readback.efer
    );
    if readback.rip != GUEST_ENTRY {
        log!("[s9vm-vmm] WARNING: RIP readback mismatch");
    }

    // Step 7: guest boot-information page (best effort on this ABI vintage).
    log!(
        "[s9vm-vmm] step 7/11: SYS_VMM_BOOT_INFO gpa={:#x}",
        SCRATCH_GPA
    );
    match vmm_boot_info(world, SCRATCH_GPA) {
        Ok(()) => log!("[s9vm-vmm] BOOT_INFO ok"),
        Err(error) => log!("[s9vm-vmm] BOOT_INFO skipped: {}", log_errno(error)),
    }

    // Step 8: introspection (INFO / STATS / VCPU_LIST).
    log!("[s9vm-vmm] step 8/11: INFO / STATS / VCPU_LIST");
    let mut info = VmmInfo::default();
    vmm_info(world, &mut info)?;
    log!(
        "[s9vm-vmm] INFO state={} vcpus={} pages={} exits={}",
        info.state,
        info.vcpu_count,
        info.mapped_pages,
        info.exit_total
    );
    let mut stats = VmmWorldStats::default();
    vmm_stats(world, &mut stats)?;
    log!(
        "[s9vm-vmm] STATS runs={} policy_exits={} emulated_io={} paused={}",
        stats.runs,
        stats.policy_exits,
        stats.emulated_io,
        stats.paused
    );
    let mut vcpus: [VmmVcpuInfo; 4] = [VmmVcpuInfo::default(); 4];
    let vcpu_total = vmm_vcpu_list(world, &mut vcpus)?;
    let mut apic_id = 0u32;
    if vcpu_total > 0 {
        apic_id = vcpus[0].apic_id;
        log!(
            "[s9vm-vmm] VCPU_LIST total={} vcpu_id={} apic_id={}",
            vcpu_total,
            vcpus[0].vcpu_id,
            vcpus[0].apic_id
        );
    } else {
        log!("[s9vm-vmm] VCPU_LIST total=0");
    }

    // Step 9: pause / RUN (expects EAGAIN) / resume.
    log!("[s9vm-vmm] step 9/11: SYS_VMM_PAUSE / RUN(EAGAIN) / RESUME");
    vmm_pause(world)?;
    match vmm_run(vcpu) {
        Err(Error::Again) => log!("[s9vm-vmm] RUN while paused -> EAGAIN (expected)"),
        Ok(()) => log!("[s9vm-vmm] WARNING: RUN accepted while paused"),
        Err(error) => log!("[s9vm-vmm] RUN while paused -> {}", log_errno(error)),
    }
    vmm_stats(world, &mut stats)?;
    log!("[s9vm-vmm] STATS paused={}", stats.paused);
    vmm_resume(world)?;

    // Step 10: run the guest and answer its exits.
    log!("[s9vm-vmm] step 10/11: SYS_VMM_RUN + policy loop");
    let (policy_exits, debug_seen, halt_seen) = run_policy_loop(world, vcpu)?;
    vmm_stats(world, &mut stats)?;
    log!(
        "[s9vm-vmm] STATS runs={} policy_exits={} emulated_io={} pending={}",
        stats.runs,
        stats.policy_exits,
        stats.emulated_io,
        stats.exits_pending
    );
    log!(
        "[s9vm-vmm] policy summary: exits={} debug_port={} halted={}",
        policy_exits,
        debug_seen,
        halt_seen
    );
    if policy_exits == 0 {
        log!("[s9vm-vmm] WARNING: the guest produced no policy exit");
    }
    let _ = apic_id;

    // Step 11: clean teardown.
    log!("[s9vm-vmm] step 11/11: DESTROY_VCPU / DESTROY");
    vmm_destroy_vcpu(vcpu)?;
    let mut remaining: [VmmVcpuInfo; 4] = [VmmVcpuInfo::default(); 4];
    match vmm_vcpu_list(world, &mut remaining) {
        Ok(total) => log!("[s9vm-vmm] VCPU_LIST after destroy total={}", total),
        Err(error) => log!("[s9vm-vmm] VCPU_LIST after destroy: {}", log_errno(error)),
    }
    vmm_destroy(world)?;
    log!("[s9vm-vmm] teardown complete");
    Ok(())
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    call::handle_panic("s9vm-vmm", info);
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    call::exit(run());
}
