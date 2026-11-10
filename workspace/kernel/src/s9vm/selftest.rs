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

//! s9vm — hardware smoke test of the engine.
//!
//! Goal: run minimal guests (64-bit long mode, EPT enabled, page tables built
//! by the kernel) that exercise the full path — guest tables and second-level
//! tables, control-block load, guest entry, exits, kernel fast paths and clean
//! shutdown — without panicking: a failure is logged and boot continues.
//!
//! Phases, selected by the boot option `s9vm.selftest`:
//!
//! - `device` (`1`/`true`): canonical guest, legacy interrupt controller
//!   fast path, I/O exit and `hlt`;
//! - `irq`: interrupt delivery through the interrupt window;
//! - `console`: virtio console transport, both directions;
//! - `blk`: virtio block request replay;
//! - `net`: virtio network transmit;
//! - `loader`: an ELF64 image built in kernel memory, loaded into a world with
//!   [`crate::s9vm::vm::load_image`] (mapping, file-backed copy, BSS zeroing),
//!   then executed: the guest prints its marker on the debug port and halts;
//! - `acpi`: the guest discovers the firmware tables written by
//!   [`crate::s9vm::vm::write_acpi`] (RSDP scan, checksum, XSDT walk, MADT
//!   Local APIC count). It needs a registered vCPU, so it runs at the
//!   `kthread` stage (see [`s9vm_acpi_selftest`]) on a **detached** vCPU
//!   driven by a direct run loop; it is opt-in in the `2`/`all` mode through
//!   `s9vm.selftest.deferred=1`;
//! - `smp`: one world with two vCPUs, each with its own page tables, code page
//!   and stack, driven through the kernel vCPU tasks (`request_run`,
//!   `complete_exit`) in an interleaved order. It validates that the two vCPU
//!   contexts (CR3, RIP, RSP, marker) are independent and persisted across
//!   runs; it is enabled by `s9vm.selftest.deferred=1` or explicitly with
//!   `s9vm.selftest=smp`;
//! - `2`/`all`: the six bootstrap phases; `acpi` and `smp` are added by
//!   `s9vm.selftest.deferred=1`.
//!
//! The task path used by `smp` (kernel threads created from a component,
//! bounded `RUN` and destroy) has its own diagnostic,
//! `s9vm.kthread_smoke=1`, which runs on hosts without VT-x and reports
//! PASS/FAIL through the serial log.
//!
//! The guest state is the canonical 64-bit flat shape produced by
//! [`GuestState::long_mode_64`]; it is entered once. Any exit the engine does
//! not expect is logged with its decoded reason so a failure is diagnosable on
//! the target machine without rebuilding.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use strat9_abi::vmm::{exit_kind, VmmRegs, VMM_ABI_VERSION};

use crate::{
    memory::frame::{FrameAllocOptions, FramePurpose, PhysFrame},
    s9vm::{
        apic::LocalApic,
        caps::HwCaps,
        emulate::{interrupt_action, InterruptAction},
        exit::{reason_name, ExitClass, ExitReason},
        guest::GuestState,
        guestcode::{
            ACPI_CODE, ACPI_FAIL_MARKER, ACPI_MARKER, LOADER_CODE, LOADER_MARKER, SMP_CODE_0,
            SMP_CODE_1, SMP_HLT_OFFSET, SMP_MARKERS, SMP_OUT_INSTRUCTION_LEN, SMP_SHARED_GPA,
        },
        machine::Machine,
        vcpu::{SecondLevelMemory, Vcpu, VcpuError},
        virtio, virtio_blk, virtio_net, vm,
    },
};

/// Size of the test guest area: 6 pages (tables + code + stack).
const GUEST_PAGES: u64 = 6;
const GPA_PML4: u64 = 0x0000;
const GPA_PDPT: u64 = 0x1000;
const GPA_PD: u64 = 0x2000;
const GPA_CODE: u64 = 0x3000;
const GPA_STACK: u64 = 0x4000;
const GPA_PT: u64 = 0x5000;
const ENTRY_POINT: u64 = GPA_CODE;
const STACK_TOP: u64 = GPA_STACK + 0x800;

/// Byte written by the guest to the test port (0xE9).
const TEST_BYTE: u8 = 0x41;
/// I/O port used by the test (standard debug port of emulators).
const TEST_PORT: u16 = 0xE9;
/// Master PIC data port, used to check that the kernel *read path* is
/// emulated (the guest reads back the interrupt mask it programmed).
const PIC_DATA_PORT: u16 = 0x21;
/// Interrupt mask read back by the guest after programming the PIC.
const PIC_READBACK: u8 = 0xFF;

// Interrupt-delivery phase.
/// Guest pages for the interrupt test: the first six, plus IDT and GDT pages.
const IRQ_GUEST_PAGES: u64 = 8;
/// Guest-physical address of the IDT page (page 6).
const GPA_IDT: u64 = 0x6000;
/// Guest-physical address of the GDT page (page 7).
const GPA_GDT: u64 = 0x7000;

// Console phase.
/// Guest-physical address of the virtio console transport page.
const CONSOLE_MMIO_BASE: u64 = 0xFEB0_0000;
/// Guest pages of the console phase: tables, code, stack, queues, buffer and
/// the second page directory that maps the MMIO window.
const CONSOLE_GUEST_PAGES: u64 = 9;
/// Guest-physical address of the queue page (descriptor table + rings).
const GPA_QUEUES: u64 = 0x6000;
/// Guest-physical address of the console buffer page.
const GPA_CONSOLE_BUFFER: u64 = 0x7000;
/// Bytes the guest sends to the console.
const CONSOLE_TEXT: &[u8] = b"ok\n";
/// Byte queued by the kernel and delivered through the receive queue.
const CONSOLE_RX_BYTE: u8 = b'R';

const CONSOLE_GPA_PML4: u64 = 0x0000;
const CONSOLE_GPA_PDPT: u64 = 0x1000;
const CONSOLE_GPA_PD: u64 = 0x2000;
const CONSOLE_GPA_PT: u64 = 0x3000;
const CONSOLE_GPA_CODE: u64 = 0x4000;
const CONSOLE_GPA_STACK: u64 = 0x5000;
/// Second page directory, reached through PML4/PDPT entry 3.
const CONSOLE_GPA_PD_HIGH: u64 = 0x8000;
/// 2 MiB-aligned start of the window containing the console transport page.
const CONSOLE_GPA_MMIO_WINDOW: u64 = 0xFEA0_0000;
/// Page-directory index of that window (0xFEA0_0000 >> 21, low 9 bits).
const CONSOLE_PD_MMIO_INDEX: usize = 0x1F5;

/// Guest code of the console phase.
///
/// Programs the virtio console transport (status, transmit queue, queue
/// address registers, ready, notify), then reports through the debug port and
/// halts. All the queue structures are prepared by the kernel, so the guest
/// only exercises the transport page.
const CONSOLE_GUEST_CODE: &[u8] = &[
    0xB8, 0x70, 0x00, 0xB0, 0xFE, // mov eax, CONSOLE_MMIO_BASE + 0x70 (STATUS)
    0xB9, 0x0F, 0x00, 0x00, 0x00, // mov ecx, ACK | DRIVER | FEATURES_OK | DRIVER_OK
    0x89, 0x08, //
    0xB8, 0x30, 0x00, 0xB0, 0xFE, // mov eax, QUEUE_SEL
    0xB9, 0x01, 0x00, 0x00, 0x00, // mov ecx, 1 (transmit queue)
    0x89, 0x08, //
    0xB8, 0x38, 0x00, 0xB0, 0xFE, // mov eax, QUEUE_NUM
    0xB9, 0x08, 0x00, 0x00, 0x00, // mov ecx, 8
    0x89, 0x08, //
    0xB8, 0x80, 0x00, 0xB0, 0xFE, // mov eax, QUEUE_DESC_LOW
    0xB9, 0x00, 0x60, 0x00, 0x00, // mov ecx, GPA_QUEUES
    0x89, 0x08, //
    0xB8, 0x90, 0x00, 0xB0, 0xFE, // mov eax, QUEUE_AVAIL_LOW
    0xB9, 0x00, 0x61, 0x00, 0x00, // mov ecx, GPA_QUEUES + 0x100
    0x89, 0x08, //
    0xB8, 0xA0, 0x00, 0xB0, 0xFE, // mov eax, QUEUE_USED_LOW
    0xB9, 0x00, 0x62, 0x00, 0x00, // mov ecx, GPA_QUEUES + 0x200
    0x89, 0x08, //
    0xB8, 0x44, 0x00, 0xB0, 0xFE, // mov eax, QUEUE_READY
    0xB9, 0x01, 0x00, 0x00, 0x00, // mov ecx, 1
    0x89, 0x08, //
    0xB8, 0x50, 0x00, 0xB0, 0xFE, // mov eax, QUEUE_NOTIFY
    0xB9, 0x01, 0x00, 0x00, 0x00, // mov ecx, 1 (transmit queue)
    0x89, 0x08, //
    // Receive queue: separate tables in the queue page and a buffer at
    // 0x7400. Its notification delivers the byte queued by the kernel.
    0xB8, 0x30, 0x00, 0xB0, 0xFE, // mov eax, QUEUE_SEL
    0xB9, 0x00, 0x00, 0x00, 0x00, // mov ecx, 0 (receive queue)
    0x89, 0x08, //
    0xB8, 0x38, 0x00, 0xB0, 0xFE, // mov eax, QUEUE_NUM
    0xB9, 0x08, 0x00, 0x00, 0x00, // mov ecx, 8
    0x89, 0x08, //
    0xB8, 0x80, 0x00, 0xB0, 0xFE, // mov eax, QUEUE_DESC_LOW
    0xB9, 0x00, 0x64, 0x00, 0x00, // mov ecx, GPA_QUEUES + 0x400
    0x89, 0x08, //
    0xB8, 0x90, 0x00, 0xB0, 0xFE, // mov eax, QUEUE_AVAIL_LOW
    0xB9, 0x00, 0x65, 0x00, 0x00, // mov ecx, GPA_QUEUES + 0x500
    0x89, 0x08, //
    0xB8, 0xA0, 0x00, 0xB0, 0xFE, // mov eax, QUEUE_USED_LOW
    0xB9, 0x00, 0x66, 0x00, 0x00, // mov ecx, GPA_QUEUES + 0x600
    0x89, 0x08, //
    0xB8, 0x44, 0x00, 0xB0, 0xFE, // mov eax, QUEUE_READY
    0xB9, 0x01, 0x00, 0x00, 0x00, // mov ecx, 1
    0x89, 0x08, //
    0xB8, 0x50, 0x00, 0xB0, 0xFE, // mov eax, QUEUE_NOTIFY
    0xB9, 0x00, 0x00, 0x00, 0x00, // mov ecx, 0 (receive queue)
    0x89, 0x08, //
    0x8A, 0x04, 0x25, 0x00, 0x74, 0x00, 0x00, // mov al, byte [0x7400]
    0xE6, 0xE9, // out 0xE9, al
    0xF4, // hlt
];

// Block phase.
/// Guest-physical address of the virtio block transport page.
const BLK_MMIO_BASE: u64 = 0xFEB0_1000;
/// First byte of the disk sector the guest reads back.
const BLK_MARKER: u8 = b'D';
/// Guest code of the block phase.
///
/// Programs the virtio block transport (status, request queue, queue address
/// registers, ready, notify), then reads the first byte of the data buffer
/// (written by the kernel device model), reports it on the debug port and
/// halts.
const BLK_GUEST_CODE: &[u8] = &[
    0xB8, 0x70, 0x10, 0xB0, 0xFE, // mov eax, BLK_MMIO_BASE + 0x70 (STATUS)
    0xB9, 0x0F, 0x00, 0x00, 0x00, // mov ecx, ACK | DRIVER | FEATURES_OK | DRIVER_OK
    0x89, 0x08, //
    0xB8, 0x30, 0x10, 0xB0, 0xFE, // mov eax, QUEUE_SEL
    0xB9, 0x00, 0x00, 0x00, 0x00, // mov ecx, 0 (request queue)
    0x89, 0x08, //
    0xB8, 0x38, 0x10, 0xB0, 0xFE, // mov eax, QUEUE_NUM
    0xB9, 0x08, 0x00, 0x00, 0x00, // mov ecx, 8
    0x89, 0x08, //
    0xB8, 0x80, 0x10, 0xB0, 0xFE, // mov eax, QUEUE_DESC_LOW
    0xB9, 0x00, 0x60, 0x00, 0x00, // mov ecx, GPA_QUEUES
    0x89, 0x08, //
    0xB8, 0x90, 0x10, 0xB0, 0xFE, // mov eax, QUEUE_AVAIL_LOW
    0xB9, 0x00, 0x61, 0x00, 0x00, // mov ecx, GPA_QUEUES + 0x100
    0x89, 0x08, //
    0xB8, 0xA0, 0x10, 0xB0, 0xFE, // mov eax, QUEUE_USED_LOW
    0xB9, 0x00, 0x62, 0x00, 0x00, // mov ecx, GPA_QUEUES + 0x200
    0x89, 0x08, //
    0xB8, 0x44, 0x10, 0xB0, 0xFE, // mov eax, QUEUE_READY
    0xB9, 0x01, 0x00, 0x00, 0x00, // mov ecx, 1
    0x89, 0x08, //
    0xB8, 0x50, 0x10, 0xB0, 0xFE, // mov eax, QUEUE_NOTIFY
    0xB9, 0x00, 0x00, 0x00, 0x00, // mov ecx, 0 (request queue)
    0x89, 0x08, //
    0x8A, 0x04, 0x25, 0x40, 0x70, 0x00, 0x00, // mov al, byte [0x7040]
    0xE6, 0xE9, // out 0xE9, al
    0xF4, // hlt
];

// Network phase.
/// Guest-physical address of the virtio network transport page.
const NET_MMIO_BASE: u64 = 0xFEB0_2000;
/// Frame the kernel sends through the transmit queue.
const NET_FRAME: &[u8] = b"PING";
/// Marker written by the guest once the transmit queue was notified.
const NET_MARKER: u8 = b'N';
/// Guest code of the network phase.
///
/// Programs the virtio network transport (status, transmit queue, queue
/// address registers, ready, notify), then reports through the debug port and
/// halts. The kernel checks the frame captured by the device model.
const NET_GUEST_CODE: &[u8] = &[
    0xB8, 0x70, 0x20, 0xB0, 0xFE, // mov eax, NET_MMIO_BASE + 0x70 (STATUS)
    0xB9, 0x0F, 0x00, 0x00, 0x00, // mov ecx, ACK | DRIVER | FEATURES_OK | DRIVER_OK
    0x89, 0x08, //
    0xB8, 0x30, 0x20, 0xB0, 0xFE, // mov eax, QUEUE_SEL
    0xB9, 0x01, 0x00, 0x00, 0x00, // mov ecx, 1 (transmit queue)
    0x89, 0x08, //
    0xB8, 0x38, 0x20, 0xB0, 0xFE, // mov eax, QUEUE_NUM
    0xB9, 0x08, 0x00, 0x00, 0x00, // mov ecx, 8
    0x89, 0x08, //
    0xB8, 0x80, 0x20, 0xB0, 0xFE, // mov eax, QUEUE_DESC_LOW
    0xB9, 0x00, 0x60, 0x00, 0x00, // mov ecx, GPA_QUEUES
    0x89, 0x08, //
    0xB8, 0x90, 0x20, 0xB0, 0xFE, // mov eax, QUEUE_AVAIL_LOW
    0xB9, 0x00, 0x61, 0x00, 0x00, // mov ecx, GPA_QUEUES + 0x100
    0x89, 0x08, //
    0xB8, 0xA0, 0x20, 0xB0, 0xFE, // mov eax, QUEUE_USED_LOW
    0xB9, 0x00, 0x62, 0x00, 0x00, // mov ecx, GPA_QUEUES + 0x200
    0x89, 0x08, //
    0xB8, 0x44, 0x20, 0xB0, 0xFE, // mov eax, QUEUE_READY
    0xB9, 0x01, 0x00, 0x00, 0x00, // mov ecx, 1
    0x89, 0x08, //
    0xB8, 0x50, 0x20, 0xB0, 0xFE, // mov eax, QUEUE_NOTIFY
    0xB9, 0x01, 0x00, 0x00, 0x00, // mov ecx, 1 (transmit queue)
    0x89, 0x08, //
    0xB0, NET_MARKER, // mov al, marker
    0xE6, 0xE9, // out 0xE9, al
    0xF4, // hlt
];

// Loader phase.
/// Guest-physical address of the page-table root used by the loaded guest.
const LOADER_GPA_PML4: u64 = 0x0000;
/// Guest-physical address of the page-directory pointer table.
const LOADER_GPA_PDPT: u64 = 0x1000;
/// Guest-physical address of the page directory.
const LOADER_GPA_PD: u64 = 0x2000;
/// Guest-physical address of the page table (identity maps 0..2 MiB).
const LOADER_GPA_PT: u64 = 0x3000;
/// Guest-physical base address where the generated ELF image is loaded.
const LOADER_IMAGE_BASE: u64 = 0x1_0000;
/// Guest-physical page used as the guest stack.
const LOADER_GPA_STACK: u64 = 0x2_0000;
/// Initial guest stack pointer (inside the stack page).
const LOADER_STACK_TOP: u64 = LOADER_GPA_STACK + 0x800;
/// Guest memory permissions of the loader phase (read | write | execute).
const LOADER_GUEST_PERMS: u32 = 7;
/// Offset of the guest code inside the generated image.
const LOADER_CODE_OFFSET: u64 = 0x100;
/// Size of an ELF64 header.
const ELF_HEADER_SIZE: usize = 64;
/// Size of one ELF64 program header.
const ELF_PROGRAM_HEADER_SIZE: usize = 56;

// ACPI-discovery phase.
//
// The guest scans the legacy BIOS window `ACPI_SCAN_START..ACPI_SCAN_END` for
// the RSDP, validates it, walks the XSDT and the MADT. Every page the payload
// touches is identity-mapped by one page table covering the first 2 MiB, so
// the scan window, the code and the stack share the same flat mapping.
/// Guest-physical address of the page-table root.
const ACPI_GPA_PML4: u64 = 0x0000;
/// Guest-physical address of the page-directory pointer table.
const ACPI_GPA_PDPT: u64 = 0x1000;
/// Guest-physical address of the page directory.
const ACPI_GPA_PD: u64 = 0x2000;
/// Guest-physical address of the page table (identity maps 0..2 MiB).
const ACPI_GPA_PT: u64 = 0x3000;
/// Guest-physical page holding the discovery payload.
const ACPI_GPA_CODE: u64 = 0x1_0000;
/// Guest-physical page used as the guest stack.
const ACPI_GPA_STACK: u64 = 0x1_1000;
/// Initial guest stack pointer (inside the stack page).
const ACPI_STACK_TOP: u64 = ACPI_GPA_STACK + 0x800;
/// First guest-physical address of the scan window (legacy EBDA/BIOS area).
const ACPI_SCAN_START: u64 = vm::ACPI_GPA;
/// End (exclusive) of the scan window covered by the ACPI specification.
const ACPI_SCAN_END: u64 = 0x10_0000;
/// Number of 4 KiB guest pages in the scan window.
const ACPI_SCAN_PAGES: u64 = (ACPI_SCAN_END - ACPI_SCAN_START) / crate::s9vm::mmu::PAGE_SIZE;
/// Guest memory permissions of the page tables, the code and the stack.
const ACPI_GUEST_PERMS: u32 = 7;
/// Read-only guest permissions of the scan window (the guest only reads it).
const ACPI_SCAN_PERMS: u32 = 1;
/// Maximum number of exits driven for the ACPI phase (safety bound).
const ACPI_MAX_EXITS: u32 = 64;

/// Deferred request flag for the ACPI phase (see [`s9vm_acpi_selftest`]).
static ACPI_SELFTEST_REQUESTED: AtomicBool = AtomicBool::new(false);

// SMP (multi-vCPU) phase.
//
// One world hosts two vCPUs. Each vCPU has its own page tables, code page and
// stack page, so the two guest contexts differ in CR3, RIP, RSP and marker;
// both also write their marker into one shared guest page. The phase drives
// the vCPUs through the kernel tasks (`request_run`) in an interleaved order:
// round 0 runs both vCPUs to their `out` exit, round 1 resumes both from their
// saved state to the `hlt` exit.
/// Guest-physical page-table root of the first vCPU.
const SMP_VCPU0_GPA_PML4: u64 = 0x0000;
/// Guest-physical page-directory pointer table of the first vCPU.
const SMP_VCPU0_GPA_PDPT: u64 = 0x1000;
/// Guest-physical page directory of the first vCPU.
const SMP_VCPU0_GPA_PD: u64 = 0x2000;
/// Guest-physical page table of the first vCPU.
const SMP_VCPU0_GPA_PT: u64 = 0x3000;
/// Code page of the first vCPU.
const SMP_VCPU0_GPA_CODE: u64 = 0x1_0000;
/// Stack page of the first vCPU.
const SMP_VCPU0_GPA_STACK: u64 = 0x1_1000;
/// Guest-physical page-table root of the second vCPU.
const SMP_VCPU1_GPA_PML4: u64 = 0x8000;
/// Guest-physical page-directory pointer table of the second vCPU.
const SMP_VCPU1_GPA_PDPT: u64 = 0x9000;
/// Guest-physical page directory of the second vCPU.
const SMP_VCPU1_GPA_PD: u64 = 0xA000;
/// Guest-physical page table of the second vCPU.
const SMP_VCPU1_GPA_PT: u64 = 0xB000;
/// Code page of the second vCPU.
const SMP_VCPU1_GPA_CODE: u64 = 0x1_2000;
/// Stack page of the second vCPU.
const SMP_VCPU1_GPA_STACK: u64 = 0x1_3000;
/// Guest memory permissions of the SMP page tables, code and stacks.
const SMP_GUEST_PERMS: u32 = 7;
/// Maximum number of `request_run` calls driven by the SMP phase.
const SMP_MAX_RUNS: u32 = 8;

/// Static description of one vCPU of the SMP phase.
struct SmpLayout {
    pml4: u64,
    pdpt: u64,
    pd: u64,
    pt: u64,
    code: u64,
    stack: u64,
    stack_top: u64,
    marker: u8,
    payload: &'static [u8],
}

/// Layouts of the two vCPUs, in APIC-id order.
const SMP_LAYOUTS: [SmpLayout; 2] = [
    SmpLayout {
        pml4: SMP_VCPU0_GPA_PML4,
        pdpt: SMP_VCPU0_GPA_PDPT,
        pd: SMP_VCPU0_GPA_PD,
        pt: SMP_VCPU0_GPA_PT,
        code: SMP_VCPU0_GPA_CODE,
        stack: SMP_VCPU0_GPA_STACK,
        stack_top: SMP_VCPU0_GPA_STACK + 0x800,
        marker: SMP_MARKERS[0],
        payload: SMP_CODE_0,
    },
    SmpLayout {
        pml4: SMP_VCPU1_GPA_PML4,
        pdpt: SMP_VCPU1_GPA_PDPT,
        pd: SMP_VCPU1_GPA_PD,
        pt: SMP_VCPU1_GPA_PT,
        code: SMP_VCPU1_GPA_CODE,
        stack: SMP_VCPU1_GPA_STACK,
        stack_top: SMP_VCPU1_GPA_STACK + 0x800,
        marker: SMP_MARKERS[1],
        payload: SMP_CODE_1,
    },
];

/// Bounded wait for one smoke RUN (500 ms).
const KTHREAD_SMOKE_RUN_NS: u64 = 500_000_000;
/// Bounded wait for destroying the smoke world (2 s).
const KTHREAD_SMOKE_DESTROY_NS: u64 = 2_000_000_000;
/// Deferred request flag for the SMP phase (see [`s9vm_smp_selftest`]).
static SMP_SELFTEST_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Flat 64-bit code descriptor (selector `0x08`).
///
/// Interrupt delivery reloads `CS` from the gate selector, which requires the
/// code-segment descriptor to exist in the GDT: without a GDT the delivery
/// raises `#GP`, and with no handler for `#GP` the guest triple-faults.
const GDT_CODE64: u64 = 0x00AF_9A00_0000_FFFF;
/// Flat data descriptor (selector `0x10`).
const GDT_DATA: u64 = 0x00CF_9200_0000_FFFF;
/// Vector delivered by the kernel.
const IRQ_VECTOR: u8 = 0x20;
/// Byte written by the interrupt handler to the debug port.
const IRQ_BYTE: u8 = 0x42;
/// Offset of the handler inside the code page.
const IRQ_HANDLER_OFFSET: u64 = 8;

/// Guest code of the interrupt phase.
///
/// Entry: `sti` ; `nop` ; `hlt` ; padding. Handler (offset 8): writes the
/// marker byte to the debug port, then halts.
const IRQ_GUEST_CODE: [u8; 16] = [
    0xFB, 0x90, 0xF4, 0x00, 0x00, 0x00, 0x00, 0x00, // sti ; nop ; hlt
    0xB0, IRQ_BYTE, 0xE6, 0xE9, 0xF4, 0x00, 0x00, 0x00, // mov al,0x42; out 0xE9,al; hlt
];

/// Errors of the smoke test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelftestError {
    OutOfMemory,
    Mmu,
    Vcpu(VcpuError),
    BadExit(&'static str),
    VmFail(u32),
}

impl From<VcpuError> for SelftestError {
    fn from(value: VcpuError) -> Self {
        Self::Vcpu(value)
    }
}

/// Detailed result, logged by the caller.
pub struct SelftestReport {
    pub io_exits: u32,
    pub halt_exits: u32,
    pub total_exits: u32,
    /// Exits replayed by the kernel device model (never reported to policy).
    pub emulated_exits: u32,
    /// Last value read by the guest from the PIC data port.
    pub pic_readback: Option<u8>,
    /// Guest time slices that expired during the test.
    pub timer_exits: u32,
    pub observed_byte: Option<u8>,
    /// Name of the guest-state variant that entered successfully.
    pub variant: &'static str,
}

/// Allocates a zeroed frame for the guest.
fn alloc_frame() -> Result<PhysFrame, SelftestError> {
    crate::sync::with_irqs_disabled(|token| {
        FrameAllocOptions::new()
            .purpose(FramePurpose::KernelData)
            .allocate(token)
    })
    .map_err(|_| SelftestError::OutOfMemory)
}

/// Writes a 64-bit value into a frame through the HHDM.
fn write_u64(frame: &PhysFrame, offset: usize, value: u64) {
    let base = crate::memory::phys_to_virt(frame.start_address.as_u64()) as *mut u8;
    // SAFETY: the frame is 4 KiB and `offset` is a valid offset.
    unsafe {
        core::ptr::write_volatile(base.add(offset) as *mut u64, value);
    }
}

/// Writes bytes at `offset` inside a frame through the HHDM.
fn write_bytes_at(frame: &PhysFrame, offset: usize, bytes: &[u8]) {
    let base = crate::memory::phys_to_virt(frame.start_address.as_u64()) as *mut u8;
    // SAFETY: the frame is 4 KiB and `offset + bytes.len()` stays inside it.
    unsafe {
        for (index, byte) in bytes.iter().enumerate() {
            core::ptr::write_volatile(base.add(offset + index), *byte);
        }
    }
}

/// Writes bytes into a frame through the HHDM.
fn write_bytes(frame: &PhysFrame, bytes: &[u8]) {
    let base = crate::memory::phys_to_virt(frame.start_address.as_u64()) as *mut u8;
    // SAFETY: the frame is 4 KiB and `bytes` fits in one page.
    unsafe {
        for (index, byte) in bytes.iter().enumerate() {
            core::ptr::write_volatile(base.add(index), *byte);
        }
    }
}

/// Enters the canonical guest and drives its exits. Returns a report on success.
fn run_guest(
    caps: &HwCaps,
    second_level_pointer: u64,
    guest: &GuestState,
) -> Result<SelftestReport, SelftestError> {
    let mut vcpu = Vcpu::new(caps, second_level_pointer)?;

    // Local validation before entry: a state refused here would produce a
    // "VM entry with invalid guest state" that is difficult to diagnose.
    let fixed = crate::s9vm::guest::FixedBits {
        cr0_fixed0: caps.cr0_fixed0,
        cr0_fixed1: caps.cr0_fixed1,
        cr4_fixed0: caps.cr4_fixed0,
        cr4_fixed1: caps.cr4_fixed1,
    };
    if let Err(error) = guest.validate(&fixed, caps.unrestricted_guest) {
        log::warn!("[s9vm] guest state refused by validate(): {:?}", error);
    }

    // SAFETY: VT-x is active on this CPU (checked by the caller), interrupts
    // are disabled at the bootstrap stage, and the control
    // block has just been created for this vCPU.
    Vcpu::set_write_trace(true);
    unsafe {
        vcpu.load()?;
        let error = vcpu.instruction_error();
        if error != 0 {
            log::warn!("[s9vm] instruction error after load: {:#x}", error);
        }
        vcpu.configure_host()?;
        let error = vcpu.instruction_error();
        if error != 0 {
            log::warn!("[s9vm] instruction error after host state: {:#x}", error);
        }
        vcpu.configure(caps, guest)?;
        let error = vcpu.instruction_error();
        if error != 0 {
            log::warn!("[s9vm] instruction error after guest state: {:#x}", error);
        }
        if let Some((field, error)) = Vcpu::write_trace_failure() {
            log::warn!(
                "[s9vm] first rejected vmwrite: field={:#x} error={:#x}",
                field,
                error
            );
        }
    }
    Vcpu::set_write_trace(false);

    let mut report = SelftestReport {
        io_exits: 0,
        halt_exits: 0,
        total_exits: 0,
        emulated_exits: 0,
        pic_readback: None,
        timer_exits: 0,
        observed_byte: None,
        variant: "",
    };

    // Kernel device model: exits on these devices are replayed in place.
    let mut machine = Machine::new();
    let mut apic = LocalApic::new(0);

    let mut outcome: Result<(), SelftestError> = Ok(());
    for _ in 0..64 {
        // SAFETY: `run` contract (block loaded, IRQs disabled).
        let exit = match unsafe { vcpu.run() } {
            Ok(exit) => exit,
            Err(error) => {
                // SAFETY: the control block is still loaded; useful
                // diagnostic for `VmFail(8/9)` failures.
                unsafe {
                    log::warn!("[s9vm] {}", vcpu.host_diagnostics());
                }
                outcome = Err(SelftestError::from(error));
                break;
            }
        };
        report.total_exits += 1;
        let class = ExitReason::decode(exit.raw_reason).class();
        // Kernel fast path first: modeled device accesses are replayed in
        // place and never reach the policy path.
        if matches!(
            class,
            ExitClass::IoPort | ExitClass::Msr | ExitClass::EptViolation
        ) {
            // SAFETY: the control block is loaded and the guest is not
            // running (we are in the exit handler).
            match unsafe { machine.handle(&mut vcpu, &mut apic, &exit) } {
                Ok(true) => {
                    report.emulated_exits += 1;
                    let port = ((exit.qualification >> 16) & 0xFFFF) as u16;
                    let is_in = (exit.qualification >> 3) & 0x1 != 0;
                    if class == ExitClass::IoPort && port == PIC_DATA_PORT && is_in {
                        report.pic_readback = Some((vcpu.guest().rax & 0xFF) as u8);
                    }
                    continue;
                }
                Ok(false) | Err(_) => {}
            }
        }
        match class {
            ExitClass::IoPort => {
                report.io_exits += 1;
                // I/O qualification: port in bits 16..31.
                let port = ((exit.qualification >> 16) & 0xFFFF) as u16;
                if port == TEST_PORT {
                    report.observed_byte = Some((vcpu.guest().rax & 0xFF) as u8);
                }
                log::info!(
                    "[s9vm] I/O exit port={:#x} byte={:?} rip={:#x} len={}",
                    port,
                    report.observed_byte,
                    vcpu.guest().rip,
                    exit.instruction_length
                );
                // On a VM exit caused by an I/O instruction, GUEST_RIP points at
                // the instruction itself, not the next one: the processor does
                // not auto-advance. Skip it with the reported instruction length,
                // otherwise the resume re-executes the `out` forever.
                // SAFETY: the control block is loaded and the guest is inactive.
                unsafe {
                    vcpu.advance_rip(u64::from(exit.instruction_length))?;
                }
            }
            ExitClass::Halt => {
                report.halt_exits += 1;
                break;
            }
            ExitClass::ExternalInterrupt | ExitClass::InterruptWindow => {
                // At boot, host interrupts are masked: we simply
                // resume the guest.
            }
            ExitClass::PreemptionTimer => {
                // The guest time slice expired before the test finished: the
                // test is short, so this only happens on a very slow host.
                report.timer_exits += 1;
            }
            ExitClass::EntryFailure => {
                // SAFETY: the control block is still loaded; diagnostic
                // of the guest field refused by the processor.
                unsafe {
                    log::warn!("[s9vm] {}", vcpu.guest_diagnostics());
                }
                outcome = Err(SelftestError::BadExit("entry failure"));
                break;
            }
            _ => {
                let reason = ExitReason::decode(exit.raw_reason).reason;
                log::warn!(
                    "[s9vm] unexpected exit: reason={:#x} ({}) class={:?} qual={:#x} \
                     rip={:#x} exits={}",
                    reason,
                    reason_name(reason),
                    class,
                    exit.qualification,
                    vcpu.guest().rip,
                    report.total_exits,
                );
                // SAFETY: the control block is still loaded.
                unsafe {
                    log::warn!("[s9vm] {}", vcpu.guest_diagnostics());
                }
                outcome = Err(SelftestError::BadExit("unexpected exit"));
                break;
            }
        }
    }

    // SAFETY: the vCPU is no longer active; we unload its control block.
    unsafe {
        let _ = vcpu.clear();
    }

    match outcome {
        Ok(())
            if report.io_exits == 1
                && report.halt_exits >= 1
                && report.emulated_exits >= 1
                && report.pic_readback == Some(PIC_READBACK) =>
        {
            Ok(report)
        }
        Ok(()) => Err(SelftestError::BadExit("guest device fast path failed")),
        Err(error) => Err(error),
    }
}

/// Runs the smoke test. Returns the report of the first variant that entered.
pub fn run(caps: &HwCaps) -> Result<SelftestReport, SelftestError> {
    if !caps.can_run() {
        return Err(SelftestError::BadExit("platform cannot run"));
    }

    // Guest pages: PML4, PDPT, PD, code, stack, PT.
    let pml4 = alloc_frame()?;
    let pdpt = alloc_frame()?;
    let pd = alloc_frame()?;
    let code = alloc_frame()?;
    let stack = alloc_frame()?;
    let pt = alloc_frame()?;

    // Guest paging tables: GVA = GPA identity over 6 pages.
    //
    // The entries must hold *guest-physical* addresses (the GPA_* constants),
    // not the host-physical frame addresses: the guest MMU walk yields GPAs,
    // which the EPT then translates to HPAs. Writing HPAs here sends the walk
    // to an unmapped GPA (EPT violation on the second level).
    write_u64(&pml4, 0, GPA_PDPT | 0x3);
    write_u64(&pdpt, 0, GPA_PD | 0x3);
    write_u64(&pd, 0, GPA_PT | 0x3);
    for page in 0..GUEST_PAGES {
        let gpa = page * crate::s9vm::mmu::PAGE_SIZE;
        write_u64(&pt, page as usize * 8, gpa | 0x3);
    }

    // Guest code:
    //   1. program the master 8259A (ICW1..ICW4) through ports 0x20/0x21;
    //   2. mask every line, then read the mask back (kernel fast path);
    //   3. write one byte to the debug port (policy path) and halt.
    // Steps 1 and 2 must be serviced by the kernel without a policy exit.
    write_bytes(
        &code,
        &[
            0xB0,
            0x11,
            0xE6,
            0x20, // mov al, 0x11 ; out 0x20, al (ICW1)
            0xB0,
            0x20,
            0xE6,
            0x21, // mov al, 0x20 ; out 0x21, al (ICW2)
            0xB0,
            0x04,
            0xE6,
            0x21, // mov al, 0x04 ; out 0x21, al (ICW3)
            0xB0,
            0x01,
            0xE6,
            0x21, // mov al, 0x01 ; out 0x21, al (ICW4)
            0xB0,
            0x00,
            0xE6,
            0x21, // mov al, 0x00 ; out 0x21, al (unmask)
            0xE4,
            0x21, // in al, 0x21 (mask = 0x00)
            0xB0,
            PIC_READBACK,
            0xE6,
            0x21, // mov al, 0xFF ; out 0x21, al
            0xE4,
            0x21, // in al, 0x21 (mask = 0xFF)
            0xB0,
            TEST_BYTE,
            0xE6,
            TEST_PORT as u8, // mov al, byte ; out 0xE9, al
            0xF4,            // hlt
        ],
    );

    // Second-level translation: GPA → HPA for the 6 pages.
    let mut second_level = SecondLevelMemory::new().map_err(|_| SelftestError::Mmu)?;
    let pages = [
        (GPA_PML4, &pml4),
        (GPA_PDPT, &pdpt),
        (GPA_PD, &pd),
        (GPA_CODE, &code),
        (GPA_STACK, &stack),
        (GPA_PT, &pt),
    ];
    for (gpa, frame) in pages {
        second_level
            .map_4k(
                gpa,
                frame.start_address.as_u64(),
                crate::s9vm::mmu::Perms::read_write_execute(),
            )
            .map_err(|_| SelftestError::Mmu)?;
    }
    let pointer = second_level.pointer(caps);

    let guest = GuestState::long_mode_64(ENTRY_POINT, STACK_TOP, GPA_PML4);
    match run_guest(caps, pointer, &guest) {
        Ok(mut report) => {
            report.variant = "canonical";
            log::info!("[s9vm] guest entered (canonical 64-bit flat state)");
            Ok(report)
        }
        Err(error) => {
            log::warn!("[s9vm] guest failed: {:?}", error);
            Err(error)
        }
    }
}

/// Report of the interrupt-delivery phase.
pub struct InterruptReport {
    pub total_exits: u32,
    pub window_exits: u32,
    pub io_exits: u32,
    pub halt_exits: u32,
    pub injected: u32,
    pub observed_byte: Option<u8>,
}

/// Interrupt-delivery test.
///
/// The guest installs an interrupt gate for [`IRQ_VECTOR`], enables
/// interrupts, and expects the vector injected by the kernel. This exercises
/// the interrupt window: the guest is not interruptible at entry (`IF = 0`),
/// so the kernel arms interrupt-window exiting; the `sti` opens the window,
/// the kernel injects the pending vector, and the handler runs.
pub fn run_interrupt(caps: &HwCaps) -> Result<InterruptReport, SelftestError> {
    if !caps.can_run() {
        return Err(SelftestError::BadExit("platform cannot run"));
    }

    // Guest pages: tables, code, stack, IDT.
    let pml4 = alloc_frame()?;
    let pdpt = alloc_frame()?;
    let pd = alloc_frame()?;
    let code = alloc_frame()?;
    let stack = alloc_frame()?;
    let pt = alloc_frame()?;
    let idt = alloc_frame()?;
    let gdt = alloc_frame()?;

    // Identity guest paging over the eight pages.
    write_u64(&pml4, 0, GPA_PDPT | 0x3);
    write_u64(&pdpt, 0, GPA_PD | 0x3);
    write_u64(&pd, 0, GPA_PT | 0x3);
    for page in 0..IRQ_GUEST_PAGES {
        let gpa = page * crate::s9vm::mmu::PAGE_SIZE;
        write_u64(&pt, page as usize * 8, gpa | 0x3);
    }

    write_bytes(&code, &IRQ_GUEST_CODE);

    // Interrupt gate: present, DPL 0, 64-bit interrupt gate (type 0xE).
    let handler = GPA_CODE + IRQ_HANDLER_OFFSET;
    let low = (handler & 0xFFFF)
        | (0x8 << 16)          // code selector
        | (0x8E << 40)         // type: present, DPL 0, 64-bit interrupt gate
        | (((handler >> 16) & 0xFFFF) << 48);
    let high = handler >> 32;
    let entry_offset = usize::from(IRQ_VECTOR) * 16;
    write_u64(&idt, entry_offset, low);
    write_u64(&idt, entry_offset + 8, high);

    // Minimal GDT: null, 64-bit code (0x08), flat data (0x10).
    write_u64(&gdt, 8, GDT_CODE64);
    write_u64(&gdt, 16, GDT_DATA);

    // Second-level translation.
    let mut second_level = SecondLevelMemory::new().map_err(|_| SelftestError::Mmu)?;
    let pages = [
        (GPA_PML4, &pml4),
        (GPA_PDPT, &pdpt),
        (GPA_PD, &pd),
        (GPA_CODE, &code),
        (GPA_STACK, &stack),
        (GPA_PT, &pt),
        (GPA_IDT, &idt),
        (GPA_GDT, &gdt),
    ];
    for (gpa, frame) in pages {
        second_level
            .map_4k(
                gpa,
                frame.start_address.as_u64(),
                crate::s9vm::mmu::Perms::read_write_execute(),
            )
            .map_err(|_| SelftestError::Mmu)?;
    }
    let pointer = second_level.pointer(caps);

    // The guest starts with interrupts disabled; the kernel will arm the
    // interrupt window.
    let mut guest = GuestState::long_mode_64(ENTRY_POINT, STACK_TOP, GPA_PML4);
    guest.idtr_base = GPA_IDT;
    guest.idtr_limit = u32::from(IRQ_VECTOR) * 16 + 15;
    // Interrupt delivery reloads CS from the gate selector, which reads the
    // code-segment descriptor from the GDT.
    guest.gdtr_base = GPA_GDT;
    guest.gdtr_limit = 16 + 7;

    let mut vcpu = Vcpu::new(caps, pointer)?;
    // SAFETY: VT-x is active on this CPU (checked above), interrupts are
    // disabled, and the block was just created for this vCPU.
    unsafe {
        vcpu.load()?;
        vcpu.configure_host()?;
        vcpu.configure(caps, &guest)?;
    }

    let mut apic = LocalApic::new(0);
    apic.inject(IRQ_VECTOR);

    let mut report = InterruptReport {
        total_exits: 0,
        window_exits: 0,
        io_exits: 0,
        halt_exits: 0,
        injected: 0,
        observed_byte: None,
    };
    let mut window_armed = false;
    let mut outcome: Result<(), SelftestError> = Ok(());

    for _ in 0..32 {
        // Same delivery policy as the execution loop.
        let interruptible = vcpu.guest().rflags & (1 << 9) != 0;
        let pending = apic.pending_vector();
        match interrupt_action(pending.is_some(), interruptible, window_armed) {
            InterruptAction::Inject => {
                if let Some(vector) = pending {
                    // SAFETY: the block is loaded and the guest is inactive.
                    unsafe {
                        vcpu.inject_interrupt(vector)?;
                    }
                    let _ = apic.service();
                    report.injected += 1;
                }
                if window_armed {
                    // SAFETY: same contract.
                    unsafe {
                        vcpu.set_interrupt_window_exiting(caps, false)?;
                    }
                    window_armed = false;
                }
            }
            InterruptAction::ArmWindow => {
                // SAFETY: same contract.
                window_armed = unsafe { vcpu.set_interrupt_window_exiting(caps, true)? };
                if !window_armed {
                    outcome = Err(SelftestError::BadExit("interrupt window unavailable"));
                    break;
                }
            }
            InterruptAction::DisarmWindow => {
                // SAFETY: same contract.
                unsafe {
                    vcpu.set_interrupt_window_exiting(caps, false)?;
                }
                window_armed = false;
            }
            InterruptAction::None => {}
        }

        // SAFETY: `run` contract (block loaded, IRQs disabled).
        let exit = match unsafe { vcpu.run() } {
            Ok(exit) => exit,
            Err(error) => {
                outcome = Err(SelftestError::from(error));
                break;
            }
        };
        report.total_exits += 1;
        match ExitReason::decode(exit.raw_reason).class() {
            ExitClass::IoPort => {
                report.io_exits += 1;
                let port = ((exit.qualification >> 16) & 0xFFFF) as u16;
                if port == TEST_PORT {
                    report.observed_byte = Some((vcpu.guest().rax & 0xFF) as u8);
                }
                // SAFETY: block loaded, guest inactive.
                unsafe {
                    vcpu.advance_rip(u64::from(exit.instruction_length))?;
                }
            }
            ExitClass::Halt => {
                report.halt_exits += 1;
                break;
            }
            ExitClass::InterruptWindow => {
                report.window_exits += 1;
            }
            ExitClass::PreemptionTimer => {}
            ExitClass::ExternalInterrupt => {}
            other => {
                log::warn!(
                    "[s9vm] interrupt test: unexpected exit class={:?} reason={:#x} \
                     qual={:#x} intr={:#x} rflags={:#x} rip={:#x} window={}",
                    other,
                    exit.raw_reason,
                    exit.qualification,
                    exit.interrupt_info,
                    vcpu.guest().rflags,
                    vcpu.guest().rip,
                    window_armed
                );
                outcome = Err(SelftestError::BadExit("unexpected interrupt-test exit"));
                break;
            }
        }
    }

    // SAFETY: the vCPU is no longer active.
    unsafe {
        let _ = vcpu.clear();
    }

    match outcome {
        Ok(())
            if report.injected >= 1
                && report.halt_exits >= 1
                && report.observed_byte == Some(IRQ_BYTE) =>
        {
            Ok(report)
        }
        Ok(()) => Err(SelftestError::BadExit("interrupt was not delivered")),
        Err(error) => Err(error),
    }
}

/// Report of the console phase.
pub struct ConsoleReport {
    pub total_exits: u32,
    pub emulated_exits: u32,
    pub io_exits: u32,
    pub halt_exits: u32,
    pub marker: Option<u8>,
    pub output: Vec<u8>,
}

/// Console transport test.
///
/// The kernel prepares a transmit queue (descriptor, available ring, buffer)
/// **and** a receive queue in guest memory, and queues one input byte. The
/// guest programs the transport page, notifies the transmit queue (the device
/// must collect the buffer) and then the receive queue (the device must write
/// the queued byte into the guest buffer). The guest reports that byte on the
/// debug port. This validates both directions of the transport: EPT
/// violation, instruction replay, register file, split-queue access to guest
/// memory, and the input/output routing.
pub fn run_console(caps: &HwCaps) -> Result<ConsoleReport, SelftestError> {
    if !caps.can_run() {
        return Err(SelftestError::BadExit("platform cannot run"));
    }

    let pml4 = alloc_frame()?;
    let pdpt = alloc_frame()?;
    let pd = alloc_frame()?;
    let pt = alloc_frame()?;
    let code = alloc_frame()?;
    let stack = alloc_frame()?;
    let queues = alloc_frame()?;
    let buffer = alloc_frame()?;
    let pd_high = alloc_frame()?;

    // Identity guest paging over the nine pages, plus a 2 MiB identity page
    // covering the device MMIO window. Without it the guest would take a page
    // fault (unmapped linear address) *before* the EPT violation that the
    // transport emulation relies on, and with no IDT that is a triple fault.
    write_u64(&pml4, 0, CONSOLE_GPA_PDPT | 0x3);
    write_u64(&pdpt, 0, CONSOLE_GPA_PD | 0x3);
    write_u64(&pdpt, 3 * 8, CONSOLE_GPA_PD_HIGH | 0x3);
    write_u64(&pd, 0, CONSOLE_GPA_PT | 0x3);
    write_u64(
        &pd_high,
        CONSOLE_PD_MMIO_INDEX * 8,
        CONSOLE_GPA_MMIO_WINDOW | 0x83, // present | read-write | 2 MiB page
    );
    for page in 0..CONSOLE_GUEST_PAGES {
        let gpa = page * crate::s9vm::mmu::PAGE_SIZE;
        write_u64(&pt, page as usize * 8, gpa | 0x3);
    }

    write_bytes(&code, CONSOLE_GUEST_CODE);

    // Transmit queue prepared by the kernel:
    // - descriptor 0 at offset 0: device-readable buffer;
    // - available ring at offset 0x100: one published descriptor;
    // - used ring at offset 0x200: zeroed.
    let descriptor: [u8; 16] = {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&GPA_CONSOLE_BUFFER.to_le_bytes());
        bytes[8..12].copy_from_slice(&(CONSOLE_TEXT.len() as u32).to_le_bytes());
        bytes
    };
    write_bytes(&queues, &descriptor);
    // flags = 0, idx = 1, ring[0] = 0 (transmit).
    write_u64(&queues, 0x100, 1 << 16);

    // Receive queue: descriptor 0 at +0x400 points to the buffer at +0x7400
    // and is device-writable; available ring at +0x500 publishes it.
    let receive = [0u8; 16];
    let mut receive = receive;
    receive[..8].copy_from_slice(&(GPA_CONSOLE_BUFFER + 0x400).to_le_bytes());
    receive[8..12].copy_from_slice(&16u32.to_le_bytes());
    receive[12..14].copy_from_slice(&virtio::DESC_F_WRITE.to_le_bytes());
    write_bytes(&queues, &[]);
    write_bytes_at(&queues, 0x400, &receive);
    write_u64(&queues, 0x500, 1 << 16);

    write_bytes(&buffer, CONSOLE_TEXT);

    let mut second_level = SecondLevelMemory::new().map_err(|_| SelftestError::Mmu)?;
    let pages = [
        (CONSOLE_GPA_PML4, &pml4),
        (CONSOLE_GPA_PDPT, &pdpt),
        (CONSOLE_GPA_PD, &pd),
        (CONSOLE_GPA_PT, &pt),
        (CONSOLE_GPA_CODE, &code),
        (CONSOLE_GPA_STACK, &stack),
        (GPA_QUEUES, &queues),
        (GPA_CONSOLE_BUFFER, &buffer),
        (CONSOLE_GPA_PD_HIGH, &pd_high),
    ];
    for (gpa, frame) in pages {
        second_level
            .map_4k(
                gpa,
                frame.start_address.as_u64(),
                crate::s9vm::mmu::Perms::read_write_execute(),
            )
            .map_err(|_| SelftestError::Mmu)?;
    }
    let pointer = second_level.pointer(caps);

    let guest = GuestState::long_mode_64(
        CONSOLE_GPA_CODE,
        CONSOLE_GPA_STACK + 0x800,
        CONSOLE_GPA_PML4,
    );
    let mut vcpu = Vcpu::new(caps, pointer)?;
    // SAFETY: VT-x is active on this CPU, interrupts are disabled and the
    // control block was just created for this vCPU.
    unsafe {
        vcpu.load()?;
        vcpu.configure_host()?;
        vcpu.configure(caps, &guest)?;
    }

    let mut machine = Machine::new();
    // One byte is waiting in the console input queue before the guest starts.
    machine.devices_mut().console.push_input(&[CONSOLE_RX_BYTE]);
    let mut apic = LocalApic::new(0);
    let mut report = ConsoleReport {
        total_exits: 0,
        emulated_exits: 0,
        io_exits: 0,
        halt_exits: 0,
        marker: None,
        output: Vec::new(),
    };
    let mut outcome: Result<(), SelftestError> = Ok(());

    for _ in 0..64 {
        // SAFETY: `run` contract (block loaded, IRQs disabled).
        let exit = match unsafe { vcpu.run() } {
            Ok(exit) => exit,
            Err(error) => {
                outcome = Err(SelftestError::from(error));
                break;
            }
        };
        report.total_exits += 1;
        let class = ExitReason::decode(exit.raw_reason).class();
        if matches!(
            class,
            ExitClass::IoPort | ExitClass::Msr | ExitClass::EptViolation
        ) {
            // SAFETY: block loaded, guest inactive.
            match unsafe { machine.handle(&mut vcpu, &mut apic, &exit) } {
                Ok(true) => {
                    report.emulated_exits += 1;
                    report.output.extend(machine.drain_console());
                    let port = ((exit.qualification >> 16) & 0xFFFF) as u16;
                    if class == ExitClass::IoPort && port == TEST_PORT {
                        report.marker = Some((vcpu.guest().rax & 0xFF) as u8);
                    }
                    continue;
                }
                Ok(false) | Err(_) => {}
            }
        }
        match class {
            ExitClass::IoPort => {
                report.io_exits += 1;
                let port = ((exit.qualification >> 16) & 0xFFFF) as u16;
                if port == TEST_PORT {
                    report.marker = Some((vcpu.guest().rax & 0xFF) as u8);
                }
                // SAFETY: block loaded, guest inactive.
                unsafe {
                    vcpu.advance_rip(u64::from(exit.instruction_length))?;
                }
            }
            ExitClass::Halt => {
                report.halt_exits += 1;
                break;
            }
            ExitClass::ExternalInterrupt | ExitClass::InterruptWindow => {}
            ExitClass::PreemptionTimer => {}
            other => {
                log::warn!(
                    "[s9vm] console test: unexpected exit class={:?} reason={:#x} \
                     qual={:#x} gpa={:#x} rip={:#x}",
                    other,
                    exit.raw_reason,
                    exit.qualification,
                    exit.guest_physical_address,
                    vcpu.guest().rip
                );
                outcome = Err(SelftestError::BadExit("unexpected console-test exit"));
                break;
            }
        }
    }

    // SAFETY: the vCPU is no longer active.
    unsafe {
        let _ = vcpu.clear();
    }

    match outcome {
        Ok(())
            if report.halt_exits >= 1
                && report.marker == Some(CONSOLE_RX_BYTE)
                && report.output == CONSOLE_TEXT =>
        {
            Ok(report)
        }
        Ok(()) => Err(SelftestError::BadExit("console data was not delivered")),
        Err(error) => Err(error),
    }
}

/// Report of the block phase.
pub struct BlockReport {
    pub total_exits: u32,
    pub emulated_exits: u32,
    pub io_exits: u32,
    pub halt_exits: u32,
    pub marker: Option<u8>,
    pub requests: u32,
    pub status: u8,
}

/// Block transport test.
///
/// The kernel publishes a read request in guest memory (header, 512-byte data
/// buffer, status byte) and pre-fills disk sector 0. The guest programs the
/// transport, notifies the request queue, and reads back the first byte of the
/// data buffer. This validates the block model end to end: EPT violation,
/// instruction replay, request parsing, disk access and completion.
pub fn run_blk(caps: &HwCaps) -> Result<BlockReport, SelftestError> {
    if !caps.can_run() {
        return Err(SelftestError::BadExit("platform cannot run"));
    }

    let pml4 = alloc_frame()?;
    let pdpt = alloc_frame()?;
    let pd = alloc_frame()?;
    let pt = alloc_frame()?;
    let code = alloc_frame()?;
    let stack = alloc_frame()?;
    let queues = alloc_frame()?;
    let buffer = alloc_frame()?;
    let pd_high = alloc_frame()?;

    // Same guest layout as the console phase: identity pages plus a 2 MiB
    // identity page covering the device MMIO window.
    write_u64(&pml4, 0, CONSOLE_GPA_PDPT | 0x3);
    write_u64(&pdpt, 0, CONSOLE_GPA_PD | 0x3);
    write_u64(&pdpt, 3 * 8, CONSOLE_GPA_PD_HIGH | 0x3);
    write_u64(&pd, 0, CONSOLE_GPA_PT | 0x3);
    write_u64(
        &pd_high,
        CONSOLE_PD_MMIO_INDEX * 8,
        CONSOLE_GPA_MMIO_WINDOW | 0x83,
    );
    for page in 0..CONSOLE_GUEST_PAGES {
        let gpa = page * crate::s9vm::mmu::PAGE_SIZE;
        write_u64(&pt, page as usize * 8, gpa | 0x3);
    }

    write_bytes(&code, BLK_GUEST_CODE);

    // Request prepared by the kernel:
    // - header at buffer+0x000 (type IN, sector 0);
    // - data buffer at buffer+0x040;
    // - status byte at buffer+0x400;
    // - descriptor chain: header (readable), data (writable), status (writable).
    write_u64(&buffer, 0, u64::from(virtio_blk::request::IN));
    write_u64(&buffer, 8, 0); // sector 0
    let mut descriptors = [0u8; 3 * 16];
    let header = virtio::Descriptor {
        addr: GPA_CONSOLE_BUFFER + 0x000,
        len: 16,
        flags: virtio::DESC_F_NEXT,
        next: 1,
    };
    let data = virtio::Descriptor {
        addr: GPA_CONSOLE_BUFFER + 0x040,
        len: 512,
        flags: virtio::DESC_F_NEXT | virtio::DESC_F_WRITE,
        next: 2,
    };
    let status = virtio::Descriptor {
        addr: GPA_CONSOLE_BUFFER + 0x400,
        len: 1,
        flags: virtio::DESC_F_WRITE,
        next: 0,
    };
    descriptors[..16].copy_from_slice(&header.encode());
    descriptors[16..32].copy_from_slice(&data.encode());
    descriptors[32..].copy_from_slice(&status.encode());
    write_bytes(&queues, &descriptors);
    // Available ring: idx = 1, ring[0] = 0.
    write_u64(&queues, 0x100, 1 << 16);

    let mut second_level = SecondLevelMemory::new().map_err(|_| SelftestError::Mmu)?;
    let pages = [
        (CONSOLE_GPA_PML4, &pml4),
        (CONSOLE_GPA_PDPT, &pdpt),
        (CONSOLE_GPA_PD, &pd),
        (CONSOLE_GPA_PT, &pt),
        (CONSOLE_GPA_CODE, &code),
        (CONSOLE_GPA_STACK, &stack),
        (GPA_QUEUES, &queues),
        (GPA_CONSOLE_BUFFER, &buffer),
        (CONSOLE_GPA_PD_HIGH, &pd_high),
    ];
    for (gpa, frame) in pages {
        second_level
            .map_4k(
                gpa,
                frame.start_address.as_u64(),
                crate::s9vm::mmu::Perms::read_write_execute(),
            )
            .map_err(|_| SelftestError::Mmu)?;
    }
    let pointer = second_level.pointer(caps);

    let guest = GuestState::long_mode_64(
        CONSOLE_GPA_CODE,
        CONSOLE_GPA_STACK + 0x800,
        CONSOLE_GPA_PML4,
    );
    let mut vcpu = Vcpu::new(caps, pointer)?;
    // SAFETY: VT-x active, interrupts disabled, control block freshly created.
    unsafe {
        vcpu.load()?;
        vcpu.configure_host()?;
        vcpu.configure(caps, &guest)?;
    }

    let mut machine = Machine::new();
    // Disk content: first sector starts with the marker the guest reads back.
    let mut sector = [0u8; 512];
    sector[0] = BLK_MARKER;
    sector[1] = b'K';
    machine.devices_mut().blk.write_sector(0, &sector);
    let mut apic = LocalApic::new(0);

    let mut report = BlockReport {
        total_exits: 0,
        emulated_exits: 0,
        io_exits: 0,
        halt_exits: 0,
        marker: None,
        requests: 0,
        status: 0,
    };
    let mut outcome: Result<(), SelftestError> = Ok(());

    for _ in 0..64 {
        // SAFETY: `run` contract.
        let exit = match unsafe { vcpu.run() } {
            Ok(exit) => exit,
            Err(error) => {
                outcome = Err(SelftestError::from(error));
                break;
            }
        };
        report.total_exits += 1;
        let class = ExitReason::decode(exit.raw_reason).class();
        if matches!(
            class,
            ExitClass::IoPort | ExitClass::Msr | ExitClass::EptViolation
        ) {
            // SAFETY: block loaded, guest inactive.
            match unsafe { machine.handle(&mut vcpu, &mut apic, &exit) } {
                Ok(true) => {
                    report.emulated_exits += 1;
                    let port = ((exit.qualification >> 16) & 0xFFFF) as u16;
                    if class == ExitClass::IoPort && port == TEST_PORT {
                        report.marker = Some((vcpu.guest().rax & 0xFF) as u8);
                    }
                    continue;
                }
                Ok(false) | Err(_) => {}
            }
        }
        match class {
            ExitClass::IoPort => {
                report.io_exits += 1;
                let port = ((exit.qualification >> 16) & 0xFFFF) as u16;
                if port == TEST_PORT {
                    report.marker = Some((vcpu.guest().rax & 0xFF) as u8);
                }
                // SAFETY: block loaded, guest inactive.
                unsafe {
                    vcpu.advance_rip(u64::from(exit.instruction_length))?;
                }
            }
            ExitClass::Halt => {
                report.halt_exits += 1;
                break;
            }
            ExitClass::ExternalInterrupt | ExitClass::InterruptWindow => {}
            ExitClass::PreemptionTimer => {}
            other => {
                log::warn!(
                    "[s9vm] block test: unexpected exit class={:?} reason={:#x} qual={:#x} \
                     gpa={:#x} rip={:#x}",
                    other,
                    exit.raw_reason,
                    exit.qualification,
                    exit.guest_physical_address,
                    vcpu.guest().rip
                );
                outcome = Err(SelftestError::BadExit("unexpected block-test exit"));
                break;
            }
        }
    }

    report.requests = machine.devices().blk.completed();
    report.status = machine.devices().blk.last_status();

    // SAFETY: the vCPU is no longer active.
    unsafe {
        let _ = vcpu.clear();
    }

    match outcome {
        Ok(())
            if report.halt_exits >= 1
                && report.marker == Some(BLK_MARKER)
                && report.status == virtio_blk::request_status::OK
                && report.requests >= 1 =>
        {
            Ok(report)
        }
        Ok(()) => Err(SelftestError::BadExit("block request was not served")),
        Err(error) => Err(error),
    }
}

/// Report of the network phase.
pub struct NetworkReport {
    pub total_exits: u32,
    pub emulated_exits: u32,
    pub halt_exits: u32,
    pub marker: Option<u8>,
    pub transmitted: u32,
    pub payload: Vec<u8>,
}

/// Network transport test.
///
/// The kernel publishes a transmit packet (10-byte virtio_net_hdr + payload)
/// in guest memory; the guest programs the transport and notifies the transmit
/// queue. The device model must capture the payload. This validates the
/// network transport page end to end.
pub fn run_net(caps: &HwCaps) -> Result<NetworkReport, SelftestError> {
    if !caps.can_run() {
        return Err(SelftestError::BadExit("platform cannot run"));
    }

    let pml4 = alloc_frame()?;
    let pdpt = alloc_frame()?;
    let pd = alloc_frame()?;
    let pt = alloc_frame()?;
    let code = alloc_frame()?;
    let stack = alloc_frame()?;
    let queues = alloc_frame()?;
    let buffer = alloc_frame()?;
    let pd_high = alloc_frame()?;

    write_u64(&pml4, 0, CONSOLE_GPA_PDPT | 0x3);
    write_u64(&pdpt, 0, CONSOLE_GPA_PD | 0x3);
    write_u64(&pdpt, 3 * 8, CONSOLE_GPA_PD_HIGH | 0x3);
    write_u64(&pd, 0, CONSOLE_GPA_PT | 0x3);
    write_u64(
        &pd_high,
        CONSOLE_PD_MMIO_INDEX * 8,
        CONSOLE_GPA_MMIO_WINDOW | 0x83,
    );
    for page in 0..CONSOLE_GUEST_PAGES {
        let gpa = page * crate::s9vm::mmu::PAGE_SIZE;
        write_u64(&pt, page as usize * 8, gpa | 0x3);
    }

    write_bytes(&code, NET_GUEST_CODE);

    // Transmit packet: zeroed network header, then the frame; one readable
    // descriptor publishes it.
    let mut packet = alloc::vec![0u8; virtio_net::NET_HDR_SIZE];
    packet.extend_from_slice(NET_FRAME);
    write_bytes(&buffer, &packet);
    let descriptor = virtio::Descriptor {
        addr: GPA_CONSOLE_BUFFER,
        len: packet.len() as u32,
        flags: 0,
        next: 0,
    };
    write_bytes(&queues, &descriptor.encode());
    // Available ring: idx = 1, ring[0] = 0.
    write_u64(&queues, 0x100, 1 << 16);

    let mut second_level = SecondLevelMemory::new().map_err(|_| SelftestError::Mmu)?;
    let pages = [
        (CONSOLE_GPA_PML4, &pml4),
        (CONSOLE_GPA_PDPT, &pdpt),
        (CONSOLE_GPA_PD, &pd),
        (CONSOLE_GPA_PT, &pt),
        (CONSOLE_GPA_CODE, &code),
        (CONSOLE_GPA_STACK, &stack),
        (GPA_QUEUES, &queues),
        (GPA_CONSOLE_BUFFER, &buffer),
        (CONSOLE_GPA_PD_HIGH, &pd_high),
    ];
    for (gpa, frame) in pages {
        second_level
            .map_4k(
                gpa,
                frame.start_address.as_u64(),
                crate::s9vm::mmu::Perms::read_write_execute(),
            )
            .map_err(|_| SelftestError::Mmu)?;
    }
    let pointer = second_level.pointer(caps);

    let guest = GuestState::long_mode_64(
        CONSOLE_GPA_CODE,
        CONSOLE_GPA_STACK + 0x800,
        CONSOLE_GPA_PML4,
    );
    let mut vcpu = Vcpu::new(caps, pointer)?;
    // SAFETY: VT-x active, interrupts disabled, control block freshly created.
    unsafe {
        vcpu.load()?;
        vcpu.configure_host()?;
        vcpu.configure(caps, &guest)?;
    }

    let mut machine = Machine::new();
    let mut apic = LocalApic::new(0);
    let mut report = NetworkReport {
        total_exits: 0,
        emulated_exits: 0,
        halt_exits: 0,
        marker: None,
        transmitted: 0,
        payload: Vec::new(),
    };
    let mut outcome: Result<(), SelftestError> = Ok(());

    for _ in 0..64 {
        // SAFETY: `run` contract.
        let exit = match unsafe { vcpu.run() } {
            Ok(exit) => exit,
            Err(error) => {
                outcome = Err(SelftestError::from(error));
                break;
            }
        };
        report.total_exits += 1;
        let class = ExitReason::decode(exit.raw_reason).class();
        if matches!(
            class,
            ExitClass::IoPort | ExitClass::Msr | ExitClass::EptViolation
        ) {
            // SAFETY: block loaded, guest inactive.
            match unsafe { machine.handle(&mut vcpu, &mut apic, &exit) } {
                Ok(true) => {
                    report.emulated_exits += 1;
                    let port = ((exit.qualification >> 16) & 0xFFFF) as u16;
                    if class == ExitClass::IoPort && port == TEST_PORT {
                        report.marker = Some((vcpu.guest().rax & 0xFF) as u8);
                    }
                    continue;
                }
                Ok(false) | Err(_) => {}
            }
        }
        match class {
            ExitClass::IoPort => {
                let port = ((exit.qualification >> 16) & 0xFFFF) as u16;
                if port == TEST_PORT {
                    report.marker = Some((vcpu.guest().rax & 0xFF) as u8);
                }
                // SAFETY: block loaded, guest inactive.
                unsafe {
                    vcpu.advance_rip(u64::from(exit.instruction_length))?;
                }
            }
            ExitClass::Halt => {
                report.halt_exits += 1;
                break;
            }
            ExitClass::ExternalInterrupt | ExitClass::InterruptWindow => {}
            ExitClass::PreemptionTimer => {}
            other => {
                log::warn!(
                    "[s9vm] network test: unexpected exit class={:?} reason={:#x} qual={:#x} \
                     gpa={:#x} rip={:#x}",
                    other,
                    exit.raw_reason,
                    exit.qualification,
                    exit.guest_physical_address,
                    vcpu.guest().rip
                );
                outcome = Err(SelftestError::BadExit("unexpected network-test exit"));
                break;
            }
        }
    }

    report.transmitted = machine.devices().net.frames_sent();
    report.payload = machine.drain_network();

    // SAFETY: the vCPU is no longer active.
    unsafe {
        let _ = vcpu.clear();
    }

    match outcome {
        Ok(())
            if report.halt_exits >= 1
                && report.marker == Some(NET_MARKER)
                && report.transmitted >= 1
                && report.payload == NET_FRAME =>
        {
            Ok(report)
        }
        Ok(()) => Err(SelftestError::BadExit("network frame was not transmitted")),
        Err(error) => Err(error),
    }
}

/// Report of the image-loader phase.
pub struct LoaderReport {
    pub total_exits: u32,
    pub io_exits: u32,
    pub halt_exits: u32,
    /// Byte written by the loaded guest on the debug port.
    pub marker: Option<u8>,
    /// Guest-physical entry point returned by the loader.
    pub entry: u64,
    /// Guest-physical image base address.
    pub image_base: u64,
    /// Guest pages covered by the loaded image span.
    pub pages: u64,
}

/// Writes a little-endian `u16` at `offset` inside a byte buffer.
fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

/// Writes a little-endian `u32` at `offset` inside a byte buffer.
fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Writes a little-endian `u64` at `offset` inside a byte buffer.
fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// Builds a minimal ELF64 guest image in kernel memory.
///
/// Layout: ELF64 header, one `PT_LOAD` program header, then the guest code at
/// [`LOADER_CODE_OFFSET`]. The segment is loaded at [`LOADER_IMAGE_BASE`], its
/// file-backed prefix (`p_filesz`) covers the header and the code, and its
/// memory size (`p_memsz`) is one full page: the loader must zero the rest of
/// the page (BSS).
fn loader_image() -> Vec<u8> {
    let page_size = crate::s9vm::mmu::PAGE_SIZE;
    let mut image = Vec::new();
    image.resize(ELF_HEADER_SIZE + ELF_PROGRAM_HEADER_SIZE, 0);
    image.resize(LOADER_CODE_OFFSET as usize, 0);
    image.extend_from_slice(LOADER_CODE);
    let file_size = image.len() as u64;

    image[0..4].copy_from_slice(b"\x7fELF");
    image[4] = 2; // ELFCLASS64
    image[5] = 1; // ELFDATA2LSB
    image[6] = 1; // EV_CURRENT
    put_u16(&mut image, 0x10, 2); // e_type = ET_EXEC
    put_u16(&mut image, 0x12, 62); // e_machine = EM_X86_64
    put_u32(&mut image, 0x14, 1); // e_version = EV_CURRENT
    put_u64(&mut image, 0x18, LOADER_IMAGE_BASE + LOADER_CODE_OFFSET); // e_entry
    put_u64(&mut image, 0x20, ELF_HEADER_SIZE as u64); // e_phoff
    put_u16(&mut image, 0x34, ELF_HEADER_SIZE as u16); // e_ehsize
    put_u16(&mut image, 0x36, ELF_PROGRAM_HEADER_SIZE as u16); // e_phentsize
    put_u16(&mut image, 0x38, 1); // e_phnum

    let phdr = ELF_HEADER_SIZE;
    put_u32(&mut image, phdr, 1); // p_type = PT_LOAD
    put_u32(&mut image, phdr + 4, 5); // p_flags = PF_R | PF_X
    put_u64(&mut image, phdr + 8, 0); // p_offset
    put_u64(&mut image, phdr + 16, LOADER_IMAGE_BASE); // p_vaddr
    put_u64(&mut image, phdr + 24, LOADER_IMAGE_BASE); // p_paddr
    put_u64(&mut image, phdr + 32, file_size); // p_filesz
    put_u64(&mut image, phdr + 40, page_size); // p_memsz (one page, BSS tail)
    put_u64(&mut image, phdr + 48, page_size); // p_align
    image
}

/// Returns the HHDM pointer of the guest page at `gpa` in a world.
fn world_page(world_id: u64, gpa: u64) -> Result<*mut u8, SelftestError> {
    let hpa = vm::debug_translate(world_id, gpa).ok_or(SelftestError::Mmu)?;
    Ok(crate::memory::phys_to_virt(hpa) as *mut u8)
}

/// Writes a 64-bit page-table entry at `offset` inside the guest page at `gpa`.
fn write_world_u64(
    world_id: u64,
    gpa: u64,
    offset: usize,
    value: u64,
) -> Result<(), SelftestError> {
    let page = world_page(world_id, gpa)?;
    // SAFETY: the page belongs to a world reserved for this test, is mapped by
    // the HHDM, and the callers keep `offset + 8` inside the 4 KiB page.
    unsafe {
        core::ptr::write_volatile(page.add(offset) as *mut u64, value);
    }
    Ok(())
}

/// Reads one byte of the guest page at `gpa` in a world.
fn read_world_byte(world_id: u64, gpa: u64) -> Result<u8, SelftestError> {
    let page = world_page(world_id, gpa)?;
    // SAFETY: same invariant as `write_world_u64`; the first byte is inside
    // the page.
    Ok(unsafe { core::ptr::read_volatile(page) })
}

/// Writes `bytes` at the start of the guest page at `gpa` in a world.
fn write_world_bytes(world_id: u64, gpa: u64, bytes: &[u8]) -> Result<(), SelftestError> {
    let page_size = crate::s9vm::mmu::PAGE_SIZE as usize;
    if bytes.len() > page_size {
        return Err(SelftestError::BadExit("payload crosses a page boundary"));
    }
    let page = world_page(world_id, gpa)?;
    // SAFETY: the page belongs to a world reserved for this test, is mapped by
    // the HHDM, and the length check above keeps the write inside the page.
    unsafe {
        for (index, byte) in bytes.iter().enumerate() {
            core::ptr::write_volatile(page.add(index), *byte);
        }
    }
    Ok(())
}

/// Image-loader test.
///
/// Builds a small ELF64 image in kernel memory and loads it into a fresh world
/// with [`vm::load_image`]: guest pages mapped through `map_memory`, file-backed
/// bytes copied page by page (GPA -> HPA -> HHDM), zero-filled tail. The image
/// is then entered exactly like the other phases: the guest writes its marker
/// on the debug port and halts. The guest page tables are the canonical
/// identity layout; the run uses the world's own second-level tables
/// (`vm::second_level_pointer`), so the executed image and its EPT are exactly
/// the ones `map_memory`/`load_image` produced.
pub fn run_loader(caps: &HwCaps) -> Result<LoaderReport, SelftestError> {
    if !caps.can_run() {
        return Err(SelftestError::BadExit("platform cannot run"));
    }
    // The world is destroyed on every path, including failures.
    let record = vm::create(b"s9vm-loader", 0).ok_or(SelftestError::VmFail(1))?;
    let result = run_loader_in_world(caps, record.id);
    let _ = vm::destroy(record.id);
    result
}

/// Body of the loader phase; the caller owns and destroys the world.
fn run_loader_in_world(caps: &HwCaps, world_id: u64) -> Result<LoaderReport, SelftestError> {
    let page_size = crate::s9vm::mmu::PAGE_SIZE;

    // 1. Guest memory backing the page tables and the stack. The image pages
    //    are mapped by the loader itself, which also allocates them.
    for gpa in [
        LOADER_GPA_PML4,
        LOADER_GPA_PDPT,
        LOADER_GPA_PD,
        LOADER_GPA_PT,
        LOADER_GPA_STACK,
    ] {
        vm::map_memory(world_id, caps, gpa, page_size, LOADER_GUEST_PERMS, 0)
            .map_err(|_| SelftestError::VmFail(2))?;
    }

    // 2. Identity guest paging over the pages the guest touches. A single page
    //    table maps the first 2 MiB, which covers every GPA of the phase.
    write_world_u64(world_id, LOADER_GPA_PML4, 0, LOADER_GPA_PDPT | 0x3)?;
    write_world_u64(world_id, LOADER_GPA_PDPT, 0, LOADER_GPA_PD | 0x3)?;
    write_world_u64(world_id, LOADER_GPA_PD, 0, LOADER_GPA_PT | 0x3)?;
    for gpa in [
        LOADER_GPA_PML4,
        LOADER_GPA_PDPT,
        LOADER_GPA_PD,
        LOADER_GPA_PT,
        LOADER_IMAGE_BASE,
        LOADER_GPA_STACK,
    ] {
        let index = (gpa / page_size) as usize;
        write_world_u64(world_id, LOADER_GPA_PT, index * 8, gpa | 0x3)?;
    }

    // 3. Loads the image through the kernel loader.
    let image = loader_image();
    let loaded = vm::load_image(world_id, caps, &image, LOADER_IMAGE_BASE)
        .map_err(|_| SelftestError::VmFail(3))?;
    let expected_entry = LOADER_IMAGE_BASE + LOADER_CODE_OFFSET;
    if loaded.entry != expected_entry
        || loaded.image_base != LOADER_IMAGE_BASE
        || loaded.span_min != LOADER_IMAGE_BASE
        || loaded.span_max != LOADER_IMAGE_BASE + page_size
    {
        return Err(SelftestError::BadExit("loader returned an unexpected plan"));
    }
    // The copy and the zero-fill are observable through the world translation:
    // first opcode of the guest code, then one byte of the BSS tail.
    if read_world_byte(world_id, loaded.entry)? != LOADER_CODE[0] {
        return Err(SelftestError::BadExit("image data was not copied"));
    }
    if read_world_byte(world_id, LOADER_IMAGE_BASE + 0x800)? != 0 {
        return Err(SelftestError::BadExit("image BSS was not zeroed"));
    }

    // 4. Uses the world's own second-level translation tables: the run must
    //    exercise the EPT built by `map_memory` and the loader, not a copy.
    let pointer = vm::second_level_pointer(world_id, caps).map_err(|_| SelftestError::VmFail(4))?;

    // 5. Enters the loaded image: RIP is the relocated entry point returned by
    //    the loader, RSP points into the guest stack page.
    let guest = GuestState::long_mode_64(loaded.entry, LOADER_STACK_TOP, LOADER_GPA_PML4);
    let mut vcpu = Vcpu::new(caps, pointer)?;
    // SAFETY: VT-x is active on this CPU (checked by the caller), interrupts
    // are disabled and the control block was just created for this vCPU.
    unsafe {
        vcpu.load()?;
        vcpu.configure_host()?;
        vcpu.configure(caps, &guest)?;
    }

    let mut report = LoaderReport {
        total_exits: 0,
        io_exits: 0,
        halt_exits: 0,
        marker: None,
        entry: loaded.entry,
        image_base: loaded.image_base,
        pages: loaded.span_pages(),
    };
    let mut outcome: Result<(), SelftestError> = Ok(());
    for _ in 0..32 {
        // SAFETY: `run` contract (block loaded, IRQs disabled).
        let exit = match unsafe { vcpu.run() } {
            Ok(exit) => exit,
            Err(error) => {
                outcome = Err(SelftestError::from(error));
                break;
            }
        };
        report.total_exits += 1;
        match ExitReason::decode(exit.raw_reason).class() {
            ExitClass::IoPort => {
                report.io_exits += 1;
                let port = ((exit.qualification >> 16) & 0xFFFF) as u16;
                if port == TEST_PORT {
                    report.marker = Some((vcpu.guest().rax & 0xFF) as u8);
                }
                // SAFETY: the control block is loaded and the guest is
                // inactive (we are in the exit handler).
                unsafe {
                    vcpu.advance_rip(u64::from(exit.instruction_length))?;
                }
            }
            ExitClass::Halt => {
                report.halt_exits += 1;
                break;
            }
            ExitClass::ExternalInterrupt | ExitClass::InterruptWindow => {}
            ExitClass::PreemptionTimer => {}
            other => {
                // Report enough context to tell a bad guest payload from a
                // bad page table: how far the guest got (marker, I/O count) and
                // where it faulted.
                log::warn!(
                    "[s9vm] loader test: unexpected exit class={:?} reason={:#x} \
                     qual={:#x} rip={:#x} marker={:?} io={} total={}",
                    other,
                    exit.raw_reason,
                    exit.qualification,
                    vcpu.guest().rip,
                    report.marker,
                    report.io_exits,
                    report.total_exits
                );
                outcome = Err(SelftestError::BadExit("unexpected loader-test exit"));
                break;
            }
        }
    }

    // SAFETY: the vCPU is no longer active.
    unsafe {
        let _ = vcpu.clear();
    }

    match outcome {
        Ok(()) if report.halt_exits >= 1 && report.marker == Some(LOADER_MARKER) => Ok(report),
        Ok(()) => Err(SelftestError::BadExit(
            "loaded image did not report its marker",
        )),
        Err(error) => Err(error),
    }
}

/// Report of the ACPI-discovery phase.
pub struct AcpiReport {
    pub total_exits: u32,
    pub io_exits: u32,
    pub halt_exits: u32,
    /// First byte written by the guest on the debug port (`b'A'` on success).
    pub marker: Option<u8>,
    /// Local APIC entries counted by the guest in the MADT.
    pub madt_apics: u8,
    /// Local APIC entries the kernel expects (one per registered vCPU).
    pub expected_apics: u8,
    /// Guest-physical address of the RSDP the guest validated.
    pub rsdp: u64,
}

/// ACPI-discovery test.
///
/// Creates a fresh world with one registered vCPU (the MADT describes it),
/// maps a flat identity window covering the page tables, the payload, the
/// stack and the legacy BIOS scan window, asks the engine to write the
/// firmware tables with [`vm::write_acpi`], then runs the guest payload
/// [`ACPI_CODE`] with the world's own second-level tables.
///
/// The world (and its vCPU task) is destroyed on every path.
pub fn run_acpi(caps: &HwCaps) -> Result<AcpiReport, SelftestError> {
    if !caps.can_run() {
        return Err(SelftestError::BadExit("platform cannot run"));
    }
    // The world is destroyed on every path, including failures.
    let record = vm::create(b"s9vm-acpi", 0).ok_or(SelftestError::VmFail(1))?;
    let result = run_acpi_in_world(caps, record.id);
    let _ = vm::destroy(record.id);
    result
}

/// Body of the ACPI phase; the caller owns and destroys the world.
fn run_acpi_in_world(caps: &HwCaps, world_id: u64) -> Result<AcpiReport, SelftestError> {
    let page_size = crate::s9vm::mmu::PAGE_SIZE;

    // 1. A registered vCPU is required: `write_acpi` builds the MADT from the
    //    world's vCPU APIC identifiers. This phase therefore runs from a
    //    kernel thread (see `s9vm_acpi_selftest`), never from the early
    //    bootstrap where the scheduler is not available yet.
    log::info!("[s9vm] acpitest: registering the world vCPU");
    let _vcpu_id = vm::create_vcpu_detached(world_id, 0).map_err(|_| SelftestError::VmFail(2))?;
    log::info!("[s9vm] acpitest: mapping guest pages");
    let expected_apics = vm::get(world_id)
        .map(|record| record.vcpu_count as u8)
        .unwrap_or(0);
    if expected_apics == 0 {
        return Err(SelftestError::BadExit("ACPI phase has no vCPU"));
    }

    // 2. Guest memory: page tables, payload, stack, then the whole scan
    //    window. The scan window is read-only for the guest; the copy done by
    //    `write_acpi` goes through the HHDM and does not need EPT write
    //    permission.
    for gpa in [
        ACPI_GPA_PML4,
        ACPI_GPA_PDPT,
        ACPI_GPA_PD,
        ACPI_GPA_PT,
        ACPI_GPA_CODE,
        ACPI_GPA_STACK,
    ] {
        vm::map_memory(world_id, caps, gpa, page_size, ACPI_GUEST_PERMS, 0)
            .map_err(|_| SelftestError::VmFail(3))?;
    }
    vm::map_memory(
        world_id,
        caps,
        ACPI_SCAN_START,
        ACPI_SCAN_PAGES * page_size,
        ACPI_SCAN_PERMS,
        0,
    )
    .map_err(|_| SelftestError::VmFail(4))?;

    // 3. Identity guest paging: one page table maps the first 2 MiB, which
    //    covers the tables, the payload, the stack and the scan window.
    write_world_u64(world_id, ACPI_GPA_PML4, 0, ACPI_GPA_PDPT | 0x3)?;
    write_world_u64(world_id, ACPI_GPA_PDPT, 0, ACPI_GPA_PD | 0x3)?;
    write_world_u64(world_id, ACPI_GPA_PD, 0, ACPI_GPA_PT | 0x3)?;
    for gpa in [
        ACPI_GPA_PML4,
        ACPI_GPA_PDPT,
        ACPI_GPA_PD,
        ACPI_GPA_PT,
        ACPI_GPA_CODE,
        ACPI_GPA_STACK,
    ] {
        let index = (gpa / page_size) as usize;
        write_world_u64(world_id, ACPI_GPA_PT, index * 8, gpa | 0x3)?;
    }
    for page in 0..ACPI_SCAN_PAGES {
        let gpa = ACPI_SCAN_START + page * page_size;
        let index = (gpa / page_size) as usize;
        write_world_u64(world_id, ACPI_GPA_PT, index * 8, gpa | 0x3)?;
    }

    // 4. Payload and firmware tables.
    write_world_bytes(world_id, ACPI_GPA_CODE, ACPI_CODE)?;
    log::info!("[s9vm] acpitest: writing the firmware tables");
    vm::write_acpi(world_id, caps, vm::ACPI_GPA).map_err(|_| SelftestError::VmFail(5))?;
    // The copy is observable through the world translation: first byte of the
    // RSDP signature.
    if read_world_byte(world_id, vm::ACPI_GPA)? != b'R' {
        return Err(SelftestError::BadExit("ACPI image was not copied"));
    }

    // 5. Uses the world's own second-level translation tables.
    let pointer = vm::second_level_pointer(world_id, caps).map_err(|_| SelftestError::VmFail(6))?;

    // 6. Enters the payload; the stack lives in its own identity-mapped page.
    let guest = GuestState::long_mode_64(ACPI_GPA_CODE, ACPI_STACK_TOP, ACPI_GPA_PML4);
    let mut vcpu = Vcpu::new(caps, pointer)?;
    // SAFETY: VT-x is active on this CPU (checked by the caller), the control
    // block was just created for this vCPU and no other CPU runs it.
    unsafe {
        vcpu.load()?;
        vcpu.configure_host()?;
        vcpu.configure(caps, &guest)?;
    }

    let mut report = AcpiReport {
        total_exits: 0,
        io_exits: 0,
        halt_exits: 0,
        marker: None,
        madt_apics: 0,
        expected_apics,
        rsdp: vm::ACPI_GPA,
    };
    // The guest is entered from a kernel thread here; mask host interrupts for
    // the duration of the direct run loop, as the bootstrap phases do.
    log::info!("[s9vm] acpitest: entering the guest");
    let saved_flags = crate::arch::save_flags_and_cli();
    let mut debug_out = [0u8; 4];
    let mut debug_len = 0usize;
    let mut outcome: Result<(), SelftestError> = Ok(());
    for _ in 0..ACPI_MAX_EXITS {
        // SAFETY: `run` contract (control block loaded, IRQs disabled).
        let exit = match unsafe { vcpu.run() } {
            Ok(exit) => exit,
            Err(error) => {
                outcome = Err(SelftestError::from(error));
                break;
            }
        };
        report.total_exits += 1;
        match ExitReason::decode(exit.raw_reason).class() {
            ExitClass::IoPort => {
                report.io_exits += 1;
                let port = ((exit.qualification >> 16) & 0xFFFF) as u16;
                if port == TEST_PORT && debug_len < debug_out.len() {
                    debug_out[debug_len] = (vcpu.guest().rax & 0xFF) as u8;
                    debug_len += 1;
                }
                // SAFETY: the control block is loaded and the guest is
                // inactive (we are in the exit handler).
                if let Err(error) = unsafe { vcpu.advance_rip(u64::from(exit.instruction_length)) }
                {
                    outcome = Err(SelftestError::from(error));
                    break;
                }
            }
            ExitClass::Halt => {
                report.halt_exits += 1;
                break;
            }
            ExitClass::ExternalInterrupt | ExitClass::InterruptWindow => {}
            ExitClass::PreemptionTimer => {}
            other => {
                log::warn!(
                    "[s9vm] acpi test: unexpected exit class={:?} reason={:#x} \
                     qual={:#x} rip={:#x} marker={:?} io={} total={}",
                    other,
                    exit.raw_reason,
                    exit.qualification,
                    vcpu.guest().rip,
                    report.marker,
                    report.io_exits,
                    report.total_exits
                );
                outcome = Err(SelftestError::BadExit("unexpected ACPI-test exit"));
                break;
            }
        }
    }
    crate::arch::restore_flags(saved_flags);

    // SAFETY: the vCPU is no longer active.
    unsafe {
        let _ = vcpu.clear();
    }

    report.marker = if debug_len > 0 {
        Some(debug_out[0])
    } else {
        None
    };
    report.madt_apics = if debug_len > 1 { debug_out[1] } else { 0 };

    if let Err(error) = outcome {
        return Err(error);
    }
    if report.halt_exits == 0 {
        log::warn!(
            "[s9vm] acpi test: guest never halted (marker={:?} io={} total={})",
            report.marker,
            report.io_exits,
            report.total_exits
        );
        return Err(SelftestError::BadExit("ACPI guest did not halt"));
    }
    if report.marker != Some(ACPI_MARKER) {
        log::warn!(
            "[s9vm] acpi test: guest rejected the tables (marker={:?} expected={} io={} total={})",
            report.marker,
            ACPI_MARKER,
            report.io_exits,
            report.total_exits
        );
        return Err(SelftestError::BadExit("ACPI guest rejected the tables"));
    }
    if report.madt_apics != expected_apics {
        log::warn!(
            "[s9vm] acpi test: MADT Local APIC count={} expected={} \
             marker={:?} io={} total={}",
            report.madt_apics,
            expected_apics,
            report.marker,
            report.io_exits,
            report.total_exits
        );
        return Err(SelftestError::BadExit("unexpected MADT Local APIC count"));
    }
    Ok(report)
}

/// Kthread-stage hook: vCPU kernel-task smoke test.
///
/// Enabled by `s9vm.kthread_smoke=1`. It proves the scheduling path used by a
/// real guest: the world and its vCPU are created (`create_vcpu` spawns the
/// kernel task from this kernel thread), a bounded RUN is requested (under a
/// host without VT-x this completes with `HardwareNotReady`, which already
/// proves the task was scheduled and executed), and the world is destroyed with
/// a bounded wait. A silent task-drop in the scheduler shows up as RUN timeout
/// or destroy timeout, with an explicit FAIL log instead of a silent hang.
#[cfg(target_arch = "x86_64")]
#[component::init_component(kthread, priority = 49)]
fn s9vm_kthread_smoke() -> Result<(), component::ComponentInitError> {
    // Read the option here, not at the early `s9vm_init` stage: this path must
    // run on hosts without VT-x (QEMU TCG) where the engine activation is
    // skipped, and the boot environment is still available at the kthread
    // stage.
    let requested = crate::boot_args()
        .and_then(|args| args.env_get("s9vm.kthread_smoke"))
        .map(|value| value == "1" || value == "true")
        .unwrap_or(false);
    if !requested {
        return Ok(());
    }
    // The kthread stage still runs on the boot context, before the preemptive
    // scheduler starts: blocking here would deadlock the boot. Spawn a task
    // that runs once the scheduler is live; if this spawn is dropped, the
    // QEMU boot test never sees the PASS marker (which is the diagnostic).
    match crate::process::kthread::spawn("s9vm-kthread-smoke", run_kthread_smoke) {
        Ok(task) => log::info!(
            "[s9vm] kthread-smoke: runner task {} spawned (kthread stage)",
            task.as_u64()
        ),
        Err(error) => log::warn!("[s9vm] kthread-smoke FAIL: cannot spawn runner ({})", error),
    }
    Ok(())
}

/// Body of the vCPU kernel-task smoke test.
fn run_kthread_smoke() {
    let Some(record) = vm::create(b"s9vm-kthread-smoke", 0) else {
        log::warn!("[s9vm] kthread-smoke FAIL: cannot create the world");
        return;
    };
    let world_id = record.id;
    let vcpu = match vm::create_vcpu(world_id, 0) {
        Ok(vcpu) => vcpu,
        Err(error) => {
            log::warn!(
                "[s9vm] kthread-smoke FAIL: create_vcpu failed ({:?})",
                error
            );
            let _ = vm::destroy_timeout(world_id, KTHREAD_SMOKE_DESTROY_NS);
            return;
        }
    };
    log::info!(
        "[s9vm] kthread-smoke: world={} vcpu={} created (active_cpus={})",
        world_id,
        vcpu,
        crate::s9vm::active_cpu_count()
    );

    // Let the freshly spawned task reach its wait loop (and let a sibling CPU
    // pick it up if the scheduler placed it there).
    for _ in 0..4 {
        crate::process::sleep_current_task_ticks(1);
    }
    let alive = vm::vcpu_snapshots(world_id)
        .map(|vcpus| vcpus.iter().any(|snapshot| snapshot.id == vcpu))
        .unwrap_or(false);
    if !alive {
        log::warn!("[s9vm] kthread-smoke FAIL: vCPU disappeared after creation");
        let _ = vm::destroy_timeout(world_id, KTHREAD_SMOKE_DESTROY_NS);
        return;
    }

    // A RUN proves the task actually executes: under a host without VT-x the
    // request completes with HardwareNotReady, which is the expected result
    // here (TCG has no VMX). A timeout means the task was never scheduled.
    let run = vm::request_run_timeout(vcpu, KTHREAD_SMOKE_RUN_NS);
    let run_ok = matches!(run, Ok(()) | Err(vm::RunError::HardwareNotReady));
    log::info!("[s9vm] kthread-smoke: bounded RUN completed ({:?})", run);

    let started = crate::process::scheduler::ticks();
    let destroyed = vm::destroy_timeout(world_id, KTHREAD_SMOKE_DESTROY_NS);
    let elapsed = crate::process::scheduler::ticks().saturating_sub(started);
    let destroyed_ok = destroyed.is_some();
    if run_ok && destroyed_ok {
        log::info!(
            "[s9vm] kthread-smoke PASS: run={:?} destroy_ticks={} vcpu={}",
            run,
            elapsed,
            vcpu
        );
    } else {
        log::warn!(
            "[s9vm] kthread-smoke FAIL: run={:?} destroyed={} destroy_ticks={}",
            run,
            destroyed_ok,
            elapsed
        );
    }
}

/// Kthread-stage hook: runs the ACPI phase synchronously.
///
/// The phase used to spawn its own kernel thread (to get a scheduler for a
/// registered vCPU). It now registers a **detached** vCPU (no kernel task) and
/// drives it with a direct `Vcpu` loop, so it needs neither the scheduler nor
/// a nested kernel thread: it runs synchronously in this hook and cannot leave
/// a task waiting forever behind it.
#[cfg(target_arch = "x86_64")]
#[component::init_component(kthread, priority = 50)]
fn s9vm_acpi_selftest() -> Result<(), component::ComponentInitError> {
    if !ACPI_SELFTEST_REQUESTED.swap(false, Ordering::AcqRel) {
        return Ok(());
    }
    run_acpi_task();
    Ok(())
}

/// Body of the ACPI selftest (synchronous).
fn run_acpi_task() {
    let Some(caps) = crate::s9vm::detect() else {
        log::warn!("[s9vm] acpitest FAIL: platform capabilities unavailable");
        return;
    };
    log::info!(
        "[s9vm] acpitest: running (active_cpus={})",
        crate::s9vm::active_cpu_count()
    );
    match run_acpi(&caps) {
        Ok(report) => log::info!(
            "[s9vm] acpitest PASS: total={} io={} hlt={} marker={:?} rsdp={:#x} \
             madt_apics={} expected={}",
            report.total_exits,
            report.io_exits,
            report.halt_exits,
            report.marker,
            report.rsdp,
            report.madt_apics,
            report.expected_apics
        ),
        Err(error) => log::warn!("[s9vm] acpitest FAIL: {:?}", error),
    }
}

/// Report of the SMP (multi-vCPU) phase.
pub struct SmpReport {
    /// Number of vCPUs in the world (always 2 for this phase).
    pub vcpus: u32,
    /// Markers read back from the shared guest page, per vCPU index.
    pub markers: [Option<u8>; 2],
    /// Policy exits observed for each vCPU (`out` + `hlt`).
    pub exits_per_vcpu: [u32; 2],
    /// Total policy exits observed.
    pub exits: u32,
    /// `hlt` exits observed (one per vCPU).
    pub hlt: u32,
    /// `RUN` calls that reached the hardware (`WorldStats::runs`).
    pub runs: u64,
    /// APIC identifiers of the two vCPUs, sorted.
    pub apic_ids: [u32; 2],
    /// Final guest `RIP` of each vCPU (distinct code pages).
    pub rips: [u64; 2],
    /// Final guest `RSP` of each vCPU (distinct stacks).
    pub rsps: [u64; 2],
    /// Guest `CR3` of each vCPU (distinct page tables).
    pub cr3s: [u64; 2],
}

/// Builds the ABI register block that starts one SMP vCPU.
///
/// The long-mode guest state supplies the canonical CR0/CR4/EFER and the flat
/// segments; the caller only chooses the entry point, the stack and the page
/// tables, which is what makes the two vCPU contexts independent.
fn smp_guest_regs(entry: u64, stack_top: u64, cr3: u64) -> VmmRegs {
    let guest = GuestState::long_mode_64(entry, stack_top, cr3);
    VmmRegs {
        abi_version: VMM_ABI_VERSION,
        flags: 0,
        rax: guest.rax,
        rbx: guest.rbx,
        rcx: guest.rcx,
        rdx: guest.rdx,
        rsi: guest.rsi,
        rdi: guest.rdi,
        rbp: guest.rbp,
        rsp: guest.rsp,
        r8: guest.r8,
        r9: guest.r9,
        r10: guest.r10,
        r11: guest.r11,
        r12: guest.r12,
        r13: guest.r13,
        r14: guest.r14,
        r15: guest.r15,
        rip: guest.rip,
        rflags: guest.rflags,
        cr0: guest.cr0,
        cr3: guest.cr3,
        cr4: guest.cr4,
        efer: guest.efer,
    }
}

/// Writes the identity page tables of one SMP vCPU.
///
/// The vCPU only touches its own code page, its own stack page and the shared
/// marker page, so the leaf page table maps exactly those three pages. The
/// table pages themselves are reached only by the hardware page walker.
fn smp_write_page_tables(
    world_id: u64,
    layout: &SmpLayout,
    page_size: u64,
) -> Result<(), SelftestError> {
    write_world_u64(world_id, layout.pml4, 0, layout.pdpt | 0x3)?;
    write_world_u64(world_id, layout.pdpt, 0, layout.pd | 0x3)?;
    write_world_u64(world_id, layout.pd, 0, layout.pt | 0x3)?;
    for gpa in [layout.code, layout.stack, SMP_SHARED_GPA] {
        let index = (gpa / page_size) as usize;
        write_world_u64(world_id, layout.pt, index * 8, gpa | 0x3)?;
    }
    Ok(())
}

/// SMP (multi-vCPU) test.
///
/// Creates one world with two vCPUs (APIC ids 0 and 1), each with its own page
/// tables, code page and stack page, plus one shared guest page. The phase
/// drives the kernel vCPU tasks through `request_run` in an **interleaved**
/// order: round 0 runs both vCPUs to their `out` exit (the markers are written
/// to the shared page), round 1 resumes both from their saved context to the
/// `hlt` exit. Both contexts therefore survive a context switch between the
/// two vCPUs; this validates independent, persisted vCPU state, not parallel
/// host execution.
///
/// The world (and its vCPU tasks) is destroyed on every path.
pub fn run_smp(caps: &HwCaps) -> Result<SmpReport, SelftestError> {
    if !caps.can_run() {
        return Err(SelftestError::BadExit("platform cannot run"));
    }
    let record = vm::create(b"s9vm-smp", 0).ok_or(SelftestError::VmFail(1))?;
    let result = run_smp_in_world(caps, record.id);
    let _ = vm::destroy(record.id);
    result
}

/// Body of the SMP phase; the caller owns and destroys the world.
fn run_smp_in_world(caps: &HwCaps, world_id: u64) -> Result<SmpReport, SelftestError> {
    let page_size = crate::s9vm::mmu::PAGE_SIZE;

    // 1. Two vCPUs in the same world; the MADT/APIC ids are 0 and 1.
    log::info!("[s9vm] smptest: creating two vCPUs");
    let vcpus = [
        vm::create_vcpu(world_id, 0).map_err(|_| SelftestError::VmFail(2))?,
        vm::create_vcpu(world_id, 1).map_err(|_| SelftestError::VmFail(3))?,
    ];
    log::info!("[s9vm] smptest: mapping guest pages");

    // 2. Guest memory: per-vCPU page tables, code and stack, plus one shared
    //    page both vCPUs write to.
    for layout in SMP_LAYOUTS.iter() {
        for gpa in [
            layout.pml4,
            layout.pdpt,
            layout.pd,
            layout.pt,
            layout.code,
            layout.stack,
        ] {
            vm::map_memory(world_id, caps, gpa, page_size, SMP_GUEST_PERMS, 0)
                .map_err(|_| SelftestError::VmFail(4))?;
        }
    }
    vm::map_memory(
        world_id,
        caps,
        SMP_SHARED_GPA,
        page_size,
        SMP_GUEST_PERMS,
        0,
    )
    .map_err(|_| SelftestError::VmFail(5))?;

    // 3. Per-vCPU page tables, payload and initial register block.
    for (index, layout) in SMP_LAYOUTS.iter().enumerate() {
        smp_write_page_tables(world_id, layout, page_size)?;
        write_world_bytes(world_id, layout.code, layout.payload)?;
        let regs = smp_guest_regs(layout.code, layout.stack_top, layout.pml4);
        vm::set_vcpu_regs(vcpus[index], &regs).map_err(|_| {
            log::warn!(
                "[s9vm] smp test: vCPU {} rejected its register block",
                index
            );
            SelftestError::BadExit("smp register block rejected")
        })?;
    }

    // 4. Interleaved execution: both vCPUs run to the `out` exit, then both
    //    resume from their saved state and run to `hlt`.
    let mut markers: [Option<u8>; 2] = [None; 2];
    let mut exits_per_vcpu: [u32; 2] = [0; 2];
    let mut hlt = 0u32;
    let mut total_runs = 0u32;
    for round in 0..2u32 {
        for (index, layout) in SMP_LAYOUTS.iter().enumerate() {
            if total_runs >= SMP_MAX_RUNS {
                return Err(SelftestError::BadExit("smp RUN budget exhausted"));
            }
            let vcpu = vcpus[index];
            vm::request_run(vcpu).map_err(|error| {
                log::warn!(
                    "[s9vm] smp test: vCPU {} round {} RUN failed: {:?} \
                     markers={:?} exits={} hlt={}",
                    index,
                    round,
                    error,
                    markers,
                    exits_per_vcpu[0] + exits_per_vcpu[1],
                    hlt
                );
                SelftestError::BadExit("smp RUN failed")
            })?;
            total_runs += 1;
            // `request_run` wakes the vCPU kernel task; wait for it to publish
            // its exit before draining the queue (bounded wait: a stuck vCPU
            // turns into a diagnostic instead of a hang).
            log::info!(
                "[s9vm] smptest: vCPU {} round {} RUN requested",
                index,
                round
            );
            let _ = vm::wait_exit(vcpu, 2_000_000_000);
            let event = vm::pop_exit(world_id)
                .map_err(|_| SelftestError::BadExit("smp exit queue empty after RUN"))?;
            if event.vcpu_id != vcpu {
                log::warn!(
                    "[s9vm] smp test: vCPU {} received an event for vCPU {}",
                    index,
                    event.vcpu_id
                );
                return Err(SelftestError::BadExit("smp exit routed to the wrong vCPU"));
            }
            exits_per_vcpu[index] += 1;
            match event.kind {
                exit_kind::IO_PORT => {
                    if round != 0 || event.port as u16 != TEST_PORT || event.flags != 0 {
                        log::warn!(
                            "[s9vm] smp test: vCPU {} unexpected I/O exit round={} \
                             port={:#x} flags={:#x}",
                            index,
                            round,
                            event.port,
                            event.flags
                        );
                        return Err(SelftestError::BadExit("smp unexpected I/O exit"));
                    }
                    // The `out` instruction is two bytes and the hardware does
                    // not advance RIP for a policy I/O exit: skip it. Keep the
                    // marker in RAX so the final register block is meaningful.
                    vm::complete_exit(vcpu, u64::from(layout.marker), SMP_OUT_INSTRUCTION_LEN)
                        .map_err(|_| SelftestError::BadExit("smp complete_exit failed"))?;
                }
                exit_kind::HALT => {
                    if round != 1 {
                        log::warn!("[s9vm] smp test: vCPU {} halted in round {}", index, round);
                        return Err(SelftestError::BadExit("smp early hlt"));
                    }
                    hlt += 1;
                }
                other => {
                    log::warn!(
                        "[s9vm] smp test: vCPU {} round {} unexpected exit kind={} \
                         port={:#x} flags={:#x} gpa={:#x}",
                        index,
                        round,
                        other,
                        event.port,
                        event.flags,
                        event.gpa
                    );
                    return Err(SelftestError::BadExit("smp unexpected exit"));
                }
            }
        }
    }

    // 5. Markers: the shared page is the authoritative trace (written by the
    //    guest before the exit), and each vCPU context must also still hold
    //    its own marker in RAX.
    for index in 0..2 {
        let byte = read_world_byte(world_id, SMP_SHARED_GPA + index as u64)?;
        markers[index] = Some(byte);
    }

    let mut rips = [0u64; 2];
    let mut rsps = [0u64; 2];
    let mut cr3s = [0u64; 2];
    for (index, layout) in SMP_LAYOUTS.iter().enumerate() {
        let regs = vm::get_vcpu_regs(vcpus[index])
            .ok_or(SelftestError::BadExit("smp vCPU register block missing"))?;
        rips[index] = regs.rip;
        rsps[index] = regs.rsp;
        cr3s[index] = regs.cr3;
        if (regs.rax & 0xFF) as u8 != layout.marker {
            log::warn!(
                "[s9vm] smp test: vCPU {} RAX marker={:#x} expected={:#x}",
                index,
                regs.rax & 0xFF,
                layout.marker
            );
            return Err(SelftestError::BadExit(
                "smp marker lost from the register block",
            ));
        }
    }

    let expected_rip = [
        SMP_VCPU0_GPA_CODE + SMP_HLT_OFFSET,
        SMP_VCPU1_GPA_CODE + SMP_HLT_OFFSET,
    ];
    let expected_rsp = [SMP_VCPU0_GPA_STACK + 0x800, SMP_VCPU1_GPA_STACK + 0x800];
    let expected_cr3 = [SMP_VCPU0_GPA_PML4, SMP_VCPU1_GPA_PML4];
    if rips != expected_rip
        || rsps != expected_rsp
        || cr3s != expected_cr3
        || rips[0] == rips[1]
        || rsps[0] == rsps[1]
        || cr3s[0] == cr3s[1]
    {
        log::warn!(
            "[s9vm] smp test: contexts not independent rips={:?} rsps={:?} cr3s={:?}",
            rips,
            rsps,
            cr3s
        );
        return Err(SelftestError::BadExit(
            "smp vCPU contexts are not independent",
        ));
    }

    // 6. APIC identifiers and engine counters.
    let mut apic_ids = [0u32; 2];
    {
        let snapshots = vm::vcpu_snapshots(world_id)
            .ok_or(SelftestError::BadExit("smp world snapshots missing"))?;
        if snapshots.len() != 2 {
            return Err(SelftestError::BadExit("smp world does not have two vCPUs"));
        }
        apic_ids[0] = snapshots[0].apic_id;
        apic_ids[1] = snapshots[1].apic_id;
        apic_ids.sort_unstable();
    }
    if apic_ids != [0, 1] {
        log::warn!("[s9vm] smp test: unexpected APIC ids {:?}", apic_ids);
        return Err(SelftestError::BadExit("smp unexpected APIC ids"));
    }

    let stats = vm::stats(world_id).ok_or(SelftestError::BadExit("smp stats missing"))?;
    let pending = vm::exit_count(world_id).unwrap_or(0);
    let total_exits = exits_per_vcpu[0] + exits_per_vcpu[1];
    if hlt != 2
        || total_exits != 4
        || pending != 0
        || stats.runs < u64::from(total_runs)
        || stats.policy_exits != u64::from(total_exits)
    {
        log::warn!(
            "[s9vm] smp test: counters hlt={} exits={:?} pending={} runs={} \
             policy_exits={} markers={:?}",
            hlt,
            exits_per_vcpu,
            pending,
            stats.runs,
            stats.policy_exits,
            markers
        );
        return Err(SelftestError::BadExit("smp exit counters mismatch"));
    }

    if markers != [Some(SMP_MARKERS[0]), Some(SMP_MARKERS[1])] {
        log::warn!(
            "[s9vm] smp test: shared markers={:?} expected={:?}",
            markers,
            SMP_MARKERS
        );
        return Err(SelftestError::BadExit("smp shared markers mismatch"));
    }

    Ok(SmpReport {
        vcpus: 2,
        markers,
        exits_per_vcpu,
        exits: total_exits,
        hlt,
        runs: stats.runs,
        apic_ids,
        rips,
        rsps,
        cr3s,
    })
}

/// Kthread-stage hook: runs the deferred SMP phase.
///
/// Like the ACPI phase, the SMP phase needs registered vCPUs and therefore the
/// scheduler: it is requested during the early bootstrap and executed here in
/// its own kernel thread.
#[cfg(target_arch = "x86_64")]
#[component::init_component(kthread, priority = 51)]
fn s9vm_smp_selftest() -> Result<(), component::ComponentInitError> {
    if !SMP_SELFTEST_REQUESTED.swap(false, Ordering::AcqRel) {
        return Ok(());
    }
    match crate::process::kthread::spawn("s9vm-smp-selftest", run_smp_task) {
        Ok(_) => {}
        Err(error) => log::warn!(
            "[s9vm] smptest FAIL: cannot spawn the guest task ({})",
            error
        ),
    }
    Ok(())
}

/// Body of the deferred SMP selftest task.
fn run_smp_task() {
    let Some(caps) = crate::s9vm::detect() else {
        log::warn!("[s9vm] smptest FAIL: platform capabilities unavailable");
        return;
    };
    log::info!(
        "[s9vm] smptest: task start (active_cpus={})",
        crate::s9vm::active_cpu_count()
    );
    match run_smp(&caps) {
        Ok(report) => log::info!(
            "[s9vm] smptest PASS: vcpus={} markers={:?} exits={} hlt={} runs={} \
             apic_ids={:?} rips={:?} rsps={:?} cr3s={:?}",
            report.vcpus,
            report.markers,
            report.exits,
            report.hlt,
            report.runs,
            report.apic_ids,
            report.rips,
            report.rsps,
            report.cr3s
        ),
        Err(error) => log::warn!("[s9vm] smptest FAIL: {:?}", error),
    }
}

///
/// Does nothing if VT-x is not active. Never panics.
///
/// The ACPI phase needs the scheduler (it registers a vCPU), so when requested
/// it is deferred to the `kthread` stage through [`s9vm_acpi_selftest`]; the
/// other phases run here, during the early bootstrap.
pub fn maybe_run_from_boot_env(caps: &HwCaps) {
    // Value: 1/true = device fast path; 2/all = every phase; irq, console,
    // blk, net, loader, acpi = one phase only.
    let mode = crate::boot_args()
        .and_then(|args| args.env_get("s9vm.selftest"))
        .unwrap_or("");
    if mode.is_empty() || mode == "0" || mode == "false" {
        return;
    }
    let device_phase = matches!(mode, "1" | "true" | "2" | "all");
    let interrupt_phase = matches!(mode, "2" | "all" | "irq");
    let console_phase = matches!(mode, "2" | "all" | "console");
    let block_phase = matches!(mode, "2" | "all" | "blk");
    let network_phase = matches!(mode, "2" | "all" | "net");
    let loader_phase = matches!(mode, "2" | "all" | "loader");
    // The phases that need a registered vCPU run from kernel threads at the
    // `kthread` stage. They are opt-in for the `2`/`all` mode: they exercise
    // the newest kernel-thread path, so a boot that must stay predictable can
    // keep them out while still running the six bootstrap phases.
    let deferred_enabled = crate::boot_args()
        .and_then(|args| args.env_get("s9vm.selftest.deferred"))
        .map(|value| value == "1" || value == "true")
        .unwrap_or(false);
    let all_phases = matches!(mode, "2" | "all");
    let acpi_phase = mode == "acpi" || (all_phases && deferred_enabled);
    // The SMP phase drives registered vCPUs through their kernel tasks. It is
    // enabled with the other deferred phases now that the task path has a
    // bounded RUN/destroy diagnostic (`s9vm.kthread_smoke`), and can still be
    // selected explicitly.
    let smp_phase = mode == "smp" || (all_phases && deferred_enabled);
    if all_phases && !deferred_enabled {
        log::info!(
            "[s9vm] deferred phases (acpi, smp) not requested; set \
             s9vm.selftest.deferred=1 to run them"
        );
    }

    if acpi_phase {
        // The ACPI phase registers a vCPU, which needs the scheduler: defer it
        // to the kthread stage instead of deadlocking the bootstrap.
        ACPI_SELFTEST_REQUESTED.store(true, Ordering::Release);
        log::info!("[s9vm] ACPI-discovery test requested (kthread stage)");
    }
    if smp_phase {
        // Same constraint as ACPI: two registered vCPUs require the scheduler.
        SMP_SELFTEST_REQUESTED.store(true, Ordering::Release);
        log::info!("[s9vm] SMP (two-vCPU) test requested (kthread stage, experimental)");
    }

    if device_phase {
        log::info!("[s9vm] hardware smoke test requested");
        match run(caps) {
            Ok(report) => log::info!(
                "[s9vm] selftest PASS: variant={} exits={} io={} hlt={} emulated={} pic={:?} byte={:?}",
                report.variant,
                report.total_exits,
                report.io_exits,
                report.halt_exits,
                report.emulated_exits,
                report.pic_readback,
                report.observed_byte
            ),
            Err(error) => log::warn!("[s9vm] selftest FAIL: {:?}", error),
        }
    }

    if console_phase {
        log::info!("[s9vm] console-transport test requested");
        match run_console(caps) {
            Ok(report) => log::info!(
                "[s9vm] consoletest PASS: exits={} emulated={} io={} hlt={} marker={:?} bytes={}",
                report.total_exits,
                report.emulated_exits,
                report.io_exits,
                report.halt_exits,
                report.marker,
                report.output.len()
            ),
            Err(error) => log::warn!("[s9vm] consoletest FAIL: {:?}", error),
        }
    }

    if network_phase {
        log::info!("[s9vm] network-transport test requested");
        match run_net(caps) {
            Ok(report) => log::info!(
                "[s9vm] nettest PASS: exits={} emulated={} hlt={} marker={:?} transmitted={} payload={}",
                report.total_exits,
                report.emulated_exits,
                report.halt_exits,
                report.marker,
                report.transmitted,
                report.payload.len()
            ),
            Err(error) => log::warn!("[s9vm] nettest FAIL: {:?}", error),
        }
    }

    if block_phase {
        log::info!("[s9vm] block-transport test requested");
        match run_blk(caps) {
            Ok(report) => log::info!(
                "[s9vm] blktest PASS: exits={} emulated={} io={} hlt={} marker={:?} requests={} status={}",
                report.total_exits,
                report.emulated_exits,
                report.io_exits,
                report.halt_exits,
                report.marker,
                report.requests,
                report.status
            ),
            Err(error) => log::warn!("[s9vm] blktest FAIL: {:?}", error),
        }
    }

    if interrupt_phase {
        log::info!("[s9vm] interrupt-delivery test requested");
        match run_interrupt(caps) {
            Ok(report) => log::info!(
                "[s9vm] irqtest PASS: exits={} windows={} injected={} io={} hlt={} byte={:?}",
                report.total_exits,
                report.window_exits,
                report.injected,
                report.io_exits,
                report.halt_exits,
                report.observed_byte
            ),
            Err(error) => log::warn!("[s9vm] irqtest FAIL: {:?}", error),
        }
    }

    if loader_phase {
        log::info!("[s9vm] image-loader test requested");
        match run_loader(caps) {
            Ok(report) => log::info!(
                "[s9vm] loadertest PASS: entry={:#x} base={:#x} pages={} exits={} io={} hlt={} marker={:?}",
                report.entry,
                report.image_base,
                report.pages,
                report.total_exits,
                report.io_exits,
                report.halt_exits,
                report.marker
            ),
            Err(error) => log::warn!("[s9vm] loadertest FAIL: {:?}", error),
        }
    }
}
