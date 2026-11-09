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
//! Goal: run a minimal guest (64-bit long mode, EPT enabled, two
//! mapped pages) that writes a byte to an I/O port and then executes `hlt`, and
//! check that the full path works:
//!
//! 1. building the guest tables and the second-level tables;
//! 2. loading the control block;
//! 3. guest entry (`vmlaunch`), exit on I/O, resume, exit on `hlt`;
//! 4. clean shutdown.
//!
//! The test is only started if the kernel is enabled on VT-x and if the boot
//! option `s9vm.selftest=1` is present. It never panics: a failure is
//! logged and boot continues.
//!
//! # Guest-state variants
//!
//! Real hardware validates the guest state at VM entry much more strictly than
//! the software model. When the first variant fails with `entry failure`, the
//! test tries a few well-known valid shapes of the same guest (unusable TR,
//! real descriptor-table limits, OS-like access rights...) and logs the
//! outcome of each. This makes a strict-field failure diagnosable on the
//! target machine without rebuilding: the first passing variant identifies the
//! field family the processor objected to.

use crate::memory::frame::{FrameAllocOptions, FramePurpose, PhysFrame};
use crate::s9vm::caps::HwCaps;
use crate::s9vm::exit::{ExitClass, ExitReason};
use crate::s9vm::guest::{
    GuestState, Segment, AR_CODE_DATA, AR_DEFAULT_BIG, AR_LONG_MODE, AR_PRESENT,
};
use crate::s9vm::vcpu::{SecondLevelMemory, Vcpu, VcpuError};

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

/// Access rights of an OS-like 64-bit writable data segment (`SS`/`DS`/`ES`).
///
/// Type 3 (read/write, accessed), `S=1`, `DPL=0`, `P=1`, `D/B=1`, `G=1`:
/// `0xC093` in the VMCS access-rights format (bits 14/15 are `D/B`/`G`).
const fn os_data_access_rights() -> u32 {
    (0x3 | AR_CODE_DATA | AR_PRESENT) | AR_DEFAULT_BIG | (1 << 15)
}

/// Access rights of an OS-like 64-bit code segment (`CS`).
///
/// Type 11 (execute/read, accessed), `S=1`, `DPL=0`, `P=1`, `L=1`, `G=1`.
const fn os_code_access_rights() -> u32 {
    (0xB | AR_CODE_DATA | AR_PRESENT | AR_LONG_MODE) | (1 << 15)
}

/// Builds the guest-state variants tried by the smoke test.
///
/// Variant 0 is the software-model baseline. The others are common valid
/// shapes of the same guest; a hardware rejection of variant 0 can thus be
/// attributed to one field family.
fn build_variants(base: &GuestState) -> [(&'static str, GuestState); 15] {
    let mut variants = [("baseline", *base); 15];

    // Unusable TR: no TSS is needed by this guest (no ring transition).
    let mut guest = *base;
    guest.tr = Segment::unusable();
    variants[1] = ("tr-unusable", guest);

    // Real descriptor-table limits (KVM/OS shape: 0xFFFF, base 0).
    let mut guest = *base;
    guest.gdtr_limit = 0xFFFF;
    guest.idtr_limit = 0xFFFF;
    variants[2] = ("table-limits-ffff", guest);

    // Data segments as type-3 accessed RW (0x93 in the VMCS format).
    let mut guest = *base;
    let data = 0x3 | AR_CODE_DATA | AR_PRESENT;
    guest.ss.access_rights = data;
    guest.ds.access_rights = data;
    guest.es.access_rights = data;
    variants[3] = ("data-ar-93", guest);

    // Data segments with D/B set (0x4093): OS-like flat segments.
    let mut guest = *base;
    let data = (0x3 | AR_CODE_DATA | AR_PRESENT) | AR_DEFAULT_BIG;
    guest.ss.access_rights = data;
    guest.ds.access_rights = data;
    guest.es.access_rights = data;
    variants[4] = ("data-ar-4093", guest);

    // Data segments with D/B and G set (0xC093): exactly what a 64-bit OS uses.
    let mut guest = *base;
    let data = os_data_access_rights();
    guest.ss.access_rights = data;
    guest.ds.access_rights = data;
    guest.es.access_rights = data;
    variants[5] = ("data-ar-c093", guest);

    // Code segment with G set and accessed type (0xA09B).
    let mut guest = *base;
    guest.cs.access_rights = os_code_access_rights();
    variants[6] = ("cs-ar-a09b", guest);

    // TR usable with a non-null selector and a TSS-sized limit.
    let mut guest = *base;
    guest.tr = Segment {
        selector: 0x30,
        base: 0,
        limit: 0x67,
        access_rights: 0x8B,
    };
    variants[7] = ("tr-selector-30", guest);

    // Combination of the OS-like shape: table limits, OS data/code AR,
    // unusable TR (this guest performs no privilege transition).
    let mut guest = *base;
    guest.gdtr_limit = 0xFFFF;
    guest.idtr_limit = 0xFFFF;
    guest.ss.access_rights = os_data_access_rights();
    guest.ds.access_rights = os_data_access_rights();
    guest.es.access_rights = os_data_access_rights();
    guest.cs.access_rights = os_code_access_rights();
    guest.tr = Segment::unusable();
    variants[8] = ("os-shaped", guest);

    // SYSENTER selector set to a valid ring-0 code selector (0x8).
    let mut guest = *base;
    guest.sysenter_cs = 0x8;
    variants[9] = ("sysenter-cs-8", guest);

    // Minimal CR0: PE | NE | PG (drop MP/WP).
    let mut guest = *base;
    guest.cr0 = 0x8000_0021;
    variants[10] = ("cr0-min", guest);

    // Minimal CR4: PAE | VMXE (drop PGE/OSFXSR/OSXMMEXCPT).
    let mut guest = *base;
    guest.cr4 = 0x2020;
    variants[11] = ("cr4-min", guest);

    // EFER without SCE: LME | LMA | NXE.
    let mut guest = *base;
    guest.efer = 0xD00;
    variants[12] = ("efer-no-sce", guest);

    // Descriptor tables pointing at a mapped page with a real limit.
    let mut guest = *base;
    guest.gdtr_base = GPA_PT;
    guest.gdtr_limit = 0xFFFF;
    guest.idtr_base = GPA_PT;
    guest.idtr_limit = 0xFFFF;
    variants[13] = ("tables-mapped", guest);

    // Interrupts enabled in RFLAGS (IF = 1).
    let mut guest = *base;
    guest.rflags = 0x202;
    variants[14] = ("rflags-if", guest);

    variants
}

/// Runs one guest-state variant. Returns a report on success.
fn run_variant(
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
        observed_byte: None,
        variant: "",
    };

    let mut outcome: Result<(), SelftestError> = Ok(());
    for _ in 0..16 {
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
        match class {
            ExitClass::IoPort => {
                report.io_exits += 1;
                // I/O qualification: port in bits 16..31.
                let port = ((exit.qualification >> 16) & 0xFFFF) as u16;
                if port == TEST_PORT {
                    report.observed_byte = Some((vcpu.guest().rax & 0xFF) as u8);
                }
                // For an exit on an I/O instruction, the processor has already
                // set `GUEST_RIP` to the next instruction: do not
                // advance it again, otherwise the resume would skip the `hlt`.
                log::info!(
                    "[s9vm] I/O exit port={:#x} byte={:?} rip={:#x} len={}",
                    port,
                    report.observed_byte,
                    vcpu.guest().rip,
                    exit.instruction_length
                );
            }
            ExitClass::Halt => {
                report.halt_exits += 1;
                break;
            }
            ExitClass::ExternalInterrupt | ExitClass::InterruptWindow => {
                // At boot, host interrupts are masked: we simply
                // resume the guest.
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
        Ok(()) if report.io_exits >= 1 && report.halt_exits >= 1 => Ok(report),
        Ok(()) => Err(SelftestError::BadExit("guest did not reach hlt")),
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
    write_u64(&pml4, 0, pdpt.start_address.as_u64() | 0x3);
    write_u64(&pdpt, 0, pd.start_address.as_u64() | 0x3);
    write_u64(&pd, 0, pt.start_address.as_u64() | 0x3);
    for page in 0..GUEST_PAGES {
        let gpa = page * crate::s9vm::mmu::PAGE_SIZE;
        write_u64(&pt, page as usize * 8, gpa | 0x3);
    }

    // Guest code: mov al, imm8 ; out 0xE9, al ; hlt.
    write_bytes(&code, &[0xB0, TEST_BYTE, 0xE6, TEST_PORT as u8, 0xF4]);

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

    let base = GuestState::long_mode_64(ENTRY_POINT, STACK_TOP, GPA_PML4);
    let variants = build_variants(&base);
    let mut last_error = SelftestError::BadExit("no variant tried");
    for (index, (name, guest)) in variants.iter().enumerate() {
        match run_variant(caps, pointer, guest) {
            Ok(mut report) => {
                report.variant = name;
                log::info!("[s9vm] guest variant {} ({}) entered", index, name);
                return Ok(report);
            }
            Err(error) => {
                log::warn!(
                    "[s9vm] guest variant {} ({}) failed: {:?}",
                    index,
                    name,
                    error
                );
                last_error = error;
            }
        }
    }
    Err(last_error)
}

/// Starts the test if the boot option `s9vm.selftest=1` is present.
///
/// Does nothing if VT-x is not active. Never panics.
pub fn maybe_run_from_boot_env(caps: &HwCaps) {
    let enabled = crate::boot_args()
        .and_then(|args| args.env_get("s9vm.selftest"))
        .map(|value| value == "1" || value == "true")
        .unwrap_or(false);
    if !enabled {
        return;
    }
    log::info!("[s9vm] hardware smoke test requested");
    match run(caps) {
        Ok(report) => log::info!(
            "[s9vm] selftest PASS: variant={} exits={} io={} hlt={} byte={:?}",
            report.variant,
            report.total_exits,
            report.io_exits,
            report.halt_exits,
            report.observed_byte
        ),
        Err(error) => log::warn!("[s9vm] selftest FAIL: {:?}", error),
    }
}
