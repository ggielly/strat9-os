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
//! 4. kernel fast path: the guest programs the legacy interrupt controller
//!    through its ports; those exits are replayed by the kernel and never
//!    reach the policy path;
//! 5. clean shutdown.
//!
//! The test is only started if the kernel is enabled on VT-x and if the boot
//! option `s9vm.selftest=1` is present. It never panics: a failure is
//! logged and boot continues.
//!
//! The guest state is the canonical 64-bit flat shape produced by
//! [`GuestState::long_mode_64`]; it is entered once. Any exit the engine does
//! not expect is logged with its decoded reason so a failure is diagnosable on
//! the target machine without rebuilding.

use crate::{
    memory::frame::{FrameAllocOptions, FramePurpose, PhysFrame},
    s9vm::{
        apic::LocalApic,
        caps::HwCaps,
        emulate::{interrupt_action, InterruptAction},
        exit::{reason_name, ExitClass, ExitReason},
        guest::GuestState,
        machine::Machine,
        vcpu::{SecondLevelMemory, Vcpu, VcpuError},
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
            0xB0, 0x11, 0xE6, 0x20, // mov al, 0x11 ; out 0x20, al (ICW1)
            0xB0, 0x20, 0xE6, 0x21, // mov al, 0x20 ; out 0x21, al (ICW2)
            0xB0, 0x04, 0xE6, 0x21, // mov al, 0x04 ; out 0x21, al (ICW3)
            0xB0, 0x01, 0xE6, 0x21, // mov al, 0x01 ; out 0x21, al (ICW4)
            0xB0, 0x00, 0xE6, 0x21, // mov al, 0x00 ; out 0x21, al (unmask)
            0xE4, 0x21, // in al, 0x21 (mask = 0x00)
            0xB0, PIC_READBACK, 0xE6, 0x21, // mov al, 0xFF ; out 0x21, al
            0xE4, 0x21, // in al, 0x21 (mask = 0xFF)
            0xB0, TEST_BYTE, 0xE6, TEST_PORT as u8, // mov al, byte ; out 0xE9, al
            0xF4, // hlt
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

/// Starts the test if the boot option `s9vm.selftest=1` is present.
///
/// Does nothing if VT-x is not active. Never panics.
pub fn maybe_run_from_boot_env(caps: &HwCaps) {
    // Value: 1/true = device fast path, 2/all = both phases, irq = interrupt
    // phase only.
    let mode = crate::boot_args()
        .and_then(|args| args.env_get("s9vm.selftest"))
        .unwrap_or("");
    if mode.is_empty() || mode == "0" || mode == "false" {
        return;
    }
    let device_phase = matches!(mode, "1" | "true" | "2" | "all");
    let interrupt_phase = matches!(mode, "2" | "all" | "irq");

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
}
