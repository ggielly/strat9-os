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

//! s9vm : DOS-class real-mode guest runner.
//!
//! This module boots a classic 16-bit real-mode boot image **inside an s9vm
//! world**, using the firmware surface built by [`biosrom`] (IVT, BDA, ROM
//! interrupt stubs) and the interrupt handlers built by [`bios`]. It is the
//! first end-to-end guest that goes through the BIOS interrupt path instead of
//! the s9vm boot-parameter hand-off:
//!
//! 1. a world is created and the low 1 MiB window is mapped (conventional RAM
//!    and video memory below `0xC0000`, the ROM window `0xF0000..0x100000`);
//! 2. the 1.44 MiB demo floppy is loaded as the world's block device;
//! 3. the ROM stubs, IVT entries and BDA fields are written through the world
//!    translation, and the demo boot sector is copied to `0x7C00`;
//! 4. a **detached** vCPU is created and configured in 16-bit real mode;
//! 5. the guest runs until the demo writes the success marker `K` to the debug
//!    port (or halts); every BIOS interrupt it performs exits to the host on a
//!    port in `0xE000..=0xE0FF`, is decoded into [`bios::BiosRegisters`], passed
//!    to the firmware model, and the updated registers plus the CF/ZF scratch
//!    byte are written back before resuming the guest.
//!
//! The demo prints `S9VM DOS-BOOT` from its boot sector, loads its second stage
//! through `INT 13h`, prints `STAGE2 OK` through `INT 10h`, and finally reports
//! `'K'` on port `0x00E9`; both banners must be visible in the VGA text buffer
//! and the marker must be observed for the run to pass. The demo boot sector is
//! **not** accompanied by a pre-copied second stage: the second stage reaches
//! `0x7E00` through the emulated `INT 13h` disk read, which proves the disk
//! path.
//!
//! # Real-mode entry decisions
//!
//! - the guest state is exactly [`GuestState::real_mode`]: `CR0.PE = 0`,
//!   `CR0.PG = 0`, `EFER = 0`, 16-bit segments with a 64 KiB limit, `IF = 0`;
//! - the engine's [`Vcpu::configure`] now handles real mode natively: it clears
//!   the IA-32e VM-entry control for non-long-mode guests, and
//!   [`GuestState::validate`] relaxes the CR0 fixed-bit requirements for
//!   real-mode guests when unrestricted guest mode is available. No private
//!   control-block access is needed here;
//! - the host runs the whole loop with interrupts disabled
//!   (`save_flags_and_cli`), and the guest starts with `IF = 0`; the only exits
//!   the loop expects are I/O-port exits, `HLT`, and the preemption timer.
//! - the low memory map is identity (`GPA == linear address`), which is what
//!   real mode means; the world-memory adapter therefore translates each page
//!   with `vm::debug_translate` and accesses it through the HHDM.
//!
//! # Deterministic dry run
//!
//! [`run_dos_dry`] performs the whole world creation, mapping, disk load, BIOS
//! installation and boot-sector copy **without VT-x**, then verifies every
//! installed artefact through the world translation (IVT entry for `INT 10h`,
//! BDA words, per-vector stub and shared-tail bytes, `0x55AA` boot signature,
//! disk sector count, zeroed video buffer). It is the TCG regression: it must
//! pass on every host, while [`run_dos`] only passes on hardware exposing VT-x
//! with unrestricted guest mode.
//!
//! # FreeDOS 1.4 boot
//!
//! [`run_freedos`] boots the real FreeDOS 1.4 boot floppy bundled with the
//! kernel ([`freedos_image`]) in an equivalent world. Only the boot sector is
//! copied to `0x7C00`: FreeDOS loads its kernel and command interpreter from
//! the emulated floppy through `INT 13h`, which is exactly the path this runner
//! is meant to exercise. The guest additionally needs the window above 1 MiB
//! (`0x100000..0x120000`) for its A20 probe, and the legacy ports it scans are
//! replayed by the kernel device model ([`emulate::handle_exit`]) so unmapped
//! legacy hardware never fails the boot. Success is the `K` marker written by
//! the AUTOEXEC program plus the `FreeDOS` banner in the VGA text buffer.
//! [`run_freedos_dry`] is the VT-x-free regression: it installs the image and
//! verifies every artefact (disk capacity, boot signature, OEM name, boot
//! sector copy, `INT 10h` vector, BDA words, zeroed video buffer) through the
//! world translation.
//!
//! This module is `no_std` (`core` + `alloc`) and never panics on guest
//! behaviour: every failure is a [`DosError`].

use alloc::string::String;

use crate::s9vm::{
    apic::LocalApic,
    bios, biosrom,
    caps::HwCaps,
    emulate,
    exit::{reason_name, ExitClass},
    guest::GuestState,
    machine::Machine,
    vcpu::{ExitInfo, Vcpu, VcpuError},
    vm,
};

/// Guest permissions for the low-memory and ROM mappings (read/write/exec).
const DOS_GUEST_PERMS: u32 = 7;
/// First guest-physical address mapped as conventional memory.
const LOW_MEMORY_BASE: u64 = 0;
/// End of the mapped conventional low memory.
///
/// Covers the conventional 640 KiB, the VGA aperture (`0xA0000..0xC0000`) and
/// the option-ROM/video-BIOS scan window (`0xC0000..0xF0000`): a DOS-class
/// guest reads that window while scanning for expansion ROMs, and an unmapped
/// read there would abort the boot.
const LOW_MEMORY_END: u64 = 0xF0000;
/// First address of the mapped BIOS ROM window.
const ROM_WINDOW_BASE: u64 = 0xF0000;
/// End of the mapped BIOS ROM window.
const ROM_WINDOW_END: u64 = 0x100000;
/// Upper bound on guest exits for one DOS boot (a stuck guest fails).
const MAX_DOS_EXITS: u32 = 100_000;
/// Minimum number of BIOS calls expected from the demo.
const MIN_BIOS_CALLS: u32 = 6;
/// Debug port the demo uses for its success/failure marker.
const DEBUG_PORT: u16 = biosrom::DEMO_DEBUG_PORT;
/// Success marker written by the demo second stage.
const SUCCESS_MARKER: u8 = biosrom::DEMO_SUCCESS_MARKER;
/// One page of guest memory, in bytes.
const PAGE_SIZE: u32 = 4096;
/// First guest-physical address of the window above 1 MiB.
///
/// FreeDOS probes the A20 gate and keeps kernel scratch data there, so the
/// window must be mapped for the boot to proceed.
const HIGH_MEMORY_BASE: u64 = 0x10_0000;
/// End of the window above 1 MiB.
const HIGH_MEMORY_END: u64 = 0x12_0000;
/// Upper bound on guest exits for one FreeDOS boot.
///
/// A real DOS boot runs far more instructions than the synthetic demo: the
/// budget is five times larger, and a guest that reaches it is reported as
/// stuck with its current marker and screen state.
const MAX_FREEDOS_EXITS: u32 = 500_000;

/// Preemption-timer slice used by the DOS/FreeDOS runners.
///
/// The default slice (0x00FF_FFFF) is several seconds: a guest that polls
/// guest memory (BDA tick counter, disk status in RAM) never exits by itself
/// and would appear frozen. A short slice returns control often enough to
/// advance the device/BIOS time base and to honour the run budget.
const PREEMPTION_SLICE_TICKS: u32 = 32_768;
/// Upper bound on timer ticks injected to recover a `hlt`-idle guest.
///
/// A DOS-class boot waits for a handful of timer ticks at most (disk motor,
/// delay loops); a guest that keeps halting after this many recoveries is
/// stuck and the run fails.
const MAX_HALT_RECOVERY: u32 = 10_000;
/// Capacity of the FreeDOS boot floppy, in 512-byte sectors (1.44 MiB).
const FREEDOS_DISK_SECTORS: u64 = 2880;
/// Offset of the OEM name inside a DOS boot sector.
const OEM_NAME_OFFSET: usize = 3;
/// OEM name stored in the FreeDOS boot sector (`format.com` default).
const FREEDOS_OEM_NAME: &[u8] = b"FRDOS5.1";
/// Offset of the `0x55AA` signature inside a boot sector (GPA `0x7DFE`).
const BOOT_SIGNATURE_OFFSET: u32 = 0x1FE;
/// Host TSC frequency assumed when the platform never detected one (1 GHz).
const FALLBACK_TSC_HZ: u64 = 1_000_000_000;

/// Result of a successful DOS boot attempt.
#[derive(Debug)]
pub struct DosReport {
    /// Guest-physical address where the boot sector was copied.
    pub boot_sector_gpa: u64,
    /// Last debug-port marker observed (`Some(b'K')` on success).
    pub marker: Option<u8>,
    /// VGA text buffer content at the end of the run (empty for the dry run).
    pub text: String,
    /// Total guest exits observed.
    pub total_exits: u32,
    /// Guest exits caused by an I/O port access.
    pub io_exits: u32,
    /// BIOS interrupts forwarded to the firmware model.
    pub bios_calls: u32,
    /// Guest `hlt` exits observed.
    pub halt_exits: u32,
    /// Capacity of the world's block device, in 512-byte sectors.
    pub disk_sectors: u64,
    /// Entry instruction pointer given to the guest (`0x7C00`).
    pub entry: u64,
    /// `true` when the run stopped on its wall-clock budget instead of
    /// reaching the success marker. The shell-facing runner reports this
    /// instead of hanging: the guest loop runs with interrupts disabled, so an
    /// unbounded boot attempt would freeze the whole system.
    pub timed_out: bool,
    /// Host external-interrupt exits observed. A pending host interrupt makes
    /// every VM entry exit immediately while interrupts are disabled; the
    /// runner disables that exit after a short burst so the guest progresses.
    pub external_interrupts: u32,
    /// Preemption-timer slices observed. With a short slice (see
    /// [`PREEMPTION_SLICE_TICKS`]) they sequence the guest time base for a
    /// guest that polls memory instead of causing exits.
    pub preemption_slices: u32,
}

/// Execution budget of one FreeDOS boot attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunLimits {
    /// Maximum number of guest exits.
    pub max_exits: u32,
    /// Maximum wall-clock duration in nanoseconds (0 = no time limit).
    pub max_nanoseconds: u64,
}

impl RunLimits {
    /// Budget of the boot-time selftest: generous, because a failure there is
    /// reported once during boot and never blocks an operator.
    pub const SELFTEST: Self = Self {
        max_exits: MAX_FREEDOS_EXITS,
        max_nanoseconds: 10_000_000_000,
    };
    /// Budget of `vm test` from the shell: the guest loop keeps interrupts
    /// disabled, so the attempt is bounded to a short, predictable pause.
    pub const SHELL: Self = Self {
        max_exits: 120_000,
        max_nanoseconds: 2_000_000_000,
    };
}

impl Default for RunLimits {
    fn default() -> Self {
        Self::SELFTEST
    }
}

/// Errors reported by the DOS boot runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DosError {
    /// A VM operation failed (the number identifies the step).
    VmFail(u64),
    /// Guest memory could not be translated or written.
    Mmu,
    /// The guest took an unexpected exit or produced an invalid result.
    BadExit(&'static str),
    /// The platform cannot enter real mode (no VT-x or no unrestricted guest).
    Unsupported,
    /// The BIOS artefacts could not be written to guest memory.
    Memory,
    /// A vCPU operation failed.
    Run(VcpuError),
}

impl From<VcpuError> for DosError {
    fn from(value: VcpuError) -> Self {
        Self::Run(value)
    }
}

/// Returns the FreeDOS 1.4 boot floppy bundled with the kernel.
///
/// The image is the official 1.44 MiB Floppy Edition boot disk
/// (`144m/x86BOOT.img`), patched so that `FDCONFIG.SYS`/`FDAUTO.BAT` boot
/// deterministically and run a COM program that writes the `K` success marker
/// on the debug port. Provenance, patch and checksums are documented in
/// `workspace/assets/disks/README.md`. The image is compiled into the kernel:
/// the boot does not depend on any external file.
pub fn freedos_image() -> &'static [u8] {
    include_bytes!("../../../assets/disks/freedos-1.4-boot.img")
}

/// Checks the platform can enter real mode and drive the device fast path.
///
/// `label` is the selftest mode name used in the diagnostics, so each caller
/// keeps its own log prefix.
fn require_real_mode(caps: &HwCaps, label: &str) -> Result<(), DosError> {
    if !caps.can_run() {
        log::warn!("[s9vm] {}: platform cannot run (VT-x unavailable)", label);
        return Err(DosError::Unsupported);
    }
    if !caps.ept {
        log::warn!("[s9vm] {}: EPT is unavailable", label);
        return Err(DosError::Unsupported);
    }
    if !caps.unrestricted_guest {
        log::warn!("[s9vm] {}: unrestricted guest mode is unavailable", label);
        return Err(DosError::Unsupported);
    }
    Ok(())
}

/// Runs the DOS-class demo in a fresh world (requires VT-x).
///
/// Returns a [`DosReport`] with the marker, the VGA text and the exit counters.
/// The world is destroyed on every path, including errors.
pub fn run_dos(caps: &HwCaps) -> Result<DosReport, DosError> {
    require_real_mode(caps, "dostest")?;
    let record = vm::create(b"s9vm-dos", 0).ok_or(DosError::VmFail(1))?;
    let result = run_dos_in_world(caps, record.id);
    let _ = vm::destroy(record.id);
    result
}

/// Boots the FreeDOS 1.4 floppy in a fresh world (requires VT-x).
///
/// The world is destroyed on every path, including errors. On success the
/// report carries the `K` marker written by the AUTOEXEC program and the VGA
/// text produced by the boot, which must contain the FreeDOS banner.
pub fn run_freedos(caps: &HwCaps) -> Result<DosReport, DosError> {
    let report = run_freedos_with_limits(caps, RunLimits::SELFTEST)?;
    if report.timed_out {
        log::warn!("[s9vm] freedostest: boot did not complete within the budget");
        return Err(DosError::BadExit("FreeDOS boot timed out"));
    }
    verify_freedos(&report)?;
    Ok(report)
}

/// Boots the FreeDOS floppy under an explicit execution budget.
///
/// Used by the shell-facing `vm test` command: the guest loop runs with host
/// interrupts disabled (the VM-entry contract), so an unbounded attempt would
/// freeze the whole system. The report carries `timed_out = true` when the
/// budget stopped the run; the world is destroyed on every path.
pub fn run_freedos_with_limits(caps: &HwCaps, limits: RunLimits) -> Result<DosReport, DosError> {
    require_real_mode(caps, "freedostest")?;
    let record = vm::create(b"s9vm-freedos", 0).ok_or(DosError::VmFail(1))?;
    let result = run_freedos_in_world(caps, record.id, limits);
    let _ = vm::destroy(record.id);
    result
}

/// Body of a full DOS boot; the caller owns and destroys the world.
/// Logs the guest architectural state around a failed VM entry.
///
/// A VM-entry failure only reports the opaque reason `0x21` ("invalid guest
/// state"): the field the processor rejected is not named anywhere, so the
/// values the kernel wrote are the only usable diagnostic. Kept next to the
/// run loops so both the demo and the FreeDOS paths can call it.
fn log_guest_state(vcpu: &Vcpu, label: &str) {
    let guest = vcpu.guest();
    log::warn!(
        "[s9vm] {}: entry-failure guest state: cr0={:#x} cr3={:#x} cr4={:#x} \
         efer={:#x} rflags={:#x} rip={:#x} rsp={:#x}",
        label,
        guest.cr0,
        guest.cr3,
        guest.cr4,
        guest.efer,
        guest.rflags,
        guest.rip,
        guest.rsp
    );
    log::warn!(
        "[s9vm] {}: cs(sel={:#x} base={:#x} lim={:#x} ar={:#x}) \
         ss(lim={:#x} ar={:#x}) tr(sel={:#x} lim={:#x} ar={:#x}) \
         gdtr(base={:#x} lim={:#x}) idtr(base={:#x} lim={:#x})",
        label,
        guest.cs.selector,
        guest.cs.base,
        guest.cs.limit,
        guest.cs.access_rights,
        guest.ss.limit,
        guest.ss.access_rights,
        guest.tr.selector,
        guest.tr.limit,
        guest.tr.access_rights,
        guest.gdtr_base,
        guest.gdtr_limit,
        guest.idtr_base,
        guest.idtr_limit
    );
}

fn run_dos_in_world(caps: &HwCaps, world_id: u64) -> Result<DosReport, DosError> {
    let disk_sectors = map_and_load(caps, world_id)?;
    install_artefacts(world_id)?;
    let mut memory = WorldMemory::new(world_id);

    // Detached vCPU: the run loop drives it directly, no scheduler.
    let _vcpu_id = vm::create_vcpu_detached(world_id, 0).map_err(|_| DosError::VmFail(5))?;
    let pointer = vm::second_level_pointer(world_id, caps).map_err(|_| DosError::VmFail(6))?;
    let mut vcpu = Vcpu::new(caps, pointer)?;
    let guest = GuestState::real_mode(
        u64::from(biosrom::BOOT_SECTOR_GPA),
        u64::from(biosrom::BOOT_STACK_TOP),
    );
    // SAFETY: VT-x is active on this CPU (checked by the caller), interrupts
    // are disabled around the whole phase, and this control block is only used
    // by this task.
    unsafe {
        vcpu.load()?;
        vcpu.configure_host()?;
        vcpu.configure(caps, &guest)?;
        vcpu.set_preemption_timer_ticks(PREEMPTION_SLICE_TICKS);
    }
    log::info!(
        "[s9vm] dostest: entering real-mode guest at {:#x}",
        guest.rip
    );

    let mut report = DosReport {
        boot_sector_gpa: u64::from(biosrom::BOOT_SECTOR_GPA),
        marker: None,
        text: String::new(),
        total_exits: 0,
        io_exits: 0,
        bios_calls: 0,
        halt_exits: 0,
        disk_sectors,
        entry: u64::from(biosrom::BOOT_SECTOR_GPA),
        timed_out: false,
        external_interrupts: 0,
        preemption_slices: 0,
    };
    let mut world_disk = WorldDisk::new(world_id, disk_sectors);
    let mut bios_state = bios::BiosState::new();
    let saved_flags = crate::arch::save_flags_and_cli();
    let mut outcome: Result<(), DosError> = Ok(());
    for _ in 0..MAX_DOS_EXITS {
        // SAFETY: `run` contract: block loaded, IRQs disabled, configured.
        let exit = match unsafe { vcpu.run() } {
            Ok(exit) => exit,
            Err(error) => {
                log::warn!("[s9vm] dostest: run failed: {:?}", error);
                outcome = Err(DosError::Run(error));
                break;
            }
        };
        report.total_exits += 1;
        match exit.class() {
            ExitClass::IoPort => {
                report.io_exits += 1;
                let port = ((exit.qualification >> 16) & 0xFFFF) as u16;
                if port == DEBUG_PORT {
                    report.marker = Some((vcpu.guest().rax & 0xFF) as u8);
                    break;
                }
                if (biosrom::BIOS_PORT_BASE..=biosrom::BIOS_PORT_BASE + 0xFF).contains(&port) {
                    let vector = (port - biosrom::BIOS_PORT_BASE) as u8;
                    let mut registers = read_bios_registers(vcpu.guest());
                    let _ = bios_state.handle(vector, &mut registers, &mut memory, &mut world_disk);
                    write_bios_registers(&mut vcpu, &registers);
                    write_scratch(&mut memory, &registers)?;
                    report.bios_calls += 1;
                }
                // SAFETY: block loaded, guest inactive: advance past the I/O
                // instruction so the resume does not repeat it.
                unsafe {
                    vcpu.advance_rip(u64::from(exit.instruction_length))?;
                }
            }
            ExitClass::Halt => {
                report.halt_exits += 1;
                break;
            }
            ExitClass::ExternalInterrupt => {
                report.external_interrupts += 1;
                // The guest runs with host interrupts disabled: a pending host
                // interrupt makes every VM entry exit immediately, so the run
                // spins without executing any guest code (no BIOS call, no
                // text). After a short burst, stop taking external-interrupt
                // exits for the rest of the run; the interrupt is serviced
                // when the caller returns to the scheduler.
                if report.external_interrupts == 8 {
                    // SAFETY: block loaded, guest inactive.
                    match unsafe { vcpu.set_external_interrupt_exiting(caps, false) } {
                        Ok(_) => log::info!(
                            "[s9vm] dosboot: host interrupt pending, \
                             external-interrupt exiting disabled"
                        ),
                        Err(error) => log::warn!(
                            "[s9vm] dosboot: cannot disable external-interrupt exiting: {:?}",
                            error
                        ),
                    }
                }
            }
            ExitClass::InterruptWindow => {}
            ExitClass::PreemptionTimer => {
                report.preemption_slices += 1;
                // One line per 64 slices names where a memory-polling guest
                // spends its time (such a guest produces no exits of its own).
                if report.preemption_slices % 64 == 1 {
                    log::info!(
                        "[s9vm] dosboot: slice {} rip={:#x} rflags={:#x}",
                        report.preemption_slices,
                        vcpu.guest().rip,
                        vcpu.guest().rflags
                    );
                }
            }
            other => {
                log::warn!(
                    "[s9vm] dostest: unexpected exit class {:?} (reason {:#x}, qualification {:#x})",
                    other,
                    exit.raw_reason,
                    exit.qualification
                );
                if matches!(other, ExitClass::EntryFailure | ExitClass::TripleFault) {
                    log_guest_state(&vcpu, "dostest");
                }
                outcome = Err(DosError::BadExit("unexpected exit"));
                break;
            }
        }
    }
    crate::arch::restore_flags(saved_flags);
    outcome?;

    if report.total_exits >= MAX_DOS_EXITS {
        return Err(DosError::BadExit("exit budget exhausted"));
    }
    report.text = bios::read_text(&mut memory);
    verify_demo(&report)?;
    Ok(report)
}

/// Maps the low memory and ROM windows and loads the demo disk.
///
/// Returns the block-device capacity in sectors.
fn map_and_load(caps: &HwCaps, world_id: u64) -> Result<u64, DosError> {
    map_low_windows(caps, world_id)?;
    let image = biosrom::demo_disk_image();
    vm::load_disk(world_id, &image).map_err(|_| DosError::VmFail(4))
}

/// Maps the conventional low memory and the BIOS ROM window.
///
/// The step numbers are the historical ones of [`run_dos`].
fn map_low_windows(caps: &HwCaps, world_id: u64) -> Result<(), DosError> {
    vm::map_memory(
        world_id,
        caps,
        LOW_MEMORY_BASE,
        LOW_MEMORY_END - LOW_MEMORY_BASE,
        DOS_GUEST_PERMS,
        0,
    )
    .map_err(|_| DosError::VmFail(2))?;
    vm::map_memory(
        world_id,
        caps,
        ROM_WINDOW_BASE,
        ROM_WINDOW_END - ROM_WINDOW_BASE,
        DOS_GUEST_PERMS,
        0,
    )
    .map(|_| ())
    .map_err(|_| DosError::VmFail(3))
}

/// Maps the window above 1 MiB (A20 probe and kernel scratch).
fn map_high_window(caps: &HwCaps, world_id: u64) -> Result<(), DosError> {
    vm::map_memory(
        world_id,
        caps,
        HIGH_MEMORY_BASE,
        HIGH_MEMORY_END - HIGH_MEMORY_BASE,
        DOS_GUEST_PERMS,
        0,
    )
    .map(|_| ())
    .map_err(|_| DosError::VmFail(7))
}

/// Maps the three windows used by FreeDOS and loads its boot floppy.
///
/// Returns the block-device capacity in sectors.
fn map_and_load_freedos(caps: &HwCaps, world_id: u64) -> Result<u64, DosError> {
    map_low_windows(caps, world_id)?;
    map_high_window(caps, world_id)?;
    vm::load_disk(world_id, freedos_image()).map_err(|_| DosError::VmFail(8))
}

/// Installs the ROM stubs/IVT/BDA and copies the demo boot sector.
fn install_artefacts(world_id: u64) -> Result<(), DosError> {
    let mut memory = WorldMemory::new(world_id);
    biosrom::install(&mut memory, &biosrom::VECTORS).map_err(|_| DosError::Memory)?;
    let boot_sector = biosrom::demo_boot_sector();
    if !biosrom::RomMemory::write(&mut memory, biosrom::BOOT_SECTOR_GPA, &boot_sector) {
        return Err(DosError::Memory);
    }
    Ok(())
}

/// Installs the ROM stubs/IVT/BDA and copies the FreeDOS boot sector.
///
/// Only sector 0 is copied. FreeDOS loads its kernel and the rest of its image
/// from the emulated floppy through `INT 13h`; pre-copying anything else would
/// hide a disk-path failure instead of exercising it.
fn install_freedos_artefacts(world_id: u64) -> Result<(), DosError> {
    let mut memory = WorldMemory::new(world_id);
    biosrom::install(&mut memory, &biosrom::VECTORS).map_err(|_| DosError::Memory)?;
    let image = freedos_image();
    let boot_sector = image.get(..biosrom::SECTOR_SIZE).ok_or(DosError::Memory)?;
    if !biosrom::RomMemory::write(&mut memory, biosrom::BOOT_SECTOR_GPA, boot_sector) {
        return Err(DosError::Memory);
    }
    Ok(())
}

/// World-facing memory adapter: linear guest-physical accesses through the
/// world translation, page by page.
struct WorldMemory {
    world_id: u64,
}

impl WorldMemory {
    const fn new(world_id: u64) -> Self {
        Self { world_id }
    }

    /// Reads `out.len()` bytes at linear address `linear`.
    fn read_bytes(&mut self, linear: u32, out: &mut [u8]) -> bool {
        let mut done = 0usize;
        while done < out.len() {
            let current = u64::from(linear) + done as u64;
            let in_page = (current & u64::from(PAGE_SIZE - 1)) as usize;
            let chunk = (PAGE_SIZE as usize - in_page).min(out.len() - done);
            let Some(page) = self.page(current & !u64::from(PAGE_SIZE - 1)) else {
                return false;
            };
            // SAFETY: the HHDM mapping of a world frame is valid for the whole
            // 4 KiB page; `chunk` keeps the access inside it.
            unsafe {
                for index in 0..chunk {
                    out[done + index] = core::ptr::read_volatile(page.add(in_page + index));
                }
            }
            done += chunk;
        }
        true
    }

    /// Writes `bytes` at linear address `linear`.
    fn write_bytes(&mut self, linear: u32, bytes: &[u8]) -> bool {
        let mut done = 0usize;
        while done < bytes.len() {
            let current = u64::from(linear) + done as u64;
            let in_page = (current & u64::from(PAGE_SIZE - 1)) as usize;
            let chunk = (PAGE_SIZE as usize - in_page).min(bytes.len() - done);
            let Some(page) = self.page(current & !u64::from(PAGE_SIZE - 1)) else {
                return false;
            };
            // SAFETY: same invariant as `read_bytes`.
            unsafe {
                for index in 0..chunk {
                    core::ptr::write_volatile(page.add(in_page + index), bytes[done + index]);
                }
            }
            done += chunk;
        }
        true
    }

    /// Reads a little-endian `u16`.
    fn word(&mut self, linear: u32) -> Option<u16> {
        let mut bytes = [0u8; 2];
        if self.read_bytes(linear, &mut bytes) {
            Some(u16::from_le_bytes(bytes))
        } else {
            None
        }
    }

    /// Reads a little-endian `u32`.
    fn dword(&mut self, linear: u32) -> Option<u32> {
        let mut bytes = [0u8; 4];
        if self.read_bytes(linear, &mut bytes) {
            Some(u32::from_le_bytes(bytes))
        } else {
            None
        }
    }

    /// HHDM pointer to the page containing `linear` (`linear` page-aligned).
    fn page(&self, linear: u64) -> Option<*mut u8> {
        let hpa = vm::debug_translate(self.world_id, linear)?;
        Some(crate::memory::phys_to_virt(hpa) as *mut u8)
    }

    /// Reads `out.len()` bytes at host-physical address `phys`.
    ///
    /// The device fast path receives addresses that the second-level walk has
    /// **already** resolved, so they must not go through [`vm::debug_translate`]
    /// a second time: the higher-half direct map is the correct window. It is
    /// linear, so a page split is unnecessary, but the access stays byte-wise
    /// and volatile like the guest-physical one.
    fn read_physical(&mut self, phys: u64, out: &mut [u8]) -> bool {
        for (index, byte) in out.iter_mut().enumerate() {
            let Some(address) = phys.checked_add(index as u64) else {
                return false;
            };
            // SAFETY: `phys` comes from a table walk over frames this kernel
            // allocated for the world; the direct map covers all of them.
            unsafe {
                *byte = core::ptr::read_volatile(crate::memory::phys_to_virt(address) as *const u8);
            }
        }
        true
    }

    /// Writes `bytes` at host-physical address `phys`.
    fn write_physical(&mut self, phys: u64, bytes: &[u8]) -> bool {
        for (index, byte) in bytes.iter().enumerate() {
            let Some(address) = phys.checked_add(index as u64) else {
                return false;
            };
            // SAFETY: same invariant as `read_physical`.
            unsafe {
                core::ptr::write_volatile(crate::memory::phys_to_virt(address) as *mut u8, *byte);
            }
        }
        true
    }
}

impl biosrom::RomMemory for WorldMemory {
    fn write(&mut self, linear: u32, bytes: &[u8]) -> bool {
        self.write_bytes(linear, bytes)
    }

    fn read(&mut self, linear: u32, out: &mut [u8]) -> bool {
        self.read_bytes(linear, out)
    }
}

/// Physical view of the world for the device fast path.
///
/// [`emulate::MemoryView`] resolves a guest address through the second-level
/// tables and then asks [`emulate::PhysMemory`] for the resulting host-physical
/// bytes. The adapter therefore uses the direct-map accessors: forwarding to
/// the guest-physical `read_bytes`/`write_bytes` would translate the address a
/// second time (as if it were a GPA) and silently break every replayed access.
impl emulate::PhysMemory for WorldMemory {
    fn read_bytes(&mut self, phys: u64, out: &mut [u8]) -> bool {
        self.read_physical(phys, out)
    }

    fn write_bytes(&mut self, phys: u64, bytes: &[u8]) -> bool {
        self.write_physical(phys, bytes)
    }
}

impl bios::BiosMemory for WorldMemory {
    fn read_u8(&mut self, linear: u32) -> Option<u8> {
        let mut byte = [0u8; 1];
        if self.read_bytes(linear, &mut byte) {
            Some(byte[0])
        } else {
            None
        }
    }

    fn write_u8(&mut self, linear: u32, value: u8) -> bool {
        self.write_bytes(linear, &[value])
    }

    fn read(&mut self, linear: u32, out: &mut [u8]) -> bool {
        self.read_bytes(linear, out)
    }

    fn write(&mut self, linear: u32, bytes: &[u8]) -> bool {
        self.write_bytes(linear, bytes)
    }
}

/// [`emulate::GuestContext`] backed by the vCPU of the FreeDOS loop.
///
/// The guest is a real-mode guest, so `CR3` is irrelevant and paging is off.
/// The MSR shadow model is left at its trait default (`None`): a replayed
/// `RDMSR`/`WRMSR` that reaches this adapter fails closed instead of touching
/// a host MSR.
struct VcpuGuest<'a> {
    vcpu: &'a mut Vcpu,
}

impl<'a> VcpuGuest<'a> {
    const fn new(vcpu: &'a mut Vcpu) -> Self {
        Self { vcpu }
    }
}

impl emulate::GuestContext for VcpuGuest<'_> {
    fn gpr(&self, register: u8) -> u64 {
        self.vcpu.guest_gpr(register)
    }

    fn set_gpr(&mut self, register: u8, value: u64) {
        // SAFETY: the guest is inactive while an exit is serviced (we are in
        // the exit handler, before the next VM entry) and the control block is
        // loaded on this CPU.
        unsafe {
            self.vcpu.set_guest_gpr(register, value);
        }
    }

    fn rip(&self) -> u64 {
        self.vcpu.guest().rip
    }

    fn set_rip(&mut self, rip: u64) {
        // SAFETY: same contract as `set_gpr`.
        unsafe {
            self.vcpu.set_guest_rip(rip);
        }
    }

    fn cr3(&self) -> u64 {
        0
    }

    fn paging(&self) -> bool {
        false
    }
}

/// Tries to consume an exit in the kernel device model.
///
/// The view reuses the world's second-level pointer, with paging disabled and
/// `CR3 = 0`, which is the real-mode address space of the guest. Returns `true`
/// when the instruction was fully replayed and the guest state advanced;
/// `false` means the access is outside the modeled device subset and the caller
/// must decide what to do with it.
fn run_device_fast_path(
    memory: &mut WorldMemory,
    vcpu: &mut Vcpu,
    ept_root: u64,
    devices: &mut emulate::Devices,
    apic: &mut LocalApic,
    class: ExitClass,
    qualification: u64,
    guest_physical_address: u64,
) -> bool {
    let mut view = emulate::MemoryView::new(memory, ept_root, 0, false);
    let mut guest = VcpuGuest::new(vcpu);
    matches!(
        emulate::handle_exit(
            devices,
            apic,
            &mut view,
            &mut guest,
            class,
            qualification,
            guest_physical_address
        ),
        Ok(true)
    )
}

/// Advances the guest RIP past an exit that was not consumed.
///
/// Calls [`Vcpu::advance_rip`] so the resumed guest does not re-execute the
/// faulting instruction forever.
fn advance_past_exit(vcpu: &mut Vcpu, exit: &ExitInfo) -> Result<(), DosError> {
    // SAFETY: block loaded, guest inactive (exit handler).
    unsafe { vcpu.advance_rip(u64::from(exit.instruction_length)) }.map_err(DosError::Run)
}

/// Block-device adapter over the world's virtio-blk image.
struct WorldDisk {
    world_id: u64,
    sectors: u64,
}

impl WorldDisk {
    const fn new(world_id: u64, sectors: u64) -> Self {
        Self { world_id, sectors }
    }
}

impl bios::BiosDisk for WorldDisk {
    fn sectors(&self) -> u64 {
        self.sectors
    }

    fn read_sector(&mut self, sector: u64, out: &mut [u8; biosrom::SECTOR_SIZE]) -> bool {
        if sector >= self.sectors {
            return false;
        }
        match vm::read_disk(self.world_id, sector, out) {
            Ok(read) => read == out.len(),
            Err(()) => false,
        }
    }
}

/// Reads the guest registers into the firmware-model structure.
fn read_bios_registers(guest: &GuestState) -> bios::BiosRegisters {
    let mut registers = bios::BiosRegisters::new();
    registers.ax = guest.rax as u16;
    registers.bx = guest.rbx as u16;
    registers.cx = guest.rcx as u16;
    registers.dx = guest.rdx as u16;
    registers.si = guest.rsi as u16;
    registers.di = guest.rdi as u16;
    registers.bp = guest.rbp as u16;
    registers.sp = guest.rsp as u16;
    registers.cs = guest.cs.selector;
    registers.ds = guest.ds.selector;
    registers.es = guest.es.selector;
    registers.ss = guest.ss.selector;
    registers.ip = guest.rip as u16;
    registers.flags = guest.rflags as u16;
    registers
}

/// Writes the registers updated by the firmware model back to the vCPU.
///
/// GPRs live in the entry frame until the next VM entry, so
/// [`Vcpu::set_guest_gpr`] is exactly the write-back path the trampoline reads.
fn write_bios_registers(vcpu: &mut Vcpu, registers: &bios::BiosRegisters) {
    let guest = *vcpu.guest();
    // Encoding order expected by `set_guest_gpr`: AX, CX, DX, BX, SP, BP, SI, DI.
    // 16-bit writes preserve the upper bits of the architectural registers.
    let values = [
        (0u8, registers.ax, guest.rax),
        (1, registers.cx, guest.rcx),
        (2, registers.dx, guest.rdx),
        (3, registers.bx, guest.rbx),
        (4, registers.sp, guest.rsp),
        (5, registers.bp, guest.rbp),
        (6, registers.si, guest.rsi),
        (7, registers.di, guest.rdi),
    ];
    for (register, value, previous) in values {
        // SAFETY: block loaded, guest inactive (exit handler).
        unsafe {
            vcpu.set_guest_gpr(register, (previous & !0xFFFF) | u64::from(value));
        }
    }
}

/// Publishes the CF/ZF result of a BIOS call in the scratch byte.
fn write_scratch(
    memory: &mut WorldMemory,
    registers: &bios::BiosRegisters,
) -> Result<(), DosError> {
    let mut scratch = 0u8;
    if registers.flags & 0x0001 != 0 {
        scratch |= 1;
    }
    if registers.flags & 0x0040 != 0 {
        scratch |= 2;
    }
    if !biosrom::RomMemory::write(memory, biosrom::SCRATCH_GPA, &[scratch]) {
        return Err(DosError::Memory);
    }
    Ok(())
}

/// Verifies the demo output: both banners and the success marker.
fn verify_demo(report: &DosReport) -> Result<(), DosError> {
    if report.marker != Some(SUCCESS_MARKER) {
        log::warn!("[s9vm] dostest: unexpected marker {:?}", report.marker);
        return Err(DosError::BadExit("missing success marker"));
    }
    if report.bios_calls < MIN_BIOS_CALLS {
        return Err(DosError::BadExit("too few BIOS calls"));
    }
    if !report.text.contains("S9VM DOS-BOOT") {
        return Err(DosError::BadExit("missing boot banner"));
    }
    if !report.text.contains("STAGE2 OK") {
        return Err(DosError::BadExit("missing stage2 banner"));
    }
    Ok(())
}

/// Body of a full FreeDOS boot; the caller owns and destroys the world.
///
/// # Exit routing
///
/// - `0x00E9` is the success port: the marker is recorded and `K` stops the
///   loop. Any other value is a progress/debug byte, skipped like an
///   unmodelled `out`.
/// - `0xE000..=0xE0FF` are the BIOS stubs installed by [`biosrom`]: the vector
///   is decoded from the port and serviced by [`bios::BiosState`].
/// - every other port is offered to the kernel device model first
///   ([`emulate::handle_exit`]) so the 8259/8254/CMOS/COM1/PCI probes FreeDOS
///   performs are replayed instead of failing the boot. A port nobody models is
///   counted and skipped: DOS probes a lot of absent legacy hardware.
/// - an EPT violation on a modeled device page (local APIC, I/O APIC, HPET,
///   virtio BAR) is replayed the same way; any other violation fails the run.
fn run_freedos_in_world(
    caps: &HwCaps,
    world_id: u64,
    limits: RunLimits,
) -> Result<DosReport, DosError> {
    let disk_sectors = map_and_load_freedos(caps, world_id)?;
    install_freedos_artefacts(world_id)?;
    let mut memory = WorldMemory::new(world_id);

    // Detached vCPU: the run loop drives it directly, no scheduler.
    let _vcpu_id = vm::create_vcpu_detached(world_id, 0).map_err(|_| DosError::VmFail(5))?;
    let pointer = vm::second_level_pointer(world_id, caps).map_err(|_| DosError::VmFail(6))?;
    let mut vcpu = Vcpu::new(caps, pointer)?;
    let guest = GuestState::real_mode(
        u64::from(biosrom::BOOT_SECTOR_GPA),
        u64::from(biosrom::BOOT_STACK_TOP),
    );
    // SAFETY: VT-x is active on this CPU (checked by the caller), interrupts
    // are disabled around the whole phase, and this control block is only used
    // by this task.
    unsafe {
        vcpu.load()?;
        vcpu.configure_host()?;
        vcpu.configure(caps, &guest)?;
        vcpu.set_preemption_timer_ticks(PREEMPTION_SLICE_TICKS);
    }
    log::info!(
        "[s9vm] freedostest: entering real-mode guest at {:#x}",
        guest.rip
    );

    let mut report = DosReport {
        boot_sector_gpa: u64::from(biosrom::BOOT_SECTOR_GPA),
        marker: None,
        text: String::new(),
        total_exits: 0,
        io_exits: 0,
        bios_calls: 0,
        halt_exits: 0,
        disk_sectors,
        entry: u64::from(biosrom::BOOT_SECTOR_GPA),
        timed_out: false,
        external_interrupts: 0,
        preemption_slices: 0,
    };
    let mut world_disk = WorldDisk::new(world_id, disk_sectors);
    let mut bios_state = bios::BiosState::new();
    // Chipset model of this world plus the local APIC its legacy devices signal
    // through, exactly like the other kernel guest phases.
    let mut machine = Machine::new();
    let mut apic = LocalApic::new(0);
    let tsc_hz = crate::s9vm::tsc::get().map_or(FALLBACK_TSC_HZ, |frequency| frequency.hz());
    let mut unhandled_ports: u32 = 0;
    // First distinct unmodeled ports, so a guest that spins on one legacy port
    // names it in the log instead of only showing an exit counter.
    let mut unhandled_seen: [u16; 8] = [0; 8];
    let mut unhandled_seen_len = 0usize;
    let saved_flags = crate::arch::save_flags_and_cli();
    // Wall-clock origin of the run: the shell-facing budget is measured from
    // here, independently of the exit counter.
    let start_tsc = unsafe { core::arch::x86_64::_rdtsc() };
    let mut last_tsc = start_tsc;
    let mut total_cycles: u64 = 0;
    let mut published_ticks: u32 = 0;
    let mut outcome: Result<(), DosError> = Ok(());
    for _ in 0..limits.max_exits {
        // One device-time advance per exit, measured from the host TSC.
        // SAFETY: same contract as the first read.
        let now = unsafe { core::arch::x86_64::_rdtsc() };
        let delta = now.wrapping_sub(last_tsc);
        last_tsc = now;
        total_cycles = total_cycles.wrapping_add(delta);
        // Wall-clock budget: the loop keeps host interrupts disabled (VM-entry
        // contract), so an unbounded attempt would freeze the whole system.
        if limits.max_nanoseconds != 0 {
            let elapsed_ns =
                u128::from(now.wrapping_sub(start_tsc)) * 1_000_000_000 / u128::from(tsc_hz.max(1));
            if elapsed_ns >= u128::from(limits.max_nanoseconds) {
                log::info!(
                    "[s9vm] freedostest: time budget reached after {} exit(s)",
                    report.total_exits
                );
                report.timed_out = true;
                break;
            }
        }
        machine.advance_time(&mut apic, delta, tsc_hz);
        // 18.2 Hz BIOS tick: `ticks` is the cumulative count derived from the
        // host cycles (182 / 10 per second). `advance_ticks` accumulates, so
        // only the difference with the previously published value is added.
        let ticks = (u128::from(total_cycles) * 182 / (u128::from(tsc_hz) * 10)) as u32;
        bios_state.advance_ticks(ticks.wrapping_sub(published_ticks));
        published_ticks = ticks;

        // SAFETY: `run` contract: block loaded, IRQs disabled, configured.
        let exit = match unsafe { vcpu.run() } {
            Ok(exit) => exit,
            Err(error) => {
                log::warn!("[s9vm] freedostest: run failed: {:?}", error);
                outcome = Err(DosError::Run(error));
                break;
            }
        };
        report.total_exits += 1;
        match exit.class() {
            ExitClass::IoPort => {
                report.io_exits += 1;
                let port = ((exit.qualification >> 16) & 0xFFFF) as u16;
                if port == DEBUG_PORT {
                    let marker = (vcpu.guest().rax & 0xFF) as u8;
                    report.marker = Some(marker);
                    if marker == SUCCESS_MARKER {
                        break;
                    }
                    // Any other marker is informational: skip the `out` and
                    // keep booting (FreeDOS may report progress bytes).
                    if let Err(error) = advance_past_exit(&mut vcpu, &exit) {
                        outcome = Err(error);
                        break;
                    }
                } else if (biosrom::BIOS_PORT_BASE..=biosrom::BIOS_PORT_BASE + 0xFF).contains(&port)
                {
                    let vector = (port - biosrom::BIOS_PORT_BASE) as u8;
                    let mut registers = read_bios_registers(vcpu.guest());
                    let _ = bios_state.handle(vector, &mut registers, &mut memory, &mut world_disk);
                    write_bios_registers(&mut vcpu, &registers);
                    if let Err(error) = write_scratch(&mut memory, &registers) {
                        outcome = Err(error);
                        break;
                    }
                    report.bios_calls += 1;
                    if let Err(error) = advance_past_exit(&mut vcpu, &exit) {
                        outcome = Err(error);
                        break;
                    }
                } else {
                    // Kernel device model first: FreeDOS programs the PIC, the
                    // PIT and the CMOS, and probes many absent legacy ports.
                    let consumed = run_device_fast_path(
                        &mut memory,
                        &mut vcpu,
                        pointer,
                        machine.devices_mut(),
                        &mut apic,
                        ExitClass::IoPort,
                        exit.qualification,
                        0,
                    );
                    if !consumed {
                        unhandled_ports += 1;
                        let port = ((exit.qualification >> 16) & 0xFFFF) as u16;
                        let direction_in = exit.qualification & 1 != 0;
                        let mut known = false;
                        for slot in &unhandled_seen[..unhandled_seen_len] {
                            if *slot == port {
                                known = true;
                                break;
                            }
                        }
                        if !known {
                            if unhandled_seen_len < unhandled_seen.len() {
                                unhandled_seen[unhandled_seen_len] = port;
                                unhandled_seen_len += 1;
                            }
                            log::info!(
                                "[s9vm] freedostest: unhandled legacy port {:#x} ({}) rip {:#x}",
                                port,
                                if direction_in { "in" } else { "out" },
                                vcpu.guest().rip
                            );
                        }
                        if let Err(error) = advance_past_exit(&mut vcpu, &exit) {
                            outcome = Err(error);
                            break;
                        }
                    }
                }
            }
            ExitClass::EptViolation => {
                let consumed = run_device_fast_path(
                    &mut memory,
                    &mut vcpu,
                    pointer,
                    machine.devices_mut(),
                    &mut apic,
                    ExitClass::EptViolation,
                    exit.qualification,
                    exit.guest_physical_address,
                );
                if !consumed {
                    log::warn!(
                        "[s9vm] freedostest: unexpected ept violation at gpa {:#x} \
                         (rip {:#x}, qualification {:#x})",
                        exit.guest_physical_address,
                        vcpu.guest().rip,
                        exit.qualification
                    );
                    outcome = Err(DosError::BadExit("unexpected ept violation"));
                    break;
                }
            }
            ExitClass::Halt => {
                report.halt_exits += 1;
                // A real DOS-class guest idles with `sti; hlt` while it waits
                // for the 18.2 Hz timer tick, which PC firmware delivers as
                // vector `0x08`. The runner plays the timer's role: inject the
                // tick and continue, otherwise the very first idle wait would
                // stall the boot. The injection is only valid when the guest
                // is interruptible; a halted guest with interrupts disabled is
                // a genuine dead end.
                let interruptible = vcpu.guest().rflags & (1 << 9) != 0;
                if interruptible && report.halt_exits <= MAX_HALT_RECOVERY {
                    // SAFETY: block loaded, guest inactive (exit handler).
                    if let Err(error) = unsafe { vcpu.inject_interrupt(0x08) } {
                        log::warn!("[s9vm] freedostest: cannot inject timer: {:?}", error);
                        outcome = Err(DosError::Run(error));
                        break;
                    }
                } else {
                    log::warn!(
                        "[s9vm] freedostest: guest halted (interruptible={}, halt exits {}, \
                         marker {:?})",
                        interruptible,
                        report.halt_exits,
                        report.marker
                    );
                    break;
                }
            }
            ExitClass::ExternalInterrupt => {
                report.external_interrupts += 1;
                // The guest runs with host interrupts disabled: a pending host
                // interrupt makes every VM entry exit immediately, so the run
                // spins without executing any guest code (no BIOS call, no
                // text). After a short burst, stop taking external-interrupt
                // exits for the rest of the run; the interrupt is serviced
                // when the caller returns to the scheduler.
                if report.external_interrupts == 8 {
                    // SAFETY: block loaded, guest inactive.
                    match unsafe { vcpu.set_external_interrupt_exiting(caps, false) } {
                        Ok(_) => log::info!(
                            "[s9vm] dosboot: host interrupt pending, \
                             external-interrupt exiting disabled"
                        ),
                        Err(error) => log::warn!(
                            "[s9vm] dosboot: cannot disable external-interrupt exiting: {:?}",
                            error
                        ),
                    }
                }
            }
            ExitClass::InterruptWindow => {}
            ExitClass::PreemptionTimer => {
                report.preemption_slices += 1;
                // One line per 64 slices names where a memory-polling guest
                // spends its time (such a guest produces no exits of its own).
                if report.preemption_slices % 64 == 1 {
                    log::info!(
                        "[s9vm] dosboot: slice {} rip={:#x} rflags={:#x}",
                        report.preemption_slices,
                        vcpu.guest().rip,
                        vcpu.guest().rflags
                    );
                }
            }
            other => {
                log::warn!(
                    "[s9vm] freedostest: unexpected exit {:?} ({} / reason {:#x}, rip {:#x})",
                    other,
                    reason_name(exit.reason.reason),
                    exit.reason.reason,
                    vcpu.guest().rip
                );
                if matches!(other, ExitClass::EntryFailure | ExitClass::TripleFault) {
                    log_guest_state(&vcpu, "freedostest");
                }
                outcome = Err(DosError::BadExit("unexpected exit"));
                break;
            }
        }
    }
    crate::arch::restore_flags(saved_flags);
    outcome?;
    if unhandled_ports != 0 {
        log::info!(
            "[s9vm] freedostest: {} unmodeled legacy port accesses ignored",
            unhandled_ports
        );
    }
    if report.total_exits >= limits.max_exits {
        report.timed_out = true;
        let text = bios::read_text(&mut memory);
        log::warn!(
            "[s9vm] freedostest: exit budget exhausted (marker {:?}, {} text characters, \
             rip {:#x})",
            report.marker,
            text.len(),
            vcpu.guest().rip
        );
    }
    report.text = bios::read_text(&mut memory);
    Ok(report)
}

/// Verifies the FreeDOS output: the AUTOEXEC marker and the boot banner.
fn verify_freedos(report: &DosReport) -> Result<(), DosError> {
    if report.marker != Some(SUCCESS_MARKER) {
        log::warn!("[s9vm] freedostest: unexpected marker {:?}", report.marker);
        return Err(DosError::BadExit("missing FreeDOS success marker"));
    }
    if !report.text.contains("FreeDOS") {
        log::warn!(
            "[s9vm] freedostest: FreeDOS banner missing from the VGA text ({} characters)",
            report.text.len()
        );
        return Err(DosError::BadExit("missing FreeDOS banner"));
    }
    Ok(())
}

/// Runs the installation half of the DOS boot **without VT-x**.
///
/// Creates a world, maps the low memory and ROM windows, loads the demo disk,
/// installs the BIOS stubs/IVT/BDA and copies the boot sector, then verifies
/// each artefact through the world translation before destroying the world.
/// The returned report has an empty text and no marker: it proves the
/// memory-side contract only, and is the deterministic regression on TCG.
pub fn run_dos_dry(caps: &HwCaps) -> Result<DosReport, DosError> {
    let record = vm::create(b"s9vm-dos-dry", 0).ok_or(DosError::VmFail(1))?;
    let result = run_dos_dry_in_world(caps, record.id);
    let _ = vm::destroy(record.id);
    result
}

/// Body of the VT-x-free dry run; the caller owns and destroys the world.
fn run_dos_dry_in_world(caps: &HwCaps, world_id: u64) -> Result<DosReport, DosError> {
    let disk_sectors = map_and_load(caps, world_id)?;
    install_artefacts(world_id)?;
    let mut memory = WorldMemory::new(world_id);
    verify_installation(&mut memory, disk_sectors)?;
    Ok(DosReport {
        boot_sector_gpa: u64::from(biosrom::BOOT_SECTOR_GPA),
        marker: None,
        text: String::new(),
        total_exits: 0,
        io_exits: 0,
        bios_calls: 0,
        halt_exits: 0,
        disk_sectors,
        entry: u64::from(biosrom::BOOT_SECTOR_GPA),
        timed_out: false,
        external_interrupts: 0,
        preemption_slices: 0,
    })
}

/// Checks every artefact written by [`install_artefacts`] in world memory.
fn verify_installation(memory: &mut WorldMemory, disk_sectors: u64) -> Result<(), DosError> {
    if disk_sectors != biosrom::FLOPPY_TOTAL_SECTORS {
        return Err(DosError::BadExit("unexpected disk capacity"));
    }
    // The boot sector was copied at 0x7C00 with its 0x55AA signature.
    let boot = biosrom::demo_boot_sector();
    let mut copied = [0u8; biosrom::SECTOR_SIZE];
    if !biosrom::RomMemory::read(memory, biosrom::BOOT_SECTOR_GPA, &mut copied) {
        return Err(DosError::Mmu);
    }
    if copied[510] != 0x55 || copied[511] != 0xAA {
        return Err(DosError::BadExit("boot sector signature missing"));
    }
    if copied != boot {
        return Err(DosError::BadExit("boot sector copy differs"));
    }
    // IVT entry for INT 10h points at the per-vector ROM stub.
    let Some(entry) = memory.dword(biosrom::IVT_BASE + 0x10 * 4) else {
        return Err(DosError::Mmu);
    };
    let offset = (entry & 0xFFFF) as u16;
    let segment = (entry >> 16) as u16;
    if segment != biosrom::ROM_SEGMENT || offset != biosrom::stub_offset(0x10) {
        return Err(DosError::BadExit("INT 10h vector is not installed"));
    }
    let stub_gpa = u32::from(segment) * 16 + u32::from(offset);
    let expected_stub = biosrom::stub_bytes(0x10);
    let mut installed_stub = [0u8; biosrom::MAX_STUB_LEN as usize];
    if !biosrom::RomMemory::read(memory, stub_gpa, &mut installed_stub) {
        return Err(DosError::Mmu);
    }
    if installed_stub[..expected_stub.len()] != expected_stub[..] {
        return Err(DosError::BadExit("ROM stub bytes differ"));
    }
    // Shared tail bytes are installed once, after the per-vector stubs.
    let expected_tail = biosrom::shared_tail_bytes();
    let mut installed_tail = [0u8; biosrom::MAX_SHARED_TAIL_LEN as usize];
    if expected_tail.len() > installed_tail.len() {
        return Err(DosError::BadExit("shared tail exceeds the stub limit"));
    }
    if !biosrom::RomMemory::read(
        memory,
        biosrom::shared_tail_gpa(),
        &mut installed_tail[..expected_tail.len()],
    ) {
        return Err(DosError::Mmu);
    }
    if installed_tail[..expected_tail.len()] != expected_tail[..] {
        return Err(DosError::BadExit("shared stub tail differs"));
    }
    // BDA: equipment word and memory size.
    let equipment = memory.word(biosrom::BDA_EQUIPMENT).ok_or(DosError::Mmu)?;
    if equipment != biosrom::EQUIPMENT_VALUE {
        return Err(DosError::BadExit("BDA equipment word is wrong"));
    }
    let memory_size = memory.word(biosrom::BDA_MEMORY_SIZE).ok_or(DosError::Mmu)?;
    if memory_size != biosrom::MEMORY_SIZE_VALUE {
        return Err(DosError::BadExit("BDA memory size is wrong"));
    }
    // The second stage must not be pre-copied: it arrives through INT 13h.
    let mut stage2 = [0u8; 16];
    if !biosrom::RomMemory::read(memory, biosrom::BOOT_SECTOR_GPA + 0x200, &mut stage2) {
        return Err(DosError::Mmu);
    }
    if stage2.iter().any(|byte| *byte != 0) {
        return Err(DosError::BadExit("second stage was pre-copied"));
    }
    // VGA text buffer starts zeroed: the guest has not printed anything yet.
    let mut video = [0xFFu8; 320];
    if !biosrom::RomMemory::read(memory, biosrom::VIDEO_BASE, &mut video) {
        return Err(DosError::Mmu);
    }
    if video.iter().any(|byte| *byte != 0) {
        return Err(DosError::BadExit("video buffer is not zeroed"));
    }
    // The block device exposes the demo floppy; sector 0 is the boot sector.
    let mut sector = [0u8; biosrom::SECTOR_SIZE];
    let mut world_disk = WorldDisk::new(memory.world_id, disk_sectors);
    if !bios::BiosDisk::read_sector(&mut world_disk, 0, &mut sector) {
        return Err(DosError::BadExit("disk sector 0 unreadable"));
    }
    if sector != boot {
        return Err(DosError::BadExit("disk boot sector differs"));
    }
    Ok(())
}

/// Runs the installation half of the FreeDOS boot **without VT-x**.
///
/// Creates a world, maps the low/ROM/1 MiB windows, loads the bundled FreeDOS
/// floppy, installs the BIOS stubs/IVT/BDA and copies only the boot sector,
/// then verifies every artefact through the world translation before destroying
/// the world. The report has an empty text and no marker: it proves the
/// memory-side contract of the boot, and is the deterministic regression on
/// TCG.
pub fn run_freedos_dry(caps: &HwCaps) -> Result<DosReport, DosError> {
    let record = vm::create(b"s9vm-freedos-dry", 0).ok_or(DosError::VmFail(1))?;
    let result = run_freedos_dry_in_world(caps, record.id);
    let _ = vm::destroy(record.id);
    result
}

/// Body of the VT-x-free FreeDOS dry run; the caller owns the world.
fn run_freedos_dry_in_world(caps: &HwCaps, world_id: u64) -> Result<DosReport, DosError> {
    let disk_sectors = map_and_load_freedos(caps, world_id)?;
    install_freedos_artefacts(world_id)?;
    let mut memory = WorldMemory::new(world_id);
    verify_freedos_installation(&mut memory, disk_sectors)?;
    Ok(DosReport {
        boot_sector_gpa: u64::from(biosrom::BOOT_SECTOR_GPA),
        marker: None,
        text: String::new(),
        total_exits: 0,
        io_exits: 0,
        bios_calls: 0,
        halt_exits: 0,
        disk_sectors,
        entry: u64::from(biosrom::BOOT_SECTOR_GPA),
        timed_out: false,
        external_interrupts: 0,
        preemption_slices: 0,
    })
}

/// Checks every artefact written by [`install_freedos_artefacts`].
///
/// All reads go through the world translation, so a mapping that silently
/// landed on the wrong frame is caught here. The checks are the contract the
/// selftest mode `freedos_dry` reports on:
///
/// 1. the block device has the 2880 sectors of a 1.44 MiB floppy and exposes
///    the image's first sector;
/// 2. `0x7C00` holds a byte-for-byte copy of image bytes `0..512`, with the
///    `0x55AA` signature at `0x7DFE` and the `FRDOS5.1` OEM name at offset 3;
/// 3. `IVT[0x10]` points into the `0xF000` ROM segment (at the `INT 10h` stub);
/// 4. the BDA reports the one-floppy 80x25 machine FreeDOS expects
///    (equipment `0x0021`, 640 KiB);
/// 5. the VGA text buffer is still zeroed (nothing has run yet);
/// 6. the window above 1 MiB is mapped and readable.
fn verify_freedos_installation(
    memory: &mut WorldMemory,
    disk_sectors: u64,
) -> Result<(), DosError> {
    let image = freedos_image();
    if disk_sectors != FREEDOS_DISK_SECTORS {
        return Err(DosError::BadExit("unexpected FreeDOS disk capacity"));
    }
    if image.len() as u64 != FREEDOS_DISK_SECTORS * biosrom::SECTOR_SIZE as u64 {
        return Err(DosError::BadExit("unexpected FreeDOS image size"));
    }
    // The boot sector is the only part of the image copied to guest memory.
    let mut copied = [0u8; biosrom::SECTOR_SIZE];
    if !biosrom::RomMemory::read(memory, biosrom::BOOT_SECTOR_GPA, &mut copied) {
        return Err(DosError::Mmu);
    }
    if copied != image[..biosrom::SECTOR_SIZE] {
        return Err(DosError::BadExit("FreeDOS boot sector copy differs"));
    }
    // Signature at 0x7DFE (0x7C00 + 0x1FE).
    let mut signature = [0u8; 2];
    if !biosrom::RomMemory::read(
        memory,
        biosrom::BOOT_SECTOR_GPA + BOOT_SIGNATURE_OFFSET,
        &mut signature,
    ) {
        return Err(DosError::Mmu);
    }
    if signature != [0x55, 0xAA] {
        return Err(DosError::BadExit("FreeDOS boot signature missing"));
    }
    let oem_end = OEM_NAME_OFFSET + FREEDOS_OEM_NAME.len();
    if copied[OEM_NAME_OFFSET..oem_end] != FREEDOS_OEM_NAME[..] {
        return Err(DosError::BadExit("unexpected FreeDOS OEM name"));
    }
    // IVT entry for INT 10h points at the per-vector ROM stub in segment F000.
    let Some(entry) = memory.dword(biosrom::IVT_BASE + 0x10 * 4) else {
        return Err(DosError::Mmu);
    };
    let offset = (entry & 0xFFFF) as u16;
    let segment = (entry >> 16) as u16;
    if segment != biosrom::ROM_SEGMENT || offset != biosrom::stub_offset(0x10) {
        return Err(DosError::BadExit("INT 10h vector is not installed"));
    }
    // BDA: equipment word and memory size.
    if memory.word(biosrom::BDA_EQUIPMENT) != Some(biosrom::EQUIPMENT_VALUE) {
        return Err(DosError::BadExit("BDA equipment word is wrong"));
    }
    if memory.word(biosrom::BDA_MEMORY_SIZE) != Some(biosrom::MEMORY_SIZE_VALUE) {
        return Err(DosError::BadExit("BDA memory size is wrong"));
    }
    // VGA text buffer starts zeroed: no guest has run yet.
    let mut video = [0xFFu8; 320];
    if !biosrom::RomMemory::read(memory, biosrom::VIDEO_BASE, &mut video) {
        return Err(DosError::Mmu);
    }
    if video.iter().any(|byte| *byte != 0) {
        return Err(DosError::BadExit("video buffer is not zeroed"));
    }
    // The block device exposes the FreeDOS image; sector 0 is its boot sector.
    let mut sector = [0u8; biosrom::SECTOR_SIZE];
    let mut world_disk = WorldDisk::new(memory.world_id, disk_sectors);
    if !bios::BiosDisk::read_sector(&mut world_disk, 0, &mut sector) {
        return Err(DosError::BadExit("disk sector 0 unreadable"));
    }
    if sector != copied {
        return Err(DosError::BadExit("disk boot sector differs"));
    }
    // The A20 / 1 MiB window is mapped: probe it through the translation.
    let probe: [u8; 4] = [0x5A, 0xA5, 0x00, 0xFF];
    let mut readback = [0u8; 4];
    if !biosrom::RomMemory::write(memory, HIGH_MEMORY_BASE as u32, &probe)
        || !biosrom::RomMemory::read(memory, HIGH_MEMORY_BASE as u32, &mut readback)
    {
        return Err(DosError::Mmu);
    }
    if readback != probe {
        return Err(DosError::BadExit("high memory window is not writable"));
    }
    Ok(())
}
