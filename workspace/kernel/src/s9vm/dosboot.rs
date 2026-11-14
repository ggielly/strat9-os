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
//! # SeaBIOS boot
//!
//! [`run_freedos_seabios`] boots the same floppy with the real SeaBIOS 1.17.0
//! and SeaVGABIOS images embedded by [`firmware`]. The guest starts at the
//! architectural reset vector (`F000:FFF0`), runs the firmware's own POST and
//! `INT 13h`, and drives the emulated chipset instead of calling back into the
//! kernel:
//!
//! - the 82077AA controller ([`crate::s9vm::fdc`]) and DMA channel 2 move the
//!   sectors;
//! - the 8259 pair delivers `INT 08h` (timer) and `INT 0Eh` (floppy) as
//!   exception-class vectors, which the run loop injects directly because the
//!   local APIC never delivers vectors below `0x10`;
//! - CMOS `0x10` advertises one 1.44 MiB drive and `0x30`/`0x31` advertise the
//!   3 MiB of extended memory (a 4 MiB machine);
//! - no stub IVT/BDA is installed: SeaBIOS builds them during POST.
//!
//! [`run_freedos_seabios_dry`] verifies the BIOS/option-ROM placement and the
//! 4 MiB window without VT-x. The same [`firmware`] installer is independent of
//! FreeDOS: another world only has to map the windows and call
//! [`firmware::install`] with its own image and [`firmware::FirmwareConfig`].
//!
//! This module is `no_std` (`core` + `alloc`) and never panics on guest
//! behaviour: every failure is a [`DosError`].

use alloc::{string::String, vec, vec::Vec};

use crate::s9vm::{
    apic::LocalApic,
    bios, biosrom,
    caps::HwCaps,
    emulate,
    exit::{reason_name, ExitClass},
    firmware,
    guest::GuestState,
    keyboard,
    machine::Machine,
    vcpu::{ExitInfo, Vcpu, VcpuError},
    vm,
};

/// Restores the interrupt flag on drop, including early-error paths.
struct IrqOff {
    flags: u64,
}

impl IrqOff {
    fn new() -> Self {
        Self {
            flags: crate::arch::save_flags_and_cli(),
        }
    }
}

impl Drop for IrqOff {
    fn drop(&mut self) {
        crate::arch::restore_flags(self.flags);
    }
}

/// Host milliseconds elapsed since `start`, from the TSC.
///
/// The DOS/SeaBIOS runner keeps host interrupts disabled, so wall-clock
/// helpers that depend on interrupts are unusable; the TSC is the only
/// monotonic source available inside the phase.
fn elapsed_millis(start: u64, tsc_hz: u64) -> u64 {
    // SAFETY: RDTSC is a plain read of the architectural counter.
    let now = unsafe { core::arch::x86_64::_rdtsc() };
    let cycles = now.wrapping_sub(start);
    (u128::from(cycles) * 1000 / u128::from(tsc_hz.max(1))) as u64
}

/// Guest permissions for the low-memory and ROM mappings (read/write/exec).
const DOS_GUEST_PERMS: u32 = 7;
/// First address of the mapped conventional low memory.
const LOW_MEMORY_BASE: u64 = 0;
/// First address of the mapped BIOS ROM window (stub firmware).
///
/// The stub ROM is a 32 KiB image at `0xF0000`; the option-ROM scan window
/// below it (`0xC0000..0xF0000`) is part of the low mapping, so a DOS-class
/// guest can read it while scanning for expansion ROMs.
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
/// End of the window above 1 MiB for a real firmware.
///
/// SeaBIOS derives `RamSize` from CMOS (4 MiB in the FreeDOS configuration)
/// and may place ACPI tables or allocator scratch above 1 MiB, so the whole
/// advertised range must be mapped.
const SEABIOS_HIGH_MEMORY_END: u64 = 0x40_0000;
/// First address of the BIOS ROM window used by a real firmware.
///
/// A 256 KiB SeaBIOS image occupies `0xC0000..0x100000`; its first 64 KiB are
/// zero padding where the VGA option ROM is installed.
const SEABIOS_ROM_WINDOW_BASE: u64 = 0xC_0000;
/// Top-of-4GiB alias of the BIOS ROM used by the reset vector and high code.
const SEABIOS_ROM_ALIAS_BASE: u64 = 0xFFFC_0000;
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
/// Preemption-timer slice of the SeaBIOS runner.
///
/// Legacy IRQs are delivered on preemption exits (the floppy ISR must not run
/// before SeaBIOS clears its BDA flag), so a slightly longer slice reduces the
/// exit count without adding perceptible interrupt latency.
const SEABIOS_PREEMPTION_SLICE_TICKS: u32 = 1 << 20;
/// Upper bound on timer ticks injected to recover a `hlt`-idle guest.
///
/// A DOS-class boot waits for a handful of timer ticks at most (disk motor,
/// delay loops); a guest that keeps halting after this many recoveries is
/// stuck and the run fails.
const MAX_HALT_RECOVERY: u32 = 10_000;
/// Upper bound on software interrupts reported by the catch-all ROM stub.
///
/// A hardware interrupt or a CPU exception aborts the run on its first
/// occurrence; a software vector (`>= 0x20`) only returns, so this bound stops a
/// guest that keeps calling a service it never installed.
const MAX_UNHANDLED_INTERRUPTS: u32 = 32;
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
    /// Interrupts the guest raised on a vector with no firmware service. The
    /// catch-all ROM stub reports them instead of letting the CPU jump through
    /// the zeroed IVT entry at `0000:0000`; the runner logs the faulting
    /// `CS:IP` and aborts on a CPU exception or a runaway count.
    pub unhandled_interrupts: u32,
    /// Platform interrupts delivered to the guest through the 8259 pair
    /// (`IRQ0` timer, `IRQ1` keyboard, ...). Real hardware interrupts, unlike
    /// [`Self::bios_calls`], do not cost one exit each.
    pub interrupts_delivered: u32,
    /// Platform interrupts that reached the firmware ROM stub while the guest
    /// had not installed its own handler yet; the runner acknowledges them at
    /// the stub exit, like the real BIOS handler does.
    pub interrupts_serviced: u32,
    /// Scancodes typed by the host into the 8042 and read by the guest.
    pub scancodes_typed: u32,
}

impl DosReport {
    /// Creates an empty report for a run over `disk_sectors` sectors.
    fn new(disk_sectors: u64) -> Self {
        Self {
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
            unhandled_interrupts: 0,
            interrupts_delivered: 0,
            interrupts_serviced: 0,
            scancodes_typed: 0,
        }
    }
}

/// Execution budget of one FreeDOS boot attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunLimits {
    /// Maximum number of guest exits.
    pub max_exits: u32,
    /// Maximum wall-clock duration in nanoseconds (0 = no time limit).
    pub max_nanoseconds: u64,
    /// Stop as soon as the guest writes the success marker.
    ///
    /// `false` keeps the guest running after the marker so typed keys can be
    /// executed at the DOS prompt; the run then ends on its time budget.
    pub stop_at_marker: bool,
}

impl RunLimits {
    /// Budget of the boot-time selftest: generous, because a failure there is
    /// reported once during boot and never blocks an operator.
    pub const SELFTEST: Self = Self {
        max_exits: MAX_FREEDOS_EXITS,
        max_nanoseconds: 10_000_000_000,
        stop_at_marker: true,
    };
    /// Budget of `vm test` from the shell: the guest loop keeps interrupts
    /// disabled, so the attempt is bounded to a short, predictable pause.
    pub const SHELL: Self = Self {
        max_exits: 120_000,
        max_nanoseconds: 2_000_000_000,
        stop_at_marker: true,
    };
}

impl Default for RunLimits {
    fn default() -> Self {
        Self::SELFTEST
    }
}

/// Firmware the FreeDOS test world boots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareKind {
    /// The s9vm 16-bit stub ROM: `INT` calls exit through port `0xE0xx` and the
    /// kernel services them ([`bios`]).
    Stub,
    /// A real SeaBIOS ROM: the guest runs the firmware's own `INT 10h`/`13h`
    /// code and drives the emulated chipset (FDC, DMA, PIC, PIT, VGA).
    SeaBios,
}

impl FirmwareKind {
    /// Diagnostics tag of the run.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Stub => "freedostest",
            Self::SeaBios => "freedos-seabios",
        }
    }

    /// True for the real-firmware path.
    pub const fn is_seabios(self) -> bool {
        matches!(self, Self::SeaBios)
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

/// FreeDOS 1.4 demo image: prints a greeting and lists the floppy contents.
///
/// Same official boot disk, with `FDAUTO.BAT` replaced by:
///
/// ```text
/// @ECHO OFF
/// ECHO Hello world, from FreeDOS
/// DIR
/// S9VMK.COM
/// ```
///
/// and the `@echo off` line removed from `FDCONFIG.SYS` (FreeDOS' CONFIG.SYS
/// parser rejects it). `S9VMK.COM` still writes the `K` marker, so the runner
/// can stop at the end of the batch.
pub fn freedos_hello_image() -> &'static [u8] {
    include_bytes!("../../../assets/disks/freedos-hello.img")
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
    if !caps.preemption_timer {
        log::warn!(
            "[s9vm] {}: the preemption timer is unavailable (no bounded guest time)",
            label
        );
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
    verify_freedos(&report, "FreeDOS")?;
    Ok(report)
}

/// Boots the FreeDOS floppy under an explicit execution budget.
///
/// Used by the shell-facing `vm test` command: the guest loop runs with host
/// interrupts disabled (the VM-entry contract), so an unbounded attempt would
/// freeze the whole system. The report carries `timed_out = true` when the
/// budget stopped the run; the world is destroyed on every path.
pub fn run_freedos_with_limits(caps: &HwCaps, limits: RunLimits) -> Result<DosReport, DosError> {
    run_freedos_with_limits_and_keys(caps, limits, &[])
}

/// Boots the FreeDOS floppy and types `keys` at the guest keyboard.
///
/// `keys` is host text in ASCII: it is translated into PS/2 set-1 scancodes and
/// delivered through the 8042 model once the guest owns `INT 9` and unmasks
/// `IRQ1`, so a DOS kernel sees a real keyboard instead of the BIOS polling
/// path. Used by the shell-facing `vm test keys=<text>` to drive the guest.
pub fn run_freedos_with_limits_and_keys(
    caps: &HwCaps,
    limits: RunLimits,
    keys: &[u8],
) -> Result<DosReport, DosError> {
    run_firmware_with_limits(
        caps,
        limits,
        FirmwareKind::Stub,
        freedos_image(),
        b"s9vm-freedos",
        keys,
    )
}

/// Boots the FreeDOS floppy with the real SeaBIOS firmware (requires VT-x).
///
/// Unlike [`run_freedos`], the guest does not call back into the kernel for
/// `INT 10h`/`INT 13h`: SeaBIOS and SeaVGABIOS run their own 16-bit code and
/// drive the emulated FDC, DMA, PIC, PIT and VGA models instead.
pub fn run_freedos_seabios(caps: &HwCaps) -> Result<DosReport, DosError> {
    let report = run_freedos_seabios_with_limits(caps, RunLimits::SELFTEST)?;
    if report.timed_out {
        log::warn!("[s9vm] freedos-seabios: boot did not complete within the budget");
        return Err(DosError::BadExit("FreeDOS SeaBIOS boot timed out"));
    }
    verify_freedos(&report, "FreeDOS")?;
    Ok(report)
}

/// Boots the FreeDOS floppy with SeaBIOS under an explicit budget.
pub fn run_freedos_seabios_with_limits(
    caps: &HwCaps,
    limits: RunLimits,
) -> Result<DosReport, DosError> {
    run_firmware_with_limits(
        caps,
        limits,
        FirmwareKind::SeaBios,
        freedos_image(),
        b"s9vm-freedos-seabios",
        &[],
    )
}

/// Boots the **Hello/DIR demo image** with SeaBIOS (requires VT-x).
///
/// Success is the `K` marker plus the exact greeting and the `DIR` listing of
/// `FDAUTO.BAT`, which proves the batch executed and the filesystem was read.
pub fn run_freedos_hello(caps: &HwCaps) -> Result<DosReport, DosError> {
    let report = run_freedos_hello_with_limits(caps, RunLimits::SELFTEST)?;
    if report.timed_out {
        log::warn!("[s9vm] freedos-hello: boot did not complete within the budget");
        return Err(DosError::BadExit("FreeDOS hello boot timed out"));
    }
    verify_freedos(&report, "Hello world, from FreeDOS")?;
    if !report.text.contains("FDAUTO") {
        return Err(DosError::BadExit("DIR listing missing FDAUTO.BAT"));
    }
    Ok(report)
}

/// Boots the Hello/DIR demo image with SeaBIOS under an explicit budget.
pub fn run_freedos_hello_with_limits(
    caps: &HwCaps,
    limits: RunLimits,
) -> Result<DosReport, DosError> {
    run_firmware_with_limits(
        caps,
        limits,
        FirmwareKind::SeaBios,
        freedos_hello_image(),
        b"s9vm-freedos-hello",
        &[],
    )
}

/// Common entry point of the FreeDOS firmware paths.
fn run_firmware_with_limits(
    caps: &HwCaps,
    limits: RunLimits,
    firmware: FirmwareKind,
    image: &'static [u8],
    world_name: &'static [u8],
    keys: &[u8],
) -> Result<DosReport, DosError> {
    require_real_mode(caps, firmware.label())?;
    let record = vm::create(world_name, 0).ok_or(DosError::VmFail(1))?;
    let result = run_freedos_in_world(caps, record.id, limits, firmware, image, keys, None);
    let _ = vm::destroy(record.id);
    result
}

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

/// Body of a full DOS boot; the caller owns and destroys the world.
fn run_dos_in_world(caps: &HwCaps, world_id: u64) -> Result<DosReport, DosError> {
    let disk_sectors = map_and_load(caps, world_id)?;
    install_artefacts(world_id)?;
    let mut memory = WorldMemory::new(world_id);

    // Detached vCPU: the run loop drives it directly, no scheduler.
    let pointer = vm::second_level_pointer(world_id, caps).map_err(|_| DosError::VmFail(6))?;
    let mut vcpu = Vcpu::new(caps, pointer)?;
    let guest = GuestState::real_mode(
        u64::from(biosrom::BOOT_SECTOR_GPA),
        u64::from(biosrom::BOOT_STACK_TOP),
    );
    // Pin the task to this CPU before the VMCS is loaded: the STI window of
    // `service_pending_host_interrupts` lets the timer interrupt run, and
    // without this guard it could migrate the task while the VMCS is active on
    // this CPU, so the final VMCLEAR would run on the wrong one. Declared
    // before `_irq` so interrupts are restored first on every return path.
    let _pin = crate::sync::preempt::PreemptGuard::new();
    // Keep host interrupts disabled for the whole run; the guard restores them
    // on every return path.
    let _irq = IrqOff::new();
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

    let mut report = DosReport::new(disk_sectors);
    let mut world_disk = WorldDisk::new(world_id, disk_sectors);
    let mut bios_state = bios::BiosState::new();
    let mut outcome: Result<(), DosError> = Ok(());
    let tsc_hz = crate::s9vm::tsc::get().map_or(FALLBACK_TSC_HZ, |frequency| frequency.hz());
    // Wall-clock origin of the run: the guest loop keeps host interrupts
    // disabled, so an unbounded attempt would freeze the whole system.
    let start_tsc = unsafe { core::arch::x86_64::_rdtsc() };
    for _ in 0..MAX_DOS_EXITS {
        // SAFETY: same contract as the origin read.
        let now = unsafe { core::arch::x86_64::_rdtsc() };
        let elapsed_ns =
            u128::from(now.wrapping_sub(start_tsc)) * 1_000_000_000 / u128::from(tsc_hz.max(1));
        if elapsed_ns >= 10_000_000_000 {
            log::info!(
                "[s9vm] dostest: time budget reached after {} exit(s)",
                report.total_exits
            );
            report.timed_out = true;
            break;
        }
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
                // The debug port is a marker only for a non-string OUT; other
                // accesses fall through to normal port handling.
                if port == DEBUG_PORT
                    && exit.qualification & 0x30 == 0
                    && exit.qualification & 0x08 == 0
                {
                    report.marker = Some((vcpu.guest().rax & 0xFF) as u8);
                    break;
                }
                if (biosrom::BIOS_PORT_BASE..=biosrom::BIOS_PORT_BASE + 0xFF).contains(&port) {
                    let vector = (port - biosrom::BIOS_PORT_BASE) as u8;
                    // Refresh the segment registers: an INT call changes
                    // ES/DS/SS and the ROM handler relies on them.
                    // SAFETY: block loaded, guest inactive (exit handler).
                    unsafe { vcpu.refresh_system_state() }.map_err(DosError::Run)?;
                    let mut registers = read_bios_call_registers(&vcpu, &mut memory);
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
                // spins without executing any guest code. Open a one-instruction
                // window so the host services the IRQ; the vector is never
                // delivered into the guest.
                crate::s9vm::vcpu::service_pending_host_interrupts();
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
    // The local vCPU is not stored in the registry: unload the control block
    // so `Drop` can release its frames on this CPU.
    unsafe {
        let _ = vcpu.clear();
    }
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
    map_low_windows(caps, world_id, FirmwareKind::Stub)?;
    let image = biosrom::demo_disk_image();
    vm::load_disk(world_id, &image).map_err(|_| DosError::VmFail(4))
}

/// Maps the conventional low memory and the BIOS ROM window.
///
/// The step numbers are the historical ones of [`run_dos`]. A real firmware
/// needs the BIOS window to start at `0xC0000` (256 KiB image and its VGA
/// option ROM); the stub ROM only uses `0xF0000..0x100000`.
fn map_low_windows(caps: &HwCaps, world_id: u64, firmware: FirmwareKind) -> Result<(), DosError> {
    let rom_window_base = match firmware {
        FirmwareKind::Stub => ROM_WINDOW_BASE,
        FirmwareKind::SeaBios => SEABIOS_ROM_WINDOW_BASE,
    };
    vm::map_memory(
        world_id,
        caps,
        LOW_MEMORY_BASE,
        rom_window_base - LOW_MEMORY_BASE,
        DOS_GUEST_PERMS,
        0,
    )
    .map_err(|_| DosError::VmFail(2))?;
    vm::map_memory(
        world_id,
        caps,
        rom_window_base,
        ROM_WINDOW_END - rom_window_base,
        DOS_GUEST_PERMS,
        0,
    )
    .map_err(|_| DosError::VmFail(3))?;
    if firmware.is_seabios() {
        // PC firmware is also visible at the top of the 4 GiB address space;
        // SeaBIOS' high code and the reset vector run from that alias. The
        // pages are shared with the low ROM window, not copied.
        vm::alias_memory(
            world_id,
            SEABIOS_ROM_ALIAS_BASE,
            rom_window_base,
            ROM_WINDOW_END - rom_window_base,
            DOS_GUEST_PERMS,
        )
        .map_err(|_| DosError::VmFail(3))?;
    }
    Ok(())
}

/// Maps the window above 1 MiB (A20 probe, allocator and firmware tables).
fn map_high_window(caps: &HwCaps, world_id: u64, firmware: FirmwareKind) -> Result<(), DosError> {
    let end = match firmware {
        FirmwareKind::Stub => HIGH_MEMORY_END,
        FirmwareKind::SeaBios => SEABIOS_HIGH_MEMORY_END,
    };
    vm::map_memory(
        world_id,
        caps,
        HIGH_MEMORY_BASE,
        end - HIGH_MEMORY_BASE,
        DOS_GUEST_PERMS,
        0,
    )
    .map(|_| ())
    .map_err(|_| DosError::VmFail(7))
}

/// Maps the three windows used by FreeDOS and loads its boot floppy.
///
/// Returns the block-device capacity in sectors.
fn map_and_load_freedos(
    caps: &HwCaps,
    world_id: u64,
    firmware: FirmwareKind,
    image: &'static [u8],
) -> Result<u64, DosError> {
    map_low_windows(caps, world_id, firmware)?;
    map_high_window(caps, world_id, firmware)?;
    vm::load_disk(world_id, image).map_err(|_| DosError::VmFail(8))
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

/// Installs the firmware and copies the FreeDOS boot sector when needed.
///
/// The stub path installs the ROM stubs/IVT/BDA and copies only sector 0:
/// FreeDOS loads its kernel and the rest of its image from the emulated floppy
/// through `INT 13h`, and pre-copying anything else would hide a disk-path
/// failure. The SeaBIOS path installs the real BIOS and its VGA option ROM;
/// SeaBIOS loads the boot sector itself.
fn install_freedos_artefacts(
    world_id: u64,
    firmware: FirmwareKind,
    image: &'static [u8],
) -> Result<(), DosError> {
    let mut memory = WorldMemory::new(world_id);
    if firmware.is_seabios() {
        firmware::install_seabios(&mut memory, firmware::FirmwareConfig::freedos()).map_err(
            |error| {
                log::warn!(
                    "[s9vm] freedos-seabios: firmware install failed: {}",
                    error.as_str()
                );
                DosError::Memory
            },
        )?;
        return Ok(());
    }
    biosrom::install(&mut memory, &biosrom::VECTORS).map_err(|_| DosError::Memory)?;
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
        let Some(end) = phys.checked_add(out.len() as u64) else {
            return false;
        };
        let _ = end;
        // SAFETY: `phys` comes from a table walk over frames this kernel
        // allocated for the world; the direct map is linear and covers all of
        // them, so the whole range is one contiguous slice.
        unsafe {
            core::ptr::copy_nonoverlapping(
                crate::memory::phys_to_virt(phys) as *const u8,
                out.as_mut_ptr(),
                out.len(),
            );
        }
        true
    }

    /// Writes `bytes` at host-physical address `phys`.
    fn write_physical(&mut self, phys: u64, bytes: &[u8]) -> bool {
        let Some(end) = phys.checked_add(bytes.len() as u64) else {
            return false;
        };
        let _ = end;
        // SAFETY: same invariant as `read_physical`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                crate::memory::phys_to_virt(phys) as *mut u8,
                bytes.len(),
            );
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

    fn rflags(&self) -> u64 {
        self.vcpu.guest().rflags
    }

    fn es_base(&self) -> u64 {
        self.vcpu.guest().es.base
    }

    fn ds_base(&self) -> u64 {
        self.vcpu.guest().ds.base
    }

    fn cs_base(&self) -> u64 {
        self.vcpu.guest().cs.base
    }

    fn msr_model(&mut self) -> Option<&mut crate::s9vm::msr::MsrModel> {
        // SeaBIOS executes `RDMSR`/`WRMSR` during POST; the model keeps those
        // guest-local instead of touching a host MSR.
        Some(self.vcpu.msr_mut())
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
    instruction_length: u32,
) -> bool {
    // Segment bases drive instruction fetch (`CS.base + IP`) and string I/O
    // (`ES`/`DS`). They may have changed since the last exit (option ROM far
    // jumps, mode switches), so refresh them before decoding the instruction.
    // SAFETY: block loaded, guest inactive (exit handler).
    let _ = unsafe { vcpu.refresh_system_state() };
    let mut view = emulate::MemoryView::new(memory, ept_root, 0, false);
    let mut guest = VcpuGuest::new(vcpu);
    matches!(
        emulate::handle_exit_with_length(
            devices,
            apic,
            &mut view,
            &mut guest,
            class,
            qualification,
            guest_physical_address,
            instruction_length
        ),
        Ok(true)
    )
}

/// Delivers one pending 8259 request straight into the guest.
///
/// `vcpu.inject_interrupt` performs a VM-entry event injection, which is not
/// filtered by the local APIC's "vector >= 0x10" rule: that is exactly what a
/// legacy firmware needs for `INT 08h` (timer) and `INT 0Eh` (floppy). The
/// request is only acknowledged once the guest can take it, else it stays in
/// the `IRR` for the next attempt.
fn deliver_legacy_interrupt(vcpu: &mut Vcpu, devices: &mut emulate::Devices) -> bool {
    if !devices.legacy_pic() || !devices.pic.has_pending() {
        return false;
    }
    if vcpu.guest().rflags & (1 << 9) == 0 {
        return false;
    }
    let deliverable = unsafe { vcpu.interruptibility() }
        .map(|state| state & 0b11 == 0)
        .unwrap_or(false);
    if !deliverable {
        return false;
    }
    let Some(vector) = devices.pic.acknowledge() else {
        return false;
    };
    // SAFETY: block loaded, guest inactive (exit handler), and the interrupt
    // is deliverable (checked above).
    unsafe { vcpu.inject_interrupt(vector) }.is_ok()
}

/// Host text waiting to be typed into a DOS guest.
///
/// The text is translated to PS/2 set-1 scancodes once, then handed to the 8042
/// model only after the guest owns `INT 9` and has unmasked `IRQ1`: before that
/// the guest is still probing the controller and could mistake a scancode for a
/// command reply.
struct KeyboardFeed {
    scancodes: Vec<u8>,
    next: usize,
}

impl KeyboardFeed {
    fn new(keys: &[u8]) -> Self {
        let mut scancodes = Vec::new();
        if !keys.is_empty() {
            keyboard::text_to_scancodes(keys, &mut scancodes);
        }
        Self { scancodes, next: 0 }
    }

    /// Scancodes not handed to the controller yet.
    fn remaining(&self) -> usize {
        self.scancodes.len().saturating_sub(self.next)
    }

    /// Queues up to `limit` scancodes; returns how many were accepted.
    fn fill(&mut self, controller: &mut keyboard::KeyboardController, limit: usize) -> usize {
        let mut sent = 0;
        while sent < limit && self.next < self.scancodes.len() {
            if !controller.push_scancode(self.scancodes[self.next]) {
                break;
            }
            self.next += 1;
            sent += 1;
        }
        sent
    }
}

/// True when the guest has installed its own handler for `vector`.
///
/// The firmware ROM stub is the initial owner of every serviced vector; the
/// first time the guest rewrites the IVT entry it owns the vector from then on.
fn guest_owns_vector(memory: &mut WorldMemory, vector: u8) -> bool {
    let entry = biosrom::IVT_BASE + u32::from(vector) * 4;
    let read_word = |memory: &mut WorldMemory, offset: u32| -> Option<u16> {
        let lo = bios::BiosMemory::read_u8(memory, offset)?;
        let hi = bios::BiosMemory::read_u8(memory, offset + 1)?;
        Some(u16::from_le_bytes([lo, hi]))
    };
    let (Some(offset), Some(segment)) = (read_word(memory, entry), read_word(memory, entry + 2))
    else {
        return false;
    };
    offset != biosrom::stub_offset(vector) || segment != biosrom::ROM_SEGMENT
}

/// Delivers pending platform interrupts and types host keys into a DOS guest.
///
/// Called before each guest entry and on a `hlt` exit. Returns `true` when a
/// vector was injected: the guest should be resumed instead of being treated as
/// idle.
fn pump_dos_interrupts(
    vcpu: &mut Vcpu,
    devices: &mut emulate::Devices,
    memory: &mut WorldMemory,
    feed: &mut KeyboardFeed,
    report: &mut DosReport,
) -> Result<bool, DosError> {
    // Keyboard: type only when the guest's own `INT 9` handler is installed and
    // `IRQ1` is unmasked; the guest may reprogram the mask at any time.
    if feed.remaining() != 0
        && guest_owns_vector(memory, 0x09)
        && devices.pic.master().mask() & 0x02 == 0
    {
        report.scancodes_typed += feed.fill(&mut devices.keyboard, 8) as u32;
    }
    // `IRQ1` follows the controller output buffer: a real 8042 keeps the line
    // high while a scancode waits to be read.
    if devices.keyboard.has_scancode() {
        devices.pic.raise(1);
    } else {
        devices.pic.lower(1);
    }
    if deliver_legacy_interrupt(vcpu, devices) {
        report.interrupts_delivered += 1;
        return Ok(true);
    }
    Ok(false)
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
/// Block-device adapter over the machine copy the DOS runner holds.
///
/// The runner takes the world's device model out of the registry while it runs
/// (a live session keeps it between commands), so the disk image lives in that
/// copy: the BIOS call borrows the image for its duration.
struct MachineDisk<'a> {
    image: &'a mut [u8],
    sectors: u64,
}

impl bios::BiosDisk for MachineDisk<'_> {
    fn sectors(&self) -> u64 {
        self.sectors
    }

    fn read_sector(&mut self, sector: u64, out: &mut [u8; biosrom::SECTOR_SIZE]) -> bool {
        if sector >= self.sectors {
            return false;
        }
        let start = (sector as usize) * biosrom::SECTOR_SIZE;
        out.copy_from_slice(&self.image[start..start + biosrom::SECTOR_SIZE]);
        true
    }

    fn write_sector(&mut self, sector: u64, data: &[u8; biosrom::SECTOR_SIZE]) -> bool {
        if sector >= self.sectors {
            return false;
        }
        let start = (sector as usize) * biosrom::SECTOR_SIZE;
        self.image[start..start + biosrom::SECTOR_SIZE].copy_from_slice(data);
        true
    }
}

/// Block-device adapter over the registry copy of a world's disk.
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

    fn write_sector(&mut self, sector: u64, data: &[u8; biosrom::SECTOR_SIZE]) -> bool {
        if sector >= self.sectors {
            return false;
        }
        // The writes land in the world's block device: a guest that formats or
        // installs keeps its changes for the rest of the world's life.
        match vm::write_disk(self.world_id, sector, data) {
            Ok(written) => written == data.len(),
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

/// Reads the BIOS call registers, recovering the caller `AX`/`DX`.
///
/// The per-vector stub must use `DX` and `AL` to reach the kernel, so the
/// architectural register file at the `OUT` exit no longer holds the caller
/// values. The stub pushed them first; at the exit the guest stack still holds
/// `[SP] = saved DX` and `[SP + 2] = saved AX`. Recovering them is what makes
/// INT 10h/INT 13h see the real page/drive/count/character instead of the stub
/// port number in `DX`.
fn read_bios_call_registers(vcpu: &Vcpu, memory: &mut WorldMemory) -> bios::BiosRegisters {
    let mut registers = read_bios_registers(vcpu.guest());
    let guest = vcpu.guest();
    let stack = guest.ss.base.wrapping_add(u64::from(guest.rsp as u16)) as u32;
    let mut read_word = |memory: &mut WorldMemory, offset: u32| -> Option<u16> {
        let lo = bios::BiosMemory::read_u8(memory, stack.wrapping_add(offset))?;
        let hi = bios::BiosMemory::read_u8(memory, stack.wrapping_add(offset + 1))?;
        Some(u16::from_le_bytes([lo, hi]))
    };
    if let Some(dx) = read_word(memory, 0) {
        registers.dx = dx;
    }
    if let Some(ax) = read_word(memory, 2) {
        registers.ax = ax;
    }
    registers
}

/// Reads the `CS:IP` and `FLAGS` of a guest interrupt frame from its stack.
///
/// The catch-all ROM stub pushes `DX` before reporting the vector, so at the
/// `OUT` exit the frame sits at `SS:SP+2` (`IP`), `SS:SP+4` (`CS`) and
/// `SS:SP+6` (`FLAGS`). Returns `None` when the stack is not readable, which
/// makes the caller log the vector without a faulting address.
fn read_interrupt_frame(vcpu: &Vcpu, memory: &mut WorldMemory) -> Option<(u16, u16, u16)> {
    let guest = vcpu.guest();
    let stack = guest.ss.base.wrapping_add(u64::from(guest.rsp as u16)) as u32;
    let mut read_word = |memory: &mut WorldMemory, offset: u32| -> Option<u16> {
        let lo = bios::BiosMemory::read_u8(memory, stack.wrapping_add(offset))?;
        let hi = bios::BiosMemory::read_u8(memory, stack.wrapping_add(offset + 1))?;
        Some(u16::from_le_bytes([lo, hi]))
    };
    let ip = read_word(memory, 2)?;
    let cs = read_word(memory, 4)?;
    let flags = read_word(memory, 6)?;
    Some((ip, cs, flags))
}

/// Restores the interrupted code's `CF`/`ZF` through the stub scratch byte.
///
/// The shared stub tail patches the stacked `FLAGS` word from the scratch byte
/// (`CF` = bit 0, `ZF` = bit 1). That byte is the firmware *return* status for a
/// software `INT`, but for a hardware interrupt the same stacked word is the
/// interrupted code's `FLAGS`: clearing its `CF`/`ZF` would corrupt a guest
/// loop that was interrupted in the middle of a comparison. Mirroring the
/// stacked bits back leaves the guest's flags untouched.
fn preserve_interrupted_flags(vcpu: &Vcpu, memory: &mut WorldMemory) -> Result<(), DosError> {
    let guest = vcpu.guest();
    let stack = guest.ss.base.wrapping_add(u64::from(guest.rsp as u16)) as u32;
    // Stub frame: [SP] = saved DX, [SP + 2] = saved AX, [SP + 4] = IP,
    // [SP + 6] = CS, [SP + 8] = interrupted FLAGS.
    let flags_address = stack.wrapping_add(8);
    let lo = bios::BiosMemory::read_u8(memory, flags_address).ok_or(DosError::Memory)?;
    let hi = bios::BiosMemory::read_u8(memory, flags_address + 1).ok_or(DosError::Memory)?;
    let flags = u16::from_le_bytes([lo, hi]);
    let mut scratch = 0u8;
    if flags & 0x0001 != 0 {
        scratch |= 1;
    }
    if flags & 0x0040 != 0 {
        scratch |= 2;
    }
    if !biosrom::RomMemory::write(memory, biosrom::SCRATCH_GPA, &[scratch]) {
        return Err(DosError::Memory);
    }
    Ok(())
}

/// Writes the registers updated by the firmware model back to the vCPU.
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
    // Real-mode segment bases follow the selectors (`selector << 4`): make
    // ES/DS/SS current for INT 13h ES:BX, DAP DS:SI and INT 10h ES:BP.
    // SAFETY: block loaded, guest inactive (exit handler).
    unsafe {
        let _ = vcpu.set_guest_segments(registers.cs, registers.ds, registers.es, registers.ss);
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

/// Applies the firmware-specific device configuration to a DOS machine.
///
/// The SeaBIOS world uses the legacy PC device set: no PCI virtio functions, a
/// floppy loaded into the controller and the CMOS fields the firmware reads.
/// The stub-firmware world is a PC clone whose 8259 pair is programmed the way
/// a firmware leaves it, so the guest receives real `IRQ0`/`IRQ1` instead of
/// polling the BIOS.
fn configure_dos_machine(machine: &mut Machine, firmware: FirmwareKind, image: &'static [u8]) {
    if !firmware.is_seabios() {
        machine.devices_mut().set_legacy_pic(true);
        machine.devices_mut().pic = crate::s9vm::pic::Pic::bios_default();
        return;
    }
    let config = firmware::FirmwareConfig::freedos();
    let (extmem_low, extmem_high) = config.extmem_cmos();
    machine.devices_mut().set_legacy_pic(true);
    machine.devices_mut().load_floppy(image);
    machine
        .devices_mut()
        .add_fw_cfg_file("vgaroms/vgabios-stdvga.bin", firmware::seabios_vga_rom());
    machine
        .devices_mut()
        .rtc
        .set_ram(firmware::CMOS_FLOPPY_TYPE, config.cmos_floppy_type);
    machine
        .devices_mut()
        .rtc
        .set_ram(firmware::CMOS_EXTMEM_LOW, extmem_low);
    machine
        .devices_mut()
        .rtc
        .set_ram(firmware::CMOS_EXTMEM_HIGH, extmem_high);
    // QEMU-mode SeaBIOS reads its default boot order from CMOS: the low nibble
    // of 0x3D is the first device (1 = floppy), and 0x38 bit 0 would skip the
    // boot-sector signature check (it stays clear).
    machine
        .devices_mut()
        .rtc
        .set_ram(firmware::CMOS_BOOTFLAG1, 0);
    machine
        .devices_mut()
        .rtc
        .set_ram(firmware::CMOS_BOOTFLAG2, firmware::BOOT_ORDER_FLOPPY_FIRST);
}

/// A DOS world kept alive between two shell commands.
///
/// The engine is synchronous: `vm dos run` enters the guest for a bounded
/// slice, returns to the shell, and the next command resumes the same machine.
/// Keeping the vCPU, the device model and the BIOS state makes the prompt
/// interactive without a background task: `vm send <id> <text>` queues keys
/// between two runs and `vm console <id>` shows the screen the last run left.
pub struct DosSession {
    world_id: u64,
    disk_sectors: u64,
    firmware: FirmwareKind,
    image: &'static [u8],
    /// Control block of the session vCPU; `None` only after an internal error.
    vcpu: Option<Vcpu>,
    /// BIOS model state (video mode, cursor, keyboard buffer, tick count).
    bios_state: bios::BiosState,
    /// Scancodes typed by the host but not delivered to the guest yet.
    pending_keys: Vec<u8>,
    /// Number of slices entered since the session was opened.
    slices: u32,
    /// Autoexec marker seen by any slice.
    marker_seen: bool,
    /// Notable counters of the last slice, for `vm dos info`.
    last_exits: u32,
    last_irq: u32,
    last_keys: u32,
}

/// Snapshot of a live DOS session, for the shell.
#[derive(Debug, Clone, Copy)]
pub struct DosSessionStatus {
    /// World holding the session.
    pub world_id: u64,
    /// Slices entered so far.
    pub slices: u32,
    /// True once the AUTOEXEC marker was observed.
    pub marker_seen: bool,
    /// Scancodes still waiting to be typed.
    pub pending_keys: usize,
    /// Guest exits of the last slice.
    pub last_exits: u32,
    /// Platform interrupts delivered in the last slice.
    pub last_irq: u32,
    /// Scancodes typed in the last slice.
    pub last_keys: u32,
}

// SAFETY: a session is only touched by the shell task, and its control block is
// cleared (VMCLEAR) before the session is stored, so no CPU-local VT-x state
// survives a migration of that task to another core.
unsafe impl Send for DosSession {}

static DOS_SESSION: crate::sync::SpinLock<Option<DosSession>> = crate::sync::SpinLock::new(None);

/// Opens a live DOS world for the interactive `vm dos` commands.
///
/// The world is created, its memory mapped, the floppy attached and the
/// firmware installed now; the guest is not entered until [`dos_run`].
pub fn dos_open(
    caps: &HwCaps,
    firmware: FirmwareKind,
    image: &'static [u8],
) -> Result<u64, DosError> {
    require_real_mode(caps, firmware.label())?;
    if firmware.is_seabios() {
        // A live session resumes the vCPU of the stub firmware; the SeaBIOS
        // boot path builds its own legacy machine and is covered by
        // `vm test seabios`.
        return Err(DosError::BadExit(
            "live session supports the stub firmware only",
        ));
    }
    if DOS_SESSION.lock().is_some() {
        return Err(DosError::BadExit("a DOS session is already open"));
    }
    let record = vm::create(b"s9vm-dos-session", 0).ok_or(DosError::VmFail(1))?;
    let world_id = record.id;
    let setup = (|| -> Result<DosSession, DosError> {
        let disk_sectors = map_and_load_freedos(caps, world_id, firmware, image)?;
        install_freedos_artefacts(world_id, firmware, image)?;
        let pointer = vm::second_level_pointer(world_id, caps).map_err(|_| DosError::VmFail(6))?;
        let vcpu = Vcpu::new(caps, pointer)?;
        let mut machine = vm::take_machine(world_id).ok_or(DosError::VmFail(7))?;
        configure_dos_machine(&mut machine, firmware, image);
        if !vm::store_machine(world_id, machine) {
            return Err(DosError::VmFail(2));
        }
        Ok(DosSession {
            world_id,
            disk_sectors,
            firmware,
            image,
            vcpu: Some(vcpu),
            bios_state: bios::BiosState::new(),
            pending_keys: Vec::new(),
            slices: 0,
            marker_seen: false,
            last_exits: 0,
            last_irq: 0,
            last_keys: 0,
        })
    })();
    match setup {
        Ok(session) => {
            *DOS_SESSION.lock() = Some(session);
            Ok(world_id)
        }
        Err(error) => {
            let _ = vm::destroy(world_id);
            Err(error)
        }
    }
}

/// World identifier of the open session, if any.
pub fn dos_world_id() -> Option<u64> {
    DOS_SESSION.lock().as_ref().map(|session| session.world_id)
}

/// Snapshot of the open session, if any.
pub fn dos_status() -> Option<DosSessionStatus> {
    let session = DOS_SESSION.lock();
    session.as_ref().map(|session| DosSessionStatus {
        world_id: session.world_id,
        slices: session.slices,
        marker_seen: session.marker_seen,
        pending_keys: session.pending_keys.len(),
        last_exits: session.last_exits,
        last_irq: session.last_irq,
        last_keys: session.last_keys,
    })
}

/// Runs the live DOS session for one bounded slice and returns its report.
///
/// Console input queued by `vm send <id> <text>` is typed into the guest
/// keyboard, and the VGA text the run produced becomes the world's console
/// output, so a following `vm console <id>` shows the screen.
pub fn dos_run(caps: &HwCaps, limits: RunLimits) -> Result<DosReport, DosError> {
    let mut session = match DOS_SESSION.lock().take() {
        Some(session) => session,
        None => return Err(DosError::BadExit("no DOS session: run `vm dos open` first")),
    };
    let world_id = session.world_id;
    let mut keys = session.pending_keys.clone();
    keys.extend_from_slice(&vm::take_console_input(world_id));
    session.pending_keys.clear();
    let result = run_freedos_in_world(
        caps,
        world_id,
        limits,
        session.firmware,
        session.image,
        &keys,
        Some(&mut session),
    );
    if session.vcpu.is_some() {
        *DOS_SESSION.lock() = Some(session);
    } else {
        // The run failed before the vCPU was returned: keep the world from
        // leaking into the registry while its session is gone.
        let _ = vm::destroy(world_id);
    }
    let report = result?;
    let _ = vm::set_console_output(world_id, report.text.as_bytes());
    Ok(report)
}

/// Current VGA text of the open session.
pub fn dos_text() -> Option<String> {
    let world_id = DOS_SESSION
        .lock()
        .as_ref()
        .map(|session| session.world_id)?;
    let mut memory = WorldMemory::new(world_id);
    Some(bios::read_text(&mut memory))
}

/// Closes the live session and destroys its world.
pub fn dos_close() -> bool {
    let Some(mut session) = DOS_SESSION.lock().take() else {
        return false;
    };
    if let Some(mut vcpu) = session.vcpu.take() {
        // The control block was cleared at the end of the last slice.
        // SAFETY: VT-x is active while the shell runs; clear is a no-op when
        // the block is already unloaded.
        unsafe {
            let _ = vcpu.clear();
        }
    }
    let _ = vm::destroy(session.world_id);
    true
}

/// Boot-time selftest of the live DOS session.
///
/// Boots the floppy through [`dos_open`]/[`dos_run`], types `dir` through the
/// world console queue (the same path as `vm send`), runs a second slice and
/// checks that the floppy was listed. This exercises the whole interactive
/// path without an operator: 8259 delivery, the 8042 keyboard, the resumed
/// vCPU and the writable disk model.
pub fn run_freedos_session_selftest(caps: &HwCaps) -> Result<(), DosError> {
    let world_id = dos_open(caps, FirmwareKind::Stub, freedos_image())?;
    let result = (|| -> Result<(), DosError> {
        // First slice: stop at the AUTOEXEC marker, which is the proof the
        // boot reached the DOS prompt.
        let boot_limits = RunLimits {
            max_exits: MAX_FREEDOS_EXITS,
            max_nanoseconds: 15_000_000_000,
            stop_at_marker: true,
        };
        let report = dos_run(caps, boot_limits)?;
        if !report.text.contains("FreeDOS") {
            return Err(DosError::BadExit("boot banner missing"));
        }
        if report.marker != Some(SUCCESS_MARKER) {
            log::warn!(
                "[s9vm] freedos-session: no AUTOEXEC marker after boot (text {} characters)",
                report.text.len()
            );
            return Err(DosError::BadExit("boot did not reach the DOS prompt"));
        }
        // Type `dir` at the prompt: the console queue is the `vm send` path.
        vm::push_console_input(world_id, b"dir\n").map_err(|()| DosError::VmFail(9))?;
        let shell_limits = RunLimits {
            max_exits: MAX_FREEDOS_EXITS,
            max_nanoseconds: 4_000_000_000,
            stop_at_marker: false,
        };
        let report = dos_run(caps, shell_limits)?;
        if !report.text.contains("FDAUTO") {
            log::warn!(
                "[s9vm] freedos-session: screen after typed `dir`:\n{}",
                report.text
            );
            return Err(DosError::BadExit("typed `dir` did not list the floppy"));
        }
        log::info!(
            "[s9vm] freedos-session: typed keys={} irq={} and the floppy listed",
            report.scancodes_typed,
            report.interrupts_delivered
        );
        Ok(())
    })();
    let _ = dos_close();
    result
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
    firmware: FirmwareKind,
    image: &'static [u8],
    keys: &[u8],
    session: Option<&mut DosSession>,
) -> Result<DosReport, DosError> {
    // Timestamp origin of the whole launch, before the first world mapping.
    // The run budget has its own origin later; this one measures preparation
    // (mapping, firmware copy, vCPU setup) as well as execution.
    let launch_tsc = unsafe { core::arch::x86_64::_rdtsc() };
    let tsc_hz = crate::s9vm::tsc::get().map_or(FALLBACK_TSC_HZ, |frequency| frequency.hz());
    let mut session = session;
    let resuming = session.is_some();
    // Second-level tables of the world: needed by the device fast path whether
    // the world is freshly prepared or resumed.
    let pointer = vm::second_level_pointer(world_id, caps).map_err(|_| DosError::VmFail(6))?;
    // A resumed session already owns its mapped world, its firmware image, its
    // disk and its vCPU: only a fresh boot prepares those.
    let (disk_sectors, mut vcpu, mut bios_state, mut machine) =
        if let Some(session) = session.as_deref_mut() {
            let vcpu = session
                .vcpu
                .take()
                .ok_or(DosError::BadExit("DOS session without a vCPU"))?;
            let machine = vm::take_machine(world_id).ok_or(DosError::VmFail(7))?;
            let bios_state = core::mem::replace(&mut session.bios_state, bios::BiosState::new());
            let disk_sectors = session.disk_sectors;
            (disk_sectors, vcpu, bios_state, machine)
        } else {
            let disk_sectors = map_and_load_freedos(caps, world_id, firmware, image)?;
            log::info!(
                "[s9vm] {}: memory + disk ready at {} ms",
                firmware.label(),
                elapsed_millis(launch_tsc, tsc_hz)
            );
            install_freedos_artefacts(world_id, firmware, image)?;
            log::info!(
                "[s9vm] {}: firmware installed at {} ms",
                firmware.label(),
                elapsed_millis(launch_tsc, tsc_hz)
            );
            // Detached vCPU: the run loop drives it directly, no scheduler.
            let vcpu = Vcpu::new(caps, pointer)?;
            // The stub-firmware world keeps its device model in the registry
            // (the disk image is loaded there); the SeaBIOS world builds the
            // legacy PC device set itself, because it must not see the virtio
            // PCI functions the firmware would try to drive.
            let mut machine = if firmware.is_seabios() {
                Machine::new_legacy()
            } else {
                vm::take_machine(world_id).ok_or(DosError::VmFail(7))?
            };
            configure_dos_machine(&mut machine, firmware, image);
            (disk_sectors, vcpu, bios::BiosState::new(), machine)
        };
    let mut memory = WorldMemory::new(world_id);
    // Pin the task to this CPU before the VMCS is loaded: the STI window of
    // `service_pending_host_interrupts` lets the timer interrupt run, and
    // without this guard it could migrate the task while the VMCS is active on
    // this CPU, so the final VMCLEAR would run on the wrong one. Declared
    // before `_irq` so interrupts are restored first on every return path.
    let _pin = crate::sync::preempt::PreemptGuard::new();
    // Keep host interrupts disabled for the whole run; the guard restores them
    // on every return path.
    let _irq = IrqOff::new();
    // SAFETY: VT-x is active on this CPU (checked by the caller), interrupts
    // are disabled around the whole phase, and this control block is only used
    // by this task.
    unsafe {
        vcpu.load()?;
        vcpu.configure_host()?;
        if vcpu.entered() {
            // The guest already ran on this control block: import the
            // architectural state the processor saved on the last exit and
            // reconfigure from it, so a resumed session continues exactly
            // where the previous slice stopped (same rule as the RUN path).
            vcpu.refresh_system_state()?;
            let guest = *vcpu.guest();
            vcpu.configure(caps, &guest)?;
        } else {
            let guest = match firmware {
                FirmwareKind::Stub => GuestState::real_mode(
                    u64::from(biosrom::BOOT_SECTOR_GPA),
                    u64::from(biosrom::BOOT_STACK_TOP),
                ),
                FirmwareKind::SeaBios => {
                    // Architectural reset state: `CS=F000`, `IP=FFF0` (linear
                    // `0xFFFF0`), the far jump at the end of the BIOS image.
                    let mut state = GuestState::real_mode(
                        u64::from(firmware::RESET_IP),
                        u64::from(biosrom::BOOT_STACK_TOP),
                    );
                    state.cs.selector = firmware::RESET_SEGMENT;
                    state.cs.base = u64::from(firmware::RESET_SEGMENT) << 4;
                    state
                }
            };
            vcpu.configure(caps, &guest)?;
        }
        vcpu.set_preemption_timer_ticks(if firmware.is_seabios() {
            SEABIOS_PREEMPTION_SLICE_TICKS
        } else {
            PREEMPTION_SLICE_TICKS
        });
    }
    log::info!(
        "[s9vm] {}: {} {} guest at {:#x} ({} ms)",
        firmware.label(),
        if resuming { "resuming" } else { "entering" },
        if firmware.is_seabios() {
            "real-firmware"
        } else {
            "real-mode"
        },
        vcpu.guest().rip,
        elapsed_millis(launch_tsc, tsc_hz)
    );

    let mut report = DosReport::new(disk_sectors);
    if firmware.is_seabios() {
        report.boot_sector_gpa = u64::from(firmware::RESET_LINEAR);
        report.entry = u64::from(firmware::RESET_LINEAR);
    }
    // Host text typed into the guest keyboard once the guest owns `INT 9`.
    let mut keyboard_feed = KeyboardFeed::new(keys);
    let mut apic = LocalApic::new(0);
    let mut unhandled_ports: u32 = 0;
    // First distinct unmodeled ports, so a guest that spins on one legacy port
    // names it in the log instead of only showing an exit counter.
    let mut unhandled_seen: [u16; 8] = [0; 8];
    let mut unhandled_seen_len = 0usize;
    // Most-accessed I/O ports, to name a firmware polling loop in the log.
    let mut port_top: Vec<(u16, u32)> = Vec::new();
    // Wall-clock origin of the run: the shell-facing budget is measured from
    // here, independently of the exit counter.
    let start_tsc = unsafe { core::arch::x86_64::_rdtsc() };
    let mut last_tsc = start_tsc;
    let mut total_cycles: u64 = 0;
    let mut published_ticks: u32 = 0;
    let mut outcome: Result<(), DosError> = Ok(());
    // True while an interrupt is already posted in the VM-entry interruption
    // information field: a second injection before the guest runs would
    // overwrite it and silently lose the first request (the 8259 already
    // acknowledged it).
    let mut entry_injected = false;
    for _ in 0..limits.max_exits {
        // Deliver a pending interrupt while the guest is running. The stub
        // path uses the local APIC (vectors >= 0x10). A real firmware owns the
        // 8259 vectors (0x08..=0x0F), which the runner injects itself; the
        // injection is deferred to a preemption/HLT exit because the floppy
        // ISR must not run before SeaBIOS' `floppy_wait_irq` has cleared its
        // BDA flag (a real controller completes the command asynchronously).
        if !firmware.is_seabios() {
            if let Some(vector) = apic.pending_vector() {
                let deliverable = vcpu.guest().rflags & (1 << 9) != 0
                    && unsafe { vcpu.interruptibility() }
                        .map(|state| state & 0b11 == 0)
                        .unwrap_or(false);
                if deliverable {
                    unsafe { vcpu.inject_interrupt(vector) }.map_err(DosError::Run)?;
                    let _ = apic.service();
                }
            }
        }
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
                    "[s9vm] {}: time budget reached at {} ms after {} exit(s)",
                    firmware.label(),
                    elapsed_millis(launch_tsc, tsc_hz),
                    report.total_exits
                );
                report.timed_out = true;
                break;
            }
        }
        if report.total_exits != 0 && report.total_exits % 4096 == 0 {
            log::info!(
                "[s9vm] {}: progress exit={} t={} ms io={} preempt={} hlt={} rip={:#x}",
                firmware.label(),
                report.total_exits,
                elapsed_millis(launch_tsc, tsc_hz),
                report.io_exits,
                report.preemption_slices,
                report.halt_exits,
                vcpu.guest().rip
            );
        }
        machine.advance_time(&mut apic, delta, tsc_hz);
        if !firmware.is_seabios() {
            // 18.2 Hz BIOS tick: `ticks` is the cumulative count derived from
            // the host cycles (182 / 10 per second). `advance_ticks`
            // accumulates, so only the difference with the previously
            // published value is added. A real firmware increments the BDA
            // counter from its own IRQ0 handler, so it must not be done twice.
            let ticks = (u128::from(total_cycles) * 182 / (u128::from(tsc_hz) * 10)) as u32;
            bios_state.advance_ticks(ticks.wrapping_sub(published_ticks));
            published_ticks = ticks;
            // The device time base has just raised its lines: deliver whatever
            // the 8259 pair latched, and type the next host keys once the guest
            // owns the keyboard interrupt. A vector already posted for this
            // entry is left alone: the field holds one interruption.
            if !entry_injected {
                match pump_dos_interrupts(
                    &mut vcpu,
                    machine.devices_mut(),
                    &mut memory,
                    &mut keyboard_feed,
                    &mut report,
                ) {
                    Ok(injected) => entry_injected = injected,
                    Err(error) => {
                        outcome = Err(error);
                        break;
                    }
                }
            }
        }
        // SAFETY: `run` contract: block loaded, IRQs disabled, configured.
        let exit = match unsafe { vcpu.run() } {
            Ok(exit) => exit,
            Err(error) => {
                log::warn!("[s9vm] freedostest: run failed: {:?}", error);
                outcome = Err(DosError::Run(error));
                break;
            }
        };
        // The entry consumed any posted interruption.
        entry_injected = false;
        report.total_exits += 1;
        match exit.class() {
            ExitClass::IoPort => {
                report.io_exits += 1;
                let port = ((exit.qualification >> 16) & 0xFFFF) as u16;
                let mut counted = false;
                for slot in &mut port_top {
                    if slot.0 == port {
                        slot.1 = slot.1.saturating_add(1);
                        counted = true;
                        break;
                    }
                }
                if !counted {
                    port_top.push((port, 1));
                }
                // The debug port is a marker only for a non-string OUT; other
                // accesses fall through to normal port handling.
                if port == DEBUG_PORT
                    && exit.qualification & 0x30 == 0
                    && exit.qualification & 0x08 == 0
                {
                    let marker = (vcpu.guest().rax & 0xFF) as u8;
                    report.marker = Some(marker);
                    if marker == SUCCESS_MARKER && limits.stop_at_marker {
                        // Advance past the `out` before stopping: a live
                        // session resumes this vCPU, and leaving RIP on the
                        // marker would replay it in the next slice.
                        if let Err(error) = advance_past_exit(&mut vcpu, &exit) {
                            outcome = Err(error);
                        }
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
                    // Refresh the segment registers: an INT call changes
                    // ES/DS/SS and the ROM handler relies on them.
                    // SAFETY: block loaded, guest inactive (exit handler).
                    if let Err(error) =
                        unsafe { vcpu.refresh_system_state() }.map_err(DosError::Run)
                    {
                        outcome = Err(error);
                        break;
                    }
                    let mut registers = read_bios_call_registers(&vcpu, &mut memory);
                    // The boot sector reboots (`int 19h`) or enters ROM BASIC
                    // (`int 18h`) when it cannot load the kernel. Both vectors
                    // now reach the BIOS stubs; turning them into a clean
                    // abort avoids jumping into the zeroed IVT entry and
                    // executing garbage at 0000:0000.
                    if vector == 0x18 || vector == 0x19 {
                        let text = bios::read_text(&mut memory);
                        log::warn!(
                            "[s9vm] freedostest: guest requested a reboot (int {:#04x}) \
                             after {} BIOS call(s); text={:?}",
                            vector,
                            report.bios_calls,
                            text
                        );
                        outcome = Err(DosError::BadExit("guest requested reboot"));
                        break;
                    }
                    let request = (registers.ax, registers.bx, registers.cx, registers.dx);
                    {
                        // The machine is held by this runner, so the disk
                        // adapter borrows its image instead of going through
                        // the registry (which holds a placeholder while the
                        // session runs).
                        let image = machine.devices_mut().blk.disk_mut();
                        let sectors = (image.len() / biosrom::SECTOR_SIZE) as u64;
                        let mut disk = MachineDisk { image, sectors };
                        let _ = bios_state.handle(vector, &mut registers, &mut memory, &mut disk);
                    }
                    write_bios_registers(&mut vcpu, &registers);
                    // A platform interrupt (`IRQ0..IRQ7`, master vectors
                    // `0x08..=0x0F`, or the slave's `0x70..=0x77`) reaches the
                    // firmware stub while the guest has not installed its own
                    // handler yet. Its stacked FLAGS are the interrupted code's
                    // flags (keep them) and the real BIOS handler ends with an
                    // EOI, so the request must leave the 8259 in-service
                    // register here or the line would never be delivered again.
                    let platform_irq = matches!(vector, 0x08..=0x0F | 0x70..=0x77);
                    if platform_irq {
                        if let Err(error) = preserve_interrupted_flags(&vcpu, &mut memory) {
                            outcome = Err(error);
                            break;
                        }
                        machine.devices_mut().pic.eoi();
                        report.interrupts_serviced += 1;
                    } else if let Err(error) = write_scratch(&mut memory, &registers) {
                        outcome = Err(error);
                        break;
                    }
                    report.bios_calls += 1;
                    // Trace the first calls: the FreeDOS boot sector prints
                    // "Error!" after a failed INT 13h, and the exact AH/CHS
                    // request plus the returned AX is what identifies the
                    // missing BIOS behaviour.
                    if report.bios_calls <= 48 {
                        log::info!(
                            "[s9vm] freedostest: BIOS int {:#04x} ah={:#04x} in ax={:#06x} \
                             bx={:#06x} cx={:#06x} dx={:#06x} -> ax={:#06x} flags={:#06x}",
                            vector,
                            (request.0 >> 8) as u8,
                            request.0,
                            request.1,
                            request.2,
                            request.3,
                            registers.ax,
                            registers.flags
                        );
                    }
                    if let Err(error) = advance_past_exit(&mut vcpu, &exit) {
                        outcome = Err(error);
                        break;
                    }
                } else if let Some(vector) = biosrom::fault_vector(port) {
                    // The catch-all ROM stub: the guest took an interrupt whose
                    // vector has no firmware service. Reporting the faulting
                    // `CS:IP` is what turns a silent jump through the zeroed
                    // IVT entry into an actionable diagnostic.
                    report.unhandled_interrupts += 1;
                    let frame = read_interrupt_frame(&vcpu, &mut memory);
                    match frame {
                        Some((ip, cs, flags)) => log::warn!(
                            "[s9vm] {}: unhandled interrupt {:#04x} at {:#06x}:{:#04x} \
                             flags={:#06x} after {} BIOS call(s)",
                            firmware.label(),
                            vector,
                            cs,
                            ip,
                            flags,
                            report.bios_calls
                        ),
                        None => log::warn!(
                            "[s9vm] {}: unhandled interrupt {:#04x} (frame unavailable) \
                             after {} BIOS call(s)",
                            firmware.label(),
                            vector,
                            report.bios_calls
                        ),
                    }
                    // A CPU exception or a platform interrupt has no DOS owner:
                    // continuing would re-enter the same faulting instruction
                    // forever, so the run stops with the diagnostic. A software
                    // vector (>= 0x20) may be a guest calling a service it has
                    // not installed yet: it returns and the count bounds a loop.
                    let fatal =
                        vector <= 0x1F || report.unhandled_interrupts >= MAX_UNHANDLED_INTERRUPTS;
                    if fatal {
                        outcome = Err(DosError::BadExit("unhandled guest interrupt"));
                        break;
                    }
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
                        exit.instruction_length,
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
                        // An unhandled `in` returns all ones: the accumulator
                        // is the modelled destination (`in al,dx` is the common
                        // probe form).
                        if direction_in {
                            let size = ((exit.qualification & 0x7) + 1) as u8;
                            let mask: u64 = match size {
                                1 => 0xFF,
                                2 => 0xFFFF,
                                _ => 0xFFFF_FFFF,
                            };
                            let previous = vcpu.guest().rax;
                            // SAFETY: block loaded, guest inactive.
                            unsafe {
                                vcpu.set_guest_gpr(0, (previous & !mask) | mask);
                            }
                        }
                        if let Err(error) = advance_past_exit(&mut vcpu, &exit) {
                            outcome = Err(error);
                            break;
                        }
                    }
                    if machine.devices_mut().system.take_reset() {
                        log::warn!(
                            "[s9vm] {}: guest requested a machine reset",
                            firmware.label()
                        );
                        outcome = Err(DosError::BadExit("guest requested reset"));
                        break;
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
                    0,
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
                    // Advance RIP first: `advance_rip` also clears the STI /
                    // MOV-SS shadow so the injected vector is deliverable.
                    if let Err(error) = advance_past_exit(&mut vcpu, &exit) {
                        outcome = Err(error);
                        break;
                    }
                    if firmware.is_seabios() {
                        // Prefer the pending 8259 request (timer 0x08 or FDC
                        // 0x0E); fall back to the timer so a `yield()` with no
                        // armed time base still makes progress.
                        if deliver_legacy_interrupt(&mut vcpu, machine.devices_mut()) {
                            continue;
                        }
                        if let Err(error) = unsafe { vcpu.inject_interrupt(0x08) } {
                            log::warn!(
                                "[s9vm] {}: cannot inject timer: {:?}",
                                firmware.label(),
                                error
                            );
                            outcome = Err(DosError::Run(error));
                            break;
                        }
                        continue;
                    }
                    // Stub-firmware world: the 8259 pair owns the legacy
                    // vectors, so a pending timer or keyboard request is what
                    // wakes the guest from `hlt`.
                    match pump_dos_interrupts(
                        &mut vcpu,
                        machine.devices_mut(),
                        &mut memory,
                        &mut keyboard_feed,
                        &mut report,
                    ) {
                        Ok(true) => {
                            entry_injected = true;
                            continue;
                        }
                        Ok(false) => {}
                        Err(error) => {
                            outcome = Err(error);
                            break;
                        }
                    }
                    let from_apic = apic.pending_vector();
                    let vector = from_apic.unwrap_or(0x08);
                    // SAFETY: block loaded, guest inactive (exit handler).
                    if let Err(error) = unsafe { vcpu.inject_interrupt(vector) } {
                        log::warn!("[s9vm] freedostest: cannot inject timer: {:?}", error);
                        outcome = Err(DosError::Run(error));
                        break;
                    }
                    if from_apic.is_some() {
                        let _ = apic.service();
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
                // spins without executing any guest code. Open a one-instruction
                // window so the host services the IRQ; the vector is never
                // delivered into the guest.
                crate::s9vm::vcpu::service_pending_host_interrupts();
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
                if firmware.is_seabios() {
                    // The only delivery point guaranteed to be *after* the
                    // firmware entered its wait loop: a level-triggered 8259
                    // request stays in the IRR until then, so the floppy ISR
                    // cannot race `floppy_wait_irq`'s flag clear.
                    let _ = deliver_legacy_interrupt(&mut vcpu, machine.devices_mut());
                }
            }
            ExitClass::Cpuid => {
                // CPUID is replayed from the world policy. SeaBIOS probes the
                // processor during POST; the stub path never executed CPUID.
                // SAFETY: block loaded, guest inactive.
                if !matches!(
                    unsafe { machine.handle(&mut vcpu, &mut apic, &exit) },
                    Ok(true)
                ) {
                    log::warn!(
                        "[s9vm] {}: unreplayed CPUID leaf {:#x}",
                        firmware.label(),
                        vcpu.guest().rax as u32
                    );
                    outcome = Err(DosError::BadExit("unhandled cpuid"));
                    break;
                }
            }
            ExitClass::Msr => {
                // RDMSR/WRMSR are served by the per-vCPU MSR shadow (MTRRs are
                // not advertised, so SeaBIOS skips its MTRR setup; the model
                // accepts the architectural selectors it does touch).
                let consumed = run_device_fast_path(
                    &mut memory,
                    &mut vcpu,
                    pointer,
                    machine.devices_mut(),
                    &mut apic,
                    ExitClass::Msr,
                    exit.qualification,
                    0,
                    0,
                );
                if !consumed {
                    log::warn!(
                        "[s9vm] {}: unhandled MSR access (reason {:#x}, rip {:#x})",
                        firmware.label(),
                        exit.reason.reason,
                        vcpu.guest().rip
                    );
                    outcome = Err(DosError::BadExit("unhandled msr"));
                    break;
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
    // The local vCPU is not stored in the registry: unload the control block
    // so `Drop` can release its frames on this CPU.
    unsafe {
        let _ = vcpu.clear();
    }
    // Entry state of the run that just ended, used by the budget diagnostics
    // below and by the session hand-over.
    let final_rip = vcpu.guest().rip;
    if firmware.is_seabios() {
        let debug_con = machine.devices_mut().drain_debug_con();
        if !debug_con.is_empty() {
            log::info!(
                "[s9vm] {}: firmware debugcon: {}",
                firmware.label(),
                String::from_utf8_lossy(&debug_con)
            );
        }
        let serial = machine.drain_serial();
        if !serial.is_empty() {
            log::info!(
                "[s9vm] {}: firmware serial: {}",
                firmware.label(),
                String::from_utf8_lossy(&serial)
            );
        }
        port_top.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        for (port, count) in port_top.iter().take(16) {
            if *count != 0 {
                log::info!(
                    "[s9vm] {}: port {:#06x}: {} access(es)",
                    firmware.label(),
                    port,
                    count
                );
            }
        }
        log::info!(
            "[s9vm] {}: io={} preempt={} hlt={} total={} ms",
            firmware.label(),
            report.io_exits,
            report.preemption_slices,
            report.halt_exits,
            elapsed_millis(launch_tsc, tsc_hz)
        );
    }
    // Hand the machine back to a live session (or drop it with the world of a
    // fresh boot). The vCPU is stored only after its control block was
    // cleared, so the session can be resumed from another task or core.
    if let Some(session) = session.as_deref_mut() {
        session.vcpu = Some(vcpu);
        session.bios_state = bios_state;
        session.pending_keys = keyboard_feed.scancodes[keyboard_feed.next..].to_vec();
        session.slices = session.slices.saturating_add(1);
        session.marker_seen |= report.marker == Some(SUCCESS_MARKER);
        session.last_exits = report.total_exits;
        session.last_irq = report.interrupts_delivered;
        session.last_keys = report.scancodes_typed;
        // Explain a slice where the host keys never reached the guest: the
        // two gates are the guest's own INT 9 handler and the 8259 mask.
        if !session.pending_keys.is_empty() {
            let owns = guest_owns_vector(&mut memory, 0x09);
            let masked = machine.devices().pic.master().mask() & 0x02 != 0;
            log::warn!(
                "[s9vm] {}: {} host scancode(s) not typed (guest INT 9 owner: {}, IRQ1 masked: {})",
                firmware.label(),
                session.pending_keys.len(),
                owns,
                masked
            );
        }
        let _ = vm::store_machine(world_id, machine);
    }
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
            final_rip
        );
    }
    report.text = bios::read_text(&mut memory);
    Ok(report)
}

/// Verifies the FreeDOS output: the AUTOEXEC marker and the expected text.
fn verify_freedos(report: &DosReport, expected: &str) -> Result<(), DosError> {
    if report.marker != Some(SUCCESS_MARKER) {
        log::warn!("[s9vm] freedostest: unexpected marker {:?}", report.marker);
        return Err(DosError::BadExit("missing FreeDOS success marker"));
    }
    if !report.text.contains(expected) {
        log::warn!(
            "[s9vm] freedostest: expected {:?} missing from the VGA text ({} characters)",
            expected,
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
    Ok(DosReport::new(disk_sectors))
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
    run_freedos_dry_with(
        caps,
        FirmwareKind::Stub,
        freedos_image(),
        b"s9vm-freedos-dry",
    )
}

/// Verifies the Hello/DIR demo image **without VT-x**.
///
/// The stub path is used because it also verifies the disk image installation
/// (boot sector copy, OEM name, capacity); the real boot uses SeaBIOS.
pub fn run_freedos_hello_dry(caps: &HwCaps) -> Result<DosReport, DosError> {
    run_freedos_dry_with(
        caps,
        FirmwareKind::Stub,
        freedos_hello_image(),
        b"s9vm-freedos-hello-dry",
    )
}

/// Installs the real SeaBIOS firmware and its VGA option ROM **without VT-x**.
///
/// The same world mapping as the boot path is exercised, then every firmware
/// artefact is read back through the world translation: the 256 KiB BIOS at
/// `0xC0000`, its reset vector, the option ROM in its zero prefix, and the 4
/// MiB high window. This is the deterministic regression for the real-firmware
/// path on hosts without VT-x.
pub fn run_freedos_seabios_dry(caps: &HwCaps) -> Result<DosReport, DosError> {
    run_freedos_dry_with(
        caps,
        FirmwareKind::SeaBios,
        freedos_image(),
        b"s9vm-freedos-seabios-dry",
    )
}

fn run_freedos_dry_with(
    caps: &HwCaps,
    firmware: FirmwareKind,
    image: &'static [u8],
    name: &'static [u8],
) -> Result<DosReport, DosError> {
    let record = vm::create(name, 0).ok_or(DosError::VmFail(1))?;
    let result = run_freedos_dry_in_world(caps, record.id, firmware, image);
    let _ = vm::destroy(record.id);
    result
}

/// Body of the VT-x-free FreeDOS dry run; the caller owns the world.
fn run_freedos_dry_in_world(
    caps: &HwCaps,
    world_id: u64,
    firmware: FirmwareKind,
    image: &'static [u8],
) -> Result<DosReport, DosError> {
    let disk_sectors = map_and_load_freedos(caps, world_id, firmware, image)?;
    install_freedos_artefacts(world_id, firmware, image)?;
    let mut memory = WorldMemory::new(world_id);
    match firmware {
        FirmwareKind::Stub => verify_freedos_installation(&mut memory, disk_sectors, image)?,
        FirmwareKind::SeaBios => verify_seabios_installation(&mut memory, disk_sectors)?,
    }
    let mut report = DosReport::new(disk_sectors);
    if firmware.is_seabios() {
        report.boot_sector_gpa = u64::from(firmware::RESET_LINEAR);
        report.entry = u64::from(firmware::RESET_LINEAR);
    }
    Ok(report)
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
    image: &'static [u8],
) -> Result<(), DosError> {
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

/// Checks every artefact written by the SeaBIOS installation.
///
/// The contract the selftest mode `freedos_seabios_dry` reports on:
///
/// 1. the block device still exposes the 2880-sector FreeDOS floppy;
/// 2. the 256 KiB BIOS is at `0xC0000`, with the `FAR JMP F000:xxxx` reset
///    vector at `0xFFFF0`; the first 64 KiB are zero padding shared with the
///    VGA option ROM (the comparison accounts for that overlap);
/// 3. the VGA option ROM is at `0xC0000`, with its `0x55AA` signature, size
///    code and zero modulo-256 checksum;
/// 4. no stub IVT entry was installed (SeaBIOS builds its own);
/// 5. the VGA text buffer is zeroed;
/// 6. the full advertised 4 MiB window is mapped and writable.
fn verify_seabios_installation(
    memory: &mut WorldMemory,
    disk_sectors: u64,
) -> Result<(), DosError> {
    if disk_sectors != FREEDOS_DISK_SECTORS {
        return Err(DosError::BadExit("unexpected FreeDOS disk capacity"));
    }
    let image = firmware::seabios_image();
    let info =
        firmware::validate_bios(image).map_err(|_| DosError::BadExit("invalid SeaBIOS image"))?;
    let rom = firmware::seabios_vga_rom();
    let rom_info = firmware::validate_option_rom(rom)
        .map_err(|_| DosError::BadExit("invalid VGA option ROM"))?;
    let mut readback = vec![0u8; image.len()];
    if !biosrom::RomMemory::read(memory, info.base, &mut readback) {
        return Err(DosError::Mmu);
    }
    // The VGA option ROM is installed in the BIOS image's zero-filled prefix;
    // compare the shared range against the ROM and the rest against the BIOS.
    let overlap = rom_info.base >= info.base
        && rom_info.base + rom_info.len <= info.base + image.len() as u32;
    let overlap_start = if overlap {
        (rom_info.base - info.base) as usize
    } else {
        usize::MAX
    };
    let overlap_end = overlap_start.saturating_add(rom_info.len as usize);
    for (index, byte) in readback.iter().enumerate() {
        let expected = if index >= overlap_start && index < overlap_end {
            rom[index - overlap_start]
        } else {
            image[index]
        };
        if *byte != expected {
            return Err(DosError::BadExit("SeaBIOS image copy differs"));
        }
    }
    let mut reset = [0u8; firmware::RESET_VECTOR_LEN];
    if !biosrom::RomMemory::read(memory, firmware::RESET_LINEAR, &mut reset) {
        return Err(DosError::Mmu);
    }
    if reset[0] != 0xEA || reset[3] != 0x00 || reset[4] != 0xF0 {
        return Err(DosError::BadExit("SeaBIOS reset vector differs"));
    }
    // The top-of-4GiB alias must expose the same bytes: the reset vector is
    // fetched at 0xFFFFFFF0 and SeaBIOS' high code runs from this window.
    let mut alias_reset = [0u8; firmware::RESET_VECTOR_LEN];
    if !biosrom::RomMemory::read(memory, 0xFFFF_FFF0, &mut alias_reset) {
        return Err(DosError::Mmu);
    }
    if alias_reset != reset {
        return Err(DosError::BadExit("SeaBIOS high alias differs"));
    }
    let mut option = vec![0u8; rom_info.len as usize];
    if !biosrom::RomMemory::read(memory, rom_info.base, &mut option) {
        return Err(DosError::Mmu);
    }
    if option != rom[..rom_info.len as usize] {
        return Err(DosError::BadExit("VGA option ROM copy differs"));
    }
    // No stub firmware was installed: SeaBIOS owns the IVT.
    if memory.dword(biosrom::IVT_BASE + 0x10 * 4) != Some(0) {
        return Err(DosError::BadExit("stub IVT leaked into the SeaBIOS world"));
    }
    let mut video = [0xFFu8; 320];
    if !biosrom::RomMemory::read(memory, biosrom::VIDEO_BASE, &mut video) {
        return Err(DosError::Mmu);
    }
    if video.iter().any(|byte| *byte != 0) {
        return Err(DosError::BadExit("video buffer is not zeroed"));
    }
    // Probe the top of the advertised 4 MiB range: SeaBIOS may place its
    // allocator and tables anywhere inside it.
    let probe_address = (SEABIOS_HIGH_MEMORY_END - 4) as u32;
    let probe: [u8; 4] = [0x5A, 0xA5, 0x00, 0xFF];
    let mut readback = [0u8; 4];
    if !biosrom::RomMemory::write(memory, probe_address, &probe)
        || !biosrom::RomMemory::read(memory, probe_address, &mut readback)
    {
        return Err(DosError::Mmu);
    }
    if readback != probe {
        return Err(DosError::BadExit(
            "SeaBIOS high memory window is not writable",
        ));
    }
    Ok(())
}
