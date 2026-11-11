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

//! s9vm — bare-metal virtualization system of strat9-os.
//!
//! # Principle
//!
//! **Bedrock provides the mechanism** (per-CPU VT-x activation, hardware
//! control block, second-level translation, exit reception, event
//! injection), **the policy silo** (to come) will decide the life cycle
//! of machines, device model, and interrupt routing.
//!
//! # Layout
//!
//! | Module | Content | Host-testable |
//! |---|---|---|
//! | [`caps`] | VT-x capability MSR decoding | yes |
//! | [`control`] | field encoding, control block primitives | yes (compiles) |
//! | [`mmu`] | second-level translation tables | yes |
//! | [`exit`] | exit decoding and classification | yes |
//!
//! # Initialization cycle
//!
//! 1. very early detection (CPUID + MSR), without side effects;
//! 2. per-CPU activation when the frame allocator is ready (component
//!    `bootstrap`): `CR4.VMXE`, 4 KiB activation region, activation;
//! 3. vCPUs will be created later by the policy layer.
//!
//! The absence of VT-x is never fatal: the kernel boots normally and
//! logs `virtualisation inactive`.

pub mod acpi;
pub mod apic;
pub mod bootinfo;
pub mod caps;
pub mod bootparams;
pub mod bzimage;
pub mod control;
pub mod cpuid;
pub mod decode;
pub mod emulate;
pub mod exit;
pub mod exitqueue;
pub mod guest;
pub mod guestcode;
pub mod guestprog;
pub mod guestpt;
pub mod image;
pub mod ioapic;
pub mod iommu;
pub mod launch;
pub mod linuxboot;
pub mod machine;
pub mod memmap;
pub mod mmu;
pub mod msr;
pub mod pic;
pub mod pit;
pub mod rtc;
pub mod selftest;
pub mod smp;
pub mod uart;
pub mod timing;
pub mod tsc;
pub mod vcpu;
pub mod zeropage;
pub mod virtio;
pub mod virtio_blk;
pub mod virtio_console;
pub mod virtio_net;
pub mod vm;

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use caps::{CapsError, HwCaps, MsrSnapshot};

/// Global compile/behavior switch.
///
/// When `false`, `init()` only logs: useful for a diagnostic kernel or
/// an exotic platform. The code remains compiled, which avoids two
/// binary variants.
pub const S9VM_ENABLED: bool = true;

/// `CR4.VMXE` bit (hardware extension enable).
const CR4_VMXE: u64 = 1 << 13;

/// Maximum number of tracked CPUs (aligned with `percpu::MAX_CPUS`).
const MAX_CPUS: usize = crate::arch::x86_64::percpu::MAX_CPUS;

/// Per-CPU activation regions (physical address, 0 = not activated).
static REGIONS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
/// CPU whose activation succeeded.
static ACTIVATED: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];
/// Number of activated CPUs.
static ACTIVE_CPUS: AtomicU32 = AtomicU32::new(0);
/// Capabilities detected once and for all (0 = not detected).
static CAPS_VALID: AtomicBool = AtomicBool::new(false);

/// Initialization errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitError {
    /// No VT-x on this CPU.
    NotSupported,
    /// Firmware has locked the activation prohibition.
    LockedByFirmware,
    /// EPT absent or unusable.
    EptUnavailable,
    /// Cannot allocate the activation region.
    OutOfMemory,
    /// The activation instruction failed.
    ActivationFailed,
}

impl From<CapsError> for InitError {
    fn from(value: CapsError) -> Self {
        match value {
            CapsError::NotSupported => Self::NotSupported,
            CapsError::LockedByFirmware => Self::LockedByFirmware,
            CapsError::EptUnavailable => Self::EptUnavailable,
        }
    }
}

/// Reads an MSR through the architecture layer.
#[inline]
fn read_msr(msr: u32) -> u64 {
    crate::arch::x86_64::rdmsr(msr)
}

/// Writes an MSR through the architecture layer.
#[inline]
fn write_msr(msr: u32, value: u64) {
    crate::arch::x86_64::wrmsr(msr, value);
}

/// Reads `CR4`.
#[inline]
fn read_cr4() -> u64 {
    let value: u64;
    // SAFETY: read of a control register, no side effects.
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

/// Writes `CR4`.
#[inline]
unsafe fn write_cr4(value: u64) {
    // SAFETY: the caller guarantees the modified bits are valid.
    unsafe {
        core::arch::asm!("mov cr4, {}", in(reg) value, options(nomem, nostack));
    }
}

/// Explains why VT-x is unavailable, for logs and diagnostics.
///
/// Performs the same read-only CPUID/MSR probes as [`detect`] and returns a
/// short cause. Never modifies CPU state.
pub fn unavailable_reason() -> &'static str {
    let info = crate::arch::x86_64::cpuid::host();
    let cpuid_vmx = info
        .features
        .contains(crate::arch::x86_64::cpuid::CpuFeatures::VMX);
    if !cpuid_vmx {
        return "CPUID.1:ECX.VMX=0 (hypervisor or firmware hides VT-x)";
    }
    let feature_control = read_msr(caps::MSR_FEATURE_CONTROL);
    if feature_control & caps::FEATURE_CONTROL_ENABLE_OUTSIDE_SMX != 0 {
        return "unknown (CPUID and IA32_FEATURE_CONTROL both allow VT-x)";
    }
    if feature_control & caps::FEATURE_CONTROL_LOCKED != 0 {
        "IA32_FEATURE_CONTROL is locked and forbids VMXON"
    } else {
        "IA32_FEATURE_CONTROL does not enable VMXON"
    }
}

/// Detects hardware capabilities. Does not modify any CPU state.
pub fn detect() -> Option<HwCaps> {
    let info = crate::arch::x86_64::cpuid::host();
    let cpuid_vmx = info
        .features
        .contains(crate::arch::x86_64::cpuid::CpuFeatures::VMX);
    if !cpuid_vmx {
        return None;
    }
    let snapshot = MsrSnapshot::from_reader(read_msr);
    Some(HwCaps::from_snapshot(&snapshot, true))
}

/// Attempts to activate VT-x on the current CPU.
///
/// This function is idempotent: an already activated CPU returns `Ok(())`.
/// It allocates an activation region (a 4 KiB frame) that remains reserved
/// for the entire lifetime of the CPU.
pub fn activate_current_cpu() -> Result<(), InitError> {
    let cpu = crate::arch::x86_64::percpu::current_cpu_index();
    if cpu >= MAX_CPUS {
        return Err(InitError::NotSupported);
    }
    if ACTIVATED[cpu].load(Ordering::Acquire) {
        return Ok(());
    }

    let Some(mut caps) = detect() else {
        return Err(InitError::NotSupported);
    };

    // Enables activation if the firmware has not done so but has not
    // locked the MSR. If the MSR is locked without authorization, there is
    // nothing to do: it is a BIOS setting.
    if !caps.allowed {
        if caps.feature_control_locked {
            return Err(InitError::LockedByFirmware);
        }
        let feature_control = read_msr(caps::MSR_FEATURE_CONTROL);
        write_msr(
            caps::MSR_FEATURE_CONTROL,
            feature_control
                | caps::FEATURE_CONTROL_ENABLE_OUTSIDE_SMX
                | caps::FEATURE_CONTROL_LOCKED,
        );
        let Some(updated) = detect() else {
            return Err(InitError::NotSupported);
        };
        caps = updated;
        if !caps.allowed {
            return Err(InitError::LockedByFirmware);
        }
    }

    caps.validate()?;

    // Activation region: a zeroed, 4 KiB-aligned frame.
    let frame = crate::sync::with_irqs_disabled(|token| {
        crate::memory::frame::FrameAllocOptions::new()
            .purpose(crate::memory::frame::FramePurpose::PageTable)
            .allocate(token)
    })
    .map_err(|_| InitError::OutOfMemory)?;
    let phys = frame.start_address.as_u64();

    // The revision identifier must be written into the first 4 bytes.
    let virt = crate::memory::phys_to_virt(phys) as *mut u32;
    // SAFETY: the frame is exclusively reserved, the HHDM covers it, and
    // the write targets its first 4 bytes.
    unsafe {
        core::ptr::write_volatile(virt, caps.control_block_revision);
    }

    // Enables CR4.VMXE then executes the hardware activation.
    let cr4 = read_cr4();
    // SAFETY: bit 13 is legal as soon as CPUID advertises it.
    unsafe {
        write_cr4(cr4 | CR4_VMXE);
    }
    // SAFETY: region initialized, CPU advertised compatible, local
    // interrupts disabled by the caller (boot component).
    let failed = unsafe { enable_virtualization(phys) };
    if failed {
        // SAFETY: restoration of the previous state.
        unsafe {
            write_cr4(cr4);
        }
        return Err(InitError::ActivationFailed);
    }

    REGIONS[cpu].store(phys, Ordering::Release);
    ACTIVATED[cpu].store(true, Ordering::Release);
    ACTIVE_CPUS.fetch_add(1, Ordering::AcqRel);
    log::info!(
        "[s9vm] hardware activation OK (cpu {}, region {:#x})",
        cpu,
        phys
    );
    Ok(())
}

/// Executes the hardware activation (`vmxon`) on a pre-initialized region.
///
/// # Safety
/// - the CPU must advertise VT-x and `CR4.VMXE` must be set;
/// - `region_phys` must be a 4 KiB-aligned frame, initialized with
///   the revision identifier, exclusively reserved;
/// - local interrupts must be disabled.
unsafe fn enable_virtualization(region_phys: u64) -> bool {
    let fail: u8;
    // SAFETY: function contract.
    unsafe {
        core::arch::asm!(
            "vmxon qword ptr [{region}]",
            "setc {fail}",
            region = in(reg) &region_phys,
            fail = out(reg_byte) fail,
            options(nostack)
        );
    }
    fail != 0
}

/// Initialization called by the boot component.
///
/// Never panics: any unavailability is logged and the kernel
/// continues booting.
pub fn init() {
    if !S9VM_ENABLED {
        log::info!("[s9vm] disabled by configuration");
        return;
    }
    // VT-x-free diagnostic: the loader dry run only needs world memory and the
    // kernel ELF loader, so it runs on any host (the full loader phase needs
    // VT-x for the guest entry).
    selftest::maybe_run_loader_dry_from_boot_env();
    let Some(caps) = detect() else {
        log::info!(
            "[s9vm] VT-x absent — virtualization inactive ({})",
            unavailable_reason()
        );
        return;
    };
    CAPS_VALID.store(true, Ordering::Release);
    log::info!("[s9vm] capabilities: {}", caps.summary());
    match caps.validate() {
        Ok(()) => {}
        Err(error) => {
            log::warn!(
                "[s9vm] platform unusable ({:?}) — virtualization inactive",
                error
            );
            return;
        }
    }
    // Activation consumes a frame: it is only attempted at the
    // `bootstrap` stage, after the frame allocator.
    match activate_current_cpu() {
        Ok(()) => {
            log::info!(
                "[s9vm] ready ({} CPU activated)",
                ACTIVE_CPUS.load(Ordering::Acquire)
            );
            // Publish the host TSC frequency early so guest CPUID leaves
            // 0x15/0x16 are meaningful from the first guest, and so the APIC
            // timer conversion has a scale factor. The boot calibration is a
            // nominal value (CPUID 0x15/0x16 or the PIT); a later lazy CPUID
            // detection in `/dev/vmm` can only improve it (write-once cache).
            publish_tsc_frequency();
            selftest::maybe_run_from_boot_env(&caps);
        }
        Err(error) => log::warn!("[s9vm] activation failed ({:?})", error),
    }
}

/// Publishes the host TSC frequency in the `tsc` cache, once.
fn publish_tsc_frequency() {
    use crate::s9vm::tsc::TscFrequency;
    if crate::s9vm::tsc::get().is_some() {
        return;
    }
    let khz = crate::arch::x86_64::boot_timestamp::tsc_khz();
    if khz == 0 {
        return;
    }
    if let Some(frequency) = TscFrequency::from_hz(khz.saturating_mul(1_000)) {
        crate::s9vm::tsc::set(frequency);
        log::info!(
            "[s9vm] TSC frequency: {} MHz (published to guest CPUID)",
            frequency.hz() / 1_000_000
        );
    }
}

/// Number of CPUs on which VT-x is active.
pub fn active_cpu_count() -> u32 {
    ACTIVE_CPUS.load(Ordering::Acquire)
}

/// True if the capabilities were detected at boot.
pub fn detected() -> bool {
    CAPS_VALID.load(Ordering::Acquire)
}

/// Physical address of a CPU's activation region, if activated.
pub fn activation_region(cpu: usize) -> Option<u64> {
    if cpu >= MAX_CPUS || !ACTIVATED[cpu].load(Ordering::Acquire) {
        return None;
    }
    Some(REGIONS[cpu].load(Ordering::Acquire))
}

/// The memmap paging constants must remain aligned with those
/// of the translation module.
const _: () = assert!(crate::s9vm::memmap::PAGE_SIZE == crate::s9vm::mmu::PAGE_SIZE);
const _: () = assert!(crate::s9vm::memmap::MAX_GPA == crate::s9vm::mmu::MAX_GPA);

