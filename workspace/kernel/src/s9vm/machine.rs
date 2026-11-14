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

//! s9vm : kernel bridge between a vCPU and the pure emulation layer.
//!
//! [`crate::s9vm::emulate`] is written against two abstractions:
//! [`PhysMemory`] (physical memory access) and [`GuestContext`] (general
//! registers, instruction pointer, `CR3`, paging state). This module supplies
//! the kernel implementations : the higher-half direct map for physical
//! memory, the vCPU's entry frame and control block for the guest context :
//! and exposes [`Machine`], the per-world object that the exit loops call.
//!
//! Keeping the bridge separate from the model means the model stays pure and
//! host-testable, while the kernel-specific and `unsafe` parts stay in one
//! small, auditable file.

use super::{
    apic::LocalApic,
    cpuid::CpuidPolicy,
    emulate::{
        self, isa_gsi, pulse_device_line, Devices, EmuError, GuestContext, MemoryView, PhysMemory,
    },
    exit::ExitClass,
    pit,
    vcpu::{ExitInfo, Vcpu},
};

/// Length in bytes of the `CPUID` instruction (`0F A2`).
///
/// The instruction has no operands and no prefixes that could change its
/// length: on a CPUID exit the guest `RIP` points at the instruction itself, so
/// replaying it means advancing `RIP` by exactly two bytes.
const CPUID_INSTRUCTION_LEN: u64 = 2;

/// Physical memory access through the higher-half direct map.
///
/// # Safety contract
///
/// The emulation layer only passes physical addresses it obtained from the
/// guest's own second-level tables, i.e. addresses of frames this kernel
/// allocated for a world. Those are always inside the direct map.
pub struct HhdmMemory;

impl PhysMemory for HhdmMemory {
    fn read_bytes(&mut self, phys: u64, out: &mut [u8]) -> bool {
        // SAFETY: see the type contract: `phys` comes from a table walk over
        // frames owned by the world, which the HHDM maps contiguously.
        unsafe {
            let source = crate::memory::phys_to_virt(phys) as *const u8;
            core::ptr::copy_nonoverlapping(source, out.as_mut_ptr(), out.len());
        }
        true
    }

    fn write_bytes(&mut self, phys: u64, bytes: &[u8]) -> bool {
        // SAFETY: same contract as `read_bytes`.
        unsafe {
            let destination = crate::memory::phys_to_virt(phys) as *mut u8;
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), destination, bytes.len());
        }
        true
    }
}

/// Guest context backed by a vCPU.
struct VcpuGuest<'a> {
    vcpu: &'a mut Vcpu,
}

impl GuestContext for VcpuGuest<'_> {
    fn gpr(&self, register: u8) -> u64 {
        self.vcpu.guest_gpr(register)
    }

    fn set_gpr(&mut self, register: u8, value: u64) {
        // SAFETY: the caller of `Machine::handle` guarantees that the control
        // block is loaded and the guest is not running (we are in the exit
        // handler).
        unsafe {
            self.vcpu.set_guest_gpr(register, value);
        }
    }

    fn rip(&self) -> u64 {
        self.vcpu.guest().rip
    }

    fn set_rip(&mut self, rip: u64) {
        // SAFETY: see `set_gpr`.
        unsafe {
            self.vcpu.set_guest_rip(rip);
        }
    }

    fn cr3(&self) -> u64 {
        self.vcpu.guest().cr3
    }

    fn paging(&self) -> bool {
        self.vcpu.paging_enabled()
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

    fn msr_model(&mut self) -> Option<&mut crate::s9vm::msr::MsrModel> {
        Some(self.vcpu.msr_mut())
    }
}

/// Host wall-clock time, when the host RTC driver can provide it.
///
/// The guest CMOS clock starts at the UNIX epoch if the host has no readable
/// RTC; the model is also printable/patchable by the guest, so a missing host
/// clock is not an error.
fn host_unix_time() -> Option<u64> {
    let seconds = crate::hardware::timer::rtc::get_timestamp();
    if seconds == 0 {
        None
    } else {
        Some(seconds)
    }
}

/// Device model, CPU description and emulation state of one world.
///
/// The CPUID policy is stored **per world**, not per vCPU: every vCPU of the
/// world must observe the same processor, and a guest that migrates a thread
/// between vCPUs must not see the feature set change under it. A future SMP
/// extension may refine this into a per-vCPU policy.
pub struct Machine {
    devices: Devices,
    memory: HhdmMemory,
    cpuid: CpuidPolicy,
}

impl Machine {
    /// Creates the machine of a world.
    pub fn new() -> Self {
        Self::with_devices(Devices::new())
    }

    /// Creates the machine of a legacy PC: no PCI virtio functions.
    ///
    /// Used by worlds that boot a real firmware (SeaBIOS) from a floppy: the
    /// firmware enumerates PCI and would otherwise attach its own virtio
    /// drivers to the s9vm functions.
    pub fn new_legacy() -> Self {
        Self::with_devices(Devices::new_legacy())
    }

    fn with_devices(mut devices: Devices) -> Self {
        // Seed the guest CMOS clock with the host wall-clock time when the
        // host RTC driver can read it; a guest that needs the date (boot
        // logging, TLS) then sees the real time instead of the UNIX epoch.
        if let Some(seconds) = host_unix_time() {
            devices.rtc.set_unix_time(seconds);
        }
        Self {
            devices,
            memory: HhdmMemory,
            cpuid: CpuidPolicy::new(),
        }
    }

    /// Current guest CPU description.
    pub fn cpuid_policy(&self) -> CpuidPolicy {
        self.cpuid
    }

    /// Replaces the guest CPU description.
    ///
    /// The change applies to the next guest entry: while a vCPU is running, the
    /// machine is moved out of the world registry, so a concurrent update
    /// reaches the registry copy and is overwritten when the execution copy is
    /// restored at the end of `RUN`. This is intentional and benign : the
    /// policy is not meant to change mid-run, and the syscall reports success
    /// for an existing world so the caller does not need to retry.
    pub fn set_cpuid_policy(&mut self, policy: CpuidPolicy) {
        self.cpuid = policy;
    }

    /// Device model (diagnostics and event routing by the kernel).
    pub fn devices(&self) -> &Devices {
        &self.devices
    }

    /// Mutable device model (kernel-side interrupt delivery).
    pub fn devices_mut(&mut self) -> &mut Devices {
        &mut self.devices
    }

    /// Takes the bytes the guest wrote to the virtio console.
    pub fn drain_console(&mut self) -> alloc::vec::Vec<u8> {
        self.devices.console.drain_output()
    }

    /// Takes the bytes the guest wrote to the legacy COM1 UART.
    pub fn drain_serial(&mut self) -> alloc::vec::Vec<u8> {
        self.devices.uart.drain_output()
    }

    /// Queues bytes on the guest's COM1 receive path.
    ///
    /// The receive FIFO is bounded by the model; the number of bytes accepted
    /// is returned so a console front-end can retry the rest later.
    pub fn push_serial_input(&mut self, bytes: &[u8]) -> usize {
        self.devices.uart.push_input(bytes)
    }

    /// Advances the legacy time base by the host time the guest consumed.
    ///
    /// Called by the execution loop once per VM exit with the measured TSC
    /// delta. The 8254 counts at its nominal 1.193182 MHz and raises its IRQ0
    /// line when channel 0 expires; the CMOS RTC advances its calendar and
    /// raises its interrupt line when a programmed event (periodic, update
    /// ended or alarm) occurs and the corresponding status-B enable bit is
    /// set. `tsc_hz == 0` means the host frequency is unknown: the raw cycle
    /// count is used, the documented degradation of the timer model.
    pub fn advance_time(&mut self, apic: &mut LocalApic, cycles: u64, tsc_hz: u64) {
        let pit_ticks = if tsc_hz == 0 {
            cycles
        } else {
            let numerator = u128::from(cycles) * u128::from(pit::FREQUENCY_HZ);
            let ticks = numerator / u128::from(tsc_hz);
            u64::try_from(ticks).unwrap_or(u64::MAX)
        };
        if pit_ticks > 0 && self.devices.pit.advance(pit_ticks) {
            pulse_device_line(&mut self.devices, apic, isa_gsi(pit::IRQ_LINE));
        }
        // Split the elapsed time into whole seconds and the remainder in the
        // 32.768 kHz reference ticks the CMOS periodic phase consumes.
        let (seconds, sub_second_ticks) = if tsc_hz == 0 {
            (cycles / 1_000_000_000, 0)
        } else {
            let seconds = cycles / tsc_hz;
            let remainder = cycles % tsc_hz;
            let ticks = u128::from(remainder) * u128::from(crate::s9vm::rtc::REFERENCE_HZ)
                / u128::from(tsc_hz);
            (seconds, u64::try_from(ticks).unwrap_or(0))
        };
        if seconds > 0 || sub_second_ticks > 0 {
            let events = self.devices.rtc.advance_events(seconds, sub_second_ticks);
            if (events.periodic || events.update_ended || events.alarm)
                && self.devices.rtc.irq_asserted()
            {
                pulse_device_line(&mut self.devices, apic, isa_gsi(crate::s9vm::rtc::IRQ_LINE));
            }
        }
        // The high-precision event timer counts at its nominal 14.31818 MHz.
        // Its interrupt lines are not routed yet: the counter is what a guest
        // reads as a time source, and the timer events are recorded in the
        // interrupt status register for a guest that polls it.
        let hpet_ticks = if tsc_hz == 0 {
            cycles
        } else {
            let numerator = u128::from(cycles) * u128::from(crate::s9vm::hpet::FREQUENCY_HZ);
            u64::try_from(numerator / u128::from(tsc_hz)).unwrap_or(u64::MAX)
        };
        if hpet_ticks > 0 {
            let _ = self.devices.hpet.advance_ticks(hpet_ticks);
        }
    }

    /// Takes the frames the guest transmitted on the virtio network device.
    pub fn drain_network(&mut self) -> alloc::vec::Vec<u8> {
        self.devices.net.drain_output()
    }

    /// Takes the individual frames the guest transmitted.
    pub fn drain_network_frames(&mut self) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        self.devices.net.drain_frames()
    }

    /// Queues a frame for the guest's receive path.
    pub fn push_network_frame(&mut self, frame: &[u8]) {
        self.devices.net.push_frame(frame);
    }

    /// Services the device receive queues against the current guest memory.
    ///
    /// Called before a guest entry: input and frames queued by the user side
    /// are moved into the driver's available buffers.
    ///
    /// # Safety
    /// The control block must be loaded and the guest must not be running.
    pub unsafe fn service_devices(&mut self, vcpu: &mut Vcpu) {
        let Self {
            devices,
            memory,
            cpuid: _,
        } = self;
        let mut view = MemoryView::new(
            memory,
            vcpu.second_level_pointer(),
            vcpu.guest().cr3,
            vcpu.paging_enabled(),
        );
        devices.console.service_rx(&mut view);
        devices.net.service_rx(&mut view);
    }

    /// Tries to consume an exit by replaying the faulting instruction against
    /// the device model.
    ///
    /// Returns `true` when the exit was fully handled and the guest can be
    /// resumed; `false` (or an error) means the exit must be reported to
    /// policy.
    ///
    /// # Safety
    ///
    /// The control block must be loaded and the guest must not be running:
    /// this is only called from an exit handler, before resuming.
    pub unsafe fn handle(
        &mut self,
        vcpu: &mut Vcpu,
        apic: &mut LocalApic,
        exit: &ExitInfo,
    ) -> Result<bool, EmuError> {
        // CPUID is fully replayed here: the guest must never observe the exit,
        // and the answer depends only on the world's policy, not on memory.
        if exit.class() == ExitClass::Cpuid {
            self.replay_cpuid(vcpu);
            return Ok(true);
        }
        let Self {
            devices,
            memory,
            cpuid: _,
        } = self;
        let mut view = MemoryView::new(
            memory,
            vcpu.second_level_pointer(),
            vcpu.guest().cr3,
            vcpu.paging_enabled(),
        );
        let mut guest = VcpuGuest { vcpu };
        emulate::handle_exit_with_length(
            devices,
            apic,
            &mut view,
            &mut guest,
            exit.class(),
            exit.qualification,
            exit.guest_physical_address,
            exit.instruction_length,
        )
    }

    /// Replays the intercepted `CPUID` instruction against the policy.
    ///
    /// Inputs are the architectural `EAX` (leaf) and `ECX` (subleaf) registers;
    /// outputs are `EAX`, `EBX`, `ECX` and `EDX` in that order. The 32-bit
    /// results are written through the 64-bit general-purpose registers, whose
    /// upper halves are zeroed exactly like a hardware 32-bit destination.
    /// `RIP` then advances past the fixed two-byte `0F A2` encoding.
    ///
    /// # Safety
    ///
    /// Same contract as [`Machine::handle`]: the control block is loaded and
    /// the guest is not running.
    unsafe fn replay_cpuid(&self, vcpu: &mut Vcpu) {
        let mut guest = VcpuGuest { vcpu };
        let leaf = guest.gpr(0) as u32;
        let subleaf = guest.gpr(1) as u32;
        let result = self.cpuid.leaf(leaf, subleaf);
        guest.set_gpr(0, u64::from(result[0]));
        guest.set_gpr(3, u64::from(result[1]));
        guest.set_gpr(1, u64::from(result[2]));
        guest.set_gpr(2, u64::from(result[3]));
        guest.set_rip(guest.rip().wrapping_add(CPUID_INSTRUCTION_LEN));
    }
}

impl Default for Machine {
    fn default() -> Self {
        Self::new()
    }
}
