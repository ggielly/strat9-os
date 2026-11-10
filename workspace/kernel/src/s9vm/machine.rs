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

//! s9vm — kernel bridge between a vCPU and the pure emulation layer.
//!
//! [`crate::s9vm::emulate`] is written against two abstractions:
//! [`PhysMemory`] (physical memory access) and [`GuestContext`] (general
//! registers, instruction pointer, `CR3`, paging state). This module supplies
//! the kernel implementations — the higher-half direct map for physical
//! memory, the vCPU's entry frame and control block for the guest context —
//! and exposes [`Machine`], the per-world object that the exit loops call.
//!
//! Keeping the bridge separate from the model means the model stays pure and
//! host-testable, while the kernel-specific and `unsafe` parts stay in one
//! small, auditable file.

use super::{
    apic::LocalApic,
    emulate::{self, Devices, EmuError, GuestContext, MemoryView, PhysMemory},
    vcpu::{ExitInfo, Vcpu},
};

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
}

/// Device model and emulation state of one world.
pub struct Machine {
    devices: Devices,
    memory: HhdmMemory,
}

impl Machine {
    /// Creates the machine of a world.
    pub fn new() -> Self {
        Self {
            devices: Devices::new(),
            memory: HhdmMemory,
        }
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

    /// Takes the frames the guest transmitted on the virtio network device.
    pub fn drain_network(&mut self) -> alloc::vec::Vec<u8> {
        self.devices.net.drain_output()
    }

    /// Queues a frame for the guest's receive path.
    pub fn push_network_frame(&mut self, frame: &[u8]) {
        self.devices.net.push_frame(frame);
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
        let Self { devices, memory } = self;
        let mut view = MemoryView::new(
            memory,
            vcpu.second_level_pointer(),
            vcpu.guest().cr3,
            vcpu.paging_enabled(),
        );
        let mut guest = VcpuGuest { vcpu };
        emulate::handle_exit(
            devices,
            apic,
            &mut view,
            &mut guest,
            exit.class(),
            exit.qualification,
            exit.guest_physical_address,
        )
    }
}

impl Default for Machine {
    fn default() -> Self {
        Self::new()
    }
}
