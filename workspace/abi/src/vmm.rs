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

//! s9vm — ABI structures of the virtualization system.
//!
//! All structures are `#[repr(C)]`, versioned by
//! [`VMM_ABI_VERSION`] and fixed-size. The identifiers (`vmm_id`,
//! `vcpu_id`) are opaque integers: never pointers, never
//! addresses.
//!
//! Invariants:
//! - a client checks `abi_version` before any use;
//! - the kernel refuses an unexpected size or version;
//! - any evolution adds fields **at the end** of the structure and
//!   increments the version.

/// Version of the s9vm ABI. Increment on every structure change.
pub const VMM_ABI_VERSION: u32 = 3;

/// Maximum number of registers exposed by [`VmmRegs`] (general-purpose registers).
pub const VMM_REG_COUNT: usize = 16;
/// Maximum length of a world name.
pub const VMM_NAME_MAX: usize = 32;
/// Upper bound on the number of worlds the kernel can report in one
/// `SYS_VMM_LIST` call. A caller must size its buffer for at most this many
/// [`VmmWorldEntry`] values; the kernel may return fewer.
pub const VMM_LIST_MAX: usize = 64;

/// Register block shared between `SYS_VMM_SET_REGS` and `SYS_VMM_GET_REGS`.
///
/// Size: 184 bytes. The order follows the usual save order
/// (`rax`, `rbx`, …); `rsp` and `rip` are included.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VmmRegs {
    pub abi_version: u32,
    pub flags: u32,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
}

/// States of a world, exposed by [`VmmInfo::state`].
pub mod state {
    /// World created, no vCPU running.
    pub const CREATED: u32 = 0;
    /// World running.
    pub const RUNNING: u32 = 1;
    /// World paused.
    pub const PAUSED: u32 = 2;
    /// World stopped.
    pub const STOPPED: u32 = 3;
    /// World in error.
    pub const FAILED: u32 = 4;
}

/// Snapshot of a world.
///
/// Size: 96 bytes. `vmm_id == 0` is reserved for the global engine summary
/// (state, number of vCPUs, counters).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VmmInfo {
    pub abi_version: u32,
    pub state: u32,
    pub vmm_id: u64,
    pub silo_id: u32,
    pub vcpu_count: u32,
    pub exit_total: u64,
    pub ept_violations: u64,
    pub mmio_emulations: u64,
    pub irq_injected: u64,
    pub mapped_pages: u64,
    pub name: [u8; VMM_NAME_MAX],
}

/// Nature of an event reported to the policy world.
pub mod exit_kind {
    /// MMIO read to emulate.
    pub const MMIO_READ: u32 = 1;
    /// MMIO write to emulate.
    pub const MMIO_WRITE: u32 = 2;
    /// Access to an I/O port.
    pub const IO_PORT: u32 = 3;
    /// Guest `hlt`.
    pub const HALT: u32 = 4;
    /// Second-level translation violation.
    pub const TRANSLATION: u32 = 5;
    /// Exception or NMI.
    pub const EXCEPTION: u32 = 6;
    /// Other exit to be handled by the policy.
    pub const OTHER: u32 = 7;
    /// Guest time slice expired (VMX preemption timer).
    pub const PREEMPTION_TIMER: u32 = 8;
}

/// Exit event reported to the policy world.
///
/// Size: 48 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VmmExitEvent {
    pub abi_version: u32,
    /// One of the [`exit_kind`] constants.
    pub kind: u32,
    pub vcpu_id: u64,
    /// Guest physical address concerned (0 if not applicable).
    pub gpa: u64,
    /// Access width (1, 2, 4, 8) for MMIO/PIO, 0 otherwise.
    pub size: u32,
    pub flags: u32,
    /// Value read or to be written for MMIO/PIO.
    pub value: u64,
    /// I/O port for [`exit_kind::IO_PORT`].
    pub port: u32,
    pub reserved: u32,
}

/// One world entry returned by `SYS_VMM_LIST` (584).
///
/// Size: 72 bytes, alignment 8. The name is a fixed 32-byte, zero-padded
/// buffer that is **not necessarily NUL-terminated**: `name_len` gives the
/// usable length and is always `<= VMM_NAME_MAX`. Reserved fields must be
/// ignored by callers and are zeroed by the kernel.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VmmWorldEntry {
    pub abi_version: u32,
    /// One of the [`state`] constants.
    pub state: u32,
    pub vmm_id: u64,
    pub silo_id: u32,
    pub vcpu_count: u32,
    pub mapped_pages: u64,
    pub name: [u8; VMM_NAME_MAX],
    /// Usable bytes in `name`, clamped to [`VMM_NAME_MAX`].
    pub name_len: u32,
    pub reserved: u32,
}

impl VmmWorldEntry {
    /// Returns the usable name bytes, never more than [`VMM_NAME_MAX`].
    ///
    /// A kernel-provided entry always satisfies `name_len <= VMM_NAME_MAX`;
    /// clamping here keeps the accessor safe for a hostile/forged entry.
    pub fn name_slice(&self) -> &[u8] {
        let length = (self.name_len as usize).min(VMM_NAME_MAX);
        &self.name[..length]
    }
}

/// Cumulative counters of a world returned by `SYS_VMM_STATS` (585).
///
/// Size: 96 bytes, alignment 8. The counters are diagnostics only and are
/// monotonic except `exits_pending`, which is a queue depth at call time.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VmmWorldStats {
    pub abi_version: u32,
    /// 1 when the world is paused, 0 otherwise.
    pub paused: u32,
    pub vmm_id: u64,
    /// `RUN` calls that reached the hardware.
    pub runs: u64,
    /// Exits handed to the policy through the event queue.
    pub policy_exits: u64,
    /// Exits replayed in the kernel by the device model.
    pub emulated_exits: u64,
    /// Replayed I/O instructions.
    pub emulated_io: u64,
    /// Replayed MMIO accesses.
    pub emulated_mmio: u64,
    /// Replayed MSR accesses.
    pub emulated_msr: u64,
    /// Interrupts injected into the guest.
    pub injected_interrupts: u64,
    /// Times interrupt-window exiting was armed.
    pub windows_armed: u64,
    /// Guest time slices that expired (preemption timer).
    pub timer_exits: u64,
    /// Exit events queued and not yet consumed by the policy.
    pub exits_pending: u64,
}

/// Result of `SYS_VMM_LOAD_IMAGE` (586).
///
/// Size: 40 bytes, alignment 8. All addresses are guest-physical. `entry` is
/// the relocated entry point the policy must load into the vCPU `RIP`; the
/// span is the page-aligned footprint actually reserved in the world, holes
/// included.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VmmImageInfo {
    /// ABI version of the structure.
    pub abi_version: u32,
    /// Reserved, zeroed by the kernel.
    pub reserved: u32,
    /// Guest-physical entry point.
    pub entry: u64,
    /// Guest-physical base the image was loaded at.
    pub image_base: u64,
    /// Lowest guest-physical address covered (inclusive).
    pub span_min: u64,
    /// Highest guest-physical address covered (exclusive).
    pub span_max: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn struct_sizes_are_stable() {
        assert_eq!(size_of::<VmmRegs>(), 184);
        assert_eq!(size_of::<VmmInfo>(), 96);
        assert_eq!(size_of::<VmmExitEvent>(), 48);
        assert_eq!(size_of::<VmmWorldEntry>(), 72);
        assert_eq!(size_of::<VmmWorldStats>(), 96);
        assert_eq!(size_of::<VmmImageInfo>(), 40);
    }

    #[test]
    fn world_entry_name_is_bounded() {
        let mut entry = VmmWorldEntry {
            name_len: (VMM_NAME_MAX + 8) as u32,
            ..VmmWorldEntry::default()
        };
        entry.name = [0xAB; VMM_NAME_MAX];
        assert_eq!(entry.name_slice().len(), VMM_NAME_MAX);
    }
}
