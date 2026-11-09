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
pub const VMM_ABI_VERSION: u32 = 1;

/// Maximum number of registers exposed by [`VmmRegs`] (general-purpose registers).
pub const VMM_REG_COUNT: usize = 16;
/// Maximum length of a world name.
pub const VMM_NAME_MAX: usize = 32;

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

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn struct_sizes_are_stable() {
        assert_eq!(size_of::<VmmRegs>(), 184);
        assert_eq!(size_of::<VmmInfo>(), 96);
        assert_eq!(size_of::<VmmExitEvent>(), 48);
    }
}
