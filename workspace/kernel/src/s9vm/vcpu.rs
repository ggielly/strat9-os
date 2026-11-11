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

//! s9vm — vCPU: state, control block configuration, entry/exit.
//!
//! A `Vcpu` is the guest execution unit. It owns:
//! - a hardware control block ([`ControlBlock`]);
//! - a dedicated host stack (used by the trampoline to return from the guest);
//! - the guest state ([`GuestState`]) and the [`EnterFrame`] exchange area.
//!
//! Configuration is deliberately explicit (`configure_host`,
//! `configure_guest`, `configure_controls`) rather than spread across the
//! constructor: each step is checkable and hardware errors (`VMfail`) can be
//! attributed to a step.
//!
//! No policy is decided here: the module does not know what a guest OS, a
//! device or a complete virtual machine is.

use crate::{
    memory::frame::{FrameAllocOptions, FramePurpose, PhysFrame},
    s9vm::{
        caps::HwCaps,
        control::{field, ControlBlock, ControlError},
        exit::{ExitClass, ExitReason},
        guest::GuestState,
        launch::{s9vm_enter_guest, s9vm_guest_exit, EnterFrame, S9VM_ENTER_FRAME_SIZE},
        mmu::{self, Perms, SecondLevel, TableMemory},
        msr::{self, MsrModel},
    },
};

/// Control bits useful for configuration (SDM).
pub mod bits {
    /// Exit control: the host runs in 64-bit mode (IA-32e).
    pub const EXIT_HOST_ADDR_SPACE_SIZE: u32 = 1 << 9;
    /// Exit control: reload the host IA32_EFER (required in 64-bit mode).
    pub const EXIT_LOAD_IA32_EFER: u32 = 1 << 21;
    /// Entry control: the guest runs in 64-bit mode (IA-32e).
    pub const ENTRY_IA32E_MODE: u32 = 1 << 9;
    /// Entry control: reload the guest IA32_EFER (required in 64-bit mode).
    pub const ENTRY_LOAD_IA32_EFER: u32 = 1 << 15;
    /// Primary control: exit on `hlt`.
    pub const PRIMARY_HLT_EXITING: u32 = 1 << 7;
    /// Primary control: unconditional exit on every I/O instruction (`in`/`out`).
    /// Without it (and without I/O bitmaps) the guest performs port I/O
    /// natively, so the host never observes it.
    pub const PRIMARY_UNCONDITIONAL_IO_EXITING: u32 = 1 << 24;
    /// Secondary control: enable EPT.
    pub const SECONDARY_ENABLE_EPT: u32 = 1 << 1;
    /// Secondary control: unrestricted guest.
    pub const SECONDARY_UNRESTRICTED_GUEST: u32 = 1 << 7;
    /// Pin control: preemption timer (bounds guest time).
    pub const PIN_PREEMPTION_TIMER: u32 = 1 << 6;
    /// Pin control: exit on external interrupt.
    pub const PIN_EXTERNAL_INTERRUPT_EXITING: u32 = 1 << 0;
    /// Secondary control: use the MSR bitmaps (intercept `rdmsr`/`wrmsr`).
    pub const SECONDARY_USE_MSR_BITMAPS: u32 = 1 << 28;
    /// Primary control: exit when the guest opens an interrupt window.
    pub const PRIMARY_INTERRUPT_WINDOW_EXITING: u32 = 1 << 2;
}

/// vCPU lifecycle errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VcpuError {
    /// Frame allocation failed.
    OutOfMemory,
    /// Operation on the control block.
    Control(ControlError),
    /// Entry failure (`VMfail`): code read from the instruction field.
    VmFail(u32),
    /// The guest is already launched and resumption is not permitted.
    AlreadyLaunched,
    /// The EPT could not be built.
    Translation(mmu::MmuError),
    /// Unreadable exit state.
    BadExit,
}

impl From<ControlError> for VcpuError {
    fn from(value: ControlError) -> Self {
        Self::Control(value)
    }
}

impl From<mmu::MmuError> for VcpuError {
    fn from(value: mmu::MmuError) -> Self {
        Self::Translation(value)
    }
}

/// Information about a guest exit, copied out of the control block.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExitInfo {
    /// Raw reason (bit 31 = entry failure).
    pub raw_reason: u32,
    /// Decoded reason.
    pub reason: ExitReason,
    /// Exit qualification.
    pub qualification: u64,
    /// Guest physical address at the time of the exit.
    pub guest_physical_address: u64,
    /// Interrupt information.
    pub interrupt_info: u32,
    /// Vectoring information (event to be reinjected).
    pub vectoring_info: u32,
    /// Vectoring error code.
    pub vectoring_error: u32,
    /// Length of the faulting instruction.
    pub instruction_length: u32,
    /// Instruction information.
    pub instruction_info: u32,
    /// True if the exit is an entry failure.
    pub entry_failed: bool,
}

impl ExitInfo {
    /// Functional class of the exit.
    pub fn class(&self) -> ExitClass {
        self.reason.class()
    }

    /// True if there is an event to reinject.
    pub fn has_vectoring_event(&self) -> bool {
        self.vectoring_info & (1 << 31) != 0
    }
}

/// Host stack dedicated to the trampoline.
struct HostStack {
    frame: PhysFrame,
    top: u64,
}

impl HostStack {
    fn allocate() -> Result<Self, VcpuError> {
        // 16 KiB, order 2.
        let frame = crate::sync::with_irqs_disabled(|token| crate::memory::buddy::alloc(token, 2))
            .map_err(|_| VcpuError::OutOfMemory)?;
        let base = crate::memory::phys_to_virt(frame.start_address.as_u64());
        let top = (base + 16 * 1024) & !0xF;
        Ok(Self { frame, top })
    }

    fn top(&self) -> u64 {
        self.top
    }

    fn phys(&self) -> u64 {
        self.frame.start_address.as_u64()
    }
}

/// Table provider that accesses physical memory through the HHDM and keeps
/// track of the allocated tables so they can be freed.
pub struct HhdmTables {
    allocated: alloc::vec::Vec<u64>,
}

impl HhdmTables {
    /// Creates an empty provider.
    pub fn new() -> Self {
        Self {
            allocated: alloc::vec::Vec::new(),
        }
    }

    /// Frees all allocated tables (entries are no longer read after this
    /// call).
    pub fn free_all(&mut self) {
        if self.allocated.is_empty() {
            return;
        }
        crate::sync::with_irqs_disabled(|token| {
            for table in self.allocated.drain(..) {
                let frame = crate::memory::frame::PhysFrame::containing_address(
                    crate::arch::xshim::PhysAddr::new(table),
                );
                crate::memory::free_frame(token, frame);
            }
        });
    }
}

impl Default for HhdmTables {
    fn default() -> Self {
        Self::new()
    }
}

impl TableMemory for HhdmTables {
    fn alloc_table(&mut self) -> Option<u64> {
        let result = crate::sync::with_irqs_disabled(|token| {
            FrameAllocOptions::new()
                .purpose(FramePurpose::PageTable)
                .allocate(token)
                .ok()
                .map(|frame| frame.start_address.as_u64())
        });
        if let Some(table) = result {
            self.allocated.push(table);
        }
        result
    }

    fn free_table(&mut self, table: u64) {
        // Freeing is centralized in `free_all`: the free order of the tables
        // does not matter to the allocator, but avoiding double frees is
        // simpler this way. The entry is removed from the list so it is not
        // freed twice.
        if let Some(index) = self.allocated.iter().position(|entry| *entry == table) {
            self.allocated.swap_remove(index);
        }
    }

    fn read_entry(&self, table: u64, index: usize) -> u64 {
        let base = crate::memory::phys_to_virt(table) as *const u64;
        // SAFETY: `table` comes from `alloc_table` (zeroed frame, 4 KiB) and
        // `index < 512`: read within the frame bounds.
        unsafe { core::ptr::read_volatile(base.add(index)) }
    }

    fn write_entry(&mut self, table: u64, index: usize, value: u64) {
        let base = crate::memory::phys_to_virt(table) as *mut u64;
        // SAFETY: same invariant as `read_entry`; the frame is exclusive.
        unsafe { core::ptr::write_volatile(base.add(index), value) }
    }
}

/// Pre-allocated resources for second-level translation.
pub struct SecondLevelMemory {
    pub tables: HhdmTables,
    pub root: SecondLevel,
}

impl SecondLevelMemory {
    /// Creates an empty translation.
    pub fn new() -> Result<Self, VcpuError> {
        let mut tables = HhdmTables::new();
        let root = SecondLevel::new(&mut tables)?;
        Ok(Self { tables, root })
    }

    /// Frees all translation tables.
    pub fn destroy(mut self) {
        self.tables.free_all();
    }

    /// Translates a guest physical address, if it is mapped.
    pub fn translate(&self, gpa: u64) -> Option<u64> {
        self.root.translate(&self.tables, gpa)
    }

    /// Removes a 4 KiB mapping.
    pub fn unmap_4k(&mut self, gpa: u64) -> bool {
        self.root.unmap_4k(&mut self.tables, gpa)
    }

    /// Maps a 4 KiB page.
    pub fn map_4k(&mut self, gpa: u64, hpa: u64, perms: Perms) -> Result<(), VcpuError> {
        self.root
            .map_4k(&mut self.tables, gpa, hpa, mmu::PAGE_SIZE, perms)
            .map_err(VcpuError::Translation)
    }

    /// Maps a 2 MiB region.
    pub fn map_2m(&mut self, gpa: u64, hpa: u64, perms: Perms) -> Result<(), VcpuError> {
        self.root
            .map_2m(&mut self.tables, gpa, hpa, mmu::entry::LARGE_2MB, perms)
            .map_err(VcpuError::Translation)
    }

    /// Value of the translation pointer, ready for the control block.
    pub fn pointer(&self, caps: &HwCaps) -> u64 {
        mmu::encode_second_level_pointer(self.root.root_phys(), 6, true, caps.ept_ad)
    }
}

/// Layout of the 4 KiB MSR bitmap.
///
/// Four 1 KiB bitmaps: read and write maps for MSRs `0x0000..0x1FFF`, then the
/// same for `0xC000_0000..0xC000_1FFF`. A set bit means "exit".
pub mod msr_bitmap {
    /// Read map, low MSR range.
    pub const READ_LOW: usize = 0x000;
    /// Write map, low MSR range.
    pub const WRITE_LOW: usize = 0x400;
    /// Read map, high MSR range.
    pub const READ_HIGH: usize = 0x800;
    /// Write map, high MSR range.
    pub const WRITE_HIGH: usize = 0xC00;
    /// Size of the bitmap in bytes.
    pub const BYTES: usize = 4096;
    /// First intercepted MSR (x2APIC window).
    pub const X2APIC_FIRST: u32 = 0x800;
    /// Last intercepted MSR (x2APIC window).
    pub const X2APIC_LAST: u32 = 0x8FF;
    /// `IA32_TSC_DEADLINE`: the local APIC TSC-deadline timer register.
    ///
    /// It lives outside the x2APIC MSR window, so it must be intercepted
    /// explicitly: otherwise the hardware consumes the write and the emulated
    /// local APIC never sees the deadline.
    pub const TSC_DEADLINE: u32 = 0x6E0;
}

/// Marks one MSR as intercepted (read and/or write) in the bitmap.
fn set_msr_intercept(base: *mut u8, msr: u32, intercept_read: bool, intercept_write: bool) {
    // The bitmap covers 0x0000..0x1FFF and 0xC000_0000..0xC000_1FFF.
    let (offset, read_base, write_base) = if (msr as usize) < 0x2000 {
        (msr as usize, msr_bitmap::READ_LOW, msr_bitmap::WRITE_LOW)
    } else if (0xC000_0000..0xC000_2000).contains(&msr) {
        (
            (msr - 0xC000_0000) as usize,
            msr_bitmap::READ_HIGH,
            msr_bitmap::WRITE_HIGH,
        )
    } else {
        return;
    };
    let byte = offset / 8;
    let bit = 1u8 << (offset % 8);
    // SAFETY: `base` points to the 4 KiB bitmap owned by this vCPU and both
    // offsets stay inside it (`offset < 0x2000`).
    unsafe {
        if intercept_read {
            *base.add(read_base + byte) |= bit;
        }
        if intercept_write {
            *base.add(write_base + byte) |= bit;
        }
    }
}

/// Allocates the MSR bitmap of a vCPU.
///
/// The modelled MSRs and the x2APIC window are intercepted on reads and
/// writes. Every other MSR in both bitmap windows is intercepted on **writes**
/// as well: an unmodelled `WRMSR` then exits to the kernel and is reported to
/// policy, instead of modifying the host MSR file. Reads of unmodelled MSRs are
/// left native (no host state corruption, only read-only information).
///
/// The frame is deliberately leaked with the other vCPU resources (control
/// block, host stack): a vCPU currently lives as long as its world.
fn alloc_msr_bitmap() -> Option<PhysFrame> {
    let frame = crate::sync::with_irqs_disabled(|token| {
        FrameAllocOptions::new()
            .purpose(FramePurpose::KernelData)
            .allocate(token)
            .ok()
    })?;
    let base = crate::memory::phys_to_virt(frame.start_address.as_u64()) as *mut u8;
    // SAFETY: the frame is exclusively owned by this vCPU and HHDM-mapped.
    unsafe {
        core::ptr::write_bytes(base, 0, msr_bitmap::BYTES);
        for msr in msr::msr_intercept_list() {
            set_msr_intercept(base, *msr, true, true);
        }
        for msr in msr_bitmap::X2APIC_FIRST..=msr_bitmap::X2APIC_LAST {
            set_msr_intercept(base, msr, true, true);
        }
        // The TSC-deadline timer register is outside the x2APIC window.
        set_msr_intercept(base, msr_bitmap::TSC_DEADLINE, true, true);
        // Default-deny writes in both windows: an unmodelled WRMSR must not
        // reach the host MSR file.
        for msr in 0..0x2000 {
            set_msr_intercept(base, msr, false, true);
        }
        for msr in 0xC000_0000..0xC000_2000 {
            set_msr_intercept(base, msr, false, true);
        }
    }
    Some(frame)
}

/// Number of preemption-timer counts per guest time slice.
///
/// The count rate is encoded in `IA32_VMX_MISC` bits 4:0 (the timer counts at
/// the TSC rate divided by a power of two), so this value translates to a
/// different wall-clock delay per CPU. It is deliberately conservative: a
/// guest gets a long enough slice to make progress, and still cannot run
/// unbounded. The policy layer will tune it per world.
pub const DEFAULT_PREEMPTION_TIMER_TICKS: u32 = 0x00FF_FFFF;

/// Primary processor-based controls of a vCPU.
///
/// `PROC_ACTIVATE_SECONDARY` is **not** optional: without it EPT is disabled
/// and the guest addresses host-physical memory, which triple-faults it at the
/// first instruction. Every rewrite of the primary controls must go through
/// this helper so the invariant cannot be lost.
fn primary_controls(caps: &HwCaps, window_exiting: bool) -> u32 {
    let mut primary = crate::s9vm::caps::control_bits::PROC_ACTIVATE_SECONDARY
        | bits::PRIMARY_HLT_EXITING
        | bits::PRIMARY_UNCONDITIONAL_IO_EXITING;
    if window_exiting {
        primary |= bits::PRIMARY_INTERRUPT_WINDOW_EXITING;
    }
    caps.primary_proc_allowed.apply(primary)
}

/// A vCPU: resources, guest state and control block.
pub struct Vcpu {
    control: ControlBlock,
    host_stack: HostStack,
    frame: EnterFrame,
    guest: GuestState,
    launched: bool,
    second_level_pointer: u64,
    exit: Option<ExitInfo>,
    /// Preemption timer reload (counts) if the CPU supports it.
    preemption_timer: Option<u32>,
    /// MSR bitmap intercepting the modelled MSRs, the x2APIC window and all
    /// unmodelled writes, when supported.
    msr_bitmap: Option<PhysFrame>,
    /// Per-vCPU shadow of the modelled MSRs.
    msr: MsrModel,
}

impl Vcpu {
    /// Creates the resources of a vCPU (control block and host stack).
    pub fn new(caps: &HwCaps, second_level_pointer: u64) -> Result<Self, VcpuError> {
        let revision = caps.control_block_revision;
        let frame = crate::sync::with_irqs_disabled(|token| {
            FrameAllocOptions::new()
                .purpose(FramePurpose::PageTable)
                .allocate(token)
        })
        .map_err(|_| VcpuError::OutOfMemory)?;
        let phys = frame.start_address.as_u64();
        // The control block frame must exist before the descriptor is created;
        // it is deliberately "leaked" (owned by the vCPU).
        let control = unsafe { ControlBlock::new(phys, revision) };
        // SAFETY: the frame is exclusive, covered by the HHDM and is 4 KiB.
        unsafe {
            control.prepare_region(crate::memory::phys_to_virt(phys) as *mut u8);
        }
        let host_stack = HostStack::allocate()?;
        Ok(Self {
            control,
            host_stack,
            frame: EnterFrame::zeroed(),
            guest: GuestState::real_mode(0, 0),
            launched: false,
            second_level_pointer,
            exit: None,
            preemption_timer: None,
            msr_bitmap: None,
            msr: MsrModel::new(),
        })
    }

    /// Enables/disables the per-write diagnostic trace.
    pub fn set_write_trace(enabled: bool) {
        crate::s9vm::control::set_write_trace(enabled);
    }

    /// First field whose write left a non-zero instruction error.
    pub fn write_trace_failure() -> Option<(u32, u32)> {
        crate::s9vm::control::write_trace_failure()
    }

    /// VM-instruction error currently stored in the control block.
    ///
    /// # Safety
    /// The control block must be loaded on the current CPU.
    pub unsafe fn instruction_error(&self) -> u32 {
        unsafe { self.control.instruction_error() }
    }

    /// Physical address of the control block.
    pub fn control_phys(&self) -> u64 {
        self.control.phys()
    }

    /// Physical address of the host stack.
    pub fn host_stack_phys(&self) -> u64 {
        self.host_stack.phys()
    }

    /// Loads the control block on the current CPU.
    ///
    /// # Safety
    /// The CPU must be in VT-x root mode and the block must not be loaded on
    /// another CPU.
    pub unsafe fn load(&mut self) -> Result<(), VcpuError> {
        // SAFETY: caller contract.
        unsafe { self.control.load()? };
        Ok(())
    }

    /// Snapshot of the guest fields of the control block, to diagnose an entry
    /// failure ("VM entry with invalid guest state").
    ///
    /// # Safety
    /// The control block must be loaded on the current CPU.
    pub unsafe fn guest_diagnostics(&self) -> alloc::string::String {
        use alloc::format;
        let natural = |f: u32| unsafe { self.control.read_natural(f).unwrap_or(u64::MAX) };
        let u16_field = |f: u32| unsafe { self.control.read_u16(f).unwrap_or(u16::MAX) };
        let u32_field = |f: u32| unsafe { self.control.read_u32(f).unwrap_or(u32::MAX) };
        unsafe {
            format!(
                "guest cr0={:#x} cr3={:#x} cr4={:#x} efer={:#x} pat={:#x} rsp={:#x} rip={:#x} \
                 rflags={:#x} dr7={:#x} act={:#x} intr={:#x} \
                 sel(cs={:#x} ss={:#x} ds={:#x} es={:#x} fs={:#x} gs={:#x} ldtr={:#x} tr={:#x}) \
                 ar(cs={:#x} ss={:#x} ds={:#x} es={:#x} fs={:#x} gs={:#x} ldtr={:#x} tr={:#x}) \
                 lim(cs={:#x} ss={:#x} ds={:#x} es={:#x} fs={:#x} gs={:#x} ldtr={:#x} tr={:#x}) \
                 gdtr={:#x}/{:#x} idtr={:#x}/{:#x} link={:#x} dbgctl={:#x} \
                 exit(reason={:#x} qual={:#x} gpa={:#x} instrerr={:#x} len={:#x} info={:#x}) \
                 sysenter(cs={:#x} esp={:#x} eip={:#x}) \
                 ctl(pin={:#x} primary={:#x} secondary={:#x} exit={:#x} entry={:#x})",
                natural(field::GUEST_CR0),
                natural(field::GUEST_CR3),
                natural(field::GUEST_CR4),
                natural(field::GUEST_EFER),
                natural(field::GUEST_PAT),
                natural(field::GUEST_RSP),
                natural(field::GUEST_RIP),
                natural(field::GUEST_RFLAGS),
                natural(field::GUEST_DR7),
                u32_field(field::GUEST_ACTIVITY_STATE),
                u32_field(field::GUEST_INTERRUPTIBILITY_INFO),
                u16_field(field::GUEST_CS_SELECTOR),
                u16_field(field::GUEST_SS_SELECTOR),
                u16_field(field::GUEST_DS_SELECTOR),
                u16_field(field::GUEST_ES_SELECTOR),
                u16_field(field::GUEST_FS_SELECTOR),
                u16_field(field::GUEST_GS_SELECTOR),
                u16_field(field::GUEST_LDTR_SELECTOR),
                u16_field(field::GUEST_TR_SELECTOR),
                u32_field(field::GUEST_CS_ACCESS_RIGHTS),
                u32_field(field::GUEST_SS_ACCESS_RIGHTS),
                u32_field(field::GUEST_DS_ACCESS_RIGHTS),
                u32_field(field::GUEST_ES_ACCESS_RIGHTS),
                u32_field(field::GUEST_FS_ACCESS_RIGHTS),
                u32_field(field::GUEST_GS_ACCESS_RIGHTS),
                u32_field(field::GUEST_LDTR_ACCESS_RIGHTS),
                u32_field(field::GUEST_TR_ACCESS_RIGHTS),
                u32_field(field::GUEST_CS_LIMIT),
                u32_field(field::GUEST_SS_LIMIT),
                u32_field(field::GUEST_DS_LIMIT),
                u32_field(field::GUEST_ES_LIMIT),
                u32_field(field::GUEST_FS_LIMIT),
                u32_field(field::GUEST_GS_LIMIT),
                u32_field(field::GUEST_LDTR_LIMIT),
                u32_field(field::GUEST_TR_LIMIT),
                natural(field::GUEST_GDTR_BASE),
                u32_field(field::GUEST_GDTR_LIMIT),
                natural(field::GUEST_IDTR_BASE),
                u32_field(field::GUEST_IDTR_LIMIT),
                natural(field::GUEST_VMCS_LINK_POINTER),
                natural(field::GUEST_DEBUGCTL),
                u32_field(field::EXIT_REASON),
                natural(field::EXIT_QUALIFICATION),
                natural(field::GUEST_PHYSICAL_ADDRESS),
                u32_field(field::INSTRUCTION_ERROR),
                u32_field(field::EXIT_INSTRUCTION_LENGTH),
                u32_field(field::EXIT_INSTRUCTION_INFO),
                u32_field(field::GUEST_SYSENTER_CS),
                natural(field::GUEST_SYSENTER_ESP),
                natural(field::GUEST_SYSENTER_EIP),
                u32_field(field::PIN_BASED_CONTROLS),
                u32_field(field::PRIMARY_PROC_BASED_CONTROLS),
                u32_field(field::SECONDARY_PROC_BASED_CONTROLS),
                u32_field(field::EXIT_CONTROLS),
                u32_field(field::ENTRY_CONTROLS),
            )
        }
    }
    /// Schedules an NMI injection at the next entry into the guest.
    ///
    /// # Safety
    /// The control block must be loaded and the guest inactive.
    pub unsafe fn inject_nmi(&self) -> Result<(), VcpuError> {
        unsafe {
            self.control
                .write_u32(field::ENTRY_INTERRUPT_INFO, crate::s9vm::exit::nmi_info())?;
        }
        Ok(())
    }

    /// Schedules an external interrupt injection at the next entry into the
    /// guest ("VM-entry interruption information" field).
    ///
    /// # Safety
    /// The control block must be loaded and the guest inactive.
    pub unsafe fn inject_interrupt(&self, vector: u8) -> Result<(), VcpuError> {
        unsafe {
            self.control.write_u32(
                field::ENTRY_INTERRUPT_INFO,
                crate::s9vm::exit::external_interrupt_info(vector),
            )?;
        }
        Ok(())
    }
    /// Advances the guest instruction pointer after emulating an instruction
    /// that caused an exit (I/O, `rdtsc`, etc.).
    ///
    /// # Safety
    /// The control block must be loaded and the guest must not be active.
    pub unsafe fn advance_rip(&mut self, bytes: u64) -> Result<(), VcpuError> {
        self.guest.rip = self.guest.rip.wrapping_add(bytes);
        unsafe {
            self.control
                .write_natural(field::GUEST_RIP, self.guest.rip)?;
        }
        Ok(())
    }
    /// Unloads the control block.
    ///
    /// # Safety
    /// No guest must be active on this vCPU.
    pub unsafe fn clear(&mut self) -> Result<(), VcpuError> {
        // SAFETY: caller contract.
        unsafe { self.control.clear()? };
        self.launched = false;
        Ok(())
    }

    /// Writes the host state (current CPU) into the control block.
    ///
    /// # Safety
    /// The control block must be loaded.
    pub unsafe fn configure_host(&self) -> Result<(), VcpuError> {
        let cr0 = read_cr0();
        let cr3 = read_cr3();
        let cr4 = read_cr4();
        let efer = crate::arch::x86_64::rdmsr(0xC000_0080);
        let pat = crate::arch::x86_64::rdmsr(0x277);

        // SAFETY: block loaded; writes respect the widths.
        unsafe {
            self.control.write_natural(field::HOST_CR0, cr0)?;
            self.control.write_natural(field::HOST_CR3, cr3)?;
            self.control.write_natural(field::HOST_CR4, cr4)?;
            self.control.write_u64(field::HOST_EFER, efer)?;
            self.control.write_u64(field::HOST_PAT, pat)?;
            self.control
                .write_natural(field::HOST_RSP, self.host_stack.top())?;
            self.control.write_natural(
                field::HOST_RIP,
                s9vm_guest_exit as unsafe extern "C" fn() as usize as u64,
            )?;

            // Host segments: read from the current CPU registers.
            let mut cs: u16;
            let mut ss: u16;
            let mut ds: u16;
            let mut es: u16;
            let mut fs: u16;
            let mut gs: u16;
            let mut tr: u16;
            core::arch::asm!("mov ax, cs", out("ax") cs, options(nomem, nostack));
            core::arch::asm!("mov ax, ss", out("ax") ss, options(nomem, nostack));
            core::arch::asm!("mov ax, ds", out("ax") ds, options(nomem, nostack));
            core::arch::asm!("mov ax, es", out("ax") es, options(nomem, nostack));
            core::arch::asm!("mov ax, fs", out("ax") fs, options(nomem, nostack));
            core::arch::asm!("mov ax, gs", out("ax") gs, options(nomem, nostack));
            core::arch::asm!("str ax", out("ax") tr, options(nomem, nostack));

            self.control.write_u16(field::HOST_CS_SELECTOR, cs)?;
            self.control.write_u16(field::HOST_SS_SELECTOR, ss)?;
            self.control.write_u16(field::HOST_DS_SELECTOR, ds)?;
            self.control.write_u16(field::HOST_ES_SELECTOR, es)?;
            self.control.write_u16(field::HOST_FS_SELECTOR, fs)?;
            self.control.write_u16(field::HOST_GS_SELECTOR, gs)?;
            self.control.write_u16(field::HOST_TR_SELECTOR, tr)?;
            self.control
                .write_natural(field::HOST_TR_BASE, tr_base(tr))?;

            // Host system tables.
            let (gdtr_base, _gdtr_limit) = read_gdtr();
            let (idtr_base, _idtr_limit) = read_idtr();
            self.control
                .write_natural(field::HOST_GDTR_BASE, gdtr_base)?;
            self.control
                .write_natural(field::HOST_IDTR_BASE, idtr_base)?;

            // Host FS/GS bases (GS carries the per-CPU data).
            let fs_base = crate::arch::x86_64::rdmsr(0xC000_0100);
            let gs_base = crate::arch::x86_64::rdmsr(0xC000_0101);
            self.control.write_natural(field::HOST_FS_BASE, fs_base)?;
            self.control.write_natural(field::HOST_GS_BASE, gs_base)?;
            self.control.write_u32(field::HOST_SYSENTER_CS, cs as u32)?;
            self.control
                .write_natural(field::HOST_SYSENTER_ESP, crate::arch::x86_64::rdmsr(0x175))?;
            self.control
                .write_natural(field::HOST_SYSENTER_EIP, crate::arch::x86_64::rdmsr(0x176))?;
        }
        Ok(())
    }

    /// Snapshot of the host fields of the control block, to diagnose a
    /// `VmFail(8)` entry failure ("invalid host-state field").
    ///
    /// Also prints the values actually carried by the CPU at the time of the
    /// call, which helps spot a forgotten or badly encoded field.
    ///
    /// # Safety
    /// The control block must be loaded on the current CPU.
    pub unsafe fn host_diagnostics(&self) -> alloc::string::String {
        use alloc::format;
        let natural = |f: u32| unsafe { self.control.read_natural(f).unwrap_or(u64::MAX) };
        let u16_field = |f: u32| unsafe { self.control.read_u16(f).unwrap_or(u16::MAX) };
        let u32_field = |f: u32| unsafe { self.control.read_u32(f).unwrap_or(u32::MAX) };

        // Selectors actually loaded in the CPU.
        let mut tr: u16 = 0;
        let mut cs: u16 = 0;
        let mut ss: u16 = 0;
        let mut ds: u16 = 0;
        let mut es: u16 = 0;
        let mut fs: u16 = 0;
        let mut gs: u16 = 0;
        unsafe {
            core::arch::asm!("str ax", out("ax") tr, options(nomem, nostack));
            core::arch::asm!("mov ax, cs", out("ax") cs, options(nomem, nostack));
            core::arch::asm!("mov ax, ss", out("ax") ss, options(nomem, nostack));
            core::arch::asm!("mov ax, ds", out("ax") ds, options(nomem, nostack));
            core::arch::asm!("mov ax, es", out("ax") es, options(nomem, nostack));
            core::arch::asm!("mov ax, fs", out("ax") fs, options(nomem, nostack));
            core::arch::asm!("mov ax, gs", out("ax") gs, options(nomem, nostack));
        }
        let (gdtr_base, gdtr_limit) = read_gdtr();
        let (idtr_base, idtr_limit) = read_idtr();
        let efer = unsafe { crate::arch::x86_64::rdmsr(0xC000_0080) };
        let pat = unsafe { crate::arch::x86_64::rdmsr(0x277) };
        let host_sysenter_cs = u32_field(field::HOST_SYSENTER_CS);
        unsafe {
            format!(
                "host cr0={:#x} cr3={:#x} cr4={:#x} efer={:#x} pat={:#x} rsp={:#x} rip={:#x} \
                 sel(cs={:#x} ss={:#x} ds={:#x} es={:#x} fs={:#x} gs={:#x} tr={:#x}) \
                 trbase={:#x} gdtr={:#x} idtr={:#x} fsb={:#x} gsb={:#x} \
                 sysenter(cs={:#x} esp={:#x} eip={:#x}) exitctl={:#x} entryctl={:#x} \
                 cpu(cr0={:#x} cr4={:#x} efer={:#x} pat={:#x} tr={:#x} \
                 gdtr={:#x}/lim={:#x} idtr={:#x}/lim={:#x})",
                natural(field::HOST_CR0),
                natural(field::HOST_CR3),
                natural(field::HOST_CR4),
                natural(field::HOST_EFER),
                natural(field::HOST_PAT),
                natural(field::HOST_RSP),
                natural(field::HOST_RIP),
                u16_field(field::HOST_CS_SELECTOR),
                u16_field(field::HOST_SS_SELECTOR),
                u16_field(field::HOST_DS_SELECTOR),
                u16_field(field::HOST_ES_SELECTOR),
                u16_field(field::HOST_FS_SELECTOR),
                u16_field(field::HOST_GS_SELECTOR),
                u16_field(field::HOST_TR_SELECTOR),
                natural(field::HOST_TR_BASE),
                natural(field::HOST_GDTR_BASE),
                natural(field::HOST_IDTR_BASE),
                natural(field::HOST_FS_BASE),
                natural(field::HOST_GS_BASE),
                host_sysenter_cs,
                natural(field::HOST_SYSENTER_ESP),
                natural(field::HOST_SYSENTER_EIP),
                u32_field(field::EXIT_CONTROLS),
                u32_field(field::ENTRY_CONTROLS),
                read_cr0(),
                read_cr4(),
                efer,
                pat,
                tr,
                gdtr_base,
                gdtr_limit,
                idtr_base,
                idtr_limit
            )
        }
    }
    /// Writes the guest state and the execution controls.
    ///
    /// # Safety
    /// The control block must be loaded.
    pub unsafe fn configure(&mut self, caps: &HwCaps, guest: &GuestState) -> Result<(), VcpuError> {
        self.guest = *guest;
        // Seed the MSR shadows from the guest state supplied by policy. The
        // runtime WRMSR path updates the shadows; the synchronous state/control
        // block refresh is driven by [`Self::sync_msr_state`].
        self.msr.set_efer(guest.efer);
        self.msr.set_pat(guest.pat);
        self.msr.set_segment_bases(guest.fs.base, guest.gs.base, 0);
        self.msr.set_sysenter(
            u64::from(guest.sysenter_cs),
            guest.sysenter_esp,
            guest.sysenter_eip,
        );
        // The VMX preemption timer bounds the time a guest can run without
        // returning to the kernel: a guest that never exits cannot hold a
        // vCPU forever. The count rate comes from the capability MSR, so the
        // value below is a conservative slice (tuned by the policy layer
        // later); the entry path is validated, so the timer can be enabled.
        self.preemption_timer = if caps.preemption_timer {
            Some(DEFAULT_PREEMPTION_TIMER_TICKS)
        } else {
            None
        };
        // The MSR bitmap is created once, on the first configuration: it
        // intercepts the x2APIC MSRs so the kernel can model them. When the
        // processor does not allow the control, no bitmap is allocated and
        // the guest reaches the MSRs natively.
        if self.msr_bitmap.is_none()
            && caps
                .secondary_proc_allowed
                .supports(bits::SECONDARY_USE_MSR_BITMAPS)
        {
            self.msr_bitmap = alloc_msr_bitmap();
        }
        // SAFETY: block loaded; widths match the fields.
        unsafe {
            self.write_guest_state(guest)?;
            self.write_controls(caps)?;
            self.control
                .write_u64(field::GUEST_VMCS_LINK_POINTER, u64::MAX)?;
            self.control.write_u32(field::EXCEPTION_BITMAP, 0)?;
            self.control
                .write_u32(field::PAGE_FAULT_ERROR_CODE_MASK, 0)?;
            self.control
                .write_u32(field::PAGE_FAULT_ERROR_CODE_MATCH, 0)?;
            self.control.write_u32(field::CR3_TARGET_COUNT, 0)?;
            // No host-controlled CR bits and no read shadows: the guest sees
            // exactly the state loaded at entry. These fields must be
            // explicit even though the region is zeroed, because the host
            // hypervisor uses them when it merges the guest controls.
            self.control.write_u32(field::CR0_GUEST_HOST_MASK, 0)?;
            self.control.write_u32(field::CR4_GUEST_HOST_MASK, 0)?;
            self.control.write_u32(field::CR0_READ_SHADOW, 0)?;
            self.control.write_u32(field::CR4_READ_SHADOW, 0)?;
            // No MSR switching on entry/exit.
            self.control.write_u32(field::EXIT_MSR_STORE_COUNT, 0)?;
            self.control.write_u32(field::EXIT_MSR_LOAD_COUNT, 0)?;
            self.control.write_u32(field::ENTRY_MSR_LOAD_COUNT, 0)?;
            self.control.write_u32(field::TPR_THRESHOLD, 0)?;
            // PLE_GAP/PLE_WINDOW only exist when the PAUSE-loop-exiting
            // capability is available. Writing them unconditionally makes
            // the host hypervisor reject the field (VM-instruction error
            // 0xc, "unsupported VMCS component"), which was observed on a
            // CPU that exposes no PLE support. Leave them zeroed there.
            if caps.pause_loop_exiting {
                self.control.write_u32(field::PLE_GAP, 0x50)?;
                self.control.write_u32(field::PLE_WINDOW, 60_000)?;
            }
            self.control.write_u64(field::TSC_OFFSET, 0)?;
            self.control
                .write_u64(field::MSR_BITMAP, self.msr_bitmap_phys())?;
            self.control.write_u64(field::IO_BITMAP_A, 0)?;
            self.control.write_u64(field::IO_BITMAP_B, 0)?;
            self.control
                .write_u64(field::EPT_POINTER, self.second_level_pointer)?;
            self.control.write_u32(field::ENTRY_INTERRUPT_INFO, 0)?;
            self.control
                .write_u32(field::ENTRY_EXCEPTION_ERROR_CODE, 0)?;
            self.control.write_u32(field::ENTRY_INSTRUCTION_LENGTH, 0)?;
        }
        Ok(())
    }

    unsafe fn write_guest_state(&mut self, guest: &GuestState) -> Result<(), VcpuError> {
        // SAFETY: caller guarantees the block is loaded.
        unsafe {
            // General registers.
            self.frame = EnterFrame {
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
                ..EnterFrame::zeroed()
            };
            let _ = S9VM_ENTER_FRAME_SIZE;

            // Control and state registers.
            self.control.write_natural(field::GUEST_CR0, guest.cr0)?;
            self.control.write_natural(field::GUEST_CR3, guest.cr3)?;
            self.control.write_natural(field::GUEST_CR4, guest.cr4)?;
            self.control.write_u64(field::GUEST_EFER, guest.efer)?;
            self.control.write_u64(field::GUEST_PAT, guest.pat)?;
            self.control.write_natural(field::GUEST_RSP, guest.rsp)?;
            self.control.write_natural(field::GUEST_RIP, guest.rip)?;
            self.control
                .write_natural(field::GUEST_RFLAGS, guest.rflags)?;
            self.control.write_natural(field::GUEST_DR7, guest.dr7)?;
            // Auxiliary 64-bit guest fields that are loaded by VM entry on
            // most processors (PAT is written above). The hypervisor this
            // kernel may run under rebuilds the effective control block and
            // expects these fields to hold the guest's values, not leftovers:
            // an uninitialised PERF_GLOBAL_CTRL or PDPTE has already caused
            // entry failures on nested setups.
            self.control.write_u64(field::GUEST_DEBUGCTL, 0)?;
            self.control.write_u64(field::GUEST_PERF_GLOBAL_CTRL, 0)?;
            self.control.write_u64(field::GUEST_PDPTE0, 0)?;
            self.control.write_u64(field::GUEST_PDPTE1, 0)?;
            self.control.write_u64(field::GUEST_PDPTE2, 0)?;
            self.control.write_u64(field::GUEST_PDPTE3, 0)?;
            self.control.write_u64(
                field::GUEST_PENDING_DEBUG_EXCEPTIONS,
                guest.pending_debug_exceptions,
            )?;
            self.control
                .write_u32(field::GUEST_INTERRUPTIBILITY_INFO, guest.interruptibility)?;
            self.control
                .write_u32(field::GUEST_ACTIVITY_STATE, guest.activity_state)?;

            // Segments.
            self.write_segment(
                field::GUEST_ES_SELECTOR,
                field::GUEST_ES_BASE,
                field::GUEST_ES_LIMIT,
                field::GUEST_ES_ACCESS_RIGHTS,
                guest.es,
            )?;
            self.write_segment(
                field::GUEST_CS_SELECTOR,
                field::GUEST_CS_BASE,
                field::GUEST_CS_LIMIT,
                field::GUEST_CS_ACCESS_RIGHTS,
                guest.cs,
            )?;
            self.write_segment(
                field::GUEST_SS_SELECTOR,
                field::GUEST_SS_BASE,
                field::GUEST_SS_LIMIT,
                field::GUEST_SS_ACCESS_RIGHTS,
                guest.ss,
            )?;
            self.write_segment(
                field::GUEST_DS_SELECTOR,
                field::GUEST_DS_BASE,
                field::GUEST_DS_LIMIT,
                field::GUEST_DS_ACCESS_RIGHTS,
                guest.ds,
            )?;
            self.write_segment(
                field::GUEST_FS_SELECTOR,
                field::GUEST_FS_BASE,
                field::GUEST_FS_LIMIT,
                field::GUEST_FS_ACCESS_RIGHTS,
                guest.fs,
            )?;
            self.write_segment(
                field::GUEST_GS_SELECTOR,
                field::GUEST_GS_BASE,
                field::GUEST_GS_LIMIT,
                field::GUEST_GS_ACCESS_RIGHTS,
                guest.gs,
            )?;
            self.write_segment(
                field::GUEST_LDTR_SELECTOR,
                field::GUEST_LDTR_BASE,
                field::GUEST_LDTR_LIMIT,
                field::GUEST_LDTR_ACCESS_RIGHTS,
                guest.ldtr,
            )?;
            self.write_segment(
                field::GUEST_TR_SELECTOR,
                field::GUEST_TR_BASE,
                field::GUEST_TR_LIMIT,
                field::GUEST_TR_ACCESS_RIGHTS,
                guest.tr,
            )?;

            // Guest system tables and MSRs.
            self.control
                .write_natural(field::GUEST_GDTR_BASE, guest.gdtr_base)?;
            self.control
                .write_u32(field::GUEST_GDTR_LIMIT, guest.gdtr_limit)?;
            self.control
                .write_natural(field::GUEST_IDTR_BASE, guest.idtr_base)?;
            self.control
                .write_u32(field::GUEST_IDTR_LIMIT, guest.idtr_limit)?;
            self.control
                .write_u32(field::GUEST_SYSENTER_CS, guest.sysenter_cs)?;
            self.control
                .write_natural(field::GUEST_SYSENTER_ESP, guest.sysenter_esp)?;
            self.control
                .write_natural(field::GUEST_SYSENTER_EIP, guest.sysenter_eip)?;
        }
        Ok(())
    }

    unsafe fn write_segment(
        &self,
        selector_field: u32,
        base_field: u32,
        limit_field: u32,
        access_rights_field: u32,
        segment: crate::s9vm::guest::Segment,
    ) -> Result<(), VcpuError> {
        // SAFETY: caller guarantees the block is loaded.
        unsafe {
            self.control.write_u16(selector_field, segment.selector)?;
            self.control.write_natural(base_field, segment.base)?;
            self.control.write_u32(limit_field, segment.limit)?;
            self.control
                .write_u32(access_rights_field, segment.access_rights)?;
        }
        Ok(())
    }

    unsafe fn write_controls(&self, caps: &HwCaps) -> Result<(), VcpuError> {
        let mut pin = bits::PIN_EXTERNAL_INTERRUPT_EXITING;
        if self.preemption_timer.is_some() {
            pin |= bits::PIN_PREEMPTION_TIMER;
        }
        let pin = caps.pin_allowed.apply(pin);
        let primary = primary_controls(caps, false);
        let mut secondary = bits::SECONDARY_ENABLE_EPT | bits::SECONDARY_UNRESTRICTED_GUEST;
        if self.msr_bitmap.is_some() {
            secondary |= bits::SECONDARY_USE_MSR_BITMAPS;
        }
        let secondary = caps.secondary_proc_allowed.apply(secondary);
        let exit = caps
            .exit_allowed
            .apply(bits::EXIT_HOST_ADDR_SPACE_SIZE | bits::EXIT_LOAD_IA32_EFER);
        let entry = caps
            .entry_allowed
            .apply(bits::ENTRY_IA32E_MODE | bits::ENTRY_LOAD_IA32_EFER);
        // SAFETY: block loaded; 16-bit widths for the controls.
        unsafe {
            self.control.write_u32(field::PIN_BASED_CONTROLS, pin)?;
            self.control
                .write_u32(field::PRIMARY_PROC_BASED_CONTROLS, primary)?;
            self.control
                .write_u32(field::SECONDARY_PROC_BASED_CONTROLS, secondary)?;
            self.control.write_u32(field::EXIT_CONTROLS, exit)?;
            self.control.write_u32(field::ENTRY_CONTROLS, entry)?;
        }
        Ok(())
    }

    /// Launches or resumes the guest. Blocks until the next exit.
    ///
    /// # Safety
    /// - VT-x must be active on the current CPU (the block is loaded);
    /// - local interrupts must be disabled;
    /// - `configure_host` and `configure` must have been called.
    pub unsafe fn run(&mut self) -> Result<ExitInfo, VcpuError> {
        self.frame.launched = u64::from(self.launched);
        if let Some(ticks) = self.preemption_timer {
            // Re-armed on every entry: each guest time slice is bounded,
            // including after an internal resumption.
            unsafe {
                let _ = self.control.write_u32(field::VMX_PREEMPTION_TIMER, ticks);
            }
        }
        // SAFETY: caller contract; the trampoline restores the host state.
        let failed =
            unsafe { s9vm_enter_guest(&mut self.frame as *mut EnterFrame, self.host_stack.top()) };
        if failed != 0 {
            // The error code is in the block's instruction field.
            // SAFETY: block loaded.
            let code = unsafe {
                self.control
                    .read_u32(field::INSTRUCTION_ERROR)
                    .unwrap_or(u32::MAX)
            };
            return Err(VcpuError::VmFail(code));
        }
        self.launched = true;
        // SAFETY: block loaded; reading the exit fields.
        let exit = unsafe { self.read_exit()? };
        // Retrieves the post-exit guest state kept in the block.
        // SAFETY: block loaded.
        unsafe {
            if let Ok(rip) = self.control.read_natural(field::GUEST_RIP) {
                self.guest.rip = rip;
            }
            if let Ok(rsp) = self.control.read_natural(field::GUEST_RSP) {
                self.guest.rsp = rsp;
            }
            if let Ok(rflags) = self.control.read_natural(field::GUEST_RFLAGS) {
                self.guest.rflags = rflags;
            }
            if let Ok(cr0) = self.control.read_natural(field::GUEST_CR0) {
                self.guest.cr0 = cr0;
            }
            if let Ok(cr3) = self.control.read_natural(field::GUEST_CR3) {
                self.guest.cr3 = cr3;
            }
            if let Ok(cr4) = self.control.read_natural(field::GUEST_CR4) {
                self.guest.cr4 = cr4;
            }
            if let Ok(efer) = self.control.read_u64(field::GUEST_EFER) {
                self.guest.efer = efer;
            }
        }
        self.update_guest_from_exit(&exit);
        self.exit = Some(exit);
        Ok(exit)
    }

    unsafe fn read_exit(&self) -> Result<ExitInfo, VcpuError> {
        // SAFETY: block loaded; 32-bit fields.
        unsafe {
            let raw_reason = self.control.read_u32(field::EXIT_REASON)?;
            let reason = ExitReason::decode(raw_reason);
            let mut info = ExitInfo {
                raw_reason,
                reason,
                ..ExitInfo::default()
            };
            info.qualification = self
                .control
                .read_u64(field::EXIT_QUALIFICATION)
                .unwrap_or(0);
            info.guest_physical_address = self
                .control
                .read_u64(field::GUEST_PHYSICAL_ADDRESS)
                .unwrap_or(0);
            info.interrupt_info = self.control.read_u32(field::EXIT_INTERRUPT_INFO)?;
            info.vectoring_info = self.control.read_u32(field::IDT_VECTORING_INFO)?;
            info.vectoring_error = self
                .control
                .read_u32(field::IDT_VECTORING_ERROR_CODE)
                .unwrap_or(0);
            info.instruction_length = self
                .control
                .read_u32(field::EXIT_INSTRUCTION_LENGTH)
                .unwrap_or(0);
            info.instruction_info = self
                .control
                .read_u32(field::EXIT_INSTRUCTION_INFO)
                .unwrap_or(0);
            info.entry_failed = reason.entry_failed;
            Ok(info)
        }
    }

    fn update_guest_from_exit(&mut self, exit: &ExitInfo) {
        self.guest.rax = self.frame.rax;
        self.guest.rbx = self.frame.rbx;
        self.guest.rcx = self.frame.rcx;
        self.guest.rdx = self.frame.rdx;
        self.guest.rsi = self.frame.rsi;
        self.guest.rdi = self.frame.rdi;
        self.guest.rbp = self.frame.rbp;
        self.guest.r8 = self.frame.r8;
        self.guest.r9 = self.frame.r9;
        self.guest.r10 = self.frame.r10;
        self.guest.r11 = self.frame.r11;
        self.guest.r12 = self.frame.r12;
        self.guest.r13 = self.frame.r13;
        self.guest.r14 = self.frame.r14;
        self.guest.r15 = self.frame.r15;
        let _ = exit;
    }

    /// Last observed exit.
    pub fn last_exit(&self) -> Option<ExitInfo> {
        self.exit
    }

    /// Current guest state (registers updated after the last exit).
    pub fn guest(&self) -> &GuestState {
        &self.guest
    }

    /// True once the guest has actually been entered.
    ///
    /// Only then does the control block hold the architectural state the guest
    /// produced itself (descriptor tables, segments, MSRs): a vCPU that failed
    /// before its first entry must still be initialised from the ABI register
    /// block, not from the control block.
    pub fn entered(&self) -> bool {
        self.launched
    }

    /// Reads the guest architectural state that the ABI register block cannot
    /// carry back from the control block.
    ///
    /// The processor saves the complete guest state in the control block on
    /// every VM exit; the kernel only updates the ABI-visible fields. This
    /// reads the descriptor tables, the segment registers and the MSRs back so
    /// that a policy round trip (`RUN` → exit → policy → `RUN`) does not
    /// rewrite them with the boot defaults. Skipping it made the first
    /// interrupt delivered after such a round trip triple-fault the guest:
    /// the control block reloaded `IDTR` with a zero limit, so the vector
    /// could not be delivered.
    ///
    /// # Safety
    /// The control block must be loaded on the current CPU and the guest must
    /// not be running.
    pub unsafe fn refresh_system_state(&mut self) -> Result<(), VcpuError> {
        // SAFETY: caller guarantees the block is loaded and the guest inactive.
        unsafe {
            self.guest.gdtr_base = self.control.read_natural(field::GUEST_GDTR_BASE)?;
            self.guest.gdtr_limit = self.control.read_u32(field::GUEST_GDTR_LIMIT)?;
            self.guest.idtr_base = self.control.read_natural(field::GUEST_IDTR_BASE)?;
            self.guest.idtr_limit = self.control.read_u32(field::GUEST_IDTR_LIMIT)?;
            self.guest.es = self.read_segment(
                field::GUEST_ES_SELECTOR,
                field::GUEST_ES_BASE,
                field::GUEST_ES_LIMIT,
                field::GUEST_ES_ACCESS_RIGHTS,
            )?;
            self.guest.cs = self.read_segment(
                field::GUEST_CS_SELECTOR,
                field::GUEST_CS_BASE,
                field::GUEST_CS_LIMIT,
                field::GUEST_CS_ACCESS_RIGHTS,
            )?;
            self.guest.ss = self.read_segment(
                field::GUEST_SS_SELECTOR,
                field::GUEST_SS_BASE,
                field::GUEST_SS_LIMIT,
                field::GUEST_SS_ACCESS_RIGHTS,
            )?;
            self.guest.ds = self.read_segment(
                field::GUEST_DS_SELECTOR,
                field::GUEST_DS_BASE,
                field::GUEST_DS_LIMIT,
                field::GUEST_DS_ACCESS_RIGHTS,
            )?;
            self.guest.fs = self.read_segment(
                field::GUEST_FS_SELECTOR,
                field::GUEST_FS_BASE,
                field::GUEST_FS_LIMIT,
                field::GUEST_FS_ACCESS_RIGHTS,
            )?;
            self.guest.gs = self.read_segment(
                field::GUEST_GS_SELECTOR,
                field::GUEST_GS_BASE,
                field::GUEST_GS_LIMIT,
                field::GUEST_GS_ACCESS_RIGHTS,
            )?;
            self.guest.ldtr = self.read_segment(
                field::GUEST_LDTR_SELECTOR,
                field::GUEST_LDTR_BASE,
                field::GUEST_LDTR_LIMIT,
                field::GUEST_LDTR_ACCESS_RIGHTS,
            )?;
            self.guest.tr = self.read_segment(
                field::GUEST_TR_SELECTOR,
                field::GUEST_TR_BASE,
                field::GUEST_TR_LIMIT,
                field::GUEST_TR_ACCESS_RIGHTS,
            )?;
            self.guest.pat = self.control.read_u64(field::GUEST_PAT)?;
            self.guest.dr7 = self.control.read_natural(field::GUEST_DR7)?;
            self.guest.sysenter_cs = self.control.read_u32(field::GUEST_SYSENTER_CS)?;
            self.guest.sysenter_esp = self.control.read_natural(field::GUEST_SYSENTER_ESP)?;
            self.guest.sysenter_eip = self.control.read_natural(field::GUEST_SYSENTER_EIP)?;
        }
        Ok(())
    }

    /// Reads one segment register from the control block.
    ///
    /// # Safety
    /// The control block must be loaded on the current CPU.
    unsafe fn read_segment(
        &self,
        selector_field: u32,
        base_field: u32,
        limit_field: u32,
        access_rights_field: u32,
    ) -> Result<crate::s9vm::guest::Segment, VcpuError> {
        // SAFETY: caller guarantees the block is loaded; widths match.
        unsafe {
            Ok(crate::s9vm::guest::Segment {
                selector: self.control.read_u16(selector_field)?,
                base: self.control.read_natural(base_field)?,
                limit: self.control.read_u32(limit_field)?,
                access_rights: self.control.read_u32(access_rights_field)?,
            })
        }
    }

    /// Per-vCPU MSR shadow state.
    pub const fn msr(&self) -> &MsrModel {
        &self.msr
    }

    /// Mutable per-vCPU MSR shadow state, for the replay path.
    pub fn msr_mut(&mut self) -> &mut MsrModel {
        &mut self.msr
    }

    /// Refreshes the guest state and control block from the MSR shadows.
    ///
    /// Must be called after a replayed `WRMSR` whose effect is
    /// [`crate::s9vm::msr::MsrWrite::Efer`], `Pat`, `SegmentBase` or `State`,
    /// before the next guest entry.
    ///
    /// # Safety
    /// The control block must be loaded on the current CPU and the guest must
    /// not be running.
    pub unsafe fn sync_msr_state(&mut self) -> Result<(), VcpuError> {
        let efer = self.msr.read(msr::IA32_EFER).unwrap_or(self.guest.efer);
        let pat = self.msr.pat();
        let fs_base = self.msr.fs_base();
        let gs_base = self.msr.gs_base();
        let (sysenter_cs, sysenter_esp, sysenter_eip) = self.msr.sysenter();
        self.guest.efer = efer;
        self.guest.pat = pat;
        self.guest.fs.base = fs_base;
        self.guest.gs.base = gs_base;
        self.guest.sysenter_cs = sysenter_cs as u32;
        self.guest.sysenter_esp = sysenter_esp;
        self.guest.sysenter_eip = sysenter_eip;
        // SAFETY: caller guarantees the block is loaded.
        unsafe {
            self.control.write_u64(field::GUEST_EFER, efer)?;
            self.control.write_u64(field::GUEST_PAT, pat)?;
            self.control.write_natural(field::GUEST_FS_BASE, fs_base)?;
            self.control.write_natural(field::GUEST_GS_BASE, gs_base)?;
            self.control
                .write_u32(field::GUEST_SYSENTER_CS, sysenter_cs as u32)?;
            self.control
                .write_natural(field::GUEST_SYSENTER_ESP, sysenter_esp)?;
            self.control
                .write_natural(field::GUEST_SYSENTER_EIP, sysenter_eip)?;
        }
        Ok(())
    }

    /// Second-level pointer (`EPT_POINTER` value) given to this vCPU.
    pub const fn second_level_pointer(&self) -> u64 {
        self.second_level_pointer
    }

    /// True if the guest runs with paging enabled.
    pub fn paging_enabled(&self) -> bool {
        self.guest.is_long_mode()
    }

    /// Reads a guest general-purpose register.
    ///
    /// The index follows the x86 encoding order: `0` = RAX, `1` = RCX,
    /// `2` = RDX, `3` = RBX, `4` = RSP, `5` = RBP, `6` = RSI, `7` = RDI,
    /// then `8..=15` = R8..R15.
    pub fn guest_gpr(&self, register: u8) -> u64 {
        gpr_from_frame(&self.frame, register).unwrap_or(0)
    }

    /// Writes a guest general-purpose register (encoding order).
    ///
    /// # Safety
    /// The control block must be loaded on the current CPU and the guest must
    /// not be running: this is only called from an exit handler, before the
    /// guest is resumed.
    pub unsafe fn set_guest_gpr(&mut self, register: u8, value: u64) {
        if !gpr_into_frame(&mut self.frame, register, value) {
            return;
        }
        // SAFETY: caller contract.
        unsafe {
            if register == GPR_RSP {
                // RSP is loaded from the control block, not from the frame.
                let _ = self.control.write_natural(field::GUEST_RSP, value);
            }
        }
        if let Some(shadow) = shadow_gpr(&mut self.guest, register) {
            *shadow = value;
        }
    }

    /// Arms or disarms interrupt-window exiting.
    ///
    /// Interrupt-window exiting makes the processor exit as soon as the guest
    /// becomes able to take an interrupt (`RFLAGS.IF` set, no shadow). The
    /// kernel uses it to deliver a pending APIC vector to a guest that is
    /// currently running with interrupts disabled.
    ///
    /// Returns `true` when the control is armed as requested, `false` when the
    /// processor does not allow it: the caller then has to keep the vector
    /// pending until the guest enables interrupts on its own.
    ///
    /// # Safety
    /// The control block must be loaded on the current CPU and the guest must
    /// not be running.
    pub unsafe fn set_interrupt_window_exiting(
        &mut self,
        caps: &HwCaps,
        enabled: bool,
    ) -> Result<bool, VcpuError> {
        let primary = primary_controls(caps, enabled);
        if enabled && primary & bits::PRIMARY_INTERRUPT_WINDOW_EXITING == 0 {
            return Ok(false);
        }
        // SAFETY: caller contract.
        unsafe {
            self.control
                .write_u32(field::PRIMARY_PROC_BASED_CONTROLS, primary)?;
        }
        Ok(enabled)
    }

    /// Physical address of the MSR bitmap (0 when not used).
    pub fn msr_bitmap_phys(&self) -> u64 {
        self.msr_bitmap
            .as_ref()
            .map(|frame| frame.start_address.as_u64())
            .unwrap_or(0)
    }

    /// Sets the guest instruction pointer.
    ///
    /// # Safety
    /// Same contract as [`Self::set_guest_gpr`].
    pub unsafe fn set_guest_rip(&mut self, rip: u64) {
        self.guest.rip = rip;
        // SAFETY: caller contract.
        unsafe {
            let _ = self.control.write_natural(field::GUEST_RIP, rip);
        }
    }
}

/// Index of RSP in the x86 register encoding order.
const GPR_RSP: u8 = 4;

/// Reads a general-purpose register out of the entry frame (encoding order).
fn gpr_from_frame(frame: &EnterFrame, register: u8) -> Option<u64> {
    Some(match register {
        0 => frame.rax,
        1 => frame.rcx,
        2 => frame.rdx,
        3 => frame.rbx,
        4 => frame.rsp,
        5 => frame.rbp,
        6 => frame.rsi,
        7 => frame.rdi,
        8 => frame.r8,
        9 => frame.r9,
        10 => frame.r10,
        11 => frame.r11,
        12 => frame.r12,
        13 => frame.r13,
        14 => frame.r14,
        15 => frame.r15,
        _ => return None,
    })
}

/// Writes a general-purpose register into the entry frame (encoding order).
fn gpr_into_frame(frame: &mut EnterFrame, register: u8, value: u64) -> bool {
    match register {
        0 => frame.rax = value,
        1 => frame.rcx = value,
        2 => frame.rdx = value,
        3 => frame.rbx = value,
        4 => frame.rsp = value,
        5 => frame.rbp = value,
        6 => frame.rsi = value,
        7 => frame.rdi = value,
        8 => frame.r8 = value,
        9 => frame.r9 = value,
        10 => frame.r10 = value,
        11 => frame.r11 = value,
        12 => frame.r12 = value,
        13 => frame.r13 = value,
        14 => frame.r14 = value,
        15 => frame.r15 = value,
        _ => return false,
    }
    true
}

/// Mutable view of the shadow copy of a general-purpose register.
fn shadow_gpr(guest: &mut GuestState, register: u8) -> Option<&mut u64> {
    Some(match register {
        0 => &mut guest.rax,
        1 => &mut guest.rcx,
        2 => &mut guest.rdx,
        3 => &mut guest.rbx,
        4 => &mut guest.rsp,
        5 => &mut guest.rbp,
        6 => &mut guest.rsi,
        7 => &mut guest.rdi,
        8 => &mut guest.r8,
        9 => &mut guest.r9,
        10 => &mut guest.r10,
        11 => &mut guest.r11,
        12 => &mut guest.r12,
        13 => &mut guest.r13,
        14 => &mut guest.r14,
        15 => &mut guest.r15,
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// CPU access (read-only) used to build the host state.
// ---------------------------------------------------------------------------

fn read_cr0() -> u64 {
    let value: u64;
    // SAFETY: read of a control register.
    unsafe {
        core::arch::asm!("mov {}, cr0", out(reg) value, options(nomem, nostack, preserves_flags))
    };
    value
}

fn read_cr3() -> u64 {
    let value: u64;
    // SAFETY: read of a control register.
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) value, options(nomem, nostack, preserves_flags))
    };
    value
}

fn read_cr4() -> u64 {
    let value: u64;
    // SAFETY: read of a control register.
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) value, options(nomem, nostack, preserves_flags))
    };
    value
}

/// Reads the global descriptor table base (`sgdt`).
fn read_gdtr() -> (u64, u16) {
    let mut descriptor = [0u8; 10];
    // SAFETY: `sgdt` writes 10 bytes into a local buffer.
    unsafe {
        core::arch::asm!("sgdt [{}]", in(reg) descriptor.as_mut_ptr(), options(nostack));
    }
    let limit = u16::from_le_bytes([descriptor[0], descriptor[1]]);
    let base = u64::from_le_bytes([
        descriptor[2],
        descriptor[3],
        descriptor[4],
        descriptor[5],
        descriptor[6],
        descriptor[7],
        descriptor[8],
        descriptor[9],
    ]);
    (base, limit)
}

/// Reads the interrupt descriptor table base (`sidt`).
fn read_idtr() -> (u64, u16) {
    let mut descriptor = [0u8; 10];
    // SAFETY: `sidt` writes 10 bytes into a local buffer.
    unsafe {
        core::arch::asm!("sidt [{}]", in(reg) descriptor.as_mut_ptr(), options(nostack));
    }
    let limit = u16::from_le_bytes([descriptor[0], descriptor[1]]);
    let base = u64::from_le_bytes([
        descriptor[2],
        descriptor[3],
        descriptor[4],
        descriptor[5],
        descriptor[6],
        descriptor[7],
        descriptor[8],
        descriptor[9],
    ]);
    (base, limit)
}

/// Base of a TSS descriptor from its selector (GDT).
fn tr_base(selector: u16) -> u64 {
    if selector == 0 {
        return 0;
    }
    let index = (selector >> 3) as usize;
    let (gdt_base, _) = read_gdtr();
    let entry = (gdt_base as *const u8).wrapping_add(index * 8);
    // SAFETY: the TR selector designates a valid entry of the current GDT.
    unsafe {
        let low = core::ptr::read_volatile(entry as *const u64);
        let upper = core::ptr::read_volatile(entry.add(8) as *const u32);
        // 64-bit TSS: base split into four pieces (see SDM).
        ControlBlock::decode_tss_base(low, upper)
    }
}
