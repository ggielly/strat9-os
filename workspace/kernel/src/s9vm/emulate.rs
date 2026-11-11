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

//! s9vm — in-kernel emulation of a minimal guest device set.
//!
//! Every access a guest makes to the legacy PIC pair, to the local APIC page
//! or to the I/O APIC page causes a VM exit. Reporting those exits to policy
//! would move the whole device model into the ABI, cost two world switches per
//! interrupt acknowledgement, and let a guest drive the host scheduling with
//! device traffic. The kernel therefore keeps a small model of these devices
//! and *replays* the faulting instruction: the guest never observes the exit.
//!
//! # Contents
//!
//! - [`PhysMemory`]: the only side effect of the module (physical memory
//!   access); the kernel uses the higher-half direct map, the tests a byte
//!   vector;
//! - [`MemoryView`]: guest-linear and guest-physical reads/writes, built on the
//!   two page-table walks ([`walk_second_level`], [`walk_guest`]);
//! - [`GuestContext`]: the few vCPU facts the replay needs (general registers,
//!   instruction pointer, `CR3`, paging state);
//! - [`Devices`]: the modeled devices;
//! - [`handle_exit`]: the entry point, called once per exit, which returns
//!   whether the exit was fully consumed.
//!
//! Everything here is pure apart from `PhysMemory`: page walks, instruction
//! replay and device behaviour are all covered by host tests. The kernel
//! supplies `PhysMemory` and `GuestContext` (see `machine.rs`).

use super::{
    apic::{reg as apic_reg, x2apic, LocalApic, TSC_DEADLINE_MSR},
    decode::{self, Decoded, MemoryAccess, PortAccess},
    exit::ExitClass,
    ioapic::{IoApic, PIN_COUNT},
    msr::MsrModel,
    pic::Pic,
    virtio::QueueMemory,
    virtio_blk::VirtioBlk,
    virtio_console::VirtioConsole,
    virtio_net::VirtioNet,
};

/// Page size of the second-level and guest page tables.
pub const PAGE_SIZE: u64 = 4096;
/// Page offset mask.
const PAGE_OFFSET_MASK: u64 = PAGE_SIZE - 1;
/// Bits of an EPT (second-level) table entry holding the physical address.
const EPT_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
/// Physical address mask for a 2 MiB EPT entry.
const EPT_2M_ADDR_MASK: u64 = 0x000F_FFFF_FFE0_0000;
/// Physical address mask for a 1 GiB EPT entry.
const EPT_1G_ADDR_MASK: u64 = 0x000F_FFFF_C000_0000;
/// Bits of a guest table entry holding the physical address.
const GUEST_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
/// Physical address mask for a 2 MiB guest page.
const GUEST_2M_ADDR_MASK: u64 = 0x000F_FFFF_FFE0_0000;
/// Physical address mask for a 1 GiB guest page.
const GUEST_1G_ADDR_MASK: u64 = 0x000F_FFFF_C000_0000;
/// Large-page bit of a PDPTE/PDE.
const LARGE_PAGE: u64 = 1 << 7;
/// Present bit of a guest table entry.
const GUEST_PRESENT: u64 = 1 << 0;
/// Readable EPT entry (bit 0) — an EPT walk only succeeds on readable memory.
const EPT_READ: u64 = 1 << 0;

/// Base of the local APIC page in the conventional guest memory map.
pub const APIC_BASE: u64 = 0xFEE0_0000;
/// Base of the I/O APIC page in the conventional guest memory map.
pub const IOAPIC_BASE: u64 = 0xFEC0_0000;
/// Base of the virtio console transport page (virtio-mmio layout).
pub const CONSOLE_BASE: u64 = 0xFEB0_0000;
/// Base of the virtio block transport page (virtio-mmio layout).
pub const BLK_BASE: u64 = 0xFEB0_1000;
/// Interrupt vector used to signal the block device.
pub const BLK_IRQ_VECTOR: u8 = 0x22;
/// Base of the virtio network transport page (virtio-mmio layout).
pub const NET_BASE: u64 = 0xFEB0_2000;
/// Interrupt vector used to signal the network device.
pub const NET_IRQ_VECTOR: u8 = 0x23;
/// I/O APIC line wired to the console.
pub const CONSOLE_IRQ_LINE: usize = 16;
/// I/O APIC line wired to the block device.
pub const BLK_IRQ_LINE: usize = 17;
/// I/O APIC line wired to the network device.
pub const NET_IRQ_LINE: usize = 18;
/// Interrupt vector used to signal the console.
///
/// The virtio-mmio transport does not define its own interrupt: the platform
/// wires the device to an interrupt line. Until the policy layer routes device
/// lines through the I/O APIC, the kernel uses a fixed vector, which keeps the
/// device usable by a driver that programs the corresponding IDT entry.
pub const CONSOLE_IRQ_VECTOR: u8 = 0x21;
/// First and last MSR of the x2APIC window (`0x800..=0x8FF`).
pub const X2APIC_MSR_FIRST: u32 = 0x800;
pub const X2APIC_MSR_LAST: u32 = 0x8FF;

/// Base of the legacy PIC ports.
pub const PIC_BASE_PORT: u16 = 0x20;
/// POST/delay diagnostic port: writes are discarded, reads return zero.
pub const POST_PORT: u16 = 0x80;

/// Emulation error. Any error means "not emulated here": the caller reports
/// the exit to policy, exactly as if this module did not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmuError {
    /// The access targets memory that cannot be translated.
    Unmapped,
    /// The instruction could not be fetched or decoded.
    BadInstruction,
    /// The instruction, port or device is outside the modeled subset.
    Unsupported,
}

/// Physical memory access used by the page walks and the instruction replay.
///
/// Implementations must be safe to call with any physical address obtained
/// from a table walk: the kernel maps the whole physical address space in the
/// higher-half direct map, and the tests back it with a byte vector.
pub trait PhysMemory {
    /// Copies `out.len()` bytes from `phys` into `out`.
    fn read_bytes(&mut self, phys: u64, out: &mut [u8]) -> bool;
    /// Reads a little-endian 64-bit value.
    fn read_u64(&mut self, phys: u64) -> Option<u64> {
        let mut bytes = [0u8; 8];
        if self.read_bytes(phys, &mut bytes) {
            Some(u64::from_le_bytes(bytes))
        } else {
            None
        }
    }
    /// Copies `bytes` to `phys`.
    fn write_bytes(&mut self, phys: u64, bytes: &[u8]) -> bool;
}

/// Walks the second-level (EPT) tables and returns the host-physical address
/// backing `gpa`, with the size of the page that mapped it.
///
/// `ept_root` is the `EPT_POINTER` value: only bits 51:12 are significant for
/// the walk (the low bits carry the memory type, the walk length and the
/// accessed/dirty policy).
pub fn walk_second_level<M: PhysMemory + ?Sized>(
    memory: &mut M,
    ept_root: u64,
    gpa: u64,
) -> Option<(u64, u64)> {
    let table = ept_root & EPT_ADDR_MASK;

    let entry = memory.read_u64(table + index(gpa, 39) * 8)?;
    if entry & EPT_READ == 0 {
        return None;
    }
    let table = entry & EPT_ADDR_MASK;

    let entry = memory.read_u64(table + index(gpa, 30) * 8)?;
    if entry & EPT_READ == 0 {
        return None;
    }
    if entry & LARGE_PAGE != 0 {
        // 1 GiB page: the whole address is taken from this entry.
        return Some(((entry & EPT_1G_ADDR_MASK) | (gpa & 0x3FFF_FFFF), 1 << 30));
    }
    let table = entry & EPT_ADDR_MASK;

    let entry = memory.read_u64(table + index(gpa, 21) * 8)?;
    if entry & EPT_READ == 0 {
        return None;
    }
    if entry & LARGE_PAGE != 0 {
        // 2 MiB page.
        return Some((entry & EPT_2M_ADDR_MASK | (gpa & 0x1F_FFFF), 1 << 21));
    }
    let table = entry & EPT_ADDR_MASK;

    let entry = memory.read_u64(table + index(gpa, 12) * 8)?;
    if entry & EPT_READ == 0 {
        return None;
    }
    Some((
        (entry & EPT_ADDR_MASK) | (gpa & PAGE_OFFSET_MASK),
        PAGE_SIZE,
    ))
}

/// Walks the guest page tables and returns the guest-physical address for the
/// linear address `linear`.
///
/// `cr3` is the guest `CR3` (its low 12 bits are ignored); `ept_root` is used
/// to reach the guest tables, which are themselves guest-physical. Returning
/// `None` means the guest access cannot be resolved. When the guest has
/// paging disabled, the linear address *is* the physical address and the
/// caller must not use this function (see [`MemoryView`]).
pub fn walk_guest<M: PhysMemory + ?Sized>(
    memory: &mut M,
    ept_root: u64,
    cr3: u64,
    linear: u64,
) -> Option<u64> {
    let table = cr3 & EPT_ADDR_MASK;
    let entry = read_physical_u64(memory, ept_root, table + index(linear, 39) * 8)?;
    if entry & GUEST_PRESENT == 0 {
        return None;
    }
    let table = entry & GUEST_ADDR_MASK;

    let entry = read_physical_u64(memory, ept_root, table + index(linear, 30) * 8)?;
    if entry & GUEST_PRESENT == 0 {
        return None;
    }
    if entry & LARGE_PAGE != 0 {
        return Some((entry & GUEST_1G_ADDR_MASK) | (linear & 0x3FFF_FFFF));
    }
    let table = entry & GUEST_ADDR_MASK;

    let entry = read_physical_u64(memory, ept_root, table + index(linear, 21) * 8)?;
    if entry & GUEST_PRESENT == 0 {
        return None;
    }
    if entry & LARGE_PAGE != 0 {
        return Some((entry & GUEST_2M_ADDR_MASK) | (linear & 0x1F_FFFF));
    }
    let table = entry & GUEST_ADDR_MASK;

    let entry = read_physical_u64(memory, ept_root, table + index(linear, 12) * 8)?;
    if entry & GUEST_PRESENT == 0 {
        return None;
    }
    Some((entry & GUEST_ADDR_MASK) | (linear & PAGE_OFFSET_MASK))
}

/// Reads a 64-bit value at a guest-physical address.
fn read_physical_u64<M: PhysMemory + ?Sized>(
    memory: &mut M,
    ept_root: u64,
    gpa: u64,
) -> Option<u64> {
    let (hpa, _) = walk_second_level(memory, ept_root, gpa & !0x7)?;
    memory.read_u64(hpa)
}

/// Page-table index of `address` at `shift` (39, 30, 21 or 12).
const fn index(address: u64, shift: u32) -> u64 {
    (address >> shift) & 0x1FF
}

/// The vCPU facts the replay needs.
///
/// Register indices follow the x86 encoding order: `0` = RAX, `1` = RCX,
/// `2` = RDX, `3` = RBX, `4` = RSP, `5` = RBP, `6` = RSI, `7` = RDI, then
/// `8..=15` = R8..R15.
pub trait GuestContext {
    /// Reads a general-purpose register.
    fn gpr(&self, register: u8) -> u64;
    /// Writes a general-purpose register.
    fn set_gpr(&mut self, register: u8, value: u64);
    /// Guest instruction pointer.
    fn rip(&self) -> u64;
    /// Sets the guest instruction pointer.
    fn set_rip(&mut self, rip: u64);
    /// Guest `CR3`.
    fn cr3(&self) -> u64;
    /// True if guest paging is active (long mode with `CR0.PG` set).
    fn paging(&self) -> bool;

    /// Per-vCPU MSR shadow model, when the caller provides one.
    ///
    /// The default is `None`, which makes replayed `RDMSR`/`WRMSR` exits
    /// unhandleable (`Ok(false)`): the caller must then report them to policy.
    /// A caller that omits the model can never let an unmodelled guest MSR
    /// write reach the host MSR file, because the MSR bitmap intercepts all
    /// writes and this path fails closed.
    fn msr_model(&mut self) -> Option<&mut MsrModel> {
        None
    }
}

/// A window on guest memory.
///
/// Linear addresses go through the guest page tables when paging is active;
/// physical addresses go through the second-level tables. Accesses crossing a
/// page boundary are split, so an instruction fetch near the end of a page is
/// still valid.
pub struct MemoryView<'a> {
    memory: &'a mut dyn PhysMemory,
    ept_root: u64,
    cr3: u64,
    paging: bool,
}

impl<'a> MemoryView<'a> {
    /// Builds a view. `ept_root` is the `EPT_POINTER` value of the vCPU.
    pub fn new(memory: &'a mut dyn PhysMemory, ept_root: u64, cr3: u64, paging: bool) -> Self {
        Self {
            memory,
            ept_root,
            cr3,
            paging,
        }
    }

    /// Translates a linear address to a host-physical address.
    fn translate(&mut self, linear: u64) -> Option<u64> {
        let gpa = if self.paging {
            walk_guest(self.memory, self.ept_root, self.cr3, linear)?
        } else {
            linear
        };
        let (hpa, _) = walk_second_level(self.memory, self.ept_root, gpa)?;
        Some(hpa)
    }

    /// Reads `out.len()` bytes starting at a linear address.
    pub fn read(&mut self, linear: u64, out: &mut [u8]) -> bool {
        let mut done = 0usize;
        while done < out.len() {
            let address = linear.wrapping_add(done as u64);
            let Some(hpa) = self.translate(address) else {
                return false;
            };
            let chunk = core::cmp::min(
                out.len() - done,
                (PAGE_SIZE - (address & PAGE_OFFSET_MASK)) as usize,
            );
            if !self.memory.read_bytes(hpa, &mut out[done..done + chunk]) {
                return false;
            }
            done += chunk;
        }
        true
    }

    /// Writes `bytes` starting at a linear address.
    pub fn write(&mut self, linear: u64, bytes: &[u8]) -> bool {
        let mut done = 0usize;
        while done < bytes.len() {
            let address = linear.wrapping_add(done as u64);
            let Some(hpa) = self.translate(address) else {
                return false;
            };
            let chunk = core::cmp::min(
                bytes.len() - done,
                (PAGE_SIZE - (address & PAGE_OFFSET_MASK)) as usize,
            );
            if !self.memory.write_bytes(hpa, &bytes[done..done + chunk]) {
                return false;
            }
            done += chunk;
        }
        true
    }

    /// Reads `out.len()` bytes at a guest-physical address.
    pub fn read_physical(&mut self, gpa: u64, out: &mut [u8]) -> bool {
        let mut done = 0usize;
        while done < out.len() {
            let address = gpa.wrapping_add(done as u64);
            let Some((hpa, _)) = walk_second_level(self.memory, self.ept_root, address) else {
                return false;
            };
            let chunk = core::cmp::min(
                out.len() - done,
                (PAGE_SIZE - (address & PAGE_OFFSET_MASK)) as usize,
            );
            if !self.memory.read_bytes(hpa, &mut out[done..done + chunk]) {
                return false;
            }
            done += chunk;
        }
        true
    }

    /// Writes `bytes` at a guest-physical address.
    pub fn write_physical(&mut self, gpa: u64, bytes: &[u8]) -> bool {
        let mut done = 0usize;
        while done < bytes.len() {
            let address = gpa.wrapping_add(done as u64);
            let Some((hpa, _)) = walk_second_level(self.memory, self.ept_root, address) else {
                return false;
            };
            let chunk = core::cmp::min(
                bytes.len() - done,
                (PAGE_SIZE - (address & PAGE_OFFSET_MASK)) as usize,
            );
            if !self.memory.write_bytes(hpa, &bytes[done..done + chunk]) {
                return false;
            }
            done += chunk;
        }
        true
    }

    /// Fetches and decodes the instruction at the guest instruction pointer.
    fn fetch(&mut self, guest: &dyn GuestContext) -> Result<Decoded, EmuError> {
        let rip = guest.rip();
        let mut bytes = [0u8; decode::MAX_INSTRUCTION];
        if !self.read(rip, &mut bytes) {
            return Err(EmuError::Unmapped);
        }
        decode::decode(&bytes, rip, |register| guest.gpr(register))
            .map_err(|_| EmuError::BadInstruction)
    }
}

impl QueueMemory for MemoryView<'_> {
    fn read_gpa(&mut self, gpa: u64, out: &mut [u8]) -> bool {
        self.read_physical(gpa, out)
    }

    fn write_gpa(&mut self, gpa: u64, bytes: &[u8]) -> bool {
        self.write_physical(gpa, bytes)
    }
}

/// Device model owned by a world: the chipset devices shared by all its
/// vCPUs. The local APIC is per-vCPU and lives in the vCPU slot; the exit
/// handlers receive it separately.
#[derive(Debug)]
pub struct Devices {
    /// Cascaded 8259A pair.
    pub pic: Pic,
    /// I/O APIC (MMIO page).
    pub ioapic: IoApic,
    /// Virtio console (MMIO transport page).
    pub console: VirtioConsole,
    /// Virtio block device (MMIO transport page).
    pub blk: VirtioBlk,
    /// Virtio network device (MMIO transport page).
    pub net: VirtioNet,
}

impl Devices {
    /// Creates the device model.
    ///
    /// The I/O APIC redirection table is pre-programmed for the device lines
    /// (`CONSOLE_IRQ_LINE`, `BLK_IRQ_LINE`, `NET_IRQ_LINE`) with the default
    /// vectors and unmasked; the guest may reprogram them, and the kernel
    /// reads the table when a device raises its line.
    pub fn new() -> Self {
        let mut ioapic = IoApic::new(0);
        ioapic.set_pin(CONSOLE_IRQ_LINE, CONSOLE_IRQ_VECTOR, false);
        ioapic.set_pin(BLK_IRQ_LINE, BLK_IRQ_VECTOR, false);
        ioapic.set_pin(NET_IRQ_LINE, NET_IRQ_VECTOR, false);
        // Device interrupt lines are level-triggered (virtio asserts until the
        // guest acknowledges the interrupt status): model the trigger mode so
        // the remote-IRR/EOI path is exercised.
        ioapic.set_pin_mode(CONSOLE_IRQ_LINE, CONSOLE_IRQ_VECTOR, false, true, false);
        ioapic.set_pin_mode(BLK_IRQ_LINE, BLK_IRQ_VECTOR, false, true, false);
        ioapic.set_pin_mode(NET_IRQ_LINE, NET_IRQ_VECTOR, false, true, false);
        Self {
            pic: Pic::new(),
            ioapic,
            console: VirtioConsole::new(),
            blk: VirtioBlk::new(64 * 1024),
            net: VirtioNet::new(),
        }
    }

    /// True if the port belongs to a device modeled here.
    pub const fn handles_port(port: u16) -> bool {
        Pic::handles_port(port) || port == POST_PORT
    }
}

impl Default for Devices {
    fn default() -> Self {
        Self::new()
    }
}

/// What the execution loop must do before entering the guest to deliver a
/// pending interrupt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptAction {
    /// A deliverable vector is waiting and the guest is interruptible: inject
    /// it at the next entry.
    Inject,
    /// A deliverable vector is waiting but the guest has interrupts disabled:
    /// arm interrupt-window exiting so the vector is injected as soon as the
    /// guest enables interrupts.
    ArmWindow,
    /// No vector is waiting any more: disarm interrupt-window exiting,
    /// otherwise the processor would exit after every guest instruction.
    DisarmWindow,
    /// Nothing to do.
    None,
}

/// Decides the interrupt-delivery action for one guest entry.
///
/// `pending` is `true` when the local APIC has a deliverable vector,
/// `interruptible` mirrors `RFLAGS.IF`, and `window_armed` tells whether
/// interrupt-window exiting is currently armed.
pub const fn interrupt_action(
    pending: bool,
    interruptible: bool,
    window_armed: bool,
) -> InterruptAction {
    match (pending, interruptible, window_armed) {
        (true, true, _) => InterruptAction::Inject,
        (true, false, _) => InterruptAction::ArmWindow,
        (false, _, true) => InterruptAction::DisarmWindow,
        (false, _, false) => InterruptAction::None,
    }
}

/// "Blocking by STI" bit of `GUEST_INTERRUPTIBILITY_INFO`.
pub const INTERRUPTIBILITY_STI_BLOCKING: u32 = 1 << 0;
/// "Blocking by MOV SS" bit of `GUEST_INTERRUPTIBILITY_INFO`.
pub const INTERRUPTIBILITY_MOV_SS_BLOCKING: u32 = 1 << 1;

/// True if a pending external interrupt can be delivered in this guest state.
///
/// `rflags_if` mirrors `RFLAGS.IF` and `interruptibility` the control-block
/// `GUEST_INTERRUPTIBILITY_INFO` field. Delivery is inhibited while the guest
/// is blocked by `STI` or by `MOV SS`: injecting a vector during that window
/// makes the processor drop it — VM-entry interruption delivery is suppressed,
/// but the vector was already taken out of the APIC, so it is lost. The
/// execution loop must arm interrupt-window exiting instead, so the vector is
/// injected as soon as the shadow clears.
pub const fn interrupt_deliverable(rflags_if: bool, interruptibility: u32) -> bool {
    rflags_if
        && interruptibility
            & (INTERRUPTIBILITY_STI_BLOCKING | INTERRUPTIBILITY_MOV_SS_BLOCKING)
            == 0
}

/// Tries to consume an exit by replaying the faulting instruction.
///
/// Returns `Ok(true)` when the exit was fully handled and the guest state has
/// been advanced: the caller can resume the guest immediately. `Ok(false)`
/// means the exit is outside the modeled subset and must be reported to
/// policy. An error is treated like `Ok(false)`; it exists so the caller can
/// log why the fast path declined.
pub fn handle_exit(
    devices: &mut Devices,
    apic: &mut LocalApic,
    view: &mut MemoryView<'_>,
    guest: &mut dyn GuestContext,
    class: ExitClass,
    qualification: u64,
    guest_physical_address: u64,
) -> Result<bool, EmuError> {
    match class {
        ExitClass::IoPort => handle_port_exit(devices, view, guest, qualification),
        ExitClass::EptViolation => handle_mmio_exit(
            devices,
            apic,
            view,
            guest,
            qualification,
            guest_physical_address,
        ),
        ExitClass::Msr => handle_msr_exit(apic, devices, view, guest),
        _ => Ok(false),
    }
}

/// Handles an I/O instruction exit (`IN`/`OUT`).
fn handle_port_exit(
    devices: &mut Devices,
    view: &mut MemoryView<'_>,
    guest: &mut dyn GuestContext,
    qualification: u64,
) -> Result<bool, EmuError> {
    // Exit qualification: bits 2:0 = size - 1, bit 3 = direction (1 = IN),
    // bits 5:4 = string/repeated, bits 31:16 = port.
    let string = (qualification >> 4) & 0x1 != 0;
    let repeated = (qualification >> 5) & 0x1 != 0;
    if string || repeated {
        return Ok(false);
    }
    let port = ((qualification >> 16) & 0xFFFF) as u16;
    if !Devices::handles_port(port) {
        return Ok(false);
    }
    let size = ((qualification & 0x7) + 1) as u8;
    let is_in = (qualification >> 3) & 0x1 != 0;

    let Decoded::Port(access) = view.fetch(guest)? else {
        return Ok(false);
    };
    // The decoded instruction must agree with the exit qualification;
    // otherwise the encoding is outside the modeled subset.
    if access.port != port || access.size != size || access.write == is_in {
        return Ok(false);
    }
    if !serve_port(devices, guest, &access) {
        return Ok(false);
    }
    guest.set_rip(access.next_rip);
    Ok(true)
}

/// Applies one decoded port access to the device model.
fn serve_port(devices: &mut Devices, guest: &mut dyn GuestContext, access: &PortAccess) -> bool {
    if Pic::handles_port(access.port) {
        // The 8259A pair is byte-wide; a wider access is not PC-compatible.
        if access.size != 1 {
            return false;
        }
        if access.write {
            let value = (guest.gpr(access.register) & 0xFF) as u8;
            devices.pic.write(access.port, value);
        } else {
            let Some(value) = devices.pic.read(access.port) else {
                return false;
            };
            write_register(guest, access.register, access.size, u64::from(value));
        }
        return true;
    }
    if access.port == POST_PORT {
        // Diagnostic port: writes are discarded, reads return zero.
        if !access.write {
            write_register(guest, access.register, access.size, 0);
        }
        return true;
    }
    false
}

/// Handles an `RDMSR`/`WRMSR` exit.
///
/// The x2APIC window (`0x800..=0x8FF`) is modeled when the guest actually uses
/// the x2APIC interface: the kernel enables MSR bitmaps for that window, so the
/// exit tells us the guest executed the instruction. `IA32_TSC_DEADLINE`
/// (`0x6E0`) is also routed to the local APIC timer even outside the x2APIC
/// window, because it is the programming interface of the TSC-deadline mode.
/// All other intercepted MSRs are replayed against the per-vCPU [`MsrModel`].
///
/// If the caller provides no model, or if the model rejects the access, the
/// exit is **not** consumed: `Ok(false)` reports it to policy. This path never
/// writes a host MSR, so an unmapped model fails closed. A modelled invalid
/// value (for example a reserved `IA32_EFER` bit) is also reported to policy
/// rather than injected as #GP here; the policy layer owns that decision.
///
/// `ECX` holds the MSR number, `EDX:EAX` the value (`rdmsr` writes them).
fn handle_msr_exit(
    apic: &mut LocalApic,
    devices: &mut Devices,
    view: &mut MemoryView<'_>,
    guest: &mut dyn GuestContext,
) -> Result<bool, EmuError> {
    let Decoded::Msr(access) = view.fetch(guest)? else {
        return Ok(false);
    };
    // RCX (encoding order index 1) selects the MSR.
    let msr = guest.gpr(1) as u32;
    let in_x2apic_window = (X2APIC_MSR_FIRST..=X2APIC_MSR_LAST).contains(&msr);
    let is_tsc_deadline = msr == TSC_DEADLINE_MSR;

    if !in_x2apic_window && !is_tsc_deadline {
        if access.write {
            let value = ((guest.gpr(2) & 0xFFFF_FFFF) << 32) | (guest.gpr(0) & 0xFFFF_FFFF);
            let Some(model) = guest.msr_model() else {
                return Ok(false);
            };
            if model.write(msr, value).is_err() {
                return Ok(false);
            }
            // The caller refreshes the guest state/control block for the
            // returned effect (`MsrWrite`) before the next entry.
        } else {
            let value = {
                let Some(model) = guest.msr_model() else {
                    return Ok(false);
                };
                match model.read(msr) {
                    Ok(value) => value,
                    Err(_) => return Ok(false),
                }
            };
            write_register(guest, 0, 4, value & 0xFFFF_FFFF);
            write_register(guest, 2, 4, value >> 32);
        }
        guest.set_rip(access.next_rip);
        return Ok(true);
    }

    if in_x2apic_window {
        debug_assert!(x2apic::TPR <= msr);
    }
    let eoi_vector = (access.write && in_x2apic_window && msr == x2apic::EOI)
        .then(|| in_service_vector(apic))
        .flatten();
    if access.write {
        let value = ((guest.gpr(2) & 0xFFFF_FFFF) << 32) | (guest.gpr(0) & 0xFFFF_FFFF);
        if is_tsc_deadline {
            apic.set_tsc_deadline(value);
        } else if !apic.x2apic_write(msr, value) {
            return Ok(false);
        }
    } else {
        let value = if is_tsc_deadline {
            Some(apic.tsc_deadline())
        } else {
            apic.x2apic_read(msr)
        };
        let Some(value) = value else {
            return Ok(false);
        };
        // RDMSR replaces the low 32 bits of EDX and EAX only.
        write_register(guest, 0, 4, value & 0xFFFF_FFFF);
        write_register(guest, 2, 4, value >> 32);
    }
    if let Some(vector) = eoi_vector {
        if let Some(reinject) = devices.ioapic.eoi(vector) {
            apic.inject(reinject);
        }
    }
    guest.set_rip(access.next_rip);
    Ok(true)
}

/// Handles an EPT violation on a modeled device page.
///
/// The device pages are intentionally *not* mapped in the second-level tables:
/// the violation is what makes the access visible, and the replay below
/// services it from the device model.
fn handle_mmio_exit(
    devices: &mut Devices,
    apic: &mut LocalApic,
    view: &mut MemoryView<'_>,
    guest: &mut dyn GuestContext,
    qualification: u64,
    address: u64,
) -> Result<bool, EmuError> {
    // Bit 3 of the qualification distinguishes an instruction fetch (1) from
    // a data access (0); only data accesses are modeled here.
    if (qualification >> 3) & 0x1 != 0 {
        return Ok(false);
    }
    let Some(page) = device_page(address) else {
        return Ok(false);
    };

    let Decoded::Memory(access) = view.fetch(guest)? else {
        return Ok(false);
    };
    // Only plain register/memory transfers of 1, 2 or 4 bytes are modeled.
    if !matches!(access.size, 1 | 2 | 4) {
        return Ok(false);
    }
    if !serve_mmio(devices, apic, view, guest, page, &access) {
        return Ok(false);
    }
    guest.set_rip(access.next_rip);
    Ok(true)
}

/// Device page targeted by a guest-physical address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevicePage {
    /// Local APIC MMIO page.
    Apic,
    /// I/O APIC MMIO page.
    IoApic,
    /// Virtio console transport page.
    Console,
    /// Virtio block transport page.
    Blk,
    /// Virtio network transport page.
    Net,
}

/// Identifies the modeled device page containing `address`.
pub fn device_page(address: u64) -> Option<DevicePage> {
    let page = address & !PAGE_OFFSET_MASK;
    if page == APIC_BASE {
        Some(DevicePage::Apic)
    } else if page == IOAPIC_BASE {
        Some(DevicePage::IoApic)
    } else if page == CONSOLE_BASE {
        Some(DevicePage::Console)
    } else if page == BLK_BASE {
        Some(DevicePage::Blk)
    } else if page == NET_BASE {
        Some(DevicePage::Net)
    } else {
        None
    }
}

/// Base of the x86 APIC MSI address window.
pub const MSI_ADDRESS_BASE: u64 = 0xFEE0_0000;
/// Mask selecting the fixed MSI address prefix (bits 31:20).
pub const MSI_ADDRESS_MASK: u64 = 0xFFF0_0000;

/// Decodes an x86 MSI write into `(vector, destination APIC id)`.
///
/// Supported subset (the one a virtio-MSI driver emits):
///
/// - address: low 32 bits only, `0xFEE0_0000` prefix (bits 31:20 = `0xFEE`),
///   destination APIC id in bits 19:12, and all low 12 bits zero (physical
///   destination, no redirect hint); high 32 bits zero;
/// - data: fixed delivery mode, edge trigger and no level/flag bits, i.e.
///   everything above the low vector byte is zero; the vector must be a
///   usable interrupt vector (`>= 16`).
///
/// Returns `None` for any other address/data combination; the caller then
/// ignores the write instead of injecting a bogus vector.
pub fn msi_write(address: u64, data: u32) -> Option<(u8, u8)> {
    if address >> 32 != 0 || address & 0xFFF != 0 {
        return None;
    }
    if address & MSI_ADDRESS_MASK != MSI_ADDRESS_BASE {
        return None;
    }
    if data & 0xFFFF_FF00 != 0 {
        return None;
    }
    let vector = (data & 0xFF) as u8;
    if vector < 16 {
        return None;
    }
    let destination = ((address >> 12) & 0xFF) as u8;
    Some((vector, destination))
}

/// Delivers an MSI write directly to the local APIC (no I/O APIC involved).
///
/// Returns `true` when the address/data pair is in the supported subset and
/// the vector was injected into the local IRR. The destination APIC id is
/// decoded but there is a single modeled LAPIC, so it does not route.
pub fn deliver_msi(apic: &mut LocalApic, address: u64, data: u32) -> bool {
    match msi_write(address, data) {
        Some((vector, _destination)) => {
            apic.inject(vector);
            true
        }
        None => false,
    }
}

/// Returns the highest in-service vector of the local APIC.
fn in_service_vector(apic: &LocalApic) -> Option<u8> {
    for index in (0..8usize).rev() {
        let word = apic.mmio_read(apic_reg::ISR + index * 16);
        if word != 0 {
            return Some((index as u8) * 32 + (31 - word.leading_zeros() as u8));
        }
    }
    None
}

/// Applies a logical level to a device line and injects the vector, if any.
fn set_device_line(devices: &mut Devices, apic: &mut LocalApic, line: usize, asserted: bool) {
    if let Some(vector) = devices.ioapic.set_line_level(line, asserted) {
        apic.inject(vector);
    }
}

/// Applies one decoded memory access to a device page.
fn serve_mmio(
    devices: &mut Devices,
    apic: &mut LocalApic,
    view: &mut MemoryView<'_>,
    guest: &mut dyn GuestContext,
    page: DevicePage,
    access: &MemoryAccess,
) -> bool {
    let offset = (access.address & PAGE_OFFSET_MASK) as usize;
    let shift = ((offset as u32) & 0x3) * 8;
    let mask = width_mask(u64::from(access.size));
    if access.write {
        let value = guest.gpr(access.register);
        let word = read_mmio(devices, apic, page, offset);
        let merged = (word & !((mask as u32) << shift)) | (((value as u32) & mask as u32) << shift);
        write_mmio(devices, apic, view, page, offset, merged);
    } else {
        let word = read_mmio(devices, apic, page, offset);
        let value = (u64::from(word) >> shift) & mask;
        // `register_size == 0` marks a read-only probe (`test`/`cmp` with a
        // memory operand): the device read and its side effects happen, but
        // there is no destination register to update.
        if access.register_size != 0 {
            write_register(guest, access.register, access.size, value);
        }
    }
    true
}

/// Reads the 32-bit device register containing `offset`.
fn read_mmio(devices: &Devices, apic: &LocalApic, page: DevicePage, offset: usize) -> u32 {
    match page {
        DevicePage::Apic => apic.mmio_read(offset & 0xFFF),
        DevicePage::IoApic => devices.ioapic.mmio_read(offset & 0xFF),
        DevicePage::Console => devices.console.read(offset as u32 & 0xFFF),
        DevicePage::Blk => devices.blk.read(offset as u32 & 0xFFF),
        DevicePage::Net => devices.net.read(offset as u32 & 0xFFF),
    }
}

/// Writes the 32-bit device register containing `offset`.
fn write_mmio(
    devices: &mut Devices,
    apic: &mut LocalApic,
    view: &mut MemoryView<'_>,
    page: DevicePage,
    offset: usize,
    value: u32,
) {
    match page {
        DevicePage::Apic => {
            let eoi_vector = (offset & 0xFFF == apic_reg::EOI)
                .then(|| in_service_vector(apic))
                .flatten();
            apic.mmio_write(offset & 0xFFF, value);
            if let Some(vector) = eoi_vector {
                if let Some(reinject) = devices.ioapic.eoi(vector) {
                    apic.inject(reinject);
                }
            }
        }
        DevicePage::IoApic => {
            devices.ioapic.mmio_write(offset & 0xFF, value);
            // A redirection entry may have been unmasked or reprogrammed while
            // its input line was already asserted.
            for pin in 0..PIN_COUNT {
                if let Some(vector) = devices.ioapic.refresh_pin(pin) {
                    apic.inject(vector);
                }
            }
        }
        DevicePage::Console => {
            devices.console.write(offset as u32 & 0xFFF, value, view);
            // The line stays asserted until the guest acknowledges the virtio
            // interrupt status; a level-triggered entry therefore re-raises on
            // EOI while the status is still pending.
            let asserted = devices.console.interrupt_status() != 0;
            set_device_line(devices, apic, CONSOLE_IRQ_LINE, asserted);
        }
        DevicePage::Blk => {
            devices.blk.write(offset as u32 & 0xFFF, value, view);
            let asserted = devices.blk.interrupt_status() != 0;
            set_device_line(devices, apic, BLK_IRQ_LINE, asserted);
        }
        DevicePage::Net => {
            devices.net.write(offset as u32 & 0xFFF, value, view);
            let asserted = devices.net.interrupt_status() != 0;
            set_device_line(devices, apic, NET_IRQ_LINE, asserted);
        }
    }
}

/// Writes `size` bytes of `value` into a general-purpose register, preserving
/// the bits above the access width (as `IN` and `MOV` do).
fn write_register(guest: &mut dyn GuestContext, register: u8, size: u8, value: u64) {
    let mask = width_mask(u64::from(size));
    let current = guest.gpr(register);
    guest.set_gpr(register, (current & !mask) | (value & mask));
}

/// Mask of the low `size` bytes.
const fn width_mask(size: u64) -> u64 {
    match size {
        1 => 0xFF,
        2 => 0xFFFF,
        4 => 0xFFFF_FFFF,
        _ => u64::MAX,
    }
}
