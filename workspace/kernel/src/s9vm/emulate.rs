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

//! s9vm : in-kernel emulation of a minimal guest device set.
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

use alloc::vec::Vec;

use super::{
    apic::{reg as apic_reg, x2apic, LocalApic, TSC_DEADLINE_MSR},
    decode::{self, Decoded, MemoryAccess, PortAccess},
    dma::{self, Dma},
    exit::ExitClass,
    fdc::{self, FloppyController},
    fwcfg::{self, FwCfg},
    hpet::{self, Hpet},
    ioapic::{IoApic, PIN_COUNT},
    keyboard::{self, KeyboardController},
    msr::MsrModel,
    pci::{self, PciHostBridge},
    pic::Pic,
    pit::{self, Pit},
    rtc::{self, CmosRtc},
    system::{self, SystemControl},
    uart::{self, Uart},
    vga::{self, Vga},
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
/// Readable EPT entry (bit 0) : an EPT walk only succeeds on readable memory.
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
/// QEMU debug console port (`-debugcon`): SeaBIOS' `dprintf` output.
pub const DEBUG_PORT: u16 = 0x402;

/// Interrupt vector the I/O APIC delivers for the 8254 timer line.
pub const PIT_IRQ_VECTOR: u8 = 0x20;
/// Interrupt vector the I/O APIC delivers for the COM1 line.
pub const UART_IRQ_VECTOR: u8 = 0x24;
/// Interrupt vector the I/O APIC delivers for the RTC line.
pub const RTC_IRQ_VECTOR: u8 = 0x28;

/// Global system interrupt an ISA interrupt line is wired to.
///
/// The MADT's interrupt source overrides describe the non-identity wiring
/// (notably `IRQ0 -> GSI2` for the 8254 cascade); every other line is
/// identity-mapped. Raising a device line on the I/O APIC must use the GSI,
/// not the ISA number, or a guest that follows the firmware tables never
/// receives the interrupt.
pub fn isa_gsi(irq: u8) -> usize {
    for entry in &super::acpi::ISA_OVERRIDES {
        if entry.irq_source == irq {
            return entry.gsi as usize;
        }
    }
    usize::from(irq)
}

/// ISA interrupt line wired to a global system interrupt.
///
/// Inverse of [`isa_gsi`]: a device raises a *pin* (a GSI) and the 8259 pair is
/// programmed with the *ISA IRQ* numbers, so the model needs the reverse
/// mapping to drive both interrupt controllers. GSIs above the ISA range
/// (16..) have no 8259 line and return `None`.
pub fn gsi_isa_irq(gsi: usize) -> Option<u8> {
    for entry in &super::acpi::ISA_OVERRIDES {
        if entry.gsi as usize == gsi {
            return Some(entry.irq_source);
        }
    }
    if gsi < 16 {
        Some(gsi as u8)
    } else {
        None
    }
}

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

    /// Guest `RFLAGS`. The direction flag drives string-I/O addressing.
    fn rflags(&self) -> u64 {
        0
    }

    /// Base of the `ES` segment (destination of `INS`).
    fn es_base(&self) -> u64 {
        0
    }

    /// Base of the `DS` segment (source of `OUTS`).
    fn ds_base(&self) -> u64 {
        0
    }

    /// Base of the `CS` segment (instruction fetch).
    fn cs_base(&self) -> u64 {
        0
    }

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
        let ip = guest.rip();
        // Instruction fetch is `CS.base + IP` in real and 16-bit protected
        // mode. SeaBIOS' 16-bit code runs with `CS.base = 0xF0000`, so reading
        // at RIP alone would decode bytes from the wrong address.
        let linear = guest.cs_base().wrapping_add(ip);
        let mut bytes = [0u8; decode::MAX_INSTRUCTION];
        if !self.read(linear, &mut bytes) {
            return Err(EmuError::Unmapped);
        }
        // The decoder's `next_rip` is an IP offset, not a linear address.
        decode::decode(&bytes, ip, |register| guest.gpr(register))
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

/// PCI device slots used by the modeled virtio functions (bus 0).
pub const PCI_CONSOLE_SLOT: u8 = 2;
/// PCI slot of the block function.
pub const PCI_BLK_SLOT: u8 = 3;
/// PCI slot of the network function.
pub const PCI_NET_SLOT: u8 = 4;

/// Device model owned by a world: the chipset devices shared by all its
/// vCPUs. The local APIC is per-vCPU and lives in the vCPU slot; the exit
/// handlers receive it separately.
#[derive(Debug)]
pub struct Devices {
    /// Cascaded 8259A pair.
    pub pic: Pic,
    /// I/O APIC (MMIO page).
    pub ioapic: IoApic,
    /// 8254 programmable interval timer (legacy ports 0x40..=0x43).
    pub pit: Pit,
    /// MC146818 CMOS real-time clock (ports 0x70/0x71).
    pub rtc: CmosRtc,
    /// 16550A serial port, COM1 (ports 0x3F8..=0x3FF).
    pub uart: Uart,
    /// 8042 keyboard controller (ports 0x60/0x64).
    pub keyboard: KeyboardController,
    /// VGA register file and status port (0x3B0..=0x3DF).
    pub vga: Vga,
    /// 8237 DMA controller register files (0x00..=0x0F, 0x81..=0x8F, 0xC0..=0xDF).
    pub dma: Dma,
    /// 82077AA floppy controller and its 1.44 MiB drive.
    pub fdc: FloppyController,
    /// Chipset system-control ports (`0x92` A20, `0xCF9` reset).
    pub system: SystemControl,
    /// QEMU `fw_cfg` selector/data pair.
    pub fw_cfg: FwCfg,
    /// SeaBIOS `dprintf` output captured from the QEMU debug port `0x402`.
    debug_con: Vec<u8>,
    /// PCI host bridge: configuration mechanism #1 and the virtio functions
    /// the guest discovers through it (no MSI generation yet).
    pub pci: PciHostBridge,
    /// High-precision event timer (MMIO page at `0xFED0_0000`).
    pub hpet: Hpet,
    /// Virtio console (MMIO transport page).
    pub console: VirtioConsole,
    /// Virtio block device (MMIO transport page).
    pub blk: VirtioBlk,
    /// Virtio network device (MMIO transport page).
    pub net: VirtioNet,
    /// Deliver ISA interrupt lines to the 8259 pair only.
    ///
    /// A PC firmware (SeaBIOS, a DOS ROM) installs its `INT 08h`/`INT 0Eh`
    /// handlers and expects the legacy vectors `0x08..=0x0F`. The local-APIC
    /// delivery path reserves vectors below `0x10`, so such a guest needs the
    /// runner to acknowledge the 8259 and inject the programmed vector itself.
    /// When this flag is set, [`set_device_line`] no longer injects the I/O
    /// APIC vector and [`flush_pic`] leaves the request in the `IRR` for the
    /// runner.
    legacy_pic: bool,
    /// One-shot delay before the next legacy IRQ delivery.
    ///
    /// The floppy controller completes a command instantly in the model, while
    /// real hardware takes long enough for SeaBIOS to enter `floppy_wait_irq`
    /// and clear its BDA flag before the interrupt arrives. One preemption
    /// interval of grace reproduces that ordering; the request stays in the
    /// 8259 `IRR` meanwhile.
    legacy_irq_grace: u8,
}

impl Devices {
    /// Creates the device model.
    ///
    /// The I/O APIC redirection table is pre-programmed for the device lines
    /// (`CONSOLE_IRQ_LINE`, `BLK_IRQ_LINE`, `NET_IRQ_LINE`) with the default
    /// vectors and unmasked; the guest may reprogram them, and the kernel
    /// reads the table when a device raises its line.
    pub fn new() -> Self {
        Self::new_with_virtio(true)
    }

    /// Creates the device model of a **legacy PC** with no PCI virtio
    /// functions.
    ///
    /// A real firmware enumerates every PCI function and attaches the drivers
    /// it knows; the s9vm virtio functions are modern virtio-pci devices, but
    /// their BARs and capabilities are not needed to boot a floppy. Keeping
    /// them out of the SeaBIOS world removes an entire probe path from the
    /// firmware boot.
    pub fn new_legacy() -> Self {
        Self::new_with_virtio(false)
    }

    fn new_with_virtio(virtio: bool) -> Self {
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
        // Legacy devices, on the global system interrupts the MADT advertises
        // (IRQ0 -> GSI2 for the 8254 cascade, IRQ4 serial, IRQ8 RTC). A guest
        // that does not reprogram the redirection table still receives them;
        // any real OS overrides these entries with its own policy.
        let pit_pin = isa_gsi(pit::IRQ_LINE);
        ioapic.set_pin_mode(pit_pin, PIT_IRQ_VECTOR, false, false, false);
        let uart_pin = isa_gsi(uart::IRQ_LINE);
        ioapic.set_pin_mode(uart_pin, UART_IRQ_VECTOR, false, true, false);
        let rtc_pin = isa_gsi(rtc::IRQ_LINE);
        ioapic.set_pin_mode(rtc_pin, RTC_IRQ_VECTOR, false, true, false);
        // PCI: one host bridge and one virtio function per modeled device. The
        // BARs start unprogrammed (the guest assigns them, as it does on real
        // firmware), so an MMIO window only becomes visible once the guest has
        // written the base address.
        let mut pci = PciHostBridge::new();
        if virtio {
            let _ = pci.add_virtio(PCI_CONSOLE_SLOT, pci::virtio_device_type::CONSOLE);
            let _ = pci.add_virtio(PCI_BLK_SLOT, pci::virtio_device_type::BLOCK);
            let _ = pci.add_virtio(PCI_NET_SLOT, pci::virtio_device_type::NET);
        }
        Self {
            pic: Pic::new(),
            ioapic,
            pit: Pit::new(),
            rtc: CmosRtc::new(),
            uart: Uart::new(),
            keyboard: KeyboardController::new(),
            vga: Vga::new(),
            dma: Dma::new(),
            fdc: FloppyController::new(),
            system: SystemControl::new(),
            fw_cfg: FwCfg::new(),
            debug_con: Vec::new(),
            pci,
            hpet: Hpet::new(),
            console: VirtioConsole::new(),
            blk: VirtioBlk::new(64 * 1024),
            net: VirtioNet::new(),
            legacy_pic: false,
            legacy_irq_grace: 0,
        }
    }

    /// Loads the floppy image the controller serves.
    pub fn load_floppy(&mut self, image: &[u8]) {
        self.fdc.load_image(image);
    }

    /// Registers a `fw_cfg` file for the firmware (for example a VGA option
    /// ROM under `vgaroms/vgabios-stdvga.bin`).
    pub fn add_fw_cfg_file(&mut self, name: &str, data: &[u8]) {
        let _ = self.fw_cfg.add_file(name, data);
    }

    /// Takes the bytes the firmware wrote to the QEMU debug console.
    pub fn drain_debug_con(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.debug_con)
    }

    /// Selects legacy 8259 interrupt delivery (see the field documentation).
    pub fn set_legacy_pic(&mut self, enabled: bool) {
        self.legacy_pic = enabled;
    }

    /// True when legacy 8259 delivery is selected.
    pub const fn legacy_pic(&self) -> bool {
        self.legacy_pic
    }

    /// Delays the next legacy IRQ delivery by one preemption interval.
    pub fn defer_legacy_irq(&mut self) {
        self.legacy_irq_grace = 1;
    }

    /// Consumes one legacy-IRQ grace interval. Returns true while delivery
    /// must still be postponed.
    pub fn legacy_irq_deferred(&mut self) -> bool {
        if self.legacy_irq_grace == 0 {
            return false;
        }
        self.legacy_irq_grace = 0;
        true
    }

    /// True if the port belongs to a device modeled here.
    pub fn handles_port(port: u16) -> bool {
        port_kind(port).is_some()
    }
}

/// True if `port` is one of the PCI configuration mechanism #1 registers.
/// Device class serving one legacy I/O port.
///
/// The kernel classifies an exiting port once, instead of asking every device
/// model in turn whether the port belongs to it. The table is also what keeps
/// the two overlapping legacy ranges unambiguous: the system-control port
/// `0xCF9` lives inside the PCI configuration window and must win.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortKind {
    /// Cascaded 8259A pair.
    Pic,
    /// 8254 programmable interval timer.
    Pit,
    /// MC146818 CMOS clock.
    Rtc,
    /// 16550A serial port.
    Uart,
    /// 8042 keyboard controller.
    Keyboard,
    /// VGA register file.
    Vga,
    /// 8237 DMA controller pair.
    Dma,
    /// 82077 floppy controller.
    Fdc,
    /// A20 and reset control.
    System,
    /// QEMU firmware configuration interface.
    FwCfg,
    /// PCI configuration mechanism #1.
    Pci,
    /// Platform POST diagnostic port.
    Post,
    /// Firmware debug console port.
    Debug,
}

/// Classifies one legacy I/O port (`None` when no device model serves it).
pub const fn port_kind(port: u16) -> Option<PortKind> {
    match port {
        0x20 | 0x21 | 0xA0 | 0xA1 => Some(PortKind::Pic),
        0x40..=0x43 => Some(PortKind::Pit),
        0x70 | 0x71 => Some(PortKind::Rtc),
        0x3F8..=0x3FF => Some(PortKind::Uart),
        0x60 | 0x64 => Some(PortKind::Keyboard),
        // 0x3B0..=0x3BF (mono) and 0x3C0..=0x3DF (colour) are adjacent.
        0x3B0..=0x3DF => Some(PortKind::Vga),
        0x00..=0x0F | 0x81..=0x8F | 0xC0..=0xDF => Some(PortKind::Dma),
        0x3F0..=0x3F5 | 0x3F7 => Some(PortKind::Fdc),
        // `0xCF9` is inside the PCI window below: it must be matched first.
        0x92 | 0xCF9 => Some(PortKind::System),
        0x510 | 0x511 => Some(PortKind::FwCfg),
        0xCF8..=0xCFF => Some(PortKind::Pci),
        0x80 => Some(PortKind::Post),
        // QEMU firmware debug console (not the DOS `0xE9` marker port, which
        // the DOS runner intercepts before the device model).
        0x402 => Some(PortKind::Debug),
        _ => None,
    }
}

pub fn handles_pci_port(port: u16) -> bool {
    (pci::CONFIG_ADDRESS..pci::CONFIG_ADDRESS + 4).contains(&port)
        || (pci::CONFIG_DATA..pci::CONFIG_DATA + 4).contains(&port)
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
/// makes the processor drop it : VM-entry interruption delivery is suppressed,
/// but the vector was already taken out of the APIC, so it is lost. The
/// execution loop must arm interrupt-window exiting instead, so the vector is
/// injected as soon as the shadow clears.
pub const fn interrupt_deliverable(rflags_if: bool, interruptibility: u32) -> bool {
    rflags_if
        && interruptibility & (INTERRUPTIBILITY_STI_BLOCKING | INTERRUPTIBILITY_MOV_SS_BLOCKING)
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
    handle_exit_with_length(
        devices,
        apic,
        view,
        guest,
        class,
        qualification,
        guest_physical_address,
        0,
    )
}

/// [`handle_exit`] with the instruction length needed by string port I/O.
pub fn handle_exit_with_length(
    devices: &mut Devices,
    apic: &mut LocalApic,
    view: &mut MemoryView<'_>,
    guest: &mut dyn GuestContext,
    class: ExitClass,
    qualification: u64,
    guest_physical_address: u64,
    instruction_length: u32,
) -> Result<bool, EmuError> {
    match class {
        ExitClass::IoPort => handle_port_exit(
            devices,
            apic,
            view,
            guest,
            qualification,
            instruction_length,
        ),
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

/// Maximum elements moved in one replayed `INS`/`OUTS` instruction.
///
/// A firmware file transfer is at most a few hundred KiB; a guest asking for
/// billions of iterations would stall the host inside a single exit (the run
/// loop only regains control between instructions).
const MAX_STRING_IO_ELEMENTS: u64 = 1 << 20;

/// Handles an I/O instruction exit (`IN`/`OUT`).
fn handle_port_exit(
    devices: &mut Devices,
    apic: &mut LocalApic,
    view: &mut MemoryView<'_>,
    guest: &mut dyn GuestContext,
    qualification: u64,
    instruction_length: u32,
) -> Result<bool, EmuError> {
    // Exit qualification: bits 2:0 = size - 1, bit 3 = direction (1 = IN),
    // bits 5:4 = string/repeated, bits 31:16 = port.
    let string = (qualification >> 4) & 0x1 != 0;
    let repeated = (qualification >> 5) & 0x1 != 0;
    let port = ((qualification >> 16) & 0xFFFF) as u16;
    if string || repeated {
        return handle_string_port(
            devices,
            apic,
            view,
            guest,
            port,
            qualification,
            repeated,
            instruction_length,
        );
    }
    // Some processors/VMM combinations report `rep insb`/`rep insw` with the
    // string bits clear. That quirk is what the firmware file transfer depends
    // on (SeaBIOS reads the VGA ROM through `fw_cfg` with `rep insb`), so the
    // encoding is only inspected for that data port. Every other scalar
    // access is described completely by the exit qualification: inspecting the
    // instruction bytes here would fetch and decode them on every legacy port
    // exit, which is the dominant cost of a DOS boot.
    if port == fwcfg::DATA_PORT {
        let mut op = [0u8; 3];
        if view.read(guest.cs_base().wrapping_add(guest.rip()), &mut op) {
            let mut index = 0usize;
            let rep = op[0] == 0xF3;
            if rep {
                index += 1;
            }
            let mut size = 1u8;
            if index < op.len() && op[index] == 0x66 {
                size = 2;
                index += 1;
            }
            if index < op.len() && matches!(op[index], 0x6C..=0x6F) {
                let is_in = matches!(op[index], 0x6C | 0x6D);
                let synthesized = (qualification & !0x3F)
                    | u64::from(size - 1)
                    | (u64::from(is_in) << 3)
                    | 0x10
                    | if rep { 0x20 } else { 0 };
                return handle_string_port(
                    devices,
                    apic,
                    view,
                    guest,
                    port,
                    synthesized,
                    rep,
                    instruction_length,
                );
            }
        }
    }
    if !Devices::handles_port(port) {
        return Ok(false);
    }
    let size = ((qualification & 0x7) + 1) as u8;
    if !matches!(size, 1 | 2 | 4) {
        return Ok(false);
    }
    let is_in = (qualification >> 3) & 0x1 != 0;
    if instruction_length == 0 {
        // No usable instruction length (some callers synthesise exits): fall
        // back to decoding the instruction so the guest still advances.
        let Decoded::Port(access) = view.fetch(guest)? else {
            return Ok(false);
        };
        if access.port != port || access.size != size || access.write == is_in {
            return Ok(false);
        }
        if !serve_port(devices, apic, view, guest, &access) {
            return Ok(false);
        }
        guest.set_rip(access.next_rip);
        return Ok(true);
    }
    // Scalar IN/OUT always uses the accumulator; the qualification gives the
    // size and direction, so no instruction decode is needed.
    let access = PortAccess {
        port,
        size,
        write: !is_in,
        register: 0,
        next_rip: guest.rip().wrapping_add(u64::from(instruction_length)),
    };
    if !serve_port(devices, apic, view, guest, &access) {
        return Ok(false);
    }
    guest.set_rip(access.next_rip);
    Ok(true)
}

/// Handles a repeated or single `INS`/`OUTS` string transfer.
///
/// String port I/O is the transport of the QEMU `fw_cfg` interface: SeaBIOS
/// reads firmware files with `rep insb`, so the replay must move `RCX`
/// elements between the port and `ES:DI`/`DS:SI`, honouring the direction flag.
/// The port itself is served by the normal device model, one element at a
/// time, so side effects (a serial byte, a `fw_cfg` cursor) happen in order.
fn handle_string_port(
    devices: &mut Devices,
    apic: &mut LocalApic,
    view: &mut MemoryView<'_>,
    guest: &mut dyn GuestContext,
    port: u16,
    qualification: u64,
    repeated: bool,
    instruction_length: u32,
) -> Result<bool, EmuError> {
    if !Devices::handles_port(port) {
        return Ok(false);
    }
    let size = ((qualification & 0x7) + 1) as u8;
    if !matches!(size, 1 | 2 | 4) {
        return Ok(false);
    }
    let is_in = (qualification >> 3) & 0x1 != 0;
    let mut remaining = if repeated { guest.gpr(1) } else { 1 };
    if remaining > MAX_STRING_IO_ELEMENTS {
        return Ok(false);
    }
    let negative = guest.rflags() & (1 << 10) != 0;
    let step = i64::from(size) * if negative { -1 } else { 1 };
    let base = if is_in {
        guest.es_base()
    } else {
        guest.ds_base()
    };
    let mut index = if is_in { guest.gpr(7) } else { guest.gpr(6) };

    while remaining != 0 {
        let address = base.wrapping_add(index);
        if is_in {
            let mut value = 0u64;
            if port == fwcfg::DATA_PORT {
                if size != 1 {
                    return Ok(false);
                }
                value = u64::from(devices.fw_cfg.read_byte());
            } else {
                let access = PortAccess {
                    port,
                    size,
                    write: false,
                    register: 0,
                    next_rip: guest.rip(),
                };
                if !serve_port(devices, apic, view, guest, &access) {
                    return Ok(false);
                }
                value = guest.gpr(0);
            }
            let bytes = value.to_le_bytes();
            if !view.write(address, &bytes[..usize::from(size)]) {
                return Ok(false);
            }
        } else {
            let mut bytes = [0u8; 8];
            if !view.read(address, &mut bytes[..usize::from(size)]) {
                return Ok(false);
            }
            let previous = guest.gpr(0);
            let mask: u64 = match size {
                1 => 0xFF,
                2 => 0xFFFF,
                _ => 0xFFFF_FFFF,
            };
            let value = u64::from_le_bytes(bytes);
            guest.set_gpr(0, (previous & !mask) | (value & mask));
            let access = PortAccess {
                port,
                size,
                write: true,
                register: 0,
                next_rip: guest.rip(),
            };
            if !serve_port(devices, apic, view, guest, &access) {
                return Ok(false);
            }
        }
        index = (index as i64).wrapping_add(step) as u64;
        remaining -= 1;
    }
    if is_in {
        guest.set_gpr(7, index);
    } else {
        guest.set_gpr(6, index);
    }
    if repeated {
        guest.set_gpr(1, 0);
    }
    let length = if instruction_length == 0 {
        2
    } else {
        instruction_length
    };
    guest.set_rip(guest.rip().wrapping_add(u64::from(length)));
    Ok(true)
}

/// Applies one decoded port access to the device model.
///
/// Byte-wide legacy devices (8259, 8254, CMOS RTC, 16550) are served here;
/// device interrupt lines are re-evaluated after the access so a guest that
/// unmasks an interrupt sees it without another exit.
fn serve_port(
    devices: &mut Devices,
    apic: &mut LocalApic,
    view: &mut MemoryView<'_>,
    guest: &mut dyn GuestContext,
    access: &PortAccess,
) -> bool {
    // Classify the port once. `handle_port_exit` and `handle_string_port`
    // already called `Devices::handles_port`, so probing every device model
    // again here re-derived the same answer on every legacy exit — the table is
    // now the only source of that decision.
    let kind = match port_kind(access.port) {
        Some(kind) => kind,
        None => return false,
    };
    if kind == PortKind::Pic {
        // The 8259A pair is byte-wide; a wider access is not PC-compatible.
        if access.size != 1 {
            return false;
        }
        if access.write {
            let value = (guest.gpr(access.register) & 0xFF) as u8;
            devices.pic.write(access.port, value);
            // Unmasking a line or ending an interrupt can make a pending
            // request deliverable: re-evaluate the cascade immediately so the
            // guest sees it without waiting for another device event.
            flush_pic(devices, apic);
        } else {
            let Some(value) = devices.pic.read(access.port) else {
                return false;
            };
            write_register(guest, access.register, access.size, u64::from(value));
        }
        return true;
    }
    if kind == PortKind::Pit {
        // The 8254 is byte-wide.
        if access.size != 1 {
            return false;
        }
        let offset = u32::from(access.port - pit::BASE_PORT);
        if access.write {
            let value = (guest.gpr(access.register) & 0xFF) as u8;
            devices.pit.write(offset, value);
        } else {
            let value = devices.pit.read(offset);
            write_register(guest, access.register, access.size, u64::from(value));
        }
        return true;
    }
    if kind == PortKind::Rtc {
        // The CMOS index/data ports are byte-wide.
        if access.size != 1 {
            return false;
        }
        if access.port == rtc::INDEX_PORT {
            if access.write {
                devices
                    .rtc
                    .write_index((guest.gpr(access.register) & 0xFF) as u8);
            } else {
                // The index port is write-only on the real chip.
                write_register(guest, access.register, access.size, 0xFF);
            }
        } else if access.write {
            devices
                .rtc
                .write_data((guest.gpr(access.register) & 0xFF) as u8);
        } else {
            let value = devices.rtc.read_data();
            write_register(guest, access.register, access.size, u64::from(value));
        }
        return true;
    }
    if kind == PortKind::Uart {
        // COM1 is byte-wide.
        if access.size != 1 {
            return false;
        }
        let offset = u32::from(access.port - uart::BASE_PORT);
        if access.write {
            let value = (guest.gpr(access.register) & 0xFF) as u8;
            devices.uart.write(offset, value);
        } else {
            let value = devices.uart.read(offset);
            write_register(guest, access.register, access.size, u64::from(value));
        }
        // The UART interrupt line is level-triggered: it stays asserted until
        // the driver services the source, so mirror the model's line state.
        set_device_line(
            devices,
            apic,
            isa_gsi(uart::IRQ_LINE),
            devices.uart.irq_asserted(),
        );
        return true;
    }
    if kind == PortKind::Keyboard {
        // The 8042 is byte-wide.
        if access.size != 1 {
            return false;
        }
        if access.write {
            devices
                .keyboard
                .write(access.port, (guest.gpr(access.register) & 0xFF) as u8);
        } else {
            let Some(value) = devices.keyboard.read(access.port) else {
                return false;
            };
            write_register(guest, access.register, access.size, u64::from(value));
        }
        return true;
    }
    if kind == PortKind::Vga {
        // VGA registers are byte-wide.
        if access.size != 1 {
            return false;
        }
        if access.write {
            devices
                .vga
                .write(access.port, (guest.gpr(access.register) & 0xFF) as u8);
        } else {
            let Some(value) = devices.vga.read(access.port) else {
                return false;
            };
            write_register(guest, access.register, access.size, u64::from(value));
        }
        return true;
    }
    if kind == PortKind::Dma {
        // The 8237 register files are byte-wide.
        if access.size != 1 {
            return false;
        }
        if access.write {
            devices
                .dma
                .write(access.port, (guest.gpr(access.register) & 0xFF) as u8);
        } else {
            let Some(value) = devices.dma.read(access.port) else {
                return false;
            };
            write_register(guest, access.register, access.size, u64::from(value));
        }
        return true;
    }
    if kind == PortKind::Fdc {
        // The 82077 interface is byte-wide.
        if access.size != 1 {
            return false;
        }
        if access.write {
            let event = devices
                .fdc
                .write(access.port, (guest.gpr(access.register) & 0xFF) as u8);
            match event {
                fdc::FdcEvent::None => {}
                fdc::FdcEvent::Irq => {
                    devices.fdc.take_irq();
                    devices.pic.raise(fdc::IRQ_LINE);
                }
                fdc::FdcEvent::Transfer(transfer) => {
                    perform_floppy_dma(devices, view, transfer);
                    devices.fdc.take_irq();
                    devices.pic.raise(fdc::IRQ_LINE);
                }
            }
        } else {
            let Some(value) = devices.fdc.read(access.port) else {
                return false;
            };
            write_register(guest, access.register, access.size, u64::from(value));
        }
        return true;
    }
    if kind == PortKind::System {
        // The system-control ports are byte-wide.
        if access.size != 1 {
            return false;
        }
        if access.write {
            devices
                .system
                .write(access.port, (guest.gpr(access.register) & 0xFF) as u8);
        } else {
            let Some(value) = devices.system.read(access.port) else {
                return false;
            };
            write_register(guest, access.register, access.size, u64::from(value));
        }
        return true;
    }
    if kind == PortKind::FwCfg {
        if access.port == fwcfg::CTL_PORT {
            // The selector is written with `outw` by SeaBIOS; accept a byte
            // access too, like the QEMU device.
            if access.size > 2 {
                return false;
            }
            if access.write {
                devices
                    .fw_cfg
                    .select((guest.gpr(access.register) & 0xFFFF) as u16);
            } else {
                write_register(
                    guest,
                    access.register,
                    access.size,
                    u64::from(devices.fw_cfg.selector()),
                );
            }
            return true;
        }
        if access.size != 1 {
            return false;
        }
        if access.write {
            devices
                .fw_cfg
                .write_byte((guest.gpr(access.register) & 0xFF) as u8);
        } else {
            let value = devices.fw_cfg.read_byte();
            write_register(guest, access.register, access.size, u64::from(value));
        }
        return true;
    }
    if kind == PortKind::Pci {
        // Configuration mechanism #1: one 32-bit CAM register and one 32-bit
        // data register. The model also accepts byte and word accesses on the
        // data register (some early probes use them).
        if access.write {
            let value = guest.gpr(access.register) as u32;
            if !devices.pci.io_write(access.port, access.size, value) {
                return false;
            }
        } else {
            let Some(value) = devices.pci.io_read(access.port, access.size) else {
                return false;
            };
            write_register(guest, access.register, access.size, u64::from(value));
        }
        return true;
    }
    if kind == PortKind::Post {
        // Diagnostic port: writes are discarded, reads return zero.
        if !access.write {
            write_register(guest, access.register, access.size, 0);
        }
        return true;
    }
    if kind == PortKind::Debug {
        // QEMU debug console: keep the firmware's `dprintf` output for the
        // runner diagnostics; reads return zero.
        if access.write {
            devices
                .debug_con
                .push((guest.gpr(access.register) & 0xFF) as u8);
        } else {
            write_register(guest, access.register, access.size, 0);
        }
        return true;
    }
    false
}

/// Performs the DMA channel-2 transfer a floppy command requested.
///
/// The controller decoded the CHS parameters and queued its result bytes; the
/// physical transfer is the caller's job. The 8237 channel gives the 24-bit
/// address and the byte count (minus one); a firmware transfer is always
/// sector-aligned and never crosses a 64 KiB boundary, which SeaBIOS verifies
/// before programming the channel.
fn perform_floppy_dma(
    devices: &mut Devices,
    view: &mut MemoryView<'_>,
    transfer: fdc::FdcTransfer,
) {
    let Some(channel) = devices.dma.channel(dma::FLOPPY_CHANNEL) else {
        return;
    };
    let address = channel.physical_address() as u64;
    let capacity = channel
        .remaining()
        .min(u32::from(transfer.sectors) * fdc::SECTOR_SIZE as u32);
    let mut sector = [0u8; fdc::SECTOR_SIZE];
    let mut done: u32 = 0;
    for index in 0..u32::from(transfer.sectors) {
        if done + fdc::SECTOR_SIZE as u32 > capacity {
            break;
        }
        let lba = transfer.lba + u64::from(index);
        let offset = address + u64::from(done);
        let moved = if transfer.write {
            view.read_physical(offset, &mut sector) && devices.fdc.write_sector(lba, &sector)
        } else {
            devices.fdc.read_sector(lba, &mut sector) && view.write_physical(offset, &sector)
        };
        if !moved {
            break;
        }
        done += fdc::SECTOR_SIZE as u32;
    }
    devices.dma.complete(dma::FLOPPY_CHANNEL, done);
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
    let Decoded::Memory(access) = view.fetch(guest)? else {
        return Ok(false);
    };
    let Some(page) = device_page(address) else {
        // A PCI function BAR is not a fixed device page: resolve it through
        // the bridge's live placement map, which only contains the BARs the
        // guest programmed.
        if !serve_pci_mmio(devices, guest, &access) {
            return Ok(false);
        }
        guest.set_rip(access.next_rip);
        return Ok(true);
    };
    // The HPET has 64-bit registers: serve it before the 32-bit merge path.
    if page == DevicePage::Hpet {
        if !serve_hpet(devices, guest, &access) {
            return Ok(false);
        }
        guest.set_rip(access.next_rip);
        return Ok(true);
    }
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

/// Applies one decoded memory access to the high-precision event timer.
///
/// The model exposes 32- and 64-bit registers; an unaligned access or any other
/// width is outside the subset and is reported to policy.
fn serve_hpet(devices: &mut Devices, guest: &mut dyn GuestContext, access: &MemoryAccess) -> bool {
    let offset = (access.address & PAGE_OFFSET_MASK) as u16;
    if access.address % u64::from(access.size) != 0 {
        return false;
    }
    if access.write {
        let value = guest.gpr(access.register);
        devices.hpet.write(offset, access.size, value)
    } else {
        let Some(value) = devices.hpet.read(offset, access.size) else {
            return false;
        };
        write_register(guest, access.register, access.size, value);
        true
    }
}

/// Applies one decoded memory access to a PCI function BAR.
///
/// The access must be naturally aligned for its size: the configuration and
/// transport windows are made of 32-bit registers, and a misaligned access is
/// outside the modeled subset (the exit is reported to policy).
fn serve_pci_mmio(
    devices: &mut Devices,
    guest: &mut dyn GuestContext,
    access: &MemoryAccess,
) -> bool {
    if access.address % u64::from(access.size) != 0 {
        return false;
    }
    if access.write {
        let value = guest.gpr(access.register) as u32;
        devices.pci.mmio_write(access.address, access.size, value)
    } else {
        let Some(value) = devices.pci.mmio_read(access.address, access.size) else {
            return false;
        };
        write_register(guest, access.register, access.size, u64::from(value));
        true
    }
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
    /// High-precision event timer page.
    Hpet,
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
    } else if page == hpet::BASE_GPA {
        Some(DevicePage::Hpet)
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
///
/// A device pin is wired to the I/O APIC and, on a PC chipset, to the 8259 pair
/// as well. Both controllers are driven so a guest that keeps the legacy pair
/// (or that has not reprogrammed the I/O APIC yet) still receives the
/// interrupt; the 8259 only delivers when it is initialised and unmasked, so a
/// guest in APIC mode : which masks the pair : is unaffected.
pub(crate) fn set_device_line(
    devices: &mut Devices,
    apic: &mut LocalApic,
    line: usize,
    asserted: bool,
) {
    if devices.legacy_pic {
        // A legacy firmware owns the 8259 vectors (`0x08..=0x0F`), which the
        // local APIC never delivers. Drive the pair only; the runner
        // acknowledges it and injects the programmed vector directly.
        if let Some(irq) = gsi_isa_irq(line) {
            if asserted {
                devices.pic.raise(irq);
            } else {
                devices.pic.lower(irq);
            }
        }
        return;
    }
    if let Some(vector) = devices.ioapic.set_line_level(line, asserted) {
        apic.inject(vector);
    }
    let Some(irq) = gsi_isa_irq(line) else {
        return;
    };
    if asserted {
        devices.pic.raise(irq);
        flush_pic(devices, apic);
    } else {
        devices.pic.lower(irq);
    }
}

/// Delivers at most one pending 8259 request to the local APIC.
///
/// The 8259 asserts its `INT` output while a request is pending; the processor
/// acknowledges it during the interrupt cycle, which is the moment the model
/// must move the request from the `IRR` to the `ISR` and hand the vector to the
/// local APIC. Only one vector is taken per call: the local APIC `IRR` is what
/// queues the rest, and taking more would acknowledge requests the guest has
/// not seen yet. Delivery is skipped while a request is already in service, so
/// a level-triggered line that stays high cannot be acknowledged twice before
/// the guest end-of-interrupt.
pub(crate) fn flush_pic(devices: &mut Devices, apic: &mut LocalApic) {
    if devices.legacy_pic {
        // The legacy runner owns delivery: it must see the request in the IRR
        // to inject the `0x08..=0x0F` vector itself.
        return;
    }
    if devices.pic.master().isr() != 0 || devices.pic.slave().isr() != 0 {
        return;
    }
    if let Some(vector) = devices.pic.acknowledge() {
        apic.inject(vector);
    }
}

/// Raises then lowers `pin` on the I/O APIC, delivering exactly one edge.
///
/// Used by the 8254 timer, whose channel-0 expiry is a pulse: an edge-triggered
/// redirection entry accepts it on the rising transition only, and a
/// level-triggered entry latches it in the remote-IRR and is serviced by the
/// guest's EOI.
pub fn pulse_device_line(devices: &mut Devices, apic: &mut LocalApic, pin: usize) {
    set_device_line(devices, apic, pin, true);
    set_device_line(devices, apic, pin, false);
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
        // The HPET has 32/64-bit registers and is served before this path.
        DevicePage::Hpet => 0,
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
        // The HPET has 32/64-bit registers and is served before this path.
        DevicePage::Hpet => {}
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
