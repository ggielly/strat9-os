//! I/O APIC driver
//!
//! The I/O APIC handles routing of external hardware interrupts to
//! Local APICs. It uses indirect MMIO: write register index to IOREGSEL,
//! then read/write IOWIN.

use crate::{acpi::madt::InterruptSourceOverride, memory};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// Whether the I/O APIC has been initialized
static IOAPIC_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Virtual base address of the I/O APIC MMIO registers
static IOAPIC_BASE_VIRT: AtomicU64 = AtomicU64::new(0);

/// GSI base for this I/O APIC
static IOAPIC_GSI_BASE: AtomicU32 = AtomicU32::new(0);

// I/O APIC register offsets (indirect access)
const IOREGSEL: u64 = 0x00;
const IOWIN: u64 = 0x10;

// I/O APIC registers (selected via IOREGSEL)
const IOAPICID: u32 = 0x00;
const IOAPICVER: u32 = 0x01;
// Redirection table entries start at register 0x10
// Each entry is 64 bits (two 32-bit registers): low at 0x10+2*n, high at 0x10+2*n+1
const IOREDTBL_BASE: u32 = 0x10;

// Redirection entry bit fields
const REDIR_MASK: u64 = 1 << 16;
const REDIR_LEVEL_TRIGGER: u64 = 1 << 15;
const REDIR_ACTIVE_LOW: u64 = 1 << 13;

/// Read an I/O APIC register (indirect access)
///
/// # Safety
/// I/O APIC must be initialized.
unsafe fn ioapic_read(reg: u32) -> u32 {
    let base = IOAPIC_BASE_VIRT.load(Ordering::Relaxed);
    // SAFETY: I/O APIC MMIO is mapped via HHDM
    unsafe {
        core::ptr::write_volatile((base + IOREGSEL) as *mut u32, reg);
        core::ptr::read_volatile((base + IOWIN) as *const u32)
    }
}

/// Write an I/O APIC register (indirect access)
///
/// # Safety
/// I/O APIC must be initialized.
unsafe fn ioapic_write(reg: u32, value: u32) {
    let base = IOAPIC_BASE_VIRT.load(Ordering::Relaxed);
    // SAFETY: I/O APIC MMIO is mapped via HHDM
    unsafe {
        core::ptr::write_volatile((base + IOREGSEL) as *mut u32, reg);
        core::ptr::write_volatile((base + IOWIN) as *mut u32, value);
    }
}

/// Read a 64-bit redirection entry
///
/// # Safety
/// I/O APIC must be initialized, index must be valid.
unsafe fn read_redir(index: u32) -> u64 {
    let reg_low = IOREDTBL_BASE + index * 2;
    let reg_high = IOREDTBL_BASE + index * 2 + 1;
    // SAFETY: caller ensures valid index
    let low = unsafe { ioapic_read(reg_low) } as u64;
    let high = unsafe { ioapic_read(reg_high) } as u64;
    low | (high << 32)
}

/// Write a 64-bit redirection entry
///
/// # Safety
/// I/O APIC must be initialized, index must be valid.
unsafe fn write_redir(index: u32, value: u64) {
    let reg_low = IOREDTBL_BASE + index * 2;
    let reg_high = IOREDTBL_BASE + index * 2 + 1;
    // SAFETY: caller ensures valid index
    unsafe {
        ioapic_write(reg_low, value as u32);
        ioapic_write(reg_high, (value >> 32) as u32);
    }
}

/// Initialize the I/O APIC.
///
/// `phys_addr` is the I/O APIC base physical address from MADT.
/// `gsi_base` is the first GSI handled by this I/O APIC.
pub fn init(phys_addr: u32, gsi_base: u32) {
    let virt_addr = memory::phys_to_virt(phys_addr as u64);
    IOAPIC_BASE_VIRT.store(virt_addr, Ordering::Relaxed);
    IOAPIC_GSI_BASE.store(gsi_base, Ordering::Relaxed);

    // SAFETY: I/O APIC MMIO is mapped via HHDM
    let id = unsafe { ioapic_read(IOAPICID) >> 24 };
    let ver_reg = unsafe { ioapic_read(IOAPICVER) };
    let version = ver_reg & 0xFF;
    let max_redir = ((ver_reg >> 16) & 0xFF) + 1;

    // Mask all interrupts initially
    for i in 0..max_redir {
        // SAFETY: index within max_redir
        unsafe {
            let entry = read_redir(i);
            write_redir(i, entry | REDIR_MASK);
        }
    }

    IOAPIC_INITIALIZED.store(true, Ordering::Relaxed);

    log::info!(
        "I/O APIC: id={}, version={}, {} entries, GSI base={}, virt=0x{:X}",
        id,
        version,
        max_redir,
        gsi_base,
        virt_addr
    );
}

/// Route a GSI to a specific LAPIC and vector.
///
/// `gsi` is the Global System Interrupt number.
/// `lapic_id` is the destination LAPIC ID.
/// `vector` is the interrupt vector (0x20+).
/// `trigger` is the trigger mode (0=edge, 1=level).
/// `polarity` is the polarity (0=active high, 1=active low).
pub fn route_irq(gsi: u32, lapic_id: u32, vector: u8, trigger: u8, polarity: u8) {
    let gsi_base = IOAPIC_GSI_BASE.load(Ordering::Relaxed);
    if gsi < gsi_base {
        log::warn!("I/O APIC: GSI {} below base {}", gsi, gsi_base);
        return;
    }
    let index = gsi - gsi_base;

    // Build redirection entry:
    // [7:0]   vector
    // [10:8]  delivery mode (000 = fixed)
    // [11]    destination mode (0 = physical)
    // [13]    polarity (0 = active high, 1 = active low)
    // [15]    trigger mode (0 = edge, 1 = level)
    // [16]    mask (0 = enabled)
    // [63:56] destination LAPIC ID
    let mut entry: u64 = vector as u64;

    if polarity == 0x03 || polarity == 1 {
        entry |= REDIR_ACTIVE_LOW;
    }
    if trigger == 0x03 || trigger == 1 {
        entry |= REDIR_LEVEL_TRIGGER;
    }

    // Destination in bits [63:56]
    entry |= (lapic_id as u64) << 56;

    // SAFETY: I/O APIC is initialized, index is valid
    unsafe {
        write_redir(index, entry);
    }

    log::debug!(
        "I/O APIC: GSI{} -> vec 0x{:02X}, LAPIC {}, pol={}, trig={}",
        gsi,
        vector,
        lapic_id,
        polarity,
        trigger
    );
}

/// Route a legacy ISA IRQ, applying MADT interrupt source overrides.
///
/// This handles the common case of IRQ0→GSI2 remapping on QEMU q35.
pub fn route_legacy_irq(
    irq: u8,
    lapic_id: u32,
    vector: u8,
    overrides: &[Option<InterruptSourceOverride>],
) {
    // Check if there's a source override for this IRQ
    let (gsi, polarity, trigger) = find_override(irq, overrides);

    route_irq(gsi, lapic_id, vector, trigger, polarity);

    if gsi != irq as u32 {
        log::info!("I/O APIC: IRQ{} remapped to GSI{} (override)", irq, gsi);
    }
}

/// Find the override for a legacy IRQ, returning (gsi, polarity, trigger).
fn find_override(irq: u8, overrides: &[Option<InterruptSourceOverride>]) -> (u32, u8, u8) {
    for ovr in overrides {
        if let Some(ref o) = ovr {
            if o.irq_source == irq {
                return (o.gsi, o.polarity(), o.trigger_mode());
            }
        }
    }
    // No override: GSI == IRQ, ISA defaults (edge, active high)
    (irq as u32, 0, 0)
}

/// Mask a legacy IRQ, resolving MADT overrides to the correct GSI.
pub fn mask_legacy_irq(irq: u8, overrides: &[Option<InterruptSourceOverride>]) {
    let (gsi, _, _) = find_override(irq, overrides);
    mask_irq(gsi);
    log::debug!("I/O APIC: masked legacy IRQ{} (GSI{})", irq, gsi);
}

/// Mask a GSI (disable the interrupt)
pub fn mask_irq(gsi: u32) {
    let gsi_base = IOAPIC_GSI_BASE.load(Ordering::Relaxed);
    if gsi < gsi_base {
        return;
    }
    let index = gsi - gsi_base;
    // SAFETY: I/O APIC is initialized
    unsafe {
        let entry = read_redir(index);
        write_redir(index, entry | REDIR_MASK);
    }
}

/// Unmask a GSI (enable the interrupt)
#[allow(dead_code)]
pub fn unmask_irq(gsi: u32) {
    let gsi_base = IOAPIC_GSI_BASE.load(Ordering::Relaxed);
    if gsi < gsi_base {
        return;
    }
    let index = gsi - gsi_base;
    // SAFETY: I/O APIC is initialized
    unsafe {
        let entry = read_redir(index);
        write_redir(index, entry & !REDIR_MASK);
    }
}
