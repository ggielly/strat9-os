//! MSI / MSI-X interrupt support for PCI devices (x86_64).
//!
//! MSI (Message Signalled Interrupts) bypass the I/O APIC entirely:
//! the device writes a message directly to the LAPIC's system bus.
//!
//! ## Reference
//! - PCI Local Bus Spec 3.0, §6.8
//! - Intel 64 and IA-32 SDM, Vol. 3A, §10.11

use crate::{arch::x86_64::pci::*, hardware::pci_client::PciDevice};

/// Try to enable MSI on `pci_dev` with `vector`.
///
/// Returns `true` on success, `false` if MSI is not supported or
/// programming failed.  On success the device will deliver interrupts
/// via MSI instead of legacy INTx.
///
/// # Note
///
/// This does **not** clear the INTx_DISABLE bit in the PCI command
/// register.  The caller should set `COMMAND.INTx_DISABLE` after
/// enabling MSI to prevent the device from also asserting its legacy
/// interrupt pin.
fn enable_msi(pci_dev: &PciDevice, vector: u8) -> bool {
    let Some(cap) = pci_dev.msi_cap_offset() else {
        return false;
    };

    let ctrl = pci_dev.read_config_u16(cap + msi_cap::CONTROL);
    let addr64 = (ctrl & msi_ctrl::ADDR64) != 0;
    let lapic_id = crate::arch::x86_64::apic::lapic_id();

    // Message Address = 0xFEE0_0000 | (LAPIC ID << 12)
    let msg_addr = MSI_ADDR_BASE | (lapic_id << MSI_ADDR_DEST_SHIFT);

    // Message Data = vector (fixed delivery, edge-triggered)
    let msg_data = vector as u16;

    // Program the MSI registers (all 32-bit writes).
    pci_dev.write_config_u32(cap + msi_cap::ADDR_LOW, msg_addr);

    if addr64 {
        // 64-bit: upper addr at +8, data at +12
        pci_dev.write_config_u32(cap + msi_cap::ADDR_HIGH, 0);
        pci_dev.write_config_u16(cap + msi_cap::DATA + 4, msg_data);
    } else {
        // 32-bit: data at +8
        pci_dev.write_config_u16(cap + msi_cap::DATA, msg_data);
    }

    // Enable MSI: set bit 0 in the control register.
    // Keep Multi-Message Enable at 0 (single vector).
    let new_ctrl = ctrl & !msi_ctrl::MME_MASK | msi_ctrl::ENABLE;
    pci_dev.write_config_u16(cap + msi_cap::CONTROL, new_ctrl);

    // Verify that MSI Enable stuck.
    let verify = pci_dev.read_config_u16(cap + msi_cap::CONTROL);
    if verify & msi_ctrl::ENABLE == 0 {
        log::warn!(
            "MSI: enable bit did not stick on {:04x}:{:04x}",
            pci_dev.vendor_id,
            pci_dev.device_id
        );
        return false;
    }

    // Disable legacy INTx in the PCI command register so the device does
    // not assert its interrupt pin alongside the MSI message.
    let mut cmd = pci_dev.read_config_u16(config::COMMAND);
    cmd |= command::INTERRUPT_DISABLE;
    pci_dev.write_config_u16(config::COMMAND, cmd);

    log::info!(
        "MSI: enabled on {:04x}:{:04x} → vector {:#x} ({} addr)",
        pci_dev.vendor_id,
        pci_dev.device_id,
        vector,
        if addr64 { "64-bit" } else { "32-bit" },
    );
    true
}

/// Try to enable MSI-X on `pci_dev` with `vector` using the first table entry.
///
/// MSI-X requires access to the device's **BAR space** for the vector table.
/// This function maps the table BAR if not already mapped, programs the
/// first table entry with the MSI message address/data, then enables MSI-X.
///
/// Returns `true` on success, `false` if MSI-X is not supported or
/// programming failed.
///
/// # Safety
///
/// The caller must ensure that the BAR containing the MSI-X table is
/// already identity-mapped (or mapped via the kernel's phys-to-virt
/// window), otherwise the table writes will fault.
fn enable_msix(pci_dev: &PciDevice, vector: u8) -> bool {
    let Some(cap) = pci_dev.msix_cap_offset() else {
        return false;
    };

    let ctrl = pci_dev.read_config_u16(cap + msix_cap::CONTROL);
    let table_size = (ctrl & msix_ctrl::TABLE_SIZE_MASK) as usize;
    if table_size == 0 {
        log::warn!(
            "MSI-X: {:04x}:{:04x} has zero-sized table",
            pci_dev.vendor_id,
            pci_dev.device_id
        );
        return false;
    }

    // Parse Table BAR indicator + offset.
    let table_reg = pci_dev.read_config_u32(cap + msix_cap::TABLE);
    let bar_index = (table_reg & 0x7) as u8;
    let tbl_offset = (table_reg & 0xFFFF_FFF8) as u64;

    // Map the table BAR if needed.
    let bar = match pci_dev.read_bar(bar_index) {
        Some(bar) => bar,
        None => {
            log::warn!(
                "MSI-X: {:04x}:{:04x} table BAR {} invalid",
                pci_dev.vendor_id,
                pci_dev.device_id,
                bar_index
            );
            return false;
        }
    };

    let (bar_phys, _bar_size) = match bar {
        crate::hardware::pci_client::Bar::Memory32 { addr, .. } => (addr as u64, 0x1000),
        crate::hardware::pci_client::Bar::Memory64 { addr, .. } => (addr, 0x1000),
        _ => {
            log::warn!(
                "MSI-X: {:04x}:{:04x} table BAR is I/O space",
                pci_dev.vendor_id,
                pci_dev.device_id
            );
            return false;
        }
    };

    // Ensure the BAR + table region is identity-mapped.
    let table_phys = bar_phys + tbl_offset;
    crate::memory::paging::ensure_identity_map_range(table_phys, 0x1000);
    let table_virt = crate::memory::phys_to_virt(table_phys) as *mut u32;

    let lapic_id = crate::arch::x86_64::apic::lapic_id();
    let msg_addr = MSI_ADDR_BASE | (lapic_id << MSI_ADDR_DEST_SHIFT);
    let msg_data = vector as u32; // bits 7:0 = vector

    // Program the first MSI-X table entry (16 bytes per entry).
    // Entry layout: [addr_lo:32, addr_hi:32, data:32, ctrl:32]
    // Entry 0 offset in table = 0
    // SAFETY: we mapped the BAR region.
    unsafe {
        // Message Address (low 32 bits)
        core::ptr::write_volatile(table_virt, msg_addr);
        // Message Address (high 32 bits = 0 for x86_64)
        core::ptr::write_volatile(table_virt.add(1), 0u32);
        // Message Data
        core::ptr::write_volatile(table_virt.add(2), msg_data);
        // Vector Control: 0 = unmasked
        core::ptr::write_volatile(table_virt.add(3), 0u32);
    }

    // Enable MSI-X in the capability control register.
    let new_ctrl = (ctrl | msix_ctrl::ENABLE) & !msix_ctrl::FUNC_MASK;
    pci_dev.write_config_u16(cap + msix_cap::CONTROL, new_ctrl);

    // Disable legacy INTx.
    let mut cmd = pci_dev.read_config_u16(config::COMMAND);
    cmd |= command::INTERRUPT_DISABLE;
    pci_dev.write_config_u16(config::COMMAND, cmd);

    log::info!(
        "MSI-X: enabled on {:04x}:{:04x} → vector {:#x} ({} entries, table BAR{}+{:#x})",
        pci_dev.vendor_id,
        pci_dev.device_id,
        vector,
        table_size + 1,
        bar_index,
        tbl_offset,
    );
    true
}

/// Probe a PCI device and enable the best available interrupt mode.
///
/// Priority: **MSI-X** => **MSI** => **INTx** (legacy I/O APIC routing).
///
/// `vector` is the IDT vector to associate with the interrupt
/// (typically `PIC1_OFFSET + irq` for legacy IRQs, or a free vector
/// for MSI/MSI-X).
///
/// Returns `(irq_line, vector)` suitable for `register_nic_irq()`.
/// When MSI/MSI-X is active the `irq_line` value is only used for EOI
/// in the no-APIC fallback path (which MSI requires APIC, so the value
/// is cosmetic).
pub fn probe_and_enable(pci_dev: &PciDevice, prefer_msix: bool) -> (u8, u8) {
    let irq_line = pci_dev.interrupt_line;
    let vector = if irq_line < 16 && irq_line != 0 && irq_line != 0xFF {
        0x20 + irq_line
    } else if irq_line != 0 && irq_line != 0xFF {
        irq_line
    } else {
        0x20 // fallback vector
    };

    // 1. Try MSI-X first (if preferred and available).
    if prefer_msix && enable_msix(pci_dev, vector) {
        return (irq_line, vector);
    }

    // 2. Try MSI.
    if enable_msi(pci_dev, vector) {
        return (irq_line, vector);
    }

    // 3. Fall back to INTx — caller must route via I/O APIC.
    log::info!(
        "MSI/MSI-X unavailable on {:04x}:{:04x}, falling back to INTx IRQ {}",
        pci_dev.vendor_id,
        pci_dev.device_id,
        irq_line,
    );
    (irq_line, vector)
}
