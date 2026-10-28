//! Hardware and IPC namespace commands: lspci, lsns
use crate::{shell::ShellError, shell_println};
use alloc::string::String;

fn pci_class_name(class: u8, subclass: u8) -> &'static str {
    match (class, subclass) {
        (0x01, 0x00) => "SCSI",
        (0x01, 0x01) => "IDE",
        (0x01, 0x06) => "SATA",
        (0x01, 0x08) => "NVMe",
        (0x01, _) => "Storage",
        (0x02, 0x00) => "Ethernet",
        (0x02, _) => "Network",
        (0x03, 0x00) => "VGA",
        (0x03, _) => "Display",
        (0x04, _) => "Multimedia",
        (0x05, _) => "Memory",
        (0x06, 0x00) => "Host bridge",
        (0x06, 0x01) => "ISA bridge",
        (0x06, 0x04) => "PCI bridge",
        (0x06, _) => "Bridge",
        (0x07, _) => "Serial",
        (0x08, _) => "System",
        (0x0C, 0x03) => "USB",
        (0x0C, _) => "Serial bus",
        _ => "Other",
    }
}

pub fn cmd_lspci(_args: &[String]) -> Result<(), ShellError> {
    let devices = crate::arch::pci::all_devices();
    if devices.is_empty() {
        shell_println!("(no PCI devices found)");
        return Ok(());
    }

    shell_println!(
        "{:<12} {:<11} {:<12} {}",
        "Address",
        "Vendor:Dev",
        "Class",
        "Type"
    );
    shell_println!("====================================================================================================================================================================================");
    for dev in &devices {
        let addr = dev.address;
        shell_println!(
            "{:02x}:{:02x}.{:<5} {:04x}:{:04x}   {:02x}:{:02x}       {}",
            addr.bus,
            addr.device,
            addr.function,
            dev.vendor_id,
            dev.device_id,
            dev.class_code,
            dev.subclass,
            pci_class_name(dev.class_code, dev.subclass)
        );
    }
    shell_println!("{} device(s)", devices.len());
    Ok(())
}

pub fn cmd_lsns(_args: &[String]) -> Result<(), ShellError> {
    let bindings = crate::namespace::list_all_bindings();
    if bindings.is_empty() {
        shell_println!("(no IPC namespace bindings)");
        return Ok(());
    }

    shell_println!("{:<8} {}", "Port", "Path");
    shell_println!("==================================================================================================================================");
    for (path, port_id) in &bindings {
        shell_println!("{:<8} {}", port_id, path);
    }
    shell_println!("{} binding(s)", bindings.len());
    Ok(())
}

/// `iommu`: dump the IOMMU discovery, counters, groups and reserved regions.
pub fn cmd_iommu(_args: &[String]) -> Result<(), ShellError> {
    use crate::hardware::iommu;

    let discovery = crate::arch::iommu::discovery();
    shell_println!(
        "IOMMU present={} enabled={} ready={} backend={}",
        discovery.present,
        iommu::enabled(),
        discovery.ready,
        discovery.backend
    );
    shell_println!(
        "units={} rmrr={} atsr={} width={} intr_remap={} x2apic_opt_out={}",
        discovery.units,
        discovery.rmrrs,
        discovery.atsrs,
        discovery.host_address_width,
        discovery.intr_remap,
        discovery.x2apic_opt_out
    );

    let stats = iommu::stats();
    shell_println!(
        "domains live={} created={} destroyed={} maps={} unmaps={} faults={} dropped={}",
        iommu::domain_count(),
        stats.domains_created,
        stats.domains_destroyed,
        stats.maps,
        stats.unmaps,
        stats.faults,
        stats.dropped_faults
    );

    let groups = iommu::groups();
    shell_println!("IOMMU groups: {}", groups.len());
    for group in &groups {
        shell_println!(
            "  group={} seg={} bus={:02x} devices={}",
            group.id,
            group.segment,
            group.bus,
            group.devices.len()
        );
    }

    let reserved = iommu::reserved_regions();
    shell_println!("Reserved regions (RMRR/IVMD): {}", reserved.len());
    for region in &reserved {
        shell_println!(
            "  seg={} {:#x}..{:#x} devices={} all_buses={}",
            region.segment,
            region.base,
            region.limit,
            region.devices.len(),
            region.all_bus_from.is_some()
        );
    }
    Ok(())
}
