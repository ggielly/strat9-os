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
    let devices = crate::arch::x86_64::pci::all_devices();
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
    shell_println!("==================================================================================================================================─");
    for (path, port_id) in &bindings {
        shell_println!("{:<8} {}", port_id, path);
    }
    shell_println!("{} binding(s)", bindings.len());
    Ok(())
}
