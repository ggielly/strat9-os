//! Hardware and IPC namespace commands: lspci, lsns
use crate::{shell::ShellError, shell_println};
use alloc::{format, string::String};

/// Column widths for the `lspci` table.
///
/// The header, the rows and the rule all read these, so they cannot drift
/// apart. The trailing `Type` column holds a class name of variable length and
/// is therefore not listed.
const LSPCI_COLS: [usize; 3] = [12, 11, 10];

/// Column widths for the `lsns` table; the `Path` tail is variable width.
///
/// Port ids are handed out by a monotonic counter, so 8 digits is generous: a
/// wider id only makes the row overhang the rule, it cannot corrupt the layout.
const LSNS_COLS: [usize; 1] = [8];

/// A horizontal rule exactly as wide as the fixed columns of a table.
pub(crate) fn separator(widths: &[usize]) -> String {
    "=".repeat(widths.iter().sum())
}

/// Lay `cells` out in columns of `widths`, separated by a single space.
///
/// Cells beyond `widths` are appended unpadded: a table's last column holds a
/// variable-width value (a class name, a path) which must not be truncated.
pub(crate) fn pad_row(widths: &[usize], cells: &[&str]) -> String {
    let mut row = String::new();
    for (i, cell) in cells.iter().enumerate() {
        if i > 0 {
            row.push(' ');
        }
        match widths.get(i) {
            Some(&width) => {
                row.push_str(cell);
                for _ in cell.chars().count()..width {
                    row.push(' ');
                }
            }
            None => row.push_str(cell),
        }
    }
    row
}

/// PCI slot address as `bus:device.function`, all fields hex, e.g. `00:1f.2`.
pub(crate) fn format_pci_address(bus: u8, device: u8, function: u8) -> String {
    format!("{:02x}:{:02x}.{}", bus, device, function)
}

/// Human-readable PCI class, from the kernel's own decoder.
///
/// Class label for one PCI device, or the raw codes when the target cannot
/// decode them.
///
/// The lookup lives in the arch facade, so this is one code path on every
/// target: the RISC-V facade reports `None` until ECAM enumeration lands (R5),
/// and the raw pair is shown rather than a second, drifting copy of the table.
fn pci_class_label(class: u8, subclass: u8) -> String {
    match crate::arch::pci::class_name(class, subclass) {
        Some(name) => String::from(name),
        None => format!("Unknown ({:02x}:{:02x})", class, subclass),
    }
}

pub fn cmd_lspci(_args: &[String]) -> Result<(), ShellError> {
    let devices = crate::arch::pci::all_devices();
    if devices.is_empty() {
        shell_println!("(no PCI devices found)");
        return Ok(());
    }

    shell_println!(
        "{}",
        pad_row(&LSPCI_COLS, &["Address", "Vendor:Dev", "Class", "Type"])
    );
    shell_println!("{}", separator(&LSPCI_COLS));
    for dev in &devices {
        let address = format_pci_address(dev.address.bus, dev.address.device, dev.address.function);
        let ids = format!("{:04x}:{:04x}", dev.vendor_id, dev.device_id);
        let class = format!("{:02x}:{:02x}", dev.class_code, dev.subclass);
        shell_println!(
            "{}",
            pad_row(
                &LSPCI_COLS,
                &[
                    &address,
                    &ids,
                    &class,
                    &pci_class_label(dev.class_code, dev.subclass),
                ],
            )
        );
    }
    shell_println!("");
    shell_println!("{} device(s)", devices.len());
    Ok(())
}

pub fn cmd_lsns(args: &[String]) -> Result<(), ShellError> {
    if let Some(unknown) = args.iter().find(|a| a.starts_with('-')) {
        shell_println!("lsns: unknown option '{}'", unknown);
        return Err(ShellError::InvalidArguments);
    }

    let bindings = crate::namespace::list_all_bindings();
    if bindings.is_empty() {
        shell_println!("(no IPC namespace bindings)");
        return Ok(());
    }

    shell_println!("{}", pad_row(&LSNS_COLS, &["Port", "Path"]));
    shell_println!("{}", separator(&LSNS_COLS));
    for (path, port_id) in &bindings {
        let port = format!("{}", port_id);
        shell_println!("{}", pad_row(&LSNS_COLS, &[&port, path]));
    }
    shell_println!("");
    shell_println!("{} binding(s)", bindings.len());
    Ok(())
}
