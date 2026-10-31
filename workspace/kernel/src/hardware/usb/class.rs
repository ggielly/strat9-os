// USB class routing
//
// Every host controller driver (xHCI, EHCI, UHCI) calls this after reading the
// 18-byte device descriptor. The device descriptor alone is not enough to pick
// a driver: HID devices are identified by bDeviceClass, while Bluetooth
// dongles usually report bDeviceClass = 0x00 and must be probed through their
// configuration descriptor.
//
// - bDeviceClass 0x03 -> HID keyboard/mouse driver
// - everything else   -> Bluetooth transport (no-op unless an HCI interface
//                        with class 0xE0 / subclass 0x01 / protocol 0x01 is
//                        present in the configuration)

#![allow(dead_code)]

use crate::hardware::usb::{btusb, hid, xhci};

/// Routes a newly enumerated device to the driver that owns it.
///
/// The controller is passed by reference because enumeration runs inside
/// `XhciController::new()`, before the controller is published in the global
/// registry. Re-fetching it with `get_controller(0)` would return `None` (and
/// the HCI driver would silently never attach).
pub fn enumerate_device(
    controller: &mut xhci::XhciController,
    port: usize,
    slot_id: u8,
    dev_desc: &[u8; 18],
) {
    let vid = u16::from_le_bytes([dev_desc[8], dev_desc[9]]);
    let pid = u16::from_le_bytes([dev_desc[10], dev_desc[11]]);
    log::info!(
        "[USB] dev {:04x}:{:04x} class={:02x}/{:02x}/{:02x} port={} slot={}",
        vid,
        pid,
        dev_desc[4],
        dev_desc[5],
        dev_desc[6],
        port,
        slot_id
    );

    match dev_desc[4] {
        0x03 => hid::enumerate_device(port, slot_id, dev_desc),
        // 0xE0 = wireless; 0xEF = miscellaneous with an Interface Association
        // (MediaTek MT7921 reports 0xEF at device level, HCI on the interface);
        // 0x00 = composite. Other classes are not Bluetooth.
        0xE0 | 0xEF | 0x00 => btusb::enumerate_device(controller, port, slot_id, dev_desc),
        _ => {}
    }
}
