// USB subsystem
//
// Supports:
// - xHCI (USB 3.0)
// - EHCI (USB 2.0)
// - UHCI (USB 1.1)
// - HID devices (keyboard, mouse)

pub mod ehci;
pub mod hid;
#[cfg(target_arch = "x86_64")]
pub mod uhci;
pub mod xhci;

/// Performs the init operation.
pub fn init() {
    // Initialize controllers in order: xHCI first (USB 3.0), then EHCI (USB 2.0), then UHCI (USB 1.1)
    // This ensures we use the fastest available controller for each device

    log::info!("[USB] Initializing USB subsystem...");

    // Raw E9 progress marks (logger output may be silent during early boot):
    // 'X' xHCI done, 'E' EHCI done, 'U' UHCI done, 'H' HID init done, then
    // availability as digit chars (xHCI, EHCI, UHCI, HID).
    crate::e9_mark!(b'@');

    // xHCI (USB 3.0) - must be initialized first as it may control EHCI
    xhci::init();
    crate::e9_mark!(b'X');

    // EHCI (USB 2.0)
    ehci::init();
    crate::e9_mark!(b'E');

    // UHCI (USB 1.1) - for legacy devices
    #[cfg(target_arch = "x86_64")]
    uhci::init();
    crate::e9_mark!(b'U');

    // Initialize HID drivers after controllers are ready
    hid::init();
    crate::e9_mark!(b'H');

    #[cfg(target_arch = "x86_64")]
    let uhci_available = uhci::is_available();
    #[cfg(not(target_arch = "x86_64"))]
    let uhci_available = false;

    for (avail, mark) in [
        (xhci::is_available(), b'1'),
        (ehci::is_available(), b'2'),
        (uhci_available, b'3'),
        (crate::hardware::usb::hid::is_available(), b'4'),
    ] {
        let c = if avail { mark } else { mark - 1 }; // '0'..'3' when absent
        unsafe {
            crate::e9_mark!(c);
        }
    }

    let total_controllers = (if xhci::is_available() { 1 } else { 0 })
        + (if ehci::is_available() { 1 } else { 0 })
        + {
            #[cfg(target_arch = "x86_64")]
            { if uhci::is_available() { 1 } else { 0 } }
            #[cfg(not(target_arch = "x86_64"))]
            { 0 }
        };

    log::info!("[USB] Total USB controllers: {}", total_controllers);
}
