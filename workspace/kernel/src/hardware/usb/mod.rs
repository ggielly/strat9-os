// USB subsystem
//
// Supports:
// - xHCI (USB 3.0)
// - EHCI (USB 2.0)
// - UHCI (USB 1.1)
// - HID devices (keyboard, mouse)

pub mod btusb;
pub mod class;
pub mod ehci;
pub mod hid;
#[cfg(target_arch = "x86_64")]
pub mod uhci;
pub mod xhci;

use core::sync::atomic::{AtomicBool, Ordering};

/// `hardware::init()` and the component graph both run the hardware stage.
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Performs the init operation.
///
/// Idempotent: the component `usb_init` runs after `hardware::init()` has
/// already enumerated every controller.
pub fn init() {
    if INITIALIZED.swap(true, Ordering::AcqRel) {
        return;
    }
    // Initialize controllers in order: xHCI first (USB 3.0), then EHCI (USB 2.0), then UHCI (USB 1.1)
    // This ensures we use the fastest available controller for each device

    log::info!("[USB] Initializing USB subsystem...");
    log::info!("****************************************");
    log::info!("*** USB/BT EARLY: xHCI PROBE ***");
    log::info!("****************************************");

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

    // Bluetooth HCI transport. Enumeration already probed every device through
    // `class::enumerate_device`; this only announces readiness.
    btusb::init();
    log::info!("****************************************");
    log::info!(
        "*** USB/BT EARLY: HCI ATTACHED = {} ***",
        btusb::is_present()
    );
    log::info!("****************************************");

    // Compact summary of every xHCI controller + the BT device, then pause so
    // the lines can be photographed on real hardware.
    let count = xhci::controller_count();
    log::info!("*** xHCI SUMMARY: {} controller(s) ***", count);
    for i in 0..count {
        if let Some(controller) = xhci::get_controller(i) {
            let ports = crate::sync::with_irqs_disabled(|_| controller.lock().port_count());
            log::info!("*** xHCI[{}] ports={} ***", i, ports);
        }
    }
    match btusb::attached_ids() {
        Some((vid, pid)) => log::info!("*** BT DEVICE {:04x}:{:04x} ***", vid, pid),
        None => log::info!("*** BT DEVICE: none ***"),
    }
    log::info!("****************************************");
    log::info!("*** USB/BT SUMMARY ABOVE - PAUSE ***");
    log::info!("*** press a key (or wait) to continue ***");
    log::info!("****************************************");
    if crate::debug_cfg::USB_BOOT_PAUSE {
        boot_pause();
    }

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

/// Busy-wait until a PS/2 key is pressed, or ~a few seconds elapse.
///
/// Used once after the USB/BT summary so the early xHCI lines can be read or
/// photographed on real hardware where there is no serial console.
fn boot_pause() {
    let mut spins: u64 = 0;
    // ~3e9 pause hints: several seconds even on a fast CPU.
    #[cfg(target_arch = "x86_64")]
    {
        while crate::arch::keyboard::read_char().is_none() && spins < 3_000_000_000 {
            spins += 1;
            core::hint::spin_loop();
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        while spins < 3_000_000_000 {
            spins += 1;
            core::hint::spin_loop();
        }
    }
}
