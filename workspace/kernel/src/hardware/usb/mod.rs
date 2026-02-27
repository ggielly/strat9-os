// USB subsystem
//
// Supports:
// - xHCI (USB 3.0)
// - EHCI (USB 2.0)
// - UHCI (USB 1.1)
// - HID devices (keyboard, mouse)

pub mod ehci;
pub mod hid;
pub mod uhci;
pub mod xhci;

pub fn init() {
    // Initialize controllers in order: xHCI first (USB 3.0), then EHCI (USB 2.0), then UHCI (USB 1.1)
    // This ensures we use the fastest available controller for each device
    
    log::info!("[USB] Initializing USB subsystem...");
    
    // xHCI (USB 3.0) - must be initialized first as it may control EHCI
    xhci::init();
    
    // EHCI (USB 2.0)
    ehci::init();
    
    // UHCI (USB 1.1) - for legacy devices
    uhci::init();
    
    // Initialize HID drivers after controllers are ready
    hid::init();
    
    let total_controllers = 
        (if xhci::is_available() { 1 } else { 0 }) +
        (if ehci::is_available() { 1 } else { 0 }) +
        (if uhci::is_available() { 1 } else { 0 });
    
    log::info!("[USB] Total USB controllers: {}", total_controllers);
}
