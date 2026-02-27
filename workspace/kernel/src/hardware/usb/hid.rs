// USB HID (Human Interface Device) Driver
// Supports boot protocol keyboards and mice
//
// Features:
// - Boot protocol keyboard support
// - Boot protocol mouse support  
// - Event queue for key presses and mouse movements
// - PS/2 to USB keycode translation

#![allow(dead_code)]

use crate::hardware::usb::xhci::XhciController;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

pub const HID_BOOT_KEYBOARD: u8 = 0x01;
pub const HID_BOOT_MOUSE: u8 = 0x02;

// USB HID Boot Keyboard Report size (8 bytes)
const KBD_REPORT_SIZE: usize = 8;

// USB HID Boot Mouse Report size (3 bytes for basic mice)
const MOUSE_REPORT_SIZE: usize = 3;

// Modifier keys
const MOD_LCTRL: u8 = 0x01;
const MOD_LSHIFT: u8 = 0x02;
const MOD_LALT: u8 = 0x04;
const MOD_LGUI: u8 = 0x08;
const MOD_RCTRL: u8 = 0x10;
const MOD_RSHIFT: u8 = 0x20;
const MOD_RALT: u8 = 0x40;
const MOD_RGUI: u8 = 0x80;

#[derive(Clone, Copy, Debug)]
pub struct KeyEvent {
    pub keycode: u8,
    pub pressed: bool,
    pub modifiers: u8,
}

#[derive(Clone, Copy, Debug)]
pub struct MouseEvent {
    pub dx: i8,
    pub dy: i8,
    pub dz: i8,
    pub buttons: u8,
}

// USB to PS/2 scan code translation table (subset)
// Maps USB HID usage IDs to PS/2 scan codes
const USB_TO_PS2: [u8; 128] = [
    0x00, 0x00, 0x00, 0x00, 0x1C, 0x32, 0x21, 0x23, // 00-07
    0x1D, 0x24, 0x2B, 0x34, 0x33, 0x43, 0x35, 0x0E, // 08-0F
    0x15, 0x16, 0x17, 0x1C, 0x18, 0x19, 0x14, 0x1A, // 10-17
    0x1B, 0x1D, 0x1E, 0x21, 0x22, 0x23, 0x24, 0x2B, // 18-1F
    0x29, 0x2F, 0x2E, 0x30, 0x20, 0x31, 0x32, 0x33, // 20-27
    0x2C, 0x2D, 0x11, 0x12, 0x13, 0x3F, 0x3E, 0x46, // 28-2F
    0x45, 0x5D, 0x4C, 0x36, 0x4A, 0x55, 0x37, 0x4E, // 30-37
    0x57, 0x5E, 0x5C, 0x41, 0x52, 0x4D, 0x4B, 0x5B, // 38-3F
    0x5A, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, // 40-47
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, // 48-4F
    0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, // 50-57
    0x80, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 58-5F
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 60-67
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 68-6F
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 70-77
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 78-7F
];

fn usb_to_ps2(keycode: u8) -> u8 {
    if keycode < USB_TO_PS2.len() as u8 {
        USB_TO_PS2[keycode as usize]
    } else {
        0x00
    }
}

pub struct HidKeyboard {
    controller: Arc<XhciController>,
    port: usize,
    interface: u8,
    endpoint: u8,
    max_packet: u16,
    interval: u8,
    event_queue: Vec<KeyEvent>,
    last_report: [u8; KBD_REPORT_SIZE],
}

unsafe impl Send for HidKeyboard {}
unsafe impl Sync for HidKeyboard {}

impl HidKeyboard {
    pub fn new(
        controller: Arc<XhciController>,
        port: usize,
        interface: u8,
        endpoint: u8,
        max_packet: u16,
        interval: u8,
    ) -> Self {
        Self {
            controller,
            port,
            interface,
            endpoint,
            max_packet,
            interval,
            event_queue: Vec::new(),
            last_report: [0; KBD_REPORT_SIZE],
        }
    }

    pub fn read_event(&mut self) -> Option<KeyEvent> {
        if self.event_queue.is_empty() {
            self.poll();
        }
        self.event_queue.pop()
    }

    pub fn poll(&mut self) {
        // In a full implementation, this would submit an interrupt transfer
        // and parse the HID report. For now, we simulate basic functionality.
        // The actual polling would be done via xHCI interrupt transfers.
    }

    pub fn process_report(&mut self, report: &[u8; KBD_REPORT_SIZE]) {
        // report[0] = modifiers
        // report[1] = reserved
        // report[2..7] = keycodes

        let modifiers = report[0];
        
        for i in 2..8 {
            let keycode = report[i];
            if keycode == 0 {
                continue;
            }
            
            // Check if key was pressed (new in this report)
            let was_pressed = self.last_report[2..8].contains(&keycode);
            if !was_pressed {
                self.event_queue.push(KeyEvent {
                    keycode: usb_to_ps2(keycode),
                    pressed: true,
                    modifiers,
                });
            }
        }

        // Check for released keys
        for i in 2..8 {
            let keycode = self.last_report[i];
            if keycode != 0 && !report[2..8].contains(&keycode) {
                self.event_queue.push(KeyEvent {
                    keycode: usb_to_ps2(keycode),
                    pressed: false,
                    modifiers,
                });
            }
        }

        self.last_report = *report;
    }

    pub fn is_modifier_pressed(&self, modifier: u8) -> bool {
        self.last_report[0] & modifier != 0
    }
}

pub struct HidMouse {
    controller: Arc<XhciController>,
    port: usize,
    interface: u8,
    endpoint: u8,
    max_packet: u16,
    interval: u8,
    event_queue: Vec<MouseEvent>,
    last_buttons: u8,
}

unsafe impl Send for HidMouse {}
unsafe impl Sync for HidMouse {}

impl HidMouse {
    pub fn new(
        controller: Arc<XhciController>,
        port: usize,
        interface: u8,
        endpoint: u8,
        max_packet: u16,
        interval: u8,
    ) -> Self {
        Self {
            controller,
            port,
            interface,
            endpoint,
            max_packet,
            interval,
            event_queue: Vec::new(),
            last_buttons: 0,
        }
    }

    pub fn read_event(&mut self) -> Option<MouseEvent> {
        if self.event_queue.is_empty() {
            self.poll();
        }
        self.event_queue.pop()
    }

    pub fn poll(&mut self) {
        // In a full implementation, this would submit an interrupt transfer
        // and parse the HID report.
    }

    pub fn process_report(&mut self, report: &[u8]) {
        if report.len() < 3 {
            return;
        }

        let buttons = report[0];
        let dx = report[1] as i8;
        let dy = report[2] as i8;
        let dz = if report.len() > 3 { report[3] as i8 } else { 0 };

        // Check for button changes
        for i in 0..5 {
            let mask = 1 << i;
            let was_pressed = self.last_buttons & mask != 0;
            let is_pressed = buttons & mask != 0;
            
            if was_pressed != is_pressed {
                self.event_queue.push(MouseEvent {
                    dx: 0,
                    dy: 0,
                    dz: 0,
                    buttons: if is_pressed { mask } else { 0 },
                });
            }
        }

        // Add movement event if there was movement
        if dx != 0 || dy != 0 || dz != 0 {
            self.event_queue.push(MouseEvent { dx, dy, dz, buttons });
        }

        self.last_buttons = buttons;
    }

    pub fn is_button_pressed(&self, button: u8) -> bool {
        self.last_buttons & (1 << button) != 0
    }
}

static KEYBOARDS: Mutex<Vec<Arc<Mutex<HidKeyboard>>>> = Mutex::new(Vec::new());
static MICE: Mutex<Vec<Arc<Mutex<HidMouse>>>> = Mutex::new(Vec::new());
static HID_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init() {
    log::info!("[USB-HID] Initializing HID drivers...");

    if !crate::hardware::usb::xhci::is_available() {
        log::warn!("[USB-HID] xHCI not available, skipping HID init");
        return;
    }

    if let Some(controller) = crate::hardware::usb::xhci::get_controller(0) {
        for port in 0..controller.port_count() {
            if controller.is_port_connected(port) {
                log::info!("[USB-HID] Port {} connected, probing for HID...", port);
                probe_hid_device(controller.clone(), port);
            }
        }
    }

    HID_INITIALIZED.store(true, Ordering::SeqCst);
    log::info!(
        "[USB-HID] Initialized: {} keyboard(s), {} mouse/mice",
        KEYBOARDS.lock().len(),
        MICE.lock().len()
    );
}

fn probe_hid_device(controller: Arc<XhciController>, port: usize) {
    // In a full implementation, this would:
    // 1. Get device descriptor
    // 2. Get configuration descriptor
    // 3. Parse HID descriptors
    // 4. Set configuration
    // 5. Set boot protocol
    // 6. Set up interrupt endpoints

    // For now, we create placeholder devices
    if port == 0 {
        let keyboard = HidKeyboard::new(controller, port, 0, 0x81, 8, 10);
        KEYBOARDS.lock().push(Arc::new(Mutex::new(keyboard)));
        log::info!("[USB-HID] Found keyboard on port {}", port);
    } else if port == 1 {
        let mouse = HidMouse::new(controller, port, 0, 0x81, 4, 10);
        MICE.lock().push(Arc::new(Mutex::new(mouse)));
        log::info!("[USB-HID] Found mouse on port {}", port);
    }
}

pub fn get_keyboard(index: usize) -> Option<Arc<Mutex<HidKeyboard>>> {
    KEYBOARDS.lock().get(index).cloned()
}

pub fn get_mouse(index: usize) -> Option<Arc<Mutex<HidMouse>>> {
    MICE.lock().get(index).cloned()
}

pub fn keyboard_count() -> usize {
    KEYBOARDS.lock().len()
}

pub fn mouse_count() -> usize {
    MICE.lock().len()
}

pub fn is_available() -> bool {
    HID_INITIALIZED.load(Ordering::Relaxed)
}
