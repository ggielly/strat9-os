// USB HID (Human Interface Device) Driver
// Supports boot protocol keyboards and mice
//
// Features:
// - Boot protocol keyboard support
// - Boot protocol mouse support
// - Event queue for key presses and mouse movements
// - PS/2 to USB keycode translation
// - Interrupt transfer polling via xHCI
// - Unification with PS/2: events feed into the same keyboard/mouse buffers
//
// Inspired by Redox usbhid, Asterinas input subsystem, Maestro device manager.

#![allow(dead_code)]

use crate::arch::{keyboard, mouse};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

pub const HID_BOOT_KEYBOARD: u8 = 0x01;
pub const HID_BOOT_MOUSE: u8 = 0x02;

const KBD_REPORT_SIZE: usize = 8;
const MOUSE_REPORT_SIZE: usize = 4;

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

const USB_TO_PS2: [u8; 128] = [
    0x00, 0x00, 0x00, 0x00, 0x1C, 0x32, 0x21, 0x23, 0x1D, 0x24, 0x2B, 0x34, 0x33, 0x43, 0x35, 0x0E,
    0x15, 0x16, 0x17, 0x1C, 0x18, 0x19, 0x14, 0x1A, 0x1B, 0x1D, 0x1E, 0x21, 0x22, 0x23, 0x24, 0x2B,
    0x29, 0x2F, 0x2E, 0x30, 0x20, 0x31, 0x32, 0x33, 0x2C, 0x2D, 0x11, 0x12, 0x13, 0x3F, 0x3E, 0x46,
    0x45, 0x5D, 0x4C, 0x36, 0x4A, 0x55, 0x37, 0x4E, 0x57, 0x5E, 0x5C, 0x41, 0x52, 0x4D, 0x4B, 0x5B,
    0x5A, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

fn usb_to_ps2(keycode: u8) -> u8 {
    if keycode < USB_TO_PS2.len() as u8 {
        USB_TO_PS2[keycode as usize]
    } else {
        0x00
    }
}

pub struct HidKeyboard {
    port: usize,
    slot_id: u8,
    interface: u8,
    endpoint: u8,
    max_packet: u16,
    interval: u8,
    event_queue: Vec<KeyEvent>,
    last_report: [u8; KBD_REPORT_SIZE],
    report_buf: *mut u8,
}

unsafe impl Send for HidKeyboard {}
unsafe impl Sync for HidKeyboard {}

impl HidKeyboard {
    pub fn new(
        port: usize,
        slot_id: u8,
        interface: u8,
        endpoint: u8,
        max_packet: u16,
        interval: u8,
    ) -> Self {
        Self {
            port,
            slot_id,
            interface,
            endpoint,
            max_packet,
            interval,
            event_queue: Vec::new(),
            last_report: [0; KBD_REPORT_SIZE],
            report_buf: core::ptr::null_mut(),
        }
    }

    pub fn read_event(&mut self) -> Option<KeyEvent> {
        self.event_queue.pop()
    }

    pub fn process_report(&mut self, report: &[u8]) {
        if report.len() < KBD_REPORT_SIZE {
            return;
        }
        let modifiers = report[0];

        for i in 2..8 {
            let keycode = report[i];
            if keycode == 0 {
                continue;
            }
            let was_pressed = self.last_report[2..8].contains(&keycode);
            if !was_pressed {
                self.event_queue.push(KeyEvent {
                    keycode: usb_to_ps2(keycode),
                    pressed: true,
                    modifiers,
                });
            }
        }

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

        for i in 0..8 {
            self.last_report[i] = report[i];
        }
    }

    pub fn is_modifier_pressed(&self, modifier: u8) -> bool {
        self.last_report[0] & modifier != 0
    }

    pub fn drain_into_unified(&mut self) {
        while let Some(ev) = self.event_queue.pop() {
            keyboard::inject_hid_scancode(ev.keycode, ev.pressed);
        }
    }
}

pub struct HidMouse {
    port: usize,
    slot_id: u8,
    interface: u8,
    endpoint: u8,
    max_packet: u16,
    interval: u8,
    event_queue: Vec<MouseEvent>,
    last_buttons: u8,
    report_buf: *mut u8,
}

unsafe impl Send for HidMouse {}
unsafe impl Sync for HidMouse {}

impl HidMouse {
    pub fn new(
        port: usize,
        slot_id: u8,
        interface: u8,
        endpoint: u8,
        max_packet: u16,
        interval: u8,
    ) -> Self {
        Self {
            port,
            slot_id,
            interface,
            endpoint,
            max_packet,
            interval,
            event_queue: Vec::new(),
            last_buttons: 0,
            report_buf: core::ptr::null_mut(),
        }
    }

    pub fn read_event(&mut self) -> Option<MouseEvent> {
        self.event_queue.pop()
    }

    pub fn process_report(&mut self, report: &[u8]) {
        if report.len() < 3 {
            return;
        }

        let buttons = report[0];
        let dx = report[1] as i8;
        let dy = report[2] as i8;
        let dz = if report.len() > 3 { report[3] as i8 } else { 0 };

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

        if dx != 0 || dy != 0 || dz != 0 {
            self.event_queue.push(MouseEvent {
                dx,
                dy,
                dz,
                buttons,
            });
        }

        self.last_buttons = buttons;
    }

    pub fn is_button_pressed(&self, button: u8) -> bool {
        self.last_buttons & (1 << button) != 0
    }

    pub fn drain_into_unified(&mut self) {
        while let Some(ev) = self.event_queue.pop() {
            let left = ev.buttons & 0x01 != 0;
            let right = ev.buttons & 0x02 != 0;
            let middle = ev.buttons & 0x04 != 0;
            mouse::push_event_from_hid(ev.dx as i16, ev.dy as i16, ev.dz, left, right, middle);
        }
    }
}

static KEYBOARDS: Mutex<Vec<Arc<Mutex<HidKeyboard>>>> = Mutex::new(Vec::new());
static MICE: Mutex<Vec<Arc<Mutex<HidMouse>>>> = Mutex::new(Vec::new());
static HID_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init() {
    log::info!("[USB-HID] Initializing HID drivers...");
    HID_INITIALIZED.store(true, Ordering::SeqCst);
    log::info!(
        "[USB-HID] Initialized: {} keyboard(s), {} mouse/mice",
        KEYBOARDS.lock().len(),
        MICE.lock().len()
    );
}

pub fn enumerate_device(port: usize, slot_id: u8, dev_desc: &[u8; 18]) {
    let dev_class = dev_desc[4];

    if dev_class == 0x03 {
        let protocol = dev_desc[6];
        log::info!(
            "[USB-HID] HID device: port={} slot={} class=03 protocol={:02x}",
            port,
            slot_id,
            protocol
        );

        if let Some(controller_arc) = crate::hardware::usb::xhci::get_controller(0) {
            let mut controller = controller_arc.lock();

            if protocol == 1 {
                controller.set_protocol(port as u8, 0, 0).ok();
            } else if protocol == 2 {
                controller.set_protocol(port as u8, 0, 1).ok();
            }

            let mut config_desc = [0u8; 256];
            if controller
                .get_configuration_descriptor(slot_id, 0, &mut config_desc, 9)
                .is_ok()
            {
                let total_len = u16::from_le_bytes([config_desc[2], config_desc[3]]) as usize;
                if total_len > 9 && total_len <= 256 {
                    controller
                        .get_configuration_descriptor(slot_id, 0, &mut config_desc, total_len)
                        .ok();
                }

                let mut offset = 9;
                while offset + 9 <= total_len {
                    let b_length = config_desc[offset];
                    let b_descriptor_type = config_desc[offset + 1];
                    if b_length < 9 || offset + b_length as usize > total_len {
                        break;
                    }
                    if b_descriptor_type == 4 {
                        let b_interface_class = config_desc[offset + 5];
                        let b_interface_protocol = config_desc[offset + 7];

                        if b_interface_class == 0x03 {
                            let mut ep_offset = offset + 9;
                            while ep_offset + 7 <= offset + b_length as usize {
                                let ep_b_length = config_desc[ep_offset];
                                let ep_b_descriptor_type = config_desc[ep_offset + 1];
                                if ep_b_length < 7 || ep_b_descriptor_type != 5 {
                                    break;
                                }
                                let ep_addr = config_desc[ep_offset + 2];
                                let ep_max_packet = u16::from_le_bytes([
                                    config_desc[ep_offset + 4],
                                    config_desc[ep_offset + 5],
                                ]);
                                let ep_interval = config_desc[ep_offset + 6];

                                if (ep_addr & 0x80) != 0 {
                                    let ep_num = ep_addr & 0x0F;
                                    let ep_type = 7;

                                    controller
                                        .setup_endpoint(
                                            slot_id,
                                            ep_num,
                                            ep_max_packet as u32,
                                            ep_type,
                                            ep_interval as u32,
                                            0,
                                        )
                                        .ok();

                                    let buf_size = ep_max_packet as usize;
                                    if let Ok((_buf_virt, _buf_phys)) =
                                        controller.alloc_interrupt_buffer(slot_id, ep_num, buf_size)
                                    {
                                        if b_interface_protocol == 1 {
                                            let mut keyboard = HidKeyboard::new(
                                                port,
                                                slot_id,
                                                config_desc[offset + 2],
                                                ep_addr,
                                                ep_max_packet,
                                                ep_interval,
                                            );
                                            keyboard.report_buf = _buf_virt;
                                            log::info!(
                                                "[USB-HID] Keyboard: port={} slot={} ep={:02x} max_pkt={} interval={}",
                                                port,
                                                slot_id,
                                                ep_addr,
                                                ep_max_packet,
                                                ep_interval
                                            );
                                            KEYBOARDS.lock().push(Arc::new(Mutex::new(keyboard)));

                                            controller
                                                .submit_interrupt_transfer(slot_id, ep_num)
                                                .ok();
                                        } else if b_interface_protocol == 2 {
                                            let mut mouse_dev = HidMouse::new(
                                                port,
                                                slot_id,
                                                config_desc[offset + 2],
                                                ep_addr,
                                                ep_max_packet,
                                                ep_interval,
                                            );
                                            mouse_dev.report_buf = _buf_virt;
                                            log::info!(
                                                "[USB-HID] Mouse: port={} slot={} ep={:02x} max_pkt={} interval={}",
                                                port,
                                                slot_id,
                                                ep_addr,
                                                ep_max_packet,
                                                ep_interval
                                            );
                                            MICE.lock().push(Arc::new(Mutex::new(mouse_dev)));

                                            controller
                                                .submit_interrupt_transfer(slot_id, ep_num)
                                                .ok();
                                        }
                                    }
                                }
                                ep_offset += ep_b_length as usize;
                            }
                        }
                    }
                    offset += b_length as usize;
                }
            }

            controller.set_configuration(slot_id, 1).ok();
        }
    } else {
        log::info!(
            "[USB-HID] Non-HID device: port={} slot={} class={:02x}",
            port,
            slot_id,
            dev_class
        );
    }
}

pub fn receive_interrupt_report(slot_id: u8, ep_id: u8, buf: *const u8, len: usize) {
    if buf.is_null() || len == 0 {
        return;
    }

    let report = unsafe { core::slice::from_raw_parts(buf, len) };

    for kbd in KEYBOARDS.lock().iter() {
        let mut k = kbd.lock();
        if k.slot_id == slot_id && (k.endpoint & 0x0F) == ep_id {
            k.process_report(report);
            k.drain_into_unified();
            return;
        }
    }

    for m in MICE.lock().iter() {
        let mut dev = m.lock();
        if dev.slot_id == slot_id && (dev.endpoint & 0x0F) == ep_id {
            dev.process_report(report);
            dev.drain_into_unified();
            return;
        }
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

pub fn poll_all() {
    for kbd in KEYBOARDS.lock().iter() {
        let mut k = kbd.lock();
        k.drain_into_unified();
    }
    for m in MICE.lock().iter() {
        let mut dev = m.lock();
        dev.drain_into_unified();
    }
}

pub fn notify_transfer_complete(_slot_id: u8, _ep_id: u8) {
    poll_all();
}
