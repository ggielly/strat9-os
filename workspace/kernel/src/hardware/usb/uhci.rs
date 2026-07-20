// USB UHCI (Universal Host Controller Interface) Driver
// Reference: UHCI spec (USB 1.1)
//
// Features:
// - UHCI controller initialization
// - Port management
// - Frame list and TD/QH management
// - Low-speed USB 1.1 support

#![allow(dead_code)]

use crate::{
    hardware::pci_client::{self as pci, Bar, ProbeCriteria},
    memory::{allocate_zeroed_frame, phys_to_virt},
};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;
use x86_64::instructions::port::Port;

const UHCI_USBCMD: u16 = 0x00;
const UHCI_USBSTS: u16 = 0x02;
const UHCI_USBINTR: u16 = 0x04;
const UHCI_FRNUM: u16 = 0x06;
const UHCI_FRBASEADDR: u16 = 0x08;
const UHCI_SOFMOD: u16 = 0x0C;
const UHCI_PORTSC: u16 = 0x10;

const USBCMD_RUN_STOP: u16 = 1 << 0;
const USBCMD_HCRESET: u16 = 1 << 1;
const USBCMD_EGSM: u16 = 1 << 3;
const USBCMD_FGSM: u16 = 1 << 4;
const USBCMD_CONFIGURE: u16 = 1 << 6;
const USBCMD_MAX_PACKET: u16 = 1 << 7;

const USBSTS_USBINT: u16 = 1 << 0;
const USBSTS_USBERR: u16 = 1 << 1;
const USBSTS_RD: u16 = 1 << 2;
const USBSTS_HSE: u16 = 1 << 3;
const USBSTS_HCPE: u16 = 1 << 4;
const USBSTS_HCH: u16 = 1 << 5;

const PORTSC_CCS: u16 = 1 << 0;
const PORTSC_CSC: u16 = 1 << 1;
const PORTSC_PE: u16 = 1 << 2;
const PORTSC_PEC: u16 = 1 << 3;
const PORTSC_LSDA: u16 = 1 << 8;
const PORTSC_PR: u16 = 1 << 9;

const TD_TOKEN_ACTIVE: u32 = 1 << 23;
const TD_TOKEN_IOC: u32 = 1 << 24;
const TD_TOKEN_LS: u32 = 1 << 26;
const TD_TOKEN_ERRCNT_SHIFT: u32 = 27;

const TD_LINK_PTR_MASK: u32 = 0xFFFFFFF0;
const TD_LINK_VF: u32 = 1 << 0;
const TD_LINK_QH: u32 = 1 << 1;

#[repr(C)]
struct UhciTD {
    link_ptr: u32,
    ctrl_status: u32,
    token: u32,
    buffer: u32,
}

#[repr(C)]
struct UhciQH {
    head_link: u32,
    element_link: u32,
}

pub struct UhciPort {
    port_num: usize,
    enabled: bool,
    connected: bool,
    low_speed: bool,
}

pub struct UhciController {
    io_base: u16,
    usbcmd: Port<u16>,
    usbsts: Port<u16>,
    usbintr: Port<u16>,
    frnum: Port<u16>,
    frbaseaddr: Port<u32>,
    sofmod: Port<u16>,
    max_ports: usize,
    ports: Vec<UhciPort>,
    frame_list: *mut u32,
    frame_list_phys: u64,
}

unsafe impl Send for UhciController {}
unsafe impl Sync for UhciController {}

impl UhciController {
    /// Creates a new instance.
    pub unsafe fn new(pci_dev: pci::PciDevice) -> Result<Arc<Self>, &'static str> {
        let io_base = match pci_dev.read_bar(4) {
            Some(Bar::Io { port }) => port as u16,
            _ => return Err("Invalid BAR4"),
        };

        let mut controller = Self {
            io_base,
            usbcmd: Port::new(io_base + UHCI_USBCMD),
            usbsts: Port::new(io_base + UHCI_USBSTS),
            usbintr: Port::new(io_base + UHCI_USBINTR),
            frnum: Port::new(io_base + UHCI_FRNUM),
            frbaseaddr: Port::new(io_base + UHCI_FRBASEADDR),
            sofmod: Port::new(io_base + UHCI_SOFMOD),
            max_ports: 2, // UHCI typically has 2 ports
            ports: Vec::new(),
            frame_list: core::ptr::null_mut(),
            frame_list_phys: 0,
        };

        controller.init()?;
        Ok(Arc::new(controller))
    }

    /// Performs the init operation.
    fn init(&mut self) -> Result<(), &'static str> {
        unsafe {
            let mut cmd = self.usbcmd.read();
            cmd &= !USBCMD_RUN_STOP;
            self.usbcmd.write(cmd);
            let mut timeout = 10000;
            while self.usbsts.read() & USBSTS_HCH == 0 {
                core::hint::spin_loop();
                timeout -= 1;
                if timeout == 0 {
                    return Err("UHCI: controller did not halt");
                }
            }

            cmd = self.usbcmd.read();
            cmd |= USBCMD_HCRESET;
            self.usbcmd.write(cmd);
            let mut reset_ok = false;
            for _ in 0..10000 {
                if self.usbcmd.read() & USBCMD_HCRESET == 0 {
                    reset_ok = true;
                    break;
                }
                core::hint::spin_loop();
            }
            if !reset_ok {
                return Err("UHCI: controller reset timed out");
            }

            // Initialize ports
            for i in 0..self.max_ports {
                let portsc = self.read_portsc(i);
                self.ports.push(UhciPort {
                    port_num: i,
                    enabled: (portsc & PORTSC_PE) != 0,
                    connected: (portsc & PORTSC_CCS) != 0,
                    low_speed: (portsc & PORTSC_LSDA) != 0,
                });
            }

            // Initialize frame list
            self.init_frame_list()?;

            // Enable interrupts
            self.usbintr
                .write(USBSTS_USBINT | USBSTS_USBERR | USBSTS_RD);

            // Start the controller
            cmd = self.usbcmd.read();
            cmd |= USBCMD_RUN_STOP | USBCMD_CONFIGURE | USBCMD_MAX_PACKET;
            self.usbcmd.write(cmd);
        }
        Ok(())
    }

    /// Initializes frame list.
    unsafe fn init_frame_list(&mut self) -> Result<(), &'static str> {
        // Allocate frame list (4KB aligned, 1024 entries for 1ms frames)
        let frame = allocate_zeroed_frame().ok_or("Failed to allocate frame list")?;
        self.frame_list_phys = frame.start_address.as_u64();
        self.frame_list = phys_to_virt(self.frame_list_phys) as *mut u32;
        core::ptr::write_bytes(self.frame_list as *mut u8, 0, 4096);

        // Set up frame list (all entries point to termination)
        for i in 0..1024 {
            *self.frame_list.add(i) = 0x0001; // Terminate bit
        }

        self.frbaseaddr
            .write((self.frame_list_phys & 0xFFFFF000) as u32);

        Ok(())
    }

    /// Reads portsc.
    unsafe fn read_portsc(&self, port: usize) -> u16 {
        let mut port_reg = Port::new(self.io_base + UHCI_PORTSC + (port as u16) * 2);
        port_reg.read()
    }

    /// Writes portsc.
    unsafe fn write_portsc(&self, port: usize, val: u16) {
        let mut port_reg = Port::new(self.io_base + UHCI_PORTSC + (port as u16) * 2);
        port_reg.write(val);
    }

    /// Performs the port count operation.
    pub fn port_count(&self) -> usize {
        self.max_ports
    }

    /// Returns whether port connected.
    pub fn is_port_connected(&self, port: usize) -> bool {
        if port >= self.ports.len() {
            return false;
        }
        self.ports[port].connected
    }

    /// Returns whether low speed.
    pub fn is_low_speed(&self, port: usize) -> bool {
        if port >= self.ports.len() {
            return false;
        }
        self.ports[port].low_speed
    }

    /// Reset a port and wait for enable.
    unsafe fn reset_port(&self, port: usize) -> bool {
        let mut portsc = self.read_portsc(port);
        if portsc & PORTSC_CCS == 0 {
            return false;
        }

        // Port reset
        self.write_portsc(port, portsc | PORTSC_PR);
        for _ in 0..10_000u32 {
            core::hint::spin_loop();
        }
        self.write_portsc(port, self.read_portsc(port) & !PORTSC_PR);
        for _ in 0..10_000u32 {
            core::hint::spin_loop();
        }

        // Wait for port enable
        for _ in 0..100_000u32 {
            portsc = self.read_portsc(port);
            if portsc & PORTSC_PE != 0 {
                return true;
            }
            if portsc & PORTSC_CCS == 0 {
                return false;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// Execute a USB control transfer via a frame list slot.
    unsafe fn ctrl_transfer(
        &mut self,
        port: usize,
        setup_data: &[u8; 8],
        data_buf: Option<&mut [u8]>,
        data_len: usize,
        device_addr: u8,
        max_packet: u32,
        low_speed: bool,
    ) -> Result<usize, &'static str> {
        // Allocate QH
        let qh_frame = allocate_zeroed_frame().ok_or("UHCI: QH alloc failed")?;
        let qh_phys = qh_frame.start_address.as_u64();
        let qh_virt = phys_to_virt(qh_phys) as *mut UhciQH;

        // Allocate setup TD
        let td_setup_frame = allocate_zeroed_frame().ok_or("UHCI: TD alloc failed")?;
        let td_setup_phys = td_setup_frame.start_address.as_u64();
        let td_setup_virt = phys_to_virt(td_setup_phys) as *mut UhciTD;

        // Allocate setup buffer
        let setup_buf_frame = allocate_zeroed_frame().ok_or("UHCI: setup buf alloc failed")?;
        let setup_buf_phys = setup_buf_frame.start_address.as_u64();
        let setup_buf_virt = phys_to_virt(setup_buf_phys) as *mut u8;
        core::ptr::copy_nonoverlapping(setup_data.as_ptr(), setup_buf_virt, 8);

        let dir_in = (setup_data[0] & 0x80) != 0;
        let has_data = data_buf.is_some();
        let ls_flag = if low_speed { TD_TOKEN_LS } else { 0 };

        // Setup TD: PID_SETUP=0x2D, 8 bytes
        let setup_pid: u32 = 0x2D;
        (*td_setup_virt).link_ptr = 0; // link to next TD (set below)
        (*td_setup_virt).ctrl_status = (1u32 << 23) // ACTIVE
            | (3u32 << 27) // error count = 3
            | (1u32 << 24); // IOC
        (*td_setup_virt).token = ls_flag
            | (device_addr as u32 & 0x7F)
            | (0u32 << 15) // endpoint 0
            | (setup_pid << 0)
            | (1u32 << 19) // data toggle = 0 (DATA0)
            | ((8u32 & 0x7FF) << 16);
        (*td_setup_virt).buffer = setup_buf_phys as u32;

        let mut last_td_phys = td_setup_phys;

        if has_data && data_len > 0 {
            // Allocate data buffer
            let data_buf_frame =
                allocate_zeroed_frame().ok_or("UHCI: data buf alloc failed")?;
            let data_buf_phys_addr = data_buf_frame.start_address.as_u64();
            let data_buf_virt_addr = phys_to_virt(data_buf_phys_addr) as *mut u8;

            if !dir_in {
                if let Some(ref buf) = data_buf {
                    core::ptr::copy_nonoverlapping(buf.as_ptr(), data_buf_virt_addr, data_len);
                }
            }

            // Data TD
            let td_data_frame =
                allocate_zeroed_frame().ok_or("UHCI: data TD alloc failed")?;
            let td_data_phys = td_data_frame.start_address.as_u64();
            let td_data_virt = phys_to_virt(td_data_phys) as *mut UhciTD;

            let data_pid: u32 = if dir_in { 0x69 } else { 0xE1 }; // IN or OUT
            (*td_data_virt).link_ptr = 0;
            (*td_data_virt).ctrl_status = (1u32 << 23) | (3u32 << 27) | (1u32 << 24);
            (*td_data_virt).token = ls_flag
                | (device_addr as u32 & 0x7F)
                | (0u32 << 15)
                | (data_pid << 0)
                | (1u32 << 19) // data toggle = 1 (DATA1)
                | (((data_len as u32) & 0x7FF) << 16);
            (*td_data_virt).buffer = data_buf_phys_addr as u32;

            // Status TD
            let td_status_frame =
                allocate_zeroed_frame().ok_or("UHCI: status TD alloc failed")?;
            let td_status_phys = td_status_frame.start_address.as_u64();
            let td_status_virt = phys_to_virt(td_status_phys) as *mut UhciTD;

            let status_pid: u32 = if dir_in { 0xE1 } else { 0x69 }; // opposite direction
            (*td_status_virt).link_ptr = 0;
            (*td_status_virt).ctrl_status = (1u32 << 23) | (3u32 << 27) | (1u32 << 24);
            (*td_status_virt).token = ls_flag
                | (device_addr as u32 & 0x7F)
                | (0u32 << 15)
                | (status_pid << 0)
                | (1u32 << 19) // data toggle = 0
                | (0u32 << 16); // 0 bytes
            (*td_status_virt).buffer = 0;

            // Chain TDs
            (*td_setup_virt).link_ptr = (td_data_phys as u32) | TD_LINK_VF;
            (*td_data_virt).link_ptr = (td_status_phys as u32) | TD_LINK_VF;
        } else {
            // Status-only TD
            let td_status_frame =
                allocate_zeroed_frame().ok_or("UHCI: status TD alloc failed")?;
            let td_status_phys = td_status_frame.start_address.as_u64();
            let td_status_virt = phys_to_virt(td_status_phys) as *mut UhciTD;

            let status_pid: u32 = if dir_in { 0xE1 } else { 0x69 };
            (*td_status_virt).link_ptr = 0;
            (*td_status_virt).ctrl_status = (1u32 << 23) | (3u32 << 27) | (1u32 << 24);
            (*td_status_virt).token = ls_flag
                | (device_addr as u32 & 0x7F)
                | (0u32 << 15)
                | (status_pid << 0)
                | (1u32 << 19)
                | (0u32 << 16);
            (*td_status_virt).buffer = 0;

            (*td_setup_virt).link_ptr = (td_status_phys as u32) | TD_LINK_VF;
        }

        // Set up QH
        (*qh_virt).head_link = 0x0000_0002; // terminate
        (*qh_virt).element_link = td_setup_phys as u32;

        // Point frame 0 to QH
        let frame_idx = self.frnum.read() as usize % 1024;
        let old_frame = core::ptr::read_volatile(self.frame_list.add(frame_idx));
        core::ptr::write_volatile(
            self.frame_list.add(frame_idx),
            (qh_phys as u32 & 0xFFFFFFFE) | TD_LINK_QH,
        );

        // Wait for completion
        let mut transferred = 0;
        for _ in 0..1_000_000u32 {
            let token = core::ptr::read_volatile(core::ptr::addr_of!((*td_setup_virt).token));
            if token & TD_TOKEN_ACTIVE == 0 {
                if dir_in && has_data && data_len > 0 {
                    if let Some(buf) = data_buf {
                        // Read from data TD's buffer
                        let data_td_virt =
                            phys_to_virt(((*td_setup_virt).link_ptr & TD_LINK_PTR_MASK) as u64)
                                as *const UhciTD;
                        let data_buf_ptr =
                            phys_to_virt((*data_td_virt).buffer as u64)
                                as *const u8;
                        core::ptr::copy_nonoverlapping(data_buf_ptr, buf.as_mut_ptr(), data_len);
                        transferred = data_len;
                    }
                }
                break;
            }
            core::hint::spin_loop();
        }

        // Restore frame list
        core::ptr::write_volatile(self.frame_list.add(frame_idx), old_frame);

        Ok(transferred)
    }

    /// Enumerate connected ports and hand off HID devices.
    fn enumerate_all_ports(&mut self) {
        let mut usb_address: u8 = 1;

        for port in 0..self.max_ports {
            let portsc = unsafe { self.read_portsc(port) };
            if portsc & PORTSC_CCS == 0 {
                continue;
            }

            log::info!("[UHCI] Port {} connected, resetting...", port);

            if !unsafe { self.reset_port(port) } {
                log::warn!("[UHCI] Port {} reset failed", port);
                continue;
            }

            let low_speed = unsafe { self.is_low_speed(port) };
            let max_packet: u32 = if low_speed { 8 } else { 64 };
            log::info!(
                "[UHCI] Port {} low_speed={} max_pkt={}",
                port,
                low_speed,
                max_packet
            );

            // Set address
            let addr = usb_address;
            let ctrl_dev_addr = [0x00u8, 0x05, addr, 0x00, 0x00, 0x00, 0x00, 0x00];
            if unsafe {
                self.ctrl_transfer(
                    port,
                    &ctrl_dev_addr,
                    None,
                    0,
                    0,
                    max_packet,
                    low_speed,
                )
            }
            .is_err()
            {
                log::warn!("[UHCI] Port {} set address failed", port);
                continue;
            }
            usb_address += 1;

            // Get device descriptor
            let mut setup = [0x80u8, 0x06, 0x00, 0x01, 0x00, 0x00, 18, 0x00];
            let mut dev_desc = [0u8; 18];
            if unsafe {
                self.ctrl_transfer(
                    port,
                    &setup,
                    Some(&mut dev_desc),
                    18,
                    addr,
                    max_packet,
                    low_speed,
                )
            }
            .is_ok()
            {
                let vid = u16::from_le_bytes([dev_desc[2], dev_desc[3]]);
                let pid = u16::from_le_bytes([dev_desc[4], dev_desc[5]]);
                let dev_class = dev_desc[4];
                let max_pkt0 = u16::from_le_bytes([dev_desc[7], dev_desc[8]]);
                log::info!(
                    "[UHCI] Device: VID={:04x} PID={:04x} class={:02x} max_pkt0={}",
                    vid,
                    pid,
                    dev_class,
                    max_pkt0
                );

                crate::hardware::usb::hid::enumerate_device(port, addr as u8, &dev_desc);
            } else {
                log::warn!("[UHCI] Port {} get device descriptor failed", port);
            }
        }
    }
}

static UHCI_CONTROLLERS: Mutex<Vec<Arc<UhciController>>> = Mutex::new(Vec::new());
static UHCI_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Performs the init operation.
pub fn init() {
    log::info!("[UHCI] Scanning for UHCI controllers...");

    let candidates = pci::probe_all(ProbeCriteria {
        vendor_id: None,
        device_id: None,
        class_code: Some(0x0C),
        subclass: Some(0x03),
        prog_if: Some(0x00),
    });

    for pci_dev in candidates.into_iter() {
        log::info!(
            "UHCI: Found controller at {:?} (VEN:{:04x} DEV:{:04x})",
            pci_dev.address,
            pci_dev.vendor_id,
            pci_dev.device_id
        );

        pci_dev.enable_bus_master();

        match unsafe { UhciController::new(pci_dev) } {
            Ok(controller) => {
                log::info!("[UHCI] Initialized with {} ports", controller.port_count());
                UHCI_CONTROLLERS.lock().push(controller);
            }
            Err(e) => {
                log::warn!("UHCI: Failed to initialize controller: {}", e);
            }
        }
    }

    UHCI_INITIALIZED.store(true, Ordering::SeqCst);
    log::info!(
        "[UHCI] Found {} controller(s)",
        UHCI_CONTROLLERS.lock().len()
    );
}

/// Returns controller.
pub fn get_controller(index: usize) -> Option<Arc<UhciController>> {
    UHCI_CONTROLLERS.lock().get(index).cloned()
}

/// Returns whether available.
pub fn is_available() -> bool {
    UHCI_INITIALIZED.load(Ordering::Relaxed)
}
