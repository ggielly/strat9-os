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
    arch::x86_64::pci::{self, Bar, ProbeCriteria},
    memory::{allocate_dma_frame, phys_to_virt},
};
use alloc::sync::Arc;
use alloc::vec::Vec;
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

    fn init(&mut self) -> Result<(), &'static str> {
        unsafe {
            // Stop the controller
            let mut cmd = self.usbcmd.read();
            cmd &= !USBCMD_RUN_STOP;
            self.usbcmd.write(cmd);
            while self.usbsts.read() & USBSTS_HCH == 0 {
                core::hint::spin_loop();
            }

            // Reset the controller
            cmd = self.usbcmd.read();
            cmd |= USBCMD_HCRESET;
            self.usbcmd.write(cmd);
            for _ in 0..1000 {
                if self.usbcmd.read() & USBCMD_HCRESET == 0 {
                    break;
                }
                core::hint::spin_loop();
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
            self.usbintr.write(USBSTS_USBINT | USBSTS_USBERR | USBSTS_RD);

            // Start the controller
            cmd = self.usbcmd.read();
            cmd |= USBCMD_RUN_STOP | USBCMD_EGSM | USBCMD_CONFIGURE | USBCMD_MAX_PACKET;
            self.usbcmd.write(cmd);
        }
        Ok(())
    }

    unsafe fn init_frame_list(&mut self) -> Result<(), &'static str> {
        // Allocate frame list (4KB aligned, 1024 entries for 1ms frames)
        let frame = allocate_dma_frame().ok_or("Failed to allocate frame list")?;
        self.frame_list_phys = frame.start_address.as_u64();
        self.frame_list = phys_to_virt(self.frame_list_phys) as *mut u32;
        core::ptr::write_bytes(self.frame_list as *mut u8, 0, 4096);

        // Set up frame list (all entries point to termination)
        for i in 0..1024 {
            *self.frame_list.add(i) = 0x0001; // Terminate bit
        }

        self.frbaseaddr.write((self.frame_list_phys & 0xFFFFF000) as u32);

        Ok(())
    }

    unsafe fn read_portsc(&self, port: usize) -> u16 {
        let mut port_reg = Port::new(self.io_base + UHCI_PORTSC + (port as u16) * 2);
        port_reg.read()
    }

    unsafe fn write_portsc(&self, port: usize, val: u16) {
        let mut port_reg = Port::new(self.io_base + UHCI_PORTSC + (port as u16) * 2);
        port_reg.write(val);
    }

    pub fn port_count(&self) -> usize {
        self.max_ports
    }

    pub fn is_port_connected(&self, port: usize) -> bool {
        if port >= self.ports.len() {
            return false;
        }
        self.ports[port].connected
    }

    pub fn is_low_speed(&self, port: usize) -> bool {
        if port >= self.ports.len() {
            return false;
        }
        self.ports[port].low_speed
    }
}

static UHCI_CONTROLLERS: Mutex<Vec<Arc<UhciController>>> = Mutex::new(Vec::new());
static UHCI_INITIALIZED: AtomicBool = AtomicBool::new(false);

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
    log::info!("[UHCI] Found {} controller(s)", UHCI_CONTROLLERS.lock().len());
}

pub fn get_controller(index: usize) -> Option<Arc<UhciController>> {
    UHCI_CONTROLLERS.lock().get(index).cloned()
}

pub fn is_available() -> bool {
    UHCI_INITIALIZED.load(Ordering::Relaxed)
}
