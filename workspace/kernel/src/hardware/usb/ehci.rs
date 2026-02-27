// USB EHCI (Enhanced Host Controller Interface) Driver
// Reference: EHCI spec 1.0 (USB 2.0)
//
// Features:
// - EHCI controller initialization
// - Port management
// - Periodic and asynchronous schedules
// - High-speed USB 2.0 support

#![allow(dead_code)]

use crate::{
    arch::x86_64::pci::{self, Bar, ProbeCriteria},
    memory::{allocate_dma_frame, phys_to_virt},
};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

const EHCI_MMIO_SIZE: usize = 0x1000;

const USBCMD_RUN_STOP: u32 = 1 << 0;
const USBCMD_HCRST: u32 = 1 << 1;
const USBCMD_INTE: u32 = 1 << 2;
const USBCMD_PSE: u32 = 1 << 4;
const USBCMD_ASE: u32 = 1 << 5;

const USBSTS_INT: u32 = 1 << 0;
const USBSTS_ERR: u32 = 1 << 1;
const USBSTS_PCD: u32 = 1 << 2;
const USBSTS_HCH: u32 = 1 << 12;

const PORTSC_CCS: u32 = 1 << 0;
const PORTSC_CSC: u32 = 1 << 1;
const PORTSC_PE: u32 = 1 << 2;
const PORTSC_PEC: u32 = 1 << 3;
const PORTSC_OCA: u32 = 1 << 4;
const PORTSC_OCC: u32 = 1 << 5;
const PORTSC_FPR: u32 = 1 << 6;
const PORTSC_SUSP: u32 = 1 << 7;
const PORTSC_PR: u32 = 1 << 8;
const PORTSC_PP: u32 = 1 << 12;
const PORTSC_SPEED_SHIFT: u32 = 26;
const PORTSC_SPEED_MASK: u32 = 0x03 << PORTSC_SPEED_SHIFT;

const SPEED_FULL: u32 = 0;
const SPEED_LOW: u32 = 1;
const SPEED_HIGH: u32 = 2;

#[repr(C)]
struct EhciCapRegisters {
    caplength: u8,
    _reserved: u8,
    hciversion: u16,
    hcsparams1: u32,
    hcsparams2: u32,
    hccparams: u32,
}

#[repr(C)]
struct EhciOpRegisters {
    usbcmd: u32,
    usbsts: u32,
    usbintr: u32,
    frindex: u32,
    ctrl_ds_seg: u32,
    periodic_list_base: u32,
    async_list_base: u32,
    _reserved: [u32; 9],
    config_flag: u32,
}

#[repr(C)]
struct EhciPortRegisters {
    portsc: [u32; 16],
}

pub struct EhciPort {
    port_num: usize,
    enabled: bool,
    connected: bool,
    speed: u8,
}

pub struct EhciController {
    mmio_base: usize,
    cap_regs: *const EhciCapRegisters,
    op_regs: *mut EhciOpRegisters,
    port_regs: *mut EhciPortRegisters,
    max_ports: usize,
    ports: Vec<EhciPort>,
    periodic_list: *mut u32,
    periodic_list_phys: u64,
    async_list: *mut u32,
    async_list_phys: u64,
}

unsafe impl Send for EhciController {}
unsafe impl Sync for EhciController {}

impl EhciController {
    pub unsafe fn new(pci_dev: pci::PciDevice) -> Result<Arc<Self>, &'static str> {
        let bar = match pci_dev.read_bar(0) {
            Some(Bar::Memory32 { addr, .. }) => addr as u64,
            _ => return Err("Invalid BAR"),
        };

        let mmio_base = phys_to_virt(bar) as usize;
        let cap_regs = mmio_base as *const EhciCapRegisters;
        let caplength = (*cap_regs).caplength;
        let op_regs = (mmio_base + caplength as usize) as *mut EhciOpRegisters;
        let port_regs = (mmio_base + caplength as usize + 0x44) as *mut EhciPortRegisters;

        let max_ports = ((*cap_regs).hcsparams1 as usize) & 0xF;

        let mut controller = Self {
            mmio_base,
            cap_regs,
            op_regs,
            port_regs,
            max_ports,
            ports: Vec::new(),
            periodic_list: core::ptr::null_mut(),
            periodic_list_phys: 0,
            async_list: core::ptr::null_mut(),
            async_list_phys: 0,
        };

        controller.init()?;
        Ok(Arc::new(controller))
    }

    fn init(&mut self) -> Result<(), &'static str> {
        unsafe {
            let op = &mut *self.op_regs;

            // Stop the controller
            op.usbcmd &= !USBCMD_RUN_STOP;
            while op.usbsts & USBSTS_HCH == 0 {
                core::hint::spin_loop();
            }

            // Reset the controller
            op.usbcmd |= USBCMD_HCRST;
            while op.usbcmd & USBCMD_HCRST != 0 {
                core::hint::spin_loop();
            }

            // Initialize ports
            for i in 0..self.max_ports {
                let portsc = self.read_portsc(i);
                self.ports.push(EhciPort {
                    port_num: i,
                    enabled: (portsc & PORTSC_PE) != 0,
                    connected: (portsc & PORTSC_CCS) != 0,
                    speed: ((portsc >> PORTSC_SPEED_SHIFT) & 0x03) as u8,
                });
            }

            // Initialize schedules
            self.init_schedules()?;

            // Enable interrupts
            op.usbintr = USBSTS_INT | USBSTS_ERR | USBSTS_PCD;

            // Start the controller
            op.usbcmd |= USBCMD_RUN_STOP | USBCMD_PSE | USBCMD_ASE | USBCMD_INTE;
            op.config_flag = 1;
        }
        Ok(())
    }

    unsafe fn init_schedules(&mut self) -> Result<(), &'static str> {
        // Allocate periodic list (4KB aligned, 1024 entries)
        let periodic_frame = allocate_dma_frame().ok_or("Failed to allocate periodic list")?;
        self.periodic_list_phys = periodic_frame.start_address.as_u64();
        self.periodic_list = phys_to_virt(self.periodic_list_phys) as *mut u32;
        core::ptr::write_bytes(self.periodic_list as *mut u8, 0, 4096);

        // Allocate async list (32-byte aligned)
        let async_frame = allocate_dma_frame().ok_or("Failed to allocate async list")?;
        self.async_list_phys = async_frame.start_address.as_u64();
        self.async_list = phys_to_virt(self.async_list_phys) as *mut u32;
        core::ptr::write_bytes(self.async_list as *mut u8, 0, 4096);

        // Set up async list (empty, points to itself)
        *self.async_list = (self.async_list_phys as u32) & 0xFFFFFFE0;

        let op = &mut *self.op_regs;
        op.periodic_list_base = self.periodic_list_phys as u32;
        op.async_list_base = self.async_list_phys as u32;

        Ok(())
    }

    unsafe fn read_portsc(&self, port: usize) -> u32 {
        let portsc_ptr = core::ptr::addr_of!((*self.port_regs).portsc[port]) as *const u32;
        portsc_ptr.read_volatile()
    }

    unsafe fn write_portsc(&self, port: usize, val: u32) {
        let portsc_ptr = core::ptr::addr_of!((*self.port_regs).portsc[port]) as *mut u32;
        portsc_ptr.write_volatile(val);
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

    pub fn get_port_speed(&self, port: usize) -> u8 {
        if port >= self.ports.len() {
            return 0;
        }
        self.ports[port].speed
    }
}

static EHCI_CONTROLLERS: Mutex<Vec<Arc<EhciController>>> = Mutex::new(Vec::new());
static EHCI_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init() {
    log::info!("[EHCI] Scanning for EHCI controllers...");

    let candidates = pci::probe_all(ProbeCriteria {
        vendor_id: None,
        device_id: None,
        class_code: Some(0x0C),
        subclass: Some(0x03),
        prog_if: Some(0x20),
    });

    for pci_dev in candidates.into_iter() {
        log::info!(
            "EHCI: Found controller at {:?} (VEN:{:04x} DEV:{:04x})",
            pci_dev.address,
            pci_dev.vendor_id,
            pci_dev.device_id
        );

        pci_dev.enable_bus_master();

        match unsafe { EhciController::new(pci_dev) } {
            Ok(controller) => {
                log::info!("[EHCI] Initialized with {} ports", controller.port_count());
                EHCI_CONTROLLERS.lock().push(controller);
            }
            Err(e) => {
                log::warn!("EHCI: Failed to initialize controller: {}", e);
            }
        }
    }

    EHCI_INITIALIZED.store(true, Ordering::SeqCst);
    log::info!("[EHCI] Found {} controller(s)", EHCI_CONTROLLERS.lock().len());
}

pub fn get_controller(index: usize) -> Option<Arc<EhciController>> {
    EHCI_CONTROLLERS.lock().get(index).cloned()
}

pub fn is_available() -> bool {
    EHCI_INITIALIZED.load(Ordering::Relaxed)
}
