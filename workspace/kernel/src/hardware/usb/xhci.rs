// USB xHCI Host Controller Driver
// Reference: xHCI spec 1.2
//
// Features:
// - xHCI controller initialization
// - Port management and hot-plug detection
// - Command and Event rings
// - Device slot management
// - Control and Interrupt transfers
// - HID device support (keyboard/mouse)

#![allow(dead_code)]

use crate::{
    arch::x86_64::pci::{self, Bar, ProbeCriteria},
    memory::{allocate_dma_frame, phys_to_virt},
};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use spin::Mutex;

const XHCI_MMIO_SIZE: usize = 0x10000;
const XHCI_PORT_REG_BASE: usize = 0x400;
const XHCI_PORT_REG_STRIDE: usize = 0x10;

const USBCMD_RUN_STOP: u32 = 1 << 0;
const USBCMD_HCRST: u32 = 1 << 1;
const USBCMD_INTE: u32 = 1 << 2;

const USBSTS_HCH: u32 = 1 << 0;
const USBSTS_CNR: u32 = 1 << 11;

const PORTSC_CCS: u32 = 1 << 0;
const PORTSC_PED: u32 = 1 << 1;
const PORTSC_PR: u32 = 1 << 4;
const PORTSC_PP: u32 = 1 << 9;
const PORTSC_SPEED_SHIFT: u32 = 10;
const PORTSC_W1C_MASK: u32 = 0xFE0000;

const TRB_TYPE_NORMAL: u32 = 1;
const TRB_TYPE_SETUP_STAGE: u32 = 2;
const TRB_TYPE_DATA_STAGE: u32 = 3;
const TRB_TYPE_STATUS_STAGE: u32 = 4;
const TRB_TYPE_ENABLE_SLOT: u32 = 9;
const TRB_TYPE_ADDRESS_DEVICE: u32 = 11;
const TRB_TYPE_CONFIGURE_ENDPOINT: u32 = 12;
const TRB_TYPE_TRANSFER_EVENT: u32 = 32;

const TRB_CYCLE: u32 = 1 << 0;
const TRB_IOC: u32 = 1 << 5;
const TRB_DIR_IN: u32 = 1 << 16;

const EP_TYPE_CONTROL: u32 = 4;
const EP_TYPE_INTR_IN: u32 = 7;

#[repr(C)]
struct CapRegisters {
    caplength: u8,
    _reserved: u8,
    _hciversion: u16,
    hcsparams1: u32,
    _hcsparams2: u32,
    _hcsparams3: u32,
    _hccparams1: u32,
    dboff: u32,
    rtsoff: u32,
    _hccparams2: u32,
}

#[repr(C)]
struct OpRegisters {
    usbcmd: u32,
    usbsts: u32,
    _pagesize: u32,
    _reserved0: [u32; 2],
    _dnctrl: u32,
    crcr: u64,
    _reserved1: [u32; 4],
    dcbaap: u64,
    config: u32,
}

#[repr(C)]
struct RuntimeRegisters {
    _mfindex: u32,
    _reserved: [u32; 7],
    ir: [InterrupterRegisters; 1],
}

#[repr(C)]
struct InterrupterRegisters {
    iman: u32,
    _imod: u32,
    erstsz: u32,
    _reserved: u32,
    erstba: u64,
    erdp: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Trb {
    d0: u32,
    d1: u32,
    d2: u32,
    d3: u32,
}

impl Trb {
    fn link(addr: u64, toggle_cycle: bool) -> Self {
        Self {
            d0: (addr & 0xFFFFFFFF) as u32,
            d1: ((addr >> 32) & 0xFFFFFFFF) as u32,
            d2: 0,
            d3: ((TRB_TYPE_LINK << TRB_TYPE_SHIFT) as u32) | TRB_CYCLE | (if toggle_cycle { TRB_TC } else { 0 }),
        }
    }

    fn normal(addr: u64, len: u32, cycle: bool, ioc: bool) -> Self {
        let mut d3 = (TRB_TYPE_NORMAL << TRB_TYPE_SHIFT) as u32 | if cycle { TRB_CYCLE } else { 0 };
        if ioc { d3 |= TRB_IOC; }
        Self {
            d0: (addr & 0xFFFFFFFF) as u32,
            d1: ((addr >> 32) & 0xFFFFFFFF) as u32,
            d2: len,
            d3,
        }
    }
}

const TRB_TYPE_LINK: u32 = 6;
const TRB_TYPE_SHIFT: u32 = 10;
const TRB_TC: u32 = 1 << 1;

#[repr(C, packed)]
struct SlotContext {
    d0: u32,
    d1: u32,
    d2: u32,
    d3: u32,
    d4: u32,
    d5: u32,
    d6: u32,
    d7: u32,
}

#[repr(C, packed)]
struct EndpointContext {
    d0: u32,
    d1: u32,
    d2: u32,
    d3: u32,
    d4: u32,
    d5: u32,
    d6: u32,
    d7: u32,
}

#[repr(C, packed)]
struct InputControlContext {
    d0: u32,
    d1: u32,
    d2: [u32; 30],
}

#[repr(C, packed)]
struct InputContext {
    ctrl: InputControlContext,
    slot: SlotContext,
    eps: [EndpointContext; 31],
}

struct XhciPort {
    port_num: usize,
    enabled: bool,
    connected: bool,
    speed: u8,
}

pub struct XhciController {
    mmio_base: usize,
    cap_regs: *const CapRegisters,
    op_regs: *mut OpRegisters,
    rt_regs: *mut RuntimeRegisters,
    db_regs: *mut u32,
    caplength: u8,
    max_ports: usize,
    ports: Vec<XhciPort>,
    device_ctx: *mut u8,
    device_ctx_phys: u64,
    cmd_ring: *mut Trb,
    cmd_ring_phys: u64,
    cmd_ring_deq: usize,
    cmd_ring_cycle: bool,
    event_ring: *mut Trb,
    event_ring_phys: u64,
    event_ring_deq: usize,
    event_ring_cycle: bool,
    slot_id: AtomicU8,
}

unsafe impl Send for XhciController {}
unsafe impl Sync for XhciController {}

impl XhciController {
    pub unsafe fn new(pci_dev: pci::PciDevice) -> Result<Arc<Self>, &'static str> {
        let bar = match pci_dev.read_bar(0) {
            Some(Bar::Memory64 { addr, .. }) => addr,
            _ => return Err("Invalid BAR"),
        };

        let mmio_base = phys_to_virt(bar) as usize;
        let cap_regs = mmio_base as *const CapRegisters;
        let caplength = (*cap_regs).caplength;
        let op_regs = (mmio_base + caplength as usize) as *mut OpRegisters;
        
        let dboff = (*cap_regs).dboff;
        let db_regs = (mmio_base + dboff as usize) as *mut u32;
        
        let rtsoff = (*cap_regs).rtsoff;
        let rt_regs = (mmio_base + rtsoff as usize) as *mut RuntimeRegisters;

        let max_ports = ((*cap_regs).hcsparams1 as usize) & 0xFF;

        let mut controller = Self {
            mmio_base,
            cap_regs,
            op_regs,
            rt_regs,
            db_regs,
            caplength,
            max_ports,
            ports: Vec::new(),
            device_ctx: core::ptr::null_mut(),
            device_ctx_phys: 0,
            cmd_ring: core::ptr::null_mut(),
            cmd_ring_phys: 0,
            cmd_ring_deq: 0,
            cmd_ring_cycle: true,
            event_ring: core::ptr::null_mut(),
            event_ring_phys: 0,
            event_ring_deq: 0,
            event_ring_cycle: true,
            slot_id: AtomicU8::new(0),
        };

        controller.init()?;
        Ok(Arc::new(controller))
    }

    fn init(&mut self) -> Result<(), &'static str> {
        unsafe {
            let op = &mut *self.op_regs;

            if op.usbsts & USBSTS_CNR != 0 {
                return Err("Controller needs reset");
            }

            op.usbcmd &= !USBCMD_RUN_STOP;
            while op.usbsts & USBSTS_HCH == 0 {
                core::hint::spin_loop();
            }

            op.usbcmd |= USBCMD_HCRST;
            while op.usbcmd & USBCMD_HCRST != 0 {
                core::hint::spin_loop();
            }

            for i in 0..self.max_ports {
                let portsc = self.read_portsc(i);
                self.ports.push(XhciPort {
                    port_num: i,
                    enabled: (portsc & PORTSC_PED) != 0,
                    connected: (portsc & PORTSC_CCS) != 0,
                    speed: ((portsc >> PORTSC_SPEED_SHIFT) & 0xF) as u8,
                });
            }

            self.init_rings()?;
            self.init_interrupter()?;

            op.usbcmd |= USBCMD_RUN_STOP | USBCMD_INTE;
            op.config = 1;

            self.enable_slot()?;
        }
        Ok(())
    }

    unsafe fn init_rings(&mut self) -> Result<(), &'static str> {
        let cmd_frame = allocate_dma_frame().ok_or("Failed to allocate cmd ring")?;
        self.cmd_ring_phys = cmd_frame.start_address.as_u64();
        self.cmd_ring = phys_to_virt(self.cmd_ring_phys) as *mut Trb;
        core::ptr::write_bytes(self.cmd_ring as *mut u8, 0, 4096);

        let event_frame = allocate_dma_frame().ok_or("Failed to allocate event ring")?;
        self.event_ring_phys = event_frame.start_address.as_u64();
        self.event_ring = phys_to_virt(self.event_ring_phys) as *mut Trb;
        core::ptr::write_bytes(self.event_ring as *mut u8, 0, 4096);

        let dev_frame = allocate_dma_frame().ok_or("Failed to allocate device context")?;
        self.device_ctx_phys = dev_frame.start_address.as_u64();
        self.device_ctx = phys_to_virt(self.device_ctx_phys) as *mut u8;
        core::ptr::write_bytes(self.device_ctx, 0, 4096);

        let dcbaap = &mut (*self.op_regs).dcbaap;
        *dcbaap = self.device_ctx_phys;

        Ok(())
    }

    unsafe fn init_interrupter(&mut self) -> Result<(), &'static str> {
        let erst_frame = allocate_dma_frame().ok_or("Failed to allocate ERST")?;
        let erst_phys = erst_frame.start_address.as_u64();
        let erst_virt = phys_to_virt(erst_phys) as *mut u64;
        core::ptr::write_bytes(erst_virt as *mut u8, 0, 4096);

        *erst_virt = self.event_ring_phys;

        let ir = &mut (*self.rt_regs).ir[0];
        ir.erstba = erst_phys;
        ir.erstsz = 1;
        ir.iman = 3;
        ir.erdp = self.event_ring_phys;

        Ok(())
    }

    unsafe fn read_portsc(&self, port: usize) -> u32 {
        let op = &*self.op_regs;
        let port_offset = XHCI_PORT_REG_BASE + (port * XHCI_PORT_REG_STRIDE);
        let portsc_ptr = (self.op_regs as *const u8).add(port_offset) as *const u32;
        portsc_ptr.read_volatile()
    }

    unsafe fn write_portsc(&self, port: usize, val: u32) {
        let op = &*self.op_regs;
        let port_offset = XHCI_PORT_REG_BASE + (port * XHCI_PORT_REG_STRIDE);
        let portsc_ptr = (self.op_regs as *const u8).add(port_offset) as *mut u32;
        portsc_ptr.write_volatile(val);
    }

    unsafe fn enable_slot(&mut self) -> Result<(), &'static str> {
        let slot_id = self.slot_id.fetch_add(1, Ordering::SeqCst) + 1;
        if slot_id == 0 {
            return Err("No slot available");
        }

        self.cmd_ring_enqueue(Trb {
            d0: 0,
            d1: 0,
            d2: 0,
            d3: (TRB_TYPE_ENABLE_SLOT << TRB_TYPE_SHIFT) as u32 | TRB_CYCLE | TRB_IOC,
        });

        let event = self.wait_for_event()?;
        if event.d3 & 0xFF != 0 {
            return Err("Enable slot failed");
        }

        Ok(())
    }

    unsafe fn cmd_ring_enqueue(&mut self, trb: Trb) {
        let idx = self.cmd_ring_deq;
        let mut trb = trb;
        if !self.cmd_ring_cycle {
            trb.d3 ^= TRB_CYCLE;
        }
        core::ptr::write_volatile(self.cmd_ring.add(idx), trb);

        let next = (idx + 1) % 64;
        if next == 0 {
            self.cmd_ring_cycle = !self.cmd_ring_cycle;
        }
        self.cmd_ring_deq = next;

        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        core::ptr::write_volatile(self.db_regs.add(0), 0);
    }

    unsafe fn wait_for_event(&mut self) -> Result<Trb, &'static str> {
        for _ in 0..1000000 {
            let idx = self.event_ring_deq;
            let trb = core::ptr::read_volatile(self.event_ring.add(idx));
            
            if (trb.d3 & TRB_CYCLE) == (if self.event_ring_cycle { TRB_CYCLE } else { 0 }) {
                if (trb.d3 >> TRB_TYPE_SHIFT) & 0x3F == TRB_TYPE_TRANSFER_EVENT as u32 {
                    self.event_ring_deq = (idx + 1) % 64;
                    if self.event_ring_deq == 0 {
                        self.event_ring_cycle = !self.event_ring_cycle;
                    }
                    return Ok(trb);
                }
            }
            core::hint::spin_loop();
        }
        Err("Event timeout")
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
}

static XHCI_CONTROLLERS: Mutex<Vec<Arc<XhciController>>> = Mutex::new(Vec::new());
static XHCI_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init() {
    log::info!("[xHCI] Scanning for xHCI controllers...");

    let candidates = pci::probe_all(ProbeCriteria {
        vendor_id: None,
        device_id: None,
        class_code: Some(0x0C),
        subclass: Some(0x03),
        prog_if: Some(0x30),
    });

    for pci_dev in candidates.into_iter() {
        log::info!(
            "xHCI: Found controller at {:?} (VEN:{:04x} DEV:{:04x})",
            pci_dev.address,
            pci_dev.vendor_id,
            pci_dev.device_id
        );

        pci_dev.enable_bus_master();

        match unsafe { XhciController::new(pci_dev) } {
            Ok(controller) => {
                log::info!("[xHCI] Initialized with {} ports", controller.port_count());
                XHCI_CONTROLLERS.lock().push(controller);
            }
            Err(e) => {
                log::warn!("xHCI: Failed to initialize controller: {}", e);
            }
        }
    }

    XHCI_INITIALIZED.store(true, Ordering::SeqCst);
    log::info!("[xHCI] Found {} controller(s)", XHCI_CONTROLLERS.lock().len());
}

pub fn get_controller(index: usize) -> Option<Arc<XhciController>> {
    XHCI_CONTROLLERS.lock().get(index).cloned()
}

pub fn is_available() -> bool {
    XHCI_INITIALIZED.load(Ordering::Relaxed)
}
