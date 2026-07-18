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
    hardware::pci_client::{self as pci, Bar, ProbeCriteria},
    memory::{allocate_zeroed_frame, paging, phys_to_virt},
};
use alloc::{sync::Arc, vec::Vec};
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
    /// Creates a new instance.
    pub unsafe fn new(pci_dev: pci::PciDevice) -> Result<Arc<Self>, &'static str> {
        let bar = match pci_dev.read_bar(0) {
            Some(Bar::Memory32 { addr, .. }) => addr as u64,
            _ => return Err("Invalid BAR"),
        };

        paging::ensure_identity_map_range(bar, EHCI_MMIO_SIZE as u64);

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

    /// Performs the init operation.
    fn init(&mut self) -> Result<(), &'static str> {
        unsafe {
            let cmd = core::ptr::addr_of_mut!((*self.op_regs).usbcmd);
            let sts = core::ptr::addr_of!((*self.op_regs).usbsts);
            let intr = core::ptr::addr_of_mut!((*self.op_regs).usbintr);
            let cfg = core::ptr::addr_of_mut!((*self.op_regs).config_flag);

            // Stop the controller
            cmd.write_volatile(cmd.read_volatile() & !USBCMD_RUN_STOP);
            for _ in 0..100_000u32 {
                if sts.read_volatile() & USBSTS_HCH != 0 {
                    break;
                }
                core::hint::spin_loop();
            }
            if sts.read_volatile() & USBSTS_HCH == 0 {
                return Err("EHCI: halt timeout");
            }

            // Reset the controller
            cmd.write_volatile(cmd.read_volatile() | USBCMD_HCRST);
            for _ in 0..100_000u32 {
                if cmd.read_volatile() & USBCMD_HCRST == 0 {
                    break;
                }
                core::hint::spin_loop();
            }
            if cmd.read_volatile() & USBCMD_HCRST != 0 {
                return Err("EHCI: reset timeout");
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
            intr.write_volatile(USBSTS_INT | USBSTS_ERR | USBSTS_PCD);

            // Start the controller
            cmd.write_volatile(
                cmd.read_volatile() | USBCMD_RUN_STOP | USBCMD_PSE | USBCMD_ASE | USBCMD_INTE,
            );
            cfg.write_volatile(1);
        }
        Ok(())
    }

    /// Initializes schedules.
    unsafe fn init_schedules(&mut self) -> Result<(), &'static str> {
        // Allocate periodic list (4KB aligned, 1024 entries)
        let periodic_frame = allocate_zeroed_frame().ok_or("Failed to allocate periodic list")?;
        self.periodic_list_phys = periodic_frame.start_address.as_u64();
        self.periodic_list = phys_to_virt(self.periodic_list_phys) as *mut u32;
        core::ptr::write_bytes(self.periodic_list as *mut u8, 0, 4096);

        // Allocate async list (32-byte aligned)
        let async_frame = allocate_zeroed_frame().ok_or("Failed to allocate async list")?;
        self.async_list_phys = async_frame.start_address.as_u64();
        self.async_list = phys_to_virt(self.async_list_phys) as *mut u32;
        core::ptr::write_bytes(self.async_list as *mut u8, 0, 4096);

        // Set up async list (empty, points to itself)
        core::ptr::write_volatile(self.async_list, (self.async_list_phys as u32) & 0xFFFFFFE0);

        let plb = core::ptr::addr_of_mut!((*self.op_regs).periodic_list_base);
        let alb = core::ptr::addr_of_mut!((*self.op_regs).async_list_base);
        plb.write_volatile(self.periodic_list_phys as u32);
        alb.write_volatile(self.async_list_phys as u32);

        Ok(())
    }

    /// Reads portsc.
    unsafe fn read_portsc(&self, port: usize) -> u32 {
        let portsc_ptr = core::ptr::addr_of!((*self.port_regs).portsc[port]) as *const u32;
        portsc_ptr.read_volatile()
    }

    /// Writes portsc.
    unsafe fn write_portsc(&self, port: usize, val: u32) {
        let portsc_ptr = core::ptr::addr_of!((*self.port_regs).portsc[port]) as *mut u32;
        portsc_ptr.write_volatile(val);
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

    /// Returns port speed.
    pub fn get_port_speed(&self, port: usize) -> u8 {
        if port >= self.ports.len() {
            return 0;
        }
        self.ports[port].speed
    }

    /// Reset a port and wait for enable.
    unsafe fn reset_port(&self, port: usize) -> bool {
        let mut portsc = self.read_portsc(port);
        if portsc & PORTSC_CCS == 0 {
            return false;
        }

        // Port reset
        portsc = self.read_portsc(port);
        self.write_portsc(port, portsc | PORTSC_PR);
        for _ in 0..10_000u32 {
            core::hint::spin_loop();
        }
        portsc = self.read_portsc(port);
        self.write_portsc(port, portsc & !PORTSC_PR);
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

    /// Execute a USB control transfer on the async schedule.
    ///
    /// Builds a QH + TD chain in the async schedule, rings the doorbell,
    /// and polls for completion.
    unsafe fn ctrl_transfer(
        &self,
        port: usize,
        setup_data: &[u8; 8],
        data_buf: Option<&mut [u8]>,
        data_len: usize,
        device_addr: u8,
        max_packet: u32,
    ) -> Result<usize, &'static str> {
        // Allocate QH (32-byte aligned)
        let qh_frame = allocate_zeroed_frame().ok_or("EHCI: QH alloc failed")?;
        let qh_phys = qh_frame.start_address.as_u64();
        let qh_virt = phys_to_virt(qh_phys) as *mut u32;

        // Allocate TD (32-byte aligned)
        let td_frame = allocate_zeroed_frame().ok_or("EHCI: TD alloc failed")?;
        let td_phys = td_frame.start_address.as_u64();
        let td_virt = phys_to_virt(td_phys) as *mut u32;

        // Allocate setup buffer
        let setup_frame = allocate_zeroed_frame().ok_or("EHCI: setup buf alloc failed")?;
        let setup_buf_phys = setup_frame.start_address.as_u64();
        let setup_buf_virt = phys_to_virt(setup_buf_phys) as *mut u8;
        core::ptr::copy_nonoverlapping(setup_data.as_ptr(), setup_buf_virt, 8);

        let dir_in = (setup_data[0] & 0x80) != 0;
        let has_data = data_buf.is_some();

        // Build QH for control transfer (head of async schedule)
        // QH layout (32 bytes):
        //   [0] next QH (terminate)
        //   [1] next alt QH (terminate)
        //   [2] token (active, data toggle=0)
        //   [3] buffer pointer 0 (setup)
        let endpoint = (1u32) << 16 // endpoint 0
            | (max_packet & 0x7FF) << 16
            | (device_addr as u32 & 0x7F);
        qh_virt.add(0).write_volatile(0x0000_0002); // next: terminate
        qh_virt.add(1).write_volatile(0x0000_0002); // alt next: terminate
        qh_virt.add(2).write_volatile(td_phys as u32); // current TD
        // Endpoint characteristics
        qh_virt
            .add(4)
            .write_volatile((device_addr as u32) | (0u32 << 15) | (max_packet << 16));
        qh_virt.add(5).write_volatile(0); // hub info
        qh_virt.add(6).write_volatile(0); // split info
        qh_virt.add(7).write_volatile(0); // hub mult

        // Build setup TD
        // TD token: [2] = active, data toggle=0, 8 bytes, setup
        let setup_token = (1u32 << 31) // active
            | (0u32 << 30) // data toggle = 0
            | (0u32 << 16) // CERR = 3
            | (3u32 << 10) // ISO=0, IOC=0, bytes 11:10 = 0
            | (0u32 << 8) // CERR = 3
            | (8u32); // 8 bytes
        // Proper token: bit31=active, bit30=toggle(0), bits27:26=CERR(3), bits25:16=total bytes(8)
        let setup_token = (1u32 << 31) | (0u32 << 30) | (3u32 << 26) | (8u32 << 16);
        td_virt.add(0).write_volatile(0x0000_0002); // next: terminate
        td_virt.add(1).write_volatile(0x0000_0002); // alt next: terminate
        td_virt.add(2).write_volatile(setup_token);
        td_virt.add(3).write_volatile(setup_buf_phys as u32);

        if has_data && data_len > 0 {
            // Allocate data buffer
            let data_frame =
                allocate_zeroed_frame().ok_or("EHCI: data buf alloc failed")?;
            let data_buf_phys = data_frame.start_address.as_u64();
            let data_buf_virt = phys_to_virt(data_buf_phys) as *mut u8;

            if !dir_in {
                if let Some(buf) = data_buf {
                    core::ptr::copy_nonoverlapping(buf.as_ptr(), data_buf_virt, data_len);
                }
            }

            // Data TD
            let data_token = (1u32 << 31) // active
                | (1u32 << 30) // data toggle = 1
                | (3u32 << 26) // CERR = 3
                | ((data_len as u32) << 16); // bytes
            td_virt.add(4).write_volatile(0x0000_0002); // next: terminate
            td_virt.add(5).write_volatile(0x0000_0002); // alt next
            td_virt.add(6).write_volatile(data_token);
            td_virt.add(7).write_volatile(data_buf_phys as u32);

            // Status TD (toggle=0, one byte, IOC)
            let status_token = (1u32 << 31) // active
                | (0u32 << 30) // data toggle = 0
                | (3u32 << 26) // CERR = 3
                | (0u32 << 16) // 0 bytes
                | (1u32 << 24); // IOC
            td_virt.add(8).write_volatile(0x0000_0002); // next: terminate
            td_virt.add(9).write_volatile(0x0000_0002); // alt next
            td_virt.add(10).write_volatile(status_token);
            td_virt.add(11).write_volatile(0);

            // Chain: setup TD -> data TD -> status TD
            td_virt.add(0).write_volatile(td_phys + 32); // next = data TD
            td_virt.add(4).write_volatile(td_phys + 64); // next = status TD
        } else {
            // Status-only transfer (toggle=0, IOC)
            let status_token = (1u32 << 31) // active
                | (1u32 << 30) // data toggle = 1 (for status stage)
                | (3u32 << 26) // CERR = 3
                | (0u32 << 16) // 0 bytes
                | (1u32 << 24); // IOC
            td_virt.add(4).write_volatile(0x0000_0002); // next: terminate
            td_virt.add(5).write_volatile(0x0000_0002); // alt next
            td_virt.add(6).write_volatile(status_token);
            td_virt.add(7).write_volatile(0);

            // Chain: setup TD -> status TD
            td_virt.add(0).write_volatile(td_phys + 32); // next = status TD
        }

        // Link QH into async schedule (prepend)
        let async_head = self.async_list;
        let old_next = core::ptr::read_volatile(async_head) & 0xFFFFFFE0;
        qh_virt.add(0).write_volatile(old_next | 0x02); // point to old head
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        core::ptr::write_volatile(
            async_head,
            (qh_phys as u32 & 0xFFFFFFE0) | 0x02, // new head points to QH
        );

        // Enable async schedule
        let cmd = core::ptr::addr_of!((*self.op_regs).usbcmd);
        cmd.write_volatile(cmd.read_volatile() | USBCMD_ASE);
        for _ in 0..10_000u32 {
            core::hint::spin_loop();
        }

        // Poll for completion (TD inactive)
        let mut transferred = 0;
        for _ in 0..1_000_000u32 {
            let token = core::ptr::read_volatile(td_virt.add(2));
            if token & (1u32 << 31) == 0 {
                // TD completed
                if dir_in && has_data && data_len > 0 {
                    if let Some(buf) = data_buf {
                        let src = phys_to_virt(setup_buf_phys + 8) as *const u8;
                        core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), data_len);
                        transferred = data_len;
                    }
                }
                break;
            }
            core::hint::spin_loop();
        }

        // Disable async schedule and unlink
        cmd.write_volatile(cmd.read_volatile() & !USBCMD_ASE);
        for _ in 0..10_000u32 {
            core::hint::spin_loop();
        }
        core::ptr::write_volatile(async_head, old_next | 0x02);

        Ok(transferred)
    }

    /// Enumerate connected ports and hand off HID devices.
    fn enumerate_all_ports(&self) {
        let mut usb_address: u8 = 1;

        for port in 0..self.max_ports {
            let portsc = unsafe { self.read_portsc(port) };
            if portsc & PORTSC_CCS == 0 {
                continue;
            }

            log::info!("[EHCI] Port {} connected, resetting...", port);

            if !unsafe { self.reset_port(port) } {
                log::warn!("[EHCI] Port {} reset failed", port);
                continue;
            }

            let speed = unsafe { ((self.read_portsc(port) >> PORTSC_SPEED_SHIFT) & 0x03) as u8 };
            let max_packet: u32 = if speed == SPEED_HIGH { 64 } else { 8 };
            log::info!("[EHCI] Port {} speed={} max_pkt={}", port, speed, max_packet);

            // Get device descriptor (first 8 bytes to learn max_packet0)
            let mut setup = [0x80u8, 0x06, 0x00, 0x01, 0x00, 0x00, 8, 0x00];
            let mut dev_desc_short = [0u8; 8];
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
                )
            }
            .is_err()
            {
                log::warn!("[EHCI] Port {} set address failed", port);
                continue;
            }
            usb_address += 1;

            if unsafe {
                self.ctrl_transfer(
                    port,
                    &setup,
                    Some(&mut dev_desc_short),
                    8,
                    addr,
                    max_packet,
                )
            }
            .is_ok()
            {
                let vid = u16::from_le_bytes([dev_desc_short[2], dev_desc_short[3]]);
                let pid = u16::from_le_bytes([dev_desc_short[4], dev_desc_short[5]]);
                let dev_class = dev_desc_short[4];
                let max_pkt0 = u16::from_le_bytes([dev_desc_short[7], dev_desc_short[8]]);
                log::info!(
                    "[EHCI] Device: VID={:04x} PID={:04x} class={:02x} max_pkt0={}",
                    vid,
                    pid,
                    dev_class,
                    max_pkt0
                );

                // Get full 18-byte device descriptor
                let mut dev_desc = [0u8; 18];
                setup[6] = 18;
                let _ = unsafe {
                    self.ctrl_transfer(
                        port,
                        &setup,
                        Some(&mut dev_desc),
                        18,
                        addr,
                        max_pkt0 as u32,
                    )
                };

                crate::hardware::usb::hid::enumerate_device(port, addr as u8, &dev_desc);
            } else {
                log::warn!("[EHCI] Port {} get device descriptor failed", port);
            }
        }
    }
}

static EHCI_CONTROLLERS: Mutex<Vec<Arc<EhciController>>> = Mutex::new(Vec::new());
static EHCI_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Performs the init operation.
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
                controller.enumerate_all_ports();
                EHCI_CONTROLLERS.lock().push(controller);
            }
            Err(e) => {
                log::warn!("EHCI: Failed to initialize controller: {}", e);
            }
        }
    }

    EHCI_INITIALIZED.store(true, Ordering::SeqCst);
    log::info!(
        "[EHCI] Found {} controller(s)",
        EHCI_CONTROLLERS.lock().len()
    );
}

/// Returns controller.
pub fn get_controller(index: usize) -> Option<Arc<EhciController>> {
    EHCI_CONTROLLERS.lock().get(index).cloned()
}

/// Returns whether available.
pub fn is_available() -> bool {
    EHCI_INITIALIZED.load(Ordering::Relaxed)
}
