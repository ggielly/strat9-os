// USB xHCI Host Controller Driver
// Reference: xHCI spec 1.2
//
// Features:
// - xHCI controller initialization with full device enumeration
// - Port reset, Enable Slot, Address Device, Configure Endpoint
// - Per-device transfer rings and DCBAA contexts
// - Control transfers via per-device EP0 transfer rings
// - Interrupt transfer support for HID polling
// - HID device support (keyboard/mouse)

#![allow(dead_code)]

use crate::{
    hardware::pci_client::{self as pci, Bar, ProbeCriteria},
    memory::{allocate_zeroed_frame, paging, phys_to_virt},
};
use alloc::{sync::Arc, vec::Vec};
use core::{
    ptr::{read_volatile, write_volatile},
    sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
};
use spin::Mutex;

const XHCI_MMIO_SIZE: usize = 0x10000;
const XHCI_PORT_REG_BASE: usize = 0x400;
const XHCI_PORT_REG_STRIDE: usize = 0x10;
const XHCI_RING_TRBS: usize = 64;
const MAX_ENDPOINTS: usize = 31;

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
const TRB_TYPE_LINK: u32 = 6;

const TRB_CYCLE: u32 = 1 << 0;
const TRB_IOC: u32 = 1 << 5;
const TRB_DIR_IN: u32 = 1 << 16;
const TRB_DIR_OUT: u32 = 0;
const TRB_TC: u32 = 1 << 1;

const TRB_TYPE_SHIFT: u32 = 10;
const TRB_IDT: u32 = 1 << 6;
const TRB_TD_SIZE_SHIFT: u32 = 17;
const TRB_TD_SIZE_MASK: u32 = 0x1F;

const EP_TYPE_CONTROL: u32 = 4;
const EP_TYPE_INTR_IN: u32 = 7;

const fn TRB_GET_TYPE(d3: u32) -> u32 {
    (d3 >> TRB_TYPE_SHIFT) & 0xFF
}

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
            d3: ((TRB_TYPE_LINK << TRB_TYPE_SHIFT) as u32)
                | TRB_CYCLE
                | (if toggle_cycle { TRB_TC } else { 0 }),
        }
    }

    fn normal(addr: u64, len: u32, cycle: bool, ioc: bool) -> Self {
        let mut d3 =
            (TRB_TYPE_NORMAL << TRB_TYPE_SHIFT) as u32 | if cycle { TRB_CYCLE } else { 0 };
        if ioc {
            d3 |= TRB_IOC;
        }
        Self {
            d0: (addr & 0xFFFFFFFF) as u32,
            d1: ((addr >> 32) & 0xFFFFFFFF) as u32,
            d2: len,
            d3,
        }
    }

    fn setup_stage(addr: u64, cycle: bool) -> Self {
        let mut d3 =
            (TRB_TYPE_SETUP_STAGE << TRB_TYPE_SHIFT) as u32 | if cycle { TRB_CYCLE } else { 0 };
        d3 |= TRB_IDT;
        Self {
            d0: (addr & 0xFFFFFFFF) as u32,
            d1: ((addr >> 32) & 0xFFFFFFFF) as u32,
            d2: 8,
            d3,
        }
    }

    fn data_stage(addr: u64, len: u32, dir_in: bool, cycle: bool, ioc: bool) -> Self {
        let mut d3 =
            (TRB_TYPE_DATA_STAGE << TRB_TYPE_SHIFT) as u32 | if cycle { TRB_CYCLE } else { 0 };
        if dir_in {
            d3 |= TRB_DIR_IN;
        }
        if ioc {
            d3 |= TRB_IOC;
        }
        let td_size = ((len + TRB_TD_SIZE_MASK) / (TRB_TD_SIZE_MASK + 1)) & TRB_TD_SIZE_MASK;
        let d2 = (td_size << TRB_TD_SIZE_SHIFT) | len;
        Self {
            d0: (addr & 0xFFFFFFFF) as u32,
            d1: ((addr >> 32) & 0xFFFFFFFF) as u32,
            d2,
            d3,
        }
    }

    fn status_stage(cycle: bool, dir_in: bool) -> Self {
        let mut d3 =
            (TRB_TYPE_STATUS_STAGE << TRB_TYPE_SHIFT) as u32 | if cycle { TRB_CYCLE } else { 0 };
        if dir_in {
            d3 |= TRB_DIR_IN;
        }
        d3 |= TRB_IOC;
        Self {
            d0: 0,
            d1: 0,
            d2: 0,
            d3,
        }
    }
}

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

struct DeviceSlot {
    slot_id: u8,
    usb_address: u8,
    input_ctx: *mut InputContext,
    input_ctx_phys: u64,
    ep_transfer_rings: [*mut Trb; MAX_ENDPOINTS],
    ep_transfer_ring_phys: [u64; MAX_ENDPOINTS],
    ep_dequeue: [usize; MAX_ENDPOINTS],
    ep_cycle: [bool; MAX_ENDPOINTS],
    configured: bool,
    ep_buf: [*mut u8; MAX_ENDPOINTS],
    ep_buf_phys: [u64; MAX_ENDPOINTS],
    ep_buf_len: [usize; MAX_ENDPOINTS],
    ep_active: [bool; MAX_ENDPOINTS],
}

unsafe impl Send for DeviceSlot {}
unsafe impl Sync for DeviceSlot {}

impl DeviceSlot {
    fn new(slot_id: u8) -> Self {
        Self {
            slot_id,
            usb_address: 0,
            input_ctx: core::ptr::null_mut(),
            input_ctx_phys: 0,
            ep_transfer_rings: [core::ptr::null_mut(); MAX_ENDPOINTS],
            ep_transfer_ring_phys: [0; MAX_ENDPOINTS],
            ep_dequeue: [0; MAX_ENDPOINTS],
            ep_cycle: [true; MAX_ENDPOINTS],
            configured: false,
            ep_buf: [core::ptr::null_mut(); MAX_ENDPOINTS],
            ep_buf_phys: [0; MAX_ENDPOINTS],
            ep_buf_len: [0; MAX_ENDPOINTS],
            ep_active: [false; MAX_ENDPOINTS],
        }
    }
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
    event_ring_deq: AtomicUsize,
    event_ring_cycle: AtomicBool,
    slot_id: AtomicU8,
    ctrl_transfer_buf: *mut u8,
    ctrl_transfer_buf_phys: u64,
    device_slots: Vec<Option<DeviceSlot>>,
}

unsafe impl Send for XhciController {}
unsafe impl Sync for XhciController {}

impl XhciController {
    pub unsafe fn new(pci_dev: pci::PciDevice) -> Result<Self, &'static str> {
        let bar = match pci_dev.read_bar(0) {
            Some(Bar::Memory64 { addr, .. }) => addr,
            _ => return Err("Invalid BAR"),
        };
        paging::ensure_identity_map_range(bar, XHCI_MMIO_SIZE as u64);

        let mmio_base = phys_to_virt(bar) as usize;
        let cap_regs = mmio_base as *const CapRegisters;
        let caplength = (*cap_regs).caplength;
        let op_regs = (mmio_base + caplength as usize) as *mut OpRegisters;

        let dboff = (*cap_regs).dboff;
        let db_regs = (mmio_base + dboff as usize) as *mut u32;

        let rtsoff = (*cap_regs).rtsoff;
        let rt_regs = (mmio_base + rtsoff as usize) as *mut RuntimeRegisters;

        let max_ports = (((*cap_regs).hcsparams1 >> 24) & 0xFF) as usize;

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
            event_ring_deq: AtomicUsize::new(0),
            event_ring_cycle: AtomicBool::new(true),
            slot_id: AtomicU8::new(0),
            ctrl_transfer_buf: core::ptr::null_mut(),
            ctrl_transfer_buf_phys: 0,
            device_slots: Vec::new(),
        };

        controller.init()?;
        Ok(controller)
    }

    fn init(&mut self) -> Result<(), &'static str> {
        unsafe {
            for _ in 0..100_000 {
                if self.read_usbsts() & USBSTS_CNR == 0 {
                    break;
                }
                core::hint::spin_loop();
            }
            if self.read_usbsts() & USBSTS_CNR != 0 {
                return Err("xHCI: controller not ready (CNR)");
            }

            let mut usbcmd = self.read_usbcmd();
            usbcmd &= !USBCMD_RUN_STOP;
            self.write_usbcmd(usbcmd);
            for _ in 0..100_000 {
                if self.read_usbsts() & USBSTS_HCH != 0 {
                    break;
                }
                core::hint::spin_loop();
            }
            if self.read_usbsts() & USBSTS_HCH == 0 {
                return Err("xHCI: controller did not halt");
            }

            self.write_usbcmd(self.read_usbcmd() | USBCMD_HCRST);
            for _ in 0..100_000 {
                if self.read_usbcmd() & USBCMD_HCRST == 0 {
                    break;
                }
                core::hint::spin_loop();
            }
            if self.read_usbcmd() & USBCMD_HCRST != 0 {
                return Err("xHCI: controller reset timed out");
            }
            let mut cnr_timeout = 1_000_000u32;
            while self.read_usbsts() & USBSTS_CNR != 0 {
                if cnr_timeout == 0 {
                    return Err("xHCI: CNR did not clear after reset");
                }
                cnr_timeout -= 1;
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
            self.init_ctrl_transfer_buf()?;

            let max_slots = self.max_device_slots();
            self.write_config(max_slots);
            self.write_usbcmd(self.read_usbcmd() | USBCMD_RUN_STOP | USBCMD_INTE);

            self.enumerate_all_ports();
        }
        Ok(())
    }

    unsafe fn init_rings(&mut self) -> Result<(), &'static str> {
        let cmd_frame = allocate_zeroed_frame().ok_or("Failed to allocate cmd ring")?;
        self.cmd_ring_phys = cmd_frame.start_address.as_u64();
        self.cmd_ring = phys_to_virt(self.cmd_ring_phys) as *mut Trb;
        core::ptr::write_bytes(self.cmd_ring as *mut u8, 0, 4096);
        core::ptr::write(
            self.cmd_ring.add(XHCI_RING_TRBS - 1),
            Trb::link(self.cmd_ring_phys, true),
        );
        self.write_crcr(self.cmd_ring_phys | 1);

        let event_frame = allocate_zeroed_frame().ok_or("Failed to allocate event ring")?;
        self.event_ring_phys = event_frame.start_address.as_u64();
        self.event_ring = phys_to_virt(self.event_ring_phys) as *mut Trb;
        core::ptr::write_bytes(self.event_ring as *mut u8, 0, 4096);

        let dev_frame = allocate_zeroed_frame().ok_or("Failed to allocate DCBAA")?;
        self.device_ctx_phys = dev_frame.start_address.as_u64();
        self.device_ctx = phys_to_virt(self.device_ctx_phys) as *mut u8;
        core::ptr::write_bytes(self.device_ctx, 0, 4096);
        self.write_dcbaap(self.device_ctx_phys);

        Ok(())
    }

    unsafe fn init_interrupter(&mut self) -> Result<(), &'static str> {
        let erst_frame = allocate_zeroed_frame().ok_or("Failed to allocate ERST")?;
        let erst_phys = erst_frame.start_address.as_u64();
        let erst_virt = phys_to_virt(erst_phys) as *mut u64;
        core::ptr::write_bytes(erst_virt as *mut u8, 0, 4096);

        let erst_entry = erst_virt as *mut u8;
        let addr_bytes = self.event_ring_phys.to_le_bytes();
        core::ptr::copy_nonoverlapping(addr_bytes.as_ptr(), erst_entry, 8);
        let seg_size: u32 = XHCI_RING_TRBS as u32;
        let size_bytes = seg_size.to_le_bytes();
        core::ptr::copy_nonoverlapping(size_bytes.as_ptr(), erst_entry.add(8), 4);

        let ir = &mut (*self.rt_regs).ir[0];
        write_volatile(core::ptr::addr_of_mut!(ir.erstsz), 1);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        write_volatile(core::ptr::addr_of_mut!(ir.erstba), erst_phys);
        write_volatile(core::ptr::addr_of_mut!(ir.erdp), self.event_ring_phys);
        write_volatile(core::ptr::addr_of_mut!(ir.iman), 3);

        Ok(())
    }

    unsafe fn init_ctrl_transfer_buf(&mut self) -> Result<(), &'static str> {
        let buf_frame = allocate_zeroed_frame().ok_or("Failed to allocate ctrl buf")?;
        self.ctrl_transfer_buf_phys = buf_frame.start_address.as_u64();
        self.ctrl_transfer_buf = phys_to_virt(self.ctrl_transfer_buf_phys) as *mut u8;
        core::ptr::write_bytes(self.ctrl_transfer_buf, 0, 4096);
        Ok(())
    }

    unsafe fn read_portsc(&self, port: usize) -> u32 {
        let port_offset = XHCI_PORT_REG_BASE + (port * XHCI_PORT_REG_STRIDE);
        let portsc_ptr = (self.op_regs as *const u8).add(port_offset) as *const u32;
        portsc_ptr.read_volatile()
    }

    unsafe fn write_portsc(&self, port: usize, val: u32) {
        let port_offset = XHCI_PORT_REG_BASE + (port * XHCI_PORT_REG_STRIDE);
        let portsc_ptr = (self.op_regs as *const u8).add(port_offset) as *mut u32;
        portsc_ptr.write_volatile(val);
    }

    unsafe fn read_usbcmd(&self) -> u32 {
        read_volatile(core::ptr::addr_of!((*self.op_regs).usbcmd))
    }

    unsafe fn write_usbcmd(&self, value: u32) {
        write_volatile(core::ptr::addr_of_mut!((*self.op_regs).usbcmd), value);
    }

    unsafe fn read_usbsts(&self) -> u32 {
        read_volatile(core::ptr::addr_of!((*self.op_regs).usbsts))
    }

    unsafe fn write_crcr(&self, value: u64) {
        write_volatile(core::ptr::addr_of_mut!((*self.op_regs).crcr), value);
    }

    unsafe fn write_dcbaap(&self, value: u64) {
        write_volatile(core::ptr::addr_of_mut!((*self.op_regs).dcbaap), value);
    }

    unsafe fn write_config(&self, value: u32) {
        write_volatile(core::ptr::addr_of_mut!((*self.op_regs).config), value);
    }

    fn max_device_slots(&self) -> u32 {
        unsafe { read_volatile(core::ptr::addr_of!((*self.cap_regs).hcsparams1)) & 0xFF }
    }

    fn max_ports_from_hw(&self) -> u32 {
        unsafe { (read_volatile(core::ptr::addr_of!((*self.cap_regs).hcsparams1)) >> 24) & 0xFF }
    }

    unsafe fn cmd_ring_enqueue(&mut self, trb: Trb) {
        let idx = self.cmd_ring_deq;
        let mut trb = trb;
        if self.cmd_ring_cycle {
            trb.d3 |= TRB_CYCLE;
        } else {
            trb.d3 &= !TRB_CYCLE;
        }
        core::ptr::write_volatile(self.cmd_ring.add(idx), trb);
        self.cmd_ring_deq = idx + 1;

        if self.cmd_ring_deq >= 63 {
            let link = Trb::link(self.cmd_ring_phys, true);
            let mut link_trb = link;
            if self.cmd_ring_cycle {
                link_trb.d3 |= TRB_CYCLE;
            } else {
                link_trb.d3 &= !TRB_CYCLE;
            }
            core::ptr::write_volatile(self.cmd_ring.add(63), link_trb);
            self.cmd_ring_deq = 0;
            self.cmd_ring_cycle = !self.cmd_ring_cycle;
        }

        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        core::ptr::write_volatile(self.db_regs.add(0), 0);
    }

    unsafe fn wait_for_event(&mut self) -> Result<Trb, &'static str> {
        for _ in 0..1000000 {
            let idx = self.event_ring_deq.load(Ordering::Acquire);
            let trb = core::ptr::read_volatile(self.event_ring.add(idx));

            let expected_c = if self.event_ring_cycle.load(Ordering::Acquire) {
                TRB_CYCLE
            } else {
                0
            };
            if (trb.d3 & TRB_CYCLE) == expected_c {
                let new_deq = (idx + 1) % 64;
                self.event_ring_deq.store(new_deq, Ordering::Release);
                if new_deq == 0 {
                    self.event_ring_cycle.store(
                        !self.event_ring_cycle.load(Ordering::Acquire),
                        Ordering::Release,
                    );
                }
                let ir = &mut (*self.rt_regs).ir[0];
                ir.erdp = (self.event_ring_phys + (new_deq as u64) * 16) | (1 << 3);
                return Ok(trb);
            }
            core::hint::spin_loop();
        }
        Err("Event timeout")
    }

    unsafe fn ring_doorbell(&self, slot_id: u8, endpoint: u8) {
        let db_index = (slot_id as usize) * 32 + (endpoint as usize);
        core::ptr::write_volatile(self.db_regs.add(db_index), 0);
    }

    unsafe fn alloc_input_context(&mut self, slot_id: u8) -> Result<(), &'static str> {
        let frame = allocate_zeroed_frame().ok_or("Failed to allocate input context")?;
        let phys = frame.start_address.as_u64();
        let virt = phys_to_virt(phys) as *mut InputContext;

        let idx = slot_id as usize;
        if idx >= self.device_slots.len() {
            self.device_slots.resize_with(idx + 1, || None);
        }
        let dev = self.device_slots[idx].as_mut().unwrap();
        dev.input_ctx = virt;
        dev.input_ctx_phys = phys;

        let dcbaa = self.device_ctx as *mut u64;
        dcbaa.add(idx as usize).write_volatile(phys);

        Ok(())
    }

    unsafe fn alloc_transfer_ring(
        &mut self,
        slot_id: u8,
        endpoint: u8,
    ) -> Result<(), &'static str> {
        let frame = allocate_zeroed_frame().ok_or("Failed to allocate transfer ring")?;
        let phys = frame.start_address.as_u64();
        let virt = phys_to_virt(phys) as *mut Trb;

        core::ptr::write_bytes(virt as *mut u8, 0, 4096);
        core::ptr::write(
            virt.add(XHCI_RING_TRBS - 1),
            Trb::link(phys, true),
        );

        let idx = slot_id as usize;
        if idx < self.device_slots.len() {
            if let Some(ref mut dev) = self.device_slots[idx] {
                let ep = endpoint as usize;
                if ep < MAX_ENDPOINTS {
                    dev.ep_transfer_rings[ep] = virt;
                    dev.ep_transfer_ring_phys[ep] = phys;
                    dev.ep_dequeue[ep] = 0;
                    dev.ep_cycle[ep] = true;
                }
            }
        }
        Ok(())
    }

    unsafe fn write_endpoint_context(
        &self,
        slot_id: u8,
        endpoint: u8,
        tr_phys: u64,
        max_packet: u32,
        ep_type: u32,
        interval: u32,
    ) {
        let dcbaa = self.device_ctx as *mut u64;
        let ctx_addr = dcbaa.add(slot_id as usize).read_volatile() as *mut u8;
        if ctx_addr.is_null() {
            return;
        }

        let ep_offset = 32 * ((endpoint - 1) as usize) + 32;
        let ep_ctx = ctx_addr.add(ep_offset) as *mut EndpointContext;

        let d0 = (ep_type & 0x7) << 3 | 0;
        let d1 = (max_packet & 0x7FF) | (0 << 16);
        let d2 = (tr_phys & 0xFFFFFFFF) as u32;
        let d3 = ((tr_phys >> 32) & 0xFFFFFFFF) as u32;
        let d4 = interval & 0xFF;

        (*ep_ctx).d0 = d0;
        (*ep_ctx).d1 = d1;
        (*ep_ctx).d2 = d2;
        (*ep_ctx).d3 = d3;
        (*ep_ctx).d4 = d4;
        (*ep_ctx).d5 = 0;
        (*ep_ctx).d6 = 0;
        (*ep_ctx).d7 = 0;
    }

    unsafe fn reset_port(&self, port: usize) -> bool {
        let mut portsc = self.read_portsc(port);
        if portsc & PORTSC_CCS == 0 {
            return false;
        }

        portsc = self.read_portsc(port);
        self.write_portsc(port, portsc | PORTSC_PR);

        for _ in 0..500_000 {
            portsc = self.read_portsc(port);
            if portsc & PORTSC_PR == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        for _ in 0..500_000 {
            portsc = self.read_portsc(port);
            if portsc & PORTSC_PED != 0 {
                return true;
            }
            if portsc & PORTSC_CCS == 0 {
                return false;
            }
            core::hint::spin_loop();
        }

        self.read_portsc(port) & PORTSC_PED != 0
    }

    fn enable_slot(&mut self) -> Result<u8, &'static str> {
        unsafe {
            self.cmd_ring_enqueue(Trb {
                d0: 0,
                d1: 0,
                d2: 0,
                d3: (TRB_TYPE_ENABLE_SLOT << TRB_TYPE_SHIFT) as u32,
            });

            let event = self.wait_for_event()?;
            let completion_code = (event.d2 >> 24) & 0xFF;
            if completion_code != 1 {
                log::warn!("[xHCI] Enable Slot failed: completion={}", completion_code);
                return Err("Enable slot failed");
            }
            let slot_id = ((event.d3 >> 24) & 0xFF) as u8;
            if slot_id == 0 {
                return Err("No slot available");
            }
            self.slot_id.store(slot_id, Ordering::SeqCst);

            let idx = slot_id as usize;
            if idx >= self.device_slots.len() {
                self.device_slots.resize_with(idx + 1, || None);
            }
            self.device_slots[idx] = Some(DeviceSlot::new(slot_id));

            self.alloc_input_context(slot_id)?;
            self.alloc_transfer_ring(slot_id, 1)?;

            let slot_ctx = &mut (*self.device_slots[idx].as_ref().unwrap().input_ctx).slot;
            slot_ctx.d0 = (1 << 27) | (slot_id as u32);
            slot_ctx.d1 = 0;
            slot_ctx.d2 = 0;

            self.write_endpoint_context(
                slot_id,
                1,
                self.device_slots[idx].as_ref().unwrap().ep_transfer_ring_phys[1],
                8,
                EP_TYPE_CONTROL,
                0,
            );

            log::info!("[xHCI] Enable Slot: slot_id={}", slot_id);
            Ok(slot_id)
        }
    }

    fn set_address(&mut self, slot_id: u8, address: u8) -> Result<(), &'static str> {
        unsafe {
            let idx = slot_id as usize;
            if idx >= self.device_slots.len() || self.device_slots[idx].is_none() {
                return Err("Invalid slot for Address Device");
            }

            let input_ctx_phys = self.device_slots[idx].as_ref().unwrap().input_ctx_phys;

            let slot_ctx = &mut (*self.device_slots[idx].as_ref().unwrap().input_ctx).slot;
            slot_ctx.d0 = (1 << 27) | (address as u32);
            slot_ctx.d1 = 0;
            slot_ctx.d2 = 0;

            self.cmd_ring_enqueue(Trb {
                d0: (input_ctx_phys & 0xFFFFFFFF) as u32,
                d1: ((input_ctx_phys >> 32) & 0xFFFFFFFF) as u32,
                d2: (slot_id as u32) << 24,
                d3: (TRB_TYPE_ADDRESS_DEVICE << TRB_TYPE_SHIFT) as u32,
            });

            let event = self.wait_for_event()?;
            let completion = (event.d2 >> 24) & 0xFF;
            if completion != 1 {
                log::warn!(
                    "[xHCI] Address Device failed: slot={} completion={}",
                    slot_id,
                    completion
                );
                return Err("Set address failed");
            }

            self.device_slots[idx].as_mut().unwrap().usb_address = address;
            log::info!(
                "[xHCI] Address Device: slot={} addr={}",
                slot_id,
                address
            );
        }
        Ok(())
    }

    pub fn setup_endpoint(
        &mut self,
        slot_id: u8,
        endpoint: u8,
        max_packet: u32,
        ep_type: u32,
        interval: u32,
        _max_burst: u32,
    ) -> Result<(), &'static str> {
        unsafe {
            let idx = slot_id as usize;
            if idx >= self.device_slots.len() || self.device_slots[idx].is_none() {
                return Err("Invalid slot for Setup Endpoint");
            }

            self.alloc_transfer_ring(slot_id, endpoint)?;

            self.write_endpoint_context(
                slot_id,
                endpoint,
                self.device_slots[idx].as_ref().unwrap().ep_transfer_ring_phys[endpoint as usize],
                max_packet,
                ep_type,
                interval,
            );

            let input_ctx_phys = self.device_slots[idx].as_ref().unwrap().input_ctx_phys;

            self.cmd_ring_enqueue(Trb {
                d0: (input_ctx_phys & 0xFFFFFFFF) as u32,
                d1: ((input_ctx_phys >> 32) & 0xFFFFFFFF) as u32,
                d2: (slot_id as u32) << 24,
                d3: (TRB_TYPE_CONFIGURE_ENDPOINT << TRB_TYPE_SHIFT) as u32,
            });

            let event = self.wait_for_event()?;
            let completion = (event.d2 >> 24) & 0xFF;
            if completion != 1 {
                log::warn!(
                    "[xHCI] Configure Endpoint failed: slot={} ep={} completion={}",
                    slot_id,
                    endpoint,
                    completion
                );
                return Err("Configure endpoint failed");
            }

            log::info!(
                "[xHCI] Endpoint configured: slot={} ep={} type={}",
                slot_id,
                endpoint,
                ep_type
            );
        }
        Ok(())
    }

    fn enumerate_all_ports(&mut self) {
        let mut usb_address: u8 = 1;

        for port in 0..self.max_ports {
            let portsc = unsafe { self.read_portsc(port) };
            let connected = (portsc & PORTSC_CCS) != 0;
            if !connected {
                continue;
            }

            log::info!("[xHCI] Port {} connected, resetting...", port);

            if !unsafe { self.reset_port(port) } {
                log::warn!("[xHCI] Port {} reset failed", port);
                continue;
            }

            let speed = unsafe { ((self.read_portsc(port) >> PORTSC_SPEED_SHIFT) & 0xF) as u8 };
            log::info!("[xHCI] Port {} speed={}", port, speed);

            match self.enable_slot() {
                Ok(slot_id) => {
                    if self.set_address(slot_id, usb_address).is_err() {
                        log::warn!("[xHCI] Port {} address failed", port);
                        continue;
                    }
                    usb_address += 1;

                    let mut dev_desc = [0u8; 18];
                    if self.get_device_descriptor(slot_id, &mut dev_desc).is_ok() {
                        let vid = u16::from_le_bytes([dev_desc[2], dev_desc[3]]);
                        let pid = u16::from_le_bytes([dev_desc[4], dev_desc[5]]);
                        let dev_class = dev_desc[4];
                        let max_packet0 = u16::from_le_bytes([dev_desc[7], dev_desc[8]]);
                        log::info!(
                            "[xHCI] Device: VID={:04x} PID={:04x} class={:02x} max_pkt0={}",
                            vid,
                            pid,
                            dev_class,
                            max_packet0
                        );

                        if max_packet0 == 64 || max_packet0 == 32 || max_packet0 == 16 || max_packet0 == 8 {
                            let idx = slot_id as usize;
                            if idx < self.device_slots.len() {
                                if let Some(ref mut dev) = self.device_slots[idx] {
                                    dev.configured = true;
                                }
                            }
                        }

                        crate::hardware::usb::hid::enumerate_device(port, slot_id, &dev_desc);
                    } else {
                        log::warn!("[xHCI] Port {} get device descriptor failed", port);
                    }
                }
                Err(e) => {
                    log::warn!("[xHCI] Port {} enable slot failed: {}", port, e);
                }
            }
        }
    }

    pub fn alloc_interrupt_buffer(
        &mut self,
        slot_id: u8,
        endpoint: u8,
        len: usize,
    ) -> Result<(*mut u8, u64), &'static str> {
        let frame =
            allocate_zeroed_frame().ok_or("Failed to allocate interrupt buffer")?;
        let phys = frame.start_address.as_u64();
        let virt = phys_to_virt(phys) as *mut u8;

        let idx = slot_id as usize;
        if idx < self.device_slots.len() {
            if let Some(ref mut dev) = self.device_slots[idx] {
                let ep = endpoint as usize;
                if ep < MAX_ENDPOINTS {
                    dev.ep_buf[ep] = virt;
                    dev.ep_buf_phys[ep] = phys;
                    dev.ep_buf_len[ep] = len;
                }
            }
        }
        Ok((virt, phys))
    }

    pub fn submit_interrupt_transfer(
        &mut self,
        slot_id: u8,
        endpoint: u8,
    ) -> Result<(), &'static str> {
        let idx = slot_id as usize;
        if idx >= self.device_slots.len() || self.device_slots[idx].is_none() {
            return Err("Invalid slot for interrupt transfer");
        }

        let ep = endpoint as usize;
        if ep >= MAX_ENDPOINTS {
            return Err("Invalid endpoint");
        }

        let dev = self.device_slots[idx].as_ref().unwrap();
        let tr_ring = dev.ep_transfer_rings[ep];
        let tr_phys = dev.ep_transfer_ring_phys[ep];
        let buf_phys = dev.ep_buf_phys[ep];
        let buf_len = dev.ep_buf_len[ep];
        if tr_ring.is_null() || buf_phys == 0 {
            return Err("No transfer ring or buffer for endpoint");
        }

        let deq = dev.ep_dequeue[ep];
        let cycle = dev.ep_cycle[ep];

        let trb = Trb::normal(buf_phys, buf_len as u32, cycle, true);
        unsafe {
            core::ptr::write_volatile(tr_ring.add(deq), trb);
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            self.ring_doorbell(slot_id, endpoint);
        }

        self.device_slots[idx].as_mut().unwrap().ep_active[ep] = true;

        Ok(())
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

    pub fn get_device_descriptor(
        &mut self,
        slot_id: u8,
        buf: &mut [u8; 18],
    ) -> Result<usize, &'static str> {
        let setup = [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 18, 0x00];
        unsafe { self.ctrl_transfer(slot_id, &setup, Some(buf), 18) }
    }

    pub fn get_configuration_descriptor(
        &mut self,
        slot_id: u8,
        config_idx: u8,
        buf: &mut [u8],
        len: usize,
    ) -> Result<usize, &'static str> {
        let setup = [
            0x80,
            0x06,
            config_idx,
            0x02,
            0x00,
            0x00,
            (len & 0xFF) as u8,
            ((len >> 8) & 0xFF) as u8,
        ];
        unsafe { self.ctrl_transfer(slot_id, &setup, Some(buf), len) }
    }

    pub fn set_configuration(&mut self, slot_id: u8, config_value: u8) -> Result<(), &'static str> {
        let setup = [0x00, 0x09, config_value, 0x00, 0x00, 0x00, 0x00, 0x00];
        unsafe { self.ctrl_transfer(slot_id, &setup, None, 0)?; }
        Ok(())
    }

    pub fn set_protocol(&mut self, slot_id: u8, interface: u8, protocol: u8) -> Result<(), &'static str> {
        let setup = [0x21, 0x0B, protocol, interface, 0x00, 0x00, 0x00, 0x00];
        unsafe { self.ctrl_transfer(slot_id, &setup, None, 0)?; }
        Ok(())
    }

    pub fn get_port_speed(&self, port: usize) -> u8 {
        if port >= self.ports.len() {
            return 0;
        }
        self.ports[port].speed
    }

    unsafe fn ctrl_transfer(
        &mut self,
        slot_id: u8,
        setup_data: &[u8; 8],
        data_buf: Option<&mut [u8]>,
        data_len: usize,
    ) -> Result<usize, &'static str> {
        let idx = slot_id as usize;
        if idx >= self.device_slots.len() || self.device_slots[idx].is_none() {
            return Err("Invalid slot for control transfer");
        }

        let dev = self.device_slots[idx].as_ref().unwrap();
        let tr_ring = dev.ep_transfer_rings[1];
        let tr_phys = dev.ep_transfer_ring_phys[1];
        if tr_ring.is_null() {
            return Err("No transfer ring for EP0");
        }

        let mut deq;
        let cycle;

        core::ptr::write_bytes(tr_ring as *mut u8, 0, 4096);
        core::ptr::write(
            tr_ring.add(XHCI_RING_TRBS - 1),
            Trb::link(tr_phys, true),
        );
        deq = 0;
        cycle = true;

        let setup_phys = self.ctrl_transfer_buf_phys;
        let setup_virt = self.ctrl_transfer_buf;
        core::ptr::copy_nonoverlapping(setup_data.as_ptr(), setup_virt, 8);

        let setup_trb = Trb::setup_stage(setup_phys, cycle);
        core::ptr::write_volatile(tr_ring.add(deq), setup_trb);
        deq += 1;

        let has_data = data_buf.is_some();
        let dir_in = if has_data {
            (setup_data[0] & 0x80) != 0
        } else {
            false
        };

        if let Some(buf) = &data_buf {
            let data_phys = self.ctrl_transfer_buf_phys + 8;
            let data_virt = self.ctrl_transfer_buf.add(8);

            if dir_in && data_len > 0 {
                core::ptr::write_bytes(data_virt, 0, data_len);
            } else if !dir_in && data_len > 0 {
                core::ptr::copy_nonoverlapping(buf.as_ptr(), data_virt, data_len);
            }

            let data_trb = Trb::data_stage(data_phys, data_len as u32, dir_in, cycle, false);
            core::ptr::write_volatile(tr_ring.add(deq), data_trb);
            deq += 1;

            let status_trb = Trb::status_stage(cycle, !dir_in);
            core::ptr::write_volatile(tr_ring.add(deq), status_trb);
            deq += 1;
        } else {
            let status_trb = Trb::status_stage(cycle, true);
            core::ptr::write_volatile(tr_ring.add(deq), status_trb);
            deq += 1;
        }

        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.ring_doorbell(slot_id, 1);

        let mut transferred = 0;
        for _ in 0..3 {
            let event = self.wait_for_event()?;
            let trb_type = TRB_GET_TYPE(event.d3);
            let completion = (event.d2 >> 24) & 0xFF;

            if completion != 1 {
                log::warn!(
                    "[xHCI] ctrl_transfer event error: type={} completion={}",
                    trb_type,
                    completion
                );
                return Err("Control transfer event error");
            }

            if trb_type == TRB_TYPE_STATUS_STAGE {
                if has_data && data_len > 0 && dir_in {
                    let data_virt = self.ctrl_transfer_buf.add(8);
                    if let Some(buf) = data_buf {
                        core::ptr::copy_nonoverlapping(data_virt, buf.as_mut_ptr(), data_len);
                    }
                    transferred = data_len;
                }
                break;
            }
        }

        self.device_slots[idx].as_mut().unwrap().ep_dequeue[1] = deq;
        self.device_slots[idx].as_mut().unwrap().ep_cycle[1] = cycle;

        Ok(transferred)
    }
}

static XHCI_CONTROLLERS: Mutex<Vec<Arc<Mutex<XhciController>>>> = Mutex::new(Vec::new());
static XHCI_INITIALIZED: AtomicBool = AtomicBool::new(false);
pub static XHCI_IRQ_LINE: AtomicU8 = AtomicU8::new(0);

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

        let irq = pci_dev.interrupt_line;
        pci_dev.enable_memory_space();
        pci_dev.enable_bus_master();

        match unsafe { XhciController::new(pci_dev) } {
            Ok(controller) => {
                log::info!("[xHCI] Initialized with {} ports", controller.port_count());
                XHCI_IRQ_LINE.store(irq, Ordering::Relaxed);
                XHCI_CONTROLLERS
                    .lock()
                    .push(Arc::new(Mutex::new(controller)));
                crate::arch::x86_64::idt::register_xhci_irq(irq);
            }
            Err(e) => {
                log::warn!("xHCI: Failed to initialize controller: {}", e);
            }
        }
    }

    XHCI_INITIALIZED.store(true, Ordering::SeqCst);
    log::info!(
        "[xHCI] Found {} controller(s)",
        XHCI_CONTROLLERS.lock().len()
    );
}

pub fn get_controller(index: usize) -> Option<Arc<Mutex<XhciController>>> {
    XHCI_CONTROLLERS.lock().get(index).cloned()
}

pub fn is_available() -> bool {
    XHCI_INITIALIZED.load(Ordering::Relaxed) && !XHCI_CONTROLLERS.lock().is_empty()
}

pub fn handle_interrupt() {
    if let Some(controller_arc) = get_controller(0) {
        let mut controller = controller_arc.lock();
        unsafe {
            let ir = &mut (*controller.rt_regs).ir[0];
            if (ir.iman & 1) != 0 {
                let mut processed = 0;
                while processed < 16 {
                    let idx = controller.event_ring_deq.load(Ordering::Acquire);
                    let trb = core::ptr::read_volatile(controller.event_ring.add(idx));

                    let expected_c = if controller.event_ring_cycle.load(Ordering::Acquire) {
                        TRB_CYCLE
                    } else {
                        0
                    };
                    if (trb.d3 & TRB_CYCLE) != expected_c {
                        break;
                    }

                    let trb_type = TRB_GET_TYPE(trb.d3);
                    match trb_type {
                        TRB_TYPE_TRANSFER_EVENT => {
                            let slot_id = ((trb.d3 >> 24) & 0xFF) as u8;
                            let ep_id = ((trb.d2 >> 16) & 0x1F) as u8;
                            let completion = (trb.d2 >> 24) & 0xFF;
                            let transferred = (trb.d2 & 0xFFFF) as usize;

                            if completion == 1 && ep_id >= 1 && (ep_id as usize) < MAX_ENDPOINTS {
                                let idx = slot_id as usize;
                                if idx < controller.device_slots.len() {
                                    if let Some(ref mut dev) = controller.device_slots[idx] {
                                        let ep = ep_id as usize;
                                        let buf = dev.ep_buf[ep];
                                        let buf_len = dev.ep_buf_len[ep];
                                        let actual_len = if transferred < buf_len { transferred } else { buf_len };

                                        if !buf.is_null() && actual_len > 0 {
                                            crate::hardware::usb::hid::receive_interrupt_report(
                                                slot_id,
                                                ep_id,
                                                buf,
                                                actual_len,
                                            );
                                        }

                                        dev.ep_dequeue[ep] = (dev.ep_dequeue[ep] + 1) % (XHCI_RING_TRBS - 1);
                                        if dev.ep_dequeue[ep] == 0 {
                                            dev.ep_cycle[ep] = !dev.ep_cycle[ep];
                                        }
                                        dev.ep_active[ep] = false;
                                    }
                                }
                            } else if completion != 1 && completion != 13 {
                                let idx = slot_id as usize;
                                if idx < controller.device_slots.len() {
                                    if let Some(ref mut dev) = controller.device_slots[idx] {
                                        let ep = ep_id as usize;
                                        if ep < MAX_ENDPOINTS {
                                            dev.ep_dequeue[ep] = (dev.ep_dequeue[ep] + 1) % (XHCI_RING_TRBS - 1);
                                            if dev.ep_dequeue[ep] == 0 {
                                                dev.ep_cycle[ep] = !dev.ep_cycle[ep];
                                            }
                                            dev.ep_active[ep] = false;
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }

                    let new_deq = (idx + 1) % 64;
                    controller.event_ring_deq.store(new_deq, Ordering::Release);
                    if new_deq == 0 {
                        controller.event_ring_cycle.store(
                            !controller.event_ring_cycle.load(Ordering::Acquire),
                            Ordering::Release,
                        );
                    }

                    let new_erdp = controller.event_ring_phys + (new_deq as u64) * 16;
                    ir.erdp = new_erdp | (1 << 3);

                    processed += 1;
                }
            }

            let db_regs = controller.db_regs;
            for slot_idx in 0..controller.device_slots.len() {
                if let Some(ref mut dev) = controller.device_slots[slot_idx] {
                    for ep in 1..MAX_ENDPOINTS {
                        if dev.ep_active[ep] || dev.ep_buf[ep].is_null() || dev.ep_transfer_rings[ep].is_null() {
                            continue;
                        }
                        let deq = dev.ep_dequeue[ep];
                        let cycle = dev.ep_cycle[ep];
                        let buf_phys = dev.ep_buf_phys[ep];
                        let buf_len = dev.ep_buf_len[ep];
                        let tr_ring = dev.ep_transfer_rings[ep];
                        let slot = dev.slot_id;

                        let trb = Trb::normal(buf_phys, buf_len as u32, cycle, true);
                        core::ptr::write_volatile(tr_ring.add(deq), trb);

                        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
                        let db_index = (slot as usize) * 32 + ep;
                        core::ptr::write_volatile(db_regs.add(db_index), 0);
                        dev.ep_active[ep] = true;
                    }
                }
            }
        }
    }
}
