//! Intel E1000 Gigabit Ethernet driver
//!
//! Supports the 82540EM (QEMU `-device e1000`, device 0x100E) and a few
//! other common variants.  Uses MMIO (BAR0) for register access and
//! legacy descriptor rings for RX/TX DMA.
//!
//! References:
//! - Intel 8254x SDM (Software Developer's Manual)
//! - Theseus OS `kernel/e1000` (architecture inspiration)
//! - OSDev wiki: <https://wiki.osdev.org/Intel_Ethernet_i217>

use super::{register_device, NetError, NetworkDevice};
use crate::{
    arch::x86_64::pci::{self, Bar, PciDevice},
    memory::{self, get_allocator, FrameAllocator, PhysFrame},
    sync::SpinLock,
};
use alloc::{sync::Arc, vec::Vec};
use core::ptr;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const NUM_RX_DESCS: usize = 64;
const NUM_TX_DESCS: usize = 64;
const RX_BUF_SIZE: usize = 2048;

/// Supported E1000 PCI device IDs (vendor is always 0x8086).
const E1000_DEVICE_IDS: &[u16] = &[
    0x100E, // 82540EM  – QEMU default
    0x100F, // 82545EM
    0x10D3, // 82574L   – e1000e (QEMU)
    0x153A, // I217-LM
    0x1539, // I211-AT
];

// ---- Register offsets (from BAR0) -----------------------------------------

mod regs {
    pub const CTRL: usize = 0x0000;
    pub const STATUS: usize = 0x0008;
    pub const EERD: usize = 0x0014;
    pub const ICR: usize = 0x00C0;
    pub const IMS: usize = 0x00D0;
    pub const IMC: usize = 0x00D8;
    pub const RCTL: usize = 0x0100;
    pub const TCTL: usize = 0x0400;
    pub const RDBAL: usize = 0x2800;
    pub const RDBAH: usize = 0x2804;
    pub const RDLEN: usize = 0x2808;
    pub const RDH: usize = 0x2810;
    pub const RDT: usize = 0x2818;
    pub const TDBAL: usize = 0x3800;
    pub const TDBAH: usize = 0x3804;
    pub const TDLEN: usize = 0x3808;
    pub const TDH: usize = 0x3810;
    pub const TDT: usize = 0x3818;
    pub const RAL0: usize = 0x5400;
    pub const RAH0: usize = 0x5404;
}

// ---- CTRL bits ------------------------------------------------------------

mod ctrl {
    pub const SLU: u32 = 1 << 6; // Set Link Up
    pub const RST: u32 = 1 << 26; // Device Reset
}

// ---- RCTL bits ------------------------------------------------------------

#[allow(dead_code)]
mod rctl {
    pub const EN: u32 = 1 << 1;
    pub const SBP: u32 = 1 << 2;
    pub const UPE: u32 = 1 << 3;
    pub const MPE: u32 = 1 << 4;
    pub const BAM: u32 = 1 << 15;
    pub const BSIZE_2048: u32 = 0 << 16;
    pub const SECRC: u32 = 1 << 26;
}

// ---- TCTL bits ------------------------------------------------------------

mod tctl {
    pub const EN: u32 = 1 << 1;
    pub const PSP: u32 = 1 << 3;
    pub const CT_SHIFT: u32 = 4;
    pub const COLD_SHIFT: u32 = 12;
}

// ---- Interrupt bits -------------------------------------------------------

#[allow(dead_code)]
mod int_bits {
    pub const TXDW: u32 = 1 << 0;
    pub const TXQE: u32 = 1 << 1;
    pub const LSC: u32 = 1 << 2;
    pub const RXDMT0: u32 = 1 << 4;
    pub const RXO: u32 = 1 << 6;
    pub const RXT0: u32 = 1 << 7;
}

// ---- EERD (EEPROM Read) ---------------------------------------------------

mod eerd {
    pub const START: u32 = 1 << 0;
    pub const DONE: u32 = 1 << 4;
    pub const ADDR_SHIFT: u32 = 8;
    pub const DATA_SHIFT: u32 = 16;
}

// ---------------------------------------------------------------------------
// Descriptor structures (legacy format)
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RxDesc {
    addr: u64,
    length: u16,
    checksum: u16,
    status: u8,
    errors: u8,
    special: u16,
}

const RX_STATUS_DD: u8 = 1 << 0;
#[allow(dead_code)]
const RX_STATUS_EOP: u8 = 1 << 1;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TxDesc {
    addr: u64,
    length: u16,
    cso: u8,
    cmd: u8,
    status: u8,
    css: u8,
    special: u16,
}

const TX_CMD_EOP: u8 = 1 << 0;
const TX_CMD_IFCS: u8 = 1 << 1;
const TX_CMD_RS: u8 = 1 << 3;
const TX_STATUS_DD: u8 = 1 << 0;

// ---------------------------------------------------------------------------
// Internal state (protected by SpinLock)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
struct E1000Inner {
    mmio_base: u64,
    rx_descs_phys: u64,
    rx_descs_virt: *mut RxDesc,
    rx_bufs: Vec<(PhysFrame, u8)>,
    rx_tail: usize,
    tx_descs_phys: u64,
    tx_descs_virt: *mut TxDesc,
    tx_bufs: Vec<Option<(PhysFrame, u8)>>,
    tx_tail: usize,
    mac: [u8; 6],
}

unsafe impl Send for E1000Inner {}

// ---------------------------------------------------------------------------
// E1000 device
// ---------------------------------------------------------------------------

pub struct E1000Device {
    inner: SpinLock<E1000Inner>,
    #[allow(dead_code)]
    pci_dev: PciDevice,
}

unsafe impl Send for E1000Device {}
unsafe impl Sync for E1000Device {}

// ---- MMIO helpers ---------------------------------------------------------

#[inline]
unsafe fn mmio_read(base: u64, reg: usize) -> u32 {
    ptr::read_volatile((base + reg as u64) as *const u32)
}

#[inline]
unsafe fn mmio_write(base: u64, reg: usize, val: u32) {
    ptr::write_volatile((base + reg as u64) as *mut u32, val);
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

impl E1000Device {
    /// Probe and initialise an E1000 from a discovered PCI device.
    ///
    /// # Safety
    /// Caller must ensure PCI and HHDM are fully initialised.
    pub unsafe fn new(pci_dev: PciDevice) -> Result<Self, &'static str> {
        log::info!("E1000: init device at {:?}", pci_dev.address);

        // -- PCI setup ------------------------------------------------------
        pci_dev.enable_bus_master();
        pci_dev.enable_memory_space();

        let mmio_phys = match pci_dev.read_bar(0) {
            Some(Bar::Memory32 { addr, .. }) => addr as u64,
            Some(Bar::Memory64 { addr, .. }) => addr,
            _ => return Err("E1000: BAR0 is not memory-mapped"),
        };

        // Map the entire 128 KiB MMIO region.
        memory::paging::ensure_identity_map_range(mmio_phys, 0x2_0000);
        let mmio_base = memory::phys_to_virt(mmio_phys);

        // -- Device reset ---------------------------------------------------
        let c = mmio_read(mmio_base, regs::CTRL);
        mmio_write(mmio_base, regs::CTRL, c | ctrl::RST);
        // Spec says wait ≥1 µs; busy-loop ~10 ms to be safe.
        for _ in 0..10_000_000u64 {
            core::hint::spin_loop();
        }

        // Disable all interrupts while we set up.
        mmio_write(mmio_base, regs::IMC, 0xFFFF_FFFF);
        let _ = mmio_read(mmio_base, regs::ICR);

        // -- Read MAC address -----------------------------------------------
        let mac = Self::read_mac(mmio_base);
        log::info!(
            "E1000: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        );

        // -- Allocate RX descriptor ring + buffers --------------------------
        let (rx_descs_frame, _rx_order) = Self::alloc_ring(NUM_RX_DESCS, core::mem::size_of::<RxDesc>())?;
        let rx_descs_phys = rx_descs_frame.start_address.as_u64();
        let rx_descs_virt = memory::phys_to_virt(rx_descs_phys) as *mut RxDesc;

        let mut rx_bufs = Vec::with_capacity(NUM_RX_DESCS);
        for i in 0..NUM_RX_DESCS {
            let (buf_frame, buf_order) = Self::alloc_buf(RX_BUF_SIZE)?;
            let buf_phys = buf_frame.start_address.as_u64();
            // Zero the buffer
            ptr::write_bytes(memory::phys_to_virt(buf_phys) as *mut u8, 0, RX_BUF_SIZE);
            // Fill descriptor
            let desc = &mut *rx_descs_virt.add(i);
            *desc = RxDesc::default();
            desc.addr = buf_phys;
            rx_bufs.push((buf_frame, buf_order));
        }

        // Program RX registers
        mmio_write(mmio_base, regs::RDBAL, rx_descs_phys as u32);
        mmio_write(mmio_base, regs::RDBAH, (rx_descs_phys >> 32) as u32);
        mmio_write(
            mmio_base,
            regs::RDLEN,
            (NUM_RX_DESCS * core::mem::size_of::<RxDesc>()) as u32,
        );
        mmio_write(mmio_base, regs::RDH, 0);
        mmio_write(mmio_base, regs::RDT, (NUM_RX_DESCS - 1) as u32);

        // -- Allocate TX descriptor ring ------------------------------------
        let (tx_descs_frame, _tx_order) = Self::alloc_ring(NUM_TX_DESCS, core::mem::size_of::<TxDesc>())?;
        let tx_descs_phys = tx_descs_frame.start_address.as_u64();
        let tx_descs_virt = memory::phys_to_virt(tx_descs_phys) as *mut TxDesc;

        // Zero out TX descriptors
        ptr::write_bytes(tx_descs_virt, 0, NUM_TX_DESCS);

        let mut tx_bufs: Vec<Option<(PhysFrame, u8)>> = Vec::with_capacity(NUM_TX_DESCS);
        for _ in 0..NUM_TX_DESCS {
            tx_bufs.push(None);
        }

        // Program TX registers
        mmio_write(mmio_base, regs::TDBAL, tx_descs_phys as u32);
        mmio_write(mmio_base, regs::TDBAH, (tx_descs_phys >> 32) as u32);
        mmio_write(
            mmio_base,
            regs::TDLEN,
            (NUM_TX_DESCS * core::mem::size_of::<TxDesc>()) as u32,
        );
        mmio_write(mmio_base, regs::TDH, 0);
        mmio_write(mmio_base, regs::TDT, 0);

        // -- Enable TX ------------------------------------------------------
        let tctl_val = tctl::EN
            | tctl::PSP
            | (0x10 << tctl::CT_SHIFT)   // collision threshold
            | (0x40 << tctl::COLD_SHIFT); // collision distance (full duplex)
        mmio_write(mmio_base, regs::TCTL, tctl_val);

        // -- Enable RX ------------------------------------------------------
        let rctl_val = rctl::EN
            | rctl::BAM          // accept broadcast
            | rctl::BSIZE_2048
            | rctl::SECRC;       // strip CRC
        mmio_write(mmio_base, regs::RCTL, rctl_val);

        // -- Set link up + enable interrupts --------------------------------
        let c = mmio_read(mmio_base, regs::CTRL);
        mmio_write(mmio_base, regs::CTRL, c | ctrl::SLU);

        mmio_write(
            mmio_base,
            regs::IMS,
            int_bits::RXT0 | int_bits::LSC | int_bits::RXDMT0 | int_bits::RXO,
        );

        log::info!("E1000: device ready (link up, RX/TX enabled)");

        Ok(Self {
            inner: SpinLock::new(E1000Inner {
                mmio_base,
                rx_descs_phys,
                rx_descs_virt,
                rx_bufs,
                rx_tail: NUM_RX_DESCS - 1,
                tx_descs_phys,
                tx_descs_virt,
                tx_bufs,
                tx_tail: 0,
                mac,
            }),
            pci_dev,
        })
    }

    // -- Private helpers ----------------------------------------------------

    unsafe fn read_mac(base: u64) -> [u8; 6] {
        // Try RAL/RAH first (works on most E1000 variants).
        let ral = mmio_read(base, regs::RAL0);
        let rah = mmio_read(base, regs::RAH0);

        if ral != 0 || (rah & 0xFFFF) != 0 {
            return [
                (ral & 0xFF) as u8,
                ((ral >> 8) & 0xFF) as u8,
                ((ral >> 16) & 0xFF) as u8,
                ((ral >> 24) & 0xFF) as u8,
                (rah & 0xFF) as u8,
                ((rah >> 8) & 0xFF) as u8,
            ];
        }

        // Fallback: read from EEPROM (words 0, 1, 2).
        let mut mac = [0u8; 6];
        for i in 0u32..3 {
            let word = Self::eeprom_read(base, i as u8);
            mac[(i * 2) as usize] = (word & 0xFF) as u8;
            mac[(i * 2 + 1) as usize] = ((word >> 8) & 0xFF) as u8;
        }
        mac
    }

    unsafe fn eeprom_read(base: u64, addr: u8) -> u16 {
        mmio_write(
            base,
            regs::EERD,
            eerd::START | ((addr as u32) << eerd::ADDR_SHIFT),
        );
        loop {
            let val = mmio_read(base, regs::EERD);
            if val & eerd::DONE != 0 {
                return ((val >> eerd::DATA_SHIFT) & 0xFFFF) as u16;
            }
            core::hint::spin_loop();
        }
    }

    fn alloc_ring(count: usize, desc_size: usize) -> Result<(PhysFrame, u8), &'static str> {
        let size = count * desc_size;
        let pages = (size + 4095) / 4096;
        let order = pages.next_power_of_two().trailing_zeros() as u8;
        let mut lock = get_allocator().lock();
        let alloc = lock.as_mut().ok_or("allocator not ready")?;
        let frame = alloc.alloc(order).map_err(|_| "E1000: ring allocation failed")?;
        Ok((frame, order))
    }

    fn alloc_buf(size: usize) -> Result<(PhysFrame, u8), &'static str> {
        let pages = (size + 4095) / 4096;
        let order = pages.next_power_of_two().trailing_zeros() as u8;
        let mut lock = get_allocator().lock();
        let alloc = lock.as_mut().ok_or("allocator not ready")?;
        let frame = alloc.alloc(order).map_err(|_| "E1000: buffer allocation failed")?;
        Ok((frame, order))
    }
}

// ---------------------------------------------------------------------------
// NetworkDevice implementation
// ---------------------------------------------------------------------------

impl NetworkDevice for E1000Device {
    fn name(&self) -> &str {
        "e1000"
    }

    fn mac_address(&self) -> [u8; 6] {
        self.inner.lock().mac
    }

    fn link_up(&self) -> bool {
        let inner = self.inner.lock();
        let status = unsafe { mmio_read(inner.mmio_base, regs::STATUS) };
        status & 0x02 != 0 // STATUS.LU (Link Up)
    }

    fn receive(&self, buf: &mut [u8]) -> Result<usize, NetError> {
        let mut inner = self.inner.lock();
        let idx = (inner.rx_tail + 1) % NUM_RX_DESCS;
        let desc = unsafe { &mut *inner.rx_descs_virt.add(idx) };

        if desc.status & RX_STATUS_DD == 0 {
            return Err(NetError::NoPacket);
        }

        let pkt_len = desc.length as usize;
        if buf.len() < pkt_len {
            return Err(NetError::BufferTooSmall);
        }

        // Copy packet data from RX buffer
        let buf_phys = inner.rx_bufs[idx].0.start_address.as_u64();
        let buf_virt = memory::phys_to_virt(buf_phys) as *const u8;
        unsafe {
            ptr::copy_nonoverlapping(buf_virt, buf.as_mut_ptr(), pkt_len);
        }

        // Reset descriptor for reuse
        desc.status = 0;
        desc.length = 0;
        desc.errors = 0;

        inner.rx_tail = idx;
        unsafe {
            mmio_write(inner.mmio_base, regs::RDT, idx as u32);
        }

        Ok(pkt_len)
    }

    fn transmit(&self, buf: &[u8]) -> Result<(), NetError> {
        if buf.len() > super::MTU {
            return Err(NetError::BufferTooSmall);
        }

        let mut inner = self.inner.lock();
        let idx = inner.tx_tail;
        let desc = unsafe { &mut *inner.tx_descs_virt.add(idx) };

        // Wait for previous TX at this slot to complete (DD bit set or fresh)
        if desc.cmd != 0 && desc.status & TX_STATUS_DD == 0 {
            return Err(NetError::TxQueueFull);
        }

        // Free previous TX buffer if any
        if let Some((frame, order)) = inner.tx_bufs[idx].take() {
            let mut lock = get_allocator().lock();
            if let Some(alloc) = lock.as_mut() {
                alloc.free(frame, order);
            }
        }

        // Allocate a fresh TX buffer
        let (tx_frame, tx_order) = Self::alloc_buf(buf.len()).map_err(|_| NetError::NotReady)?;
        let tx_phys = tx_frame.start_address.as_u64();
        let tx_virt = memory::phys_to_virt(tx_phys) as *mut u8;

        unsafe {
            ptr::copy_nonoverlapping(buf.as_ptr(), tx_virt, buf.len());
        }

        // Fill descriptor
        desc.addr = tx_phys;
        desc.length = buf.len() as u16;
        desc.cso = 0;
        desc.cmd = TX_CMD_EOP | TX_CMD_IFCS | TX_CMD_RS;
        desc.status = 0;
        desc.css = 0;
        desc.special = 0;

        inner.tx_bufs[idx] = Some((tx_frame, tx_order));
        inner.tx_tail = (idx + 1) % NUM_TX_DESCS;

        // Notify hardware
        unsafe {
            mmio_write(inner.mmio_base, regs::TDT, inner.tx_tail as u32);
        }

        // Spin-wait for completion (simple, non-interrupt path).
        drop(inner);
        loop {
            let inner = self.inner.lock();
            let d = unsafe { &*inner.tx_descs_virt.add(idx) };
            if d.status & TX_STATUS_DD != 0 {
                break;
            }
            drop(inner);
            core::hint::spin_loop();
        }

        Ok(())
    }

    fn handle_interrupt(&self) {
        let inner = self.inner.lock();
        let icr = unsafe { mmio_read(inner.mmio_base, regs::ICR) };
        if icr & int_bits::LSC != 0 {
            let status = unsafe { mmio_read(inner.mmio_base, regs::STATUS) };
            log::info!("E1000: link status change (LU={})", status & 0x02 != 0);
        }
    }
}

// ---------------------------------------------------------------------------
// Global singleton + init
// ---------------------------------------------------------------------------

static E1000_DEVICE: SpinLock<Option<Arc<E1000Device>>> = SpinLock::new(None);

/// Scan PCI for an E1000 device and initialise it if found.
pub fn init() {
    for &dev_id in E1000_DEVICE_IDS {
        if let Some(pci_dev) = pci::find_device(pci::vendor::INTEL, dev_id) {
            log::info!("E1000: found PCI device {:04x}:{:04x}", pci_dev.vendor_id, pci_dev.device_id);
            match unsafe { E1000Device::new(pci_dev) } {
                Ok(dev) => {
                    let arc = Arc::new(dev);
                    *E1000_DEVICE.lock() = Some(arc.clone());
                    register_device(arc);
                    return;
                }
                Err(e) => {
                    log::error!("E1000: init failed: {}", e);
                }
            }
        }
    }
    log::info!("E1000: no compatible device found on PCI bus");
}

/// Get the E1000 device instance (if present).
pub fn get_device() -> Option<Arc<E1000Device>> {
    E1000_DEVICE.lock().clone()
}
