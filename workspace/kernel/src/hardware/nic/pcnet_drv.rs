// PCnet-PCI II Ethernet Controller Driver (AMD AM79C970/AM79C972)
// Reference: AMD PCnet-PCI II Data Sheet

use crate::{
    arch::x86_64::pci::{self, Bar, ProbeCriteria},
    hardware::nic::NetworkDevice,
    memory::{allocate_dma_frame, phys_to_virt},
};
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::{format, string::String};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

use crate::hardware::nic::NetError;

const MTU: usize = 1536;
const RX_BUFFERS_COUNT: usize = 32;
const TX_BUFFERS_COUNT: usize = 8;
const DESC_LEN: usize = 16;

const CSR0_INIT: u32 = 0;
const CSR0_STRT: u32 = 1;
const CSR0_TDMD: u32 = 3;

const DE_ENP: usize = 0;
const DE_STP: usize = 1;
const DE_OWN: usize = 7;

fn log2(x: u8) -> u8 {
    8 - 1 - x.leading_zeros() as u8
}

pub struct PcnetDevice {
    ports: Mutex<Ports>,
    rx_buffers: [*mut u8; RX_BUFFERS_COUNT],
    rx_phys: [u64; RX_BUFFERS_COUNT],
    tx_buffers: [*mut u8; TX_BUFFERS_COUNT],
    tx_phys: [u64; TX_BUFFERS_COUNT],
    rx_des: *mut u8,
    rx_des_phys: u64,
    tx_des: *mut u8,
    tx_des_phys: u64,
    rx_id: AtomicUsize,
    tx_id: AtomicUsize,
    mac: [u8; 6],
    name: String,
}

unsafe impl Send for PcnetDevice {}
unsafe impl Sync for PcnetDevice {}

struct Ports {
    io_base: u16,
}

impl Ports {
    fn new(io_base: u16) -> Self {
        Self { io_base }
    }

    #[inline]
    fn read8(&self, offset: u16) -> u8 {
        unsafe { x86_64::instructions::port::Port::new(self.io_base + offset).read() }
    }

    #[inline]
    fn write8(&mut self, offset: u16, value: u8) {
        unsafe { x86_64::instructions::port::Port::new(self.io_base + offset).write(value) }
    }

    #[inline]
    fn read32(&self, offset: u16) -> u32 {
        unsafe { x86_64::instructions::port::Port::new(self.io_base + offset).read() }
    }

    #[inline]
    fn write32(&mut self, offset: u16, value: u32) {
        unsafe { x86_64::instructions::port::Port::new(self.io_base + offset).write(value) }
    }

    fn write_rap(&mut self, val: u32) {
        unsafe { x86_64::instructions::port::Port::new(self.io_base + 0x14).write(val) }
    }

    fn read_rdp(&self) -> u32 {
        unsafe { x86_64::instructions::port::Port::new(self.io_base + 0x10).read() }
    }

    fn write_rdp(&mut self, val: u32) {
        unsafe { x86_64::instructions::port::Port::new(self.io_base + 0x10).write(val) }
    }

    fn read_bdp(&self) -> u32 {
        unsafe { x86_64::instructions::port::Port::new(self.io_base + 0x1C).read() }
    }

    fn write_bdp(&mut self, val: u32) {
        unsafe { x86_64::instructions::port::Port::new(self.io_base + 0x1C).write(val) }
    }

    fn read_csr(&mut self, csr: u32) -> u32 {
        self.write_rap(csr);
        self.read_rdp()
    }

    fn write_csr(&mut self, csr: u32, val: u32) {
        self.write_rap(csr);
        self.write_rdp(val);
    }

    fn read_bcr(&mut self, bcr: u32) -> u32 {
        self.write_rap(bcr);
        self.read_bdp()
    }

    fn write_bcr(&mut self, bcr: u32, val: u32) {
        self.write_rap(bcr);
        self.write_bdp(val);
    }

    fn mac(&mut self) -> [u8; 6] {
        [
            self.read8(0x00),
            self.read8(0x01),
            self.read8(0x02),
            self.read8(0x03),
            self.read8(0x04),
            self.read8(0x05),
        ]
    }
}

impl PcnetDevice {
    pub unsafe fn new(pci_dev: pci::PciDevice) -> Result<Self, &'static str> {
        let io_base = match pci_dev.read_bar(0) {
            Some(Bar::Io { port }) => port as u16,
            _ => return Err("Invalid BAR"),
        };

        let mut ports = Ports::new(io_base);
        let mac = ports.mac();
        let name = format!("pcnet_{:02x}{:02x}{:02x}", mac[3], mac[4], mac[5]);

        let mut rx_buffers = [core::ptr::null_mut(); RX_BUFFERS_COUNT];
        let mut rx_phys = [0u64; RX_BUFFERS_COUNT];
        for i in 0..RX_BUFFERS_COUNT {
            let frame = allocate_dma_frame().ok_or("Failed to allocate RX buffer")?;
            rx_phys[i] = frame.start_address.as_u64();
            rx_buffers[i] = phys_to_virt(rx_phys[i]) as *mut u8;
        }

        let mut tx_buffers = [core::ptr::null_mut(); TX_BUFFERS_COUNT];
        let mut tx_phys = [0u64; TX_BUFFERS_COUNT];
        for i in 0..TX_BUFFERS_COUNT {
            let frame = allocate_dma_frame().ok_or("Failed to allocate TX buffer")?;
            tx_phys[i] = frame.start_address.as_u64();
            tx_buffers[i] = phys_to_virt(tx_phys[i]) as *mut u8;
        }

        let rx_des_frame = allocate_dma_frame().ok_or("Failed to allocate RX descriptors")?;
        let rx_des_phys = rx_des_frame.start_address.as_u64();
        let rx_des = phys_to_virt(rx_des_phys) as *mut u8;
        unsafe {
            core::ptr::write_bytes(rx_des, 0, RX_BUFFERS_COUNT * DESC_LEN);
        }

        let tx_des_frame = allocate_dma_frame().ok_or("Failed to allocate TX descriptors")?;
        let tx_des_phys = tx_des_frame.start_address.as_u64();
        let tx_des = phys_to_virt(tx_des_phys) as *mut u8;
        unsafe {
            core::ptr::write_bytes(tx_des, 0, TX_BUFFERS_COUNT * DESC_LEN);
        }

        let mut device = Self {
            ports: Mutex::new(ports),
            rx_buffers,
            rx_phys,
            tx_buffers,
            tx_phys,
            rx_des,
            rx_des_phys,
            tx_des,
            tx_des_phys,
            rx_id: AtomicUsize::new(0),
            tx_id: AtomicUsize::new(0),
            mac,
            name,
        };

        device.init();
        Ok(device)
    }

    fn init(&mut self) {
        let mut ports = self.ports.lock();

        ports.read8(0x18);
        let _ = ports.read32(0x18);

        let mut csr_58 = ports.read_csr(58);
        csr_58 &= 0xFF00;
        csr_58 |= 2;
        ports.write_csr(58, csr_58);

        let mut bcr_2 = ports.read_bcr(2);
        bcr_2 |= 2;
        ports.write_bcr(2, bcr_2);

        for i in 0..RX_BUFFERS_COUNT {
            self.init_rx_descriptor(i);
        }
        for i in 0..TX_BUFFERS_COUNT {
            self.init_tx_descriptor(i);
        }

        let init_struct_frame = allocate_dma_frame().unwrap();
        let init_phys = init_struct_frame.start_address.as_u64();
        let init_virt = phys_to_virt(init_phys) as *mut u8;
        unsafe {
            core::ptr::write_bytes(init_virt, 0, 28);
        }

        unsafe {
            init_virt.write(0);
            init_virt.add(1).write(0);
            init_virt.add(2).write((log2(RX_BUFFERS_COUNT as u8) as u8) << 4);
            init_virt.add(3).write((log2(TX_BUFFERS_COUNT as u8) as u8) << 4);

            init_virt.add(4).write(self.mac[0]);
            init_virt.add(5).write(self.mac[1]);
            init_virt.add(6).write(self.mac[2]);
            init_virt.add(7).write(self.mac[3]);
            init_virt.add(8).write(self.mac[4]);
            init_virt.add(9).write(self.mac[5]);

            init_virt.add(20).write((self.rx_des_phys & 0xFF) as u8);
            init_virt.add(21).write(((self.rx_des_phys >> 8) & 0xFF) as u8);
            init_virt.add(22).write(((self.rx_des_phys >> 16) & 0xFF) as u8);
            init_virt.add(23).write(((self.rx_des_phys >> 24) & 0xFF) as u8);

            init_virt.add(24).write((self.tx_des_phys & 0xFFFF) as u8);
            init_virt.add(25).write(((self.tx_des_phys >> 8) & 0xFF) as u8);
            init_virt.add(26).write(((self.tx_des_phys >> 16) & 0xFF) as u8);
            init_virt.add(27).write(((self.tx_des_phys >> 24) & 0xFF) as u8);
        }

        ports.write_csr(1, (init_phys & 0xFFFF) as u32);
        ports.write_csr(2, ((init_phys >> 16) & 0xFFFF) as u32);

        let mut csr_0 = ports.read_csr(0);
        csr_0 |= 1 << CSR0_INIT;
        ports.write_csr(0, csr_0);

        core::hint::spin_loop();

        let mut csr_0 = ports.read_csr(0);
        csr_0 |= 1 << CSR0_STRT;
        ports.write_csr(0, csr_0);

        log::info!(
            "PCnet: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.mac[0], self.mac[1], self.mac[2],
            self.mac[3], self.mac[4], self.mac[5]
        );
    }

    fn init_rx_descriptor(&self, i: usize) {
        unsafe {
            let desc = self.rx_des.add(i * DESC_LEN);
            desc.write_bytes(0, DESC_LEN);

            let buf_addr = self.rx_phys[i];
            desc.add(0).write((buf_addr & 0xFF) as u8);
            desc.add(1).write(((buf_addr >> 8) & 0xFF) as u8);
            desc.add(2).write(((buf_addr >> 16) & 0xFF) as u8);
            desc.add(3).write(((buf_addr >> 24) & 0xFF) as u8);
            let bcnt = (!(MTU as u16)).wrapping_add(1) & 0x0FFF;
            desc.add(4).write((bcnt & 0xFF) as u8);
            desc.add(5).write(((bcnt >> 8) as u8) | 0xF0);
            desc.add(7).write(0x80);
        }
    }

    fn init_tx_descriptor(&self, i: usize) {
        unsafe {
            let desc = self.tx_des.add(i * DESC_LEN);
            desc.write_bytes(0, DESC_LEN);

            let buf_addr = self.tx_phys[i];
            desc.add(0).write((buf_addr & 0xFF) as u8);
            desc.add(1).write(((buf_addr >> 8) & 0xFF) as u8);
            desc.add(2).write(((buf_addr >> 16) & 0xFF) as u8);
            desc.add(3).write(((buf_addr >> 24) & 0xFF) as u8);
        }
    }

    fn receive_inner(&self) -> Option<Vec<u8>> {
        let rx_id = self.rx_id.load(Ordering::Relaxed);

        unsafe {
            let desc = self.rx_des.add(rx_id * DESC_LEN + 7);
            let status = desc.read_volatile();

            if (status & (1 << DE_OWN)) != 0 {
                return None;
            }

            let stp = (status & (1 << DE_STP)) != 0;
            let enp = (status & (1 << DE_ENP)) != 0;

            if stp && enp {
                let len_offset = rx_id * DESC_LEN + 8;
                let len_lo = self.rx_des.add(len_offset).read() as usize;
                let len_hi = self.rx_des.add(len_offset + 1).read() as usize & 0xF;
                let len = ((len_hi << 8) | len_lo) & 0xFFF;

                if len <= MTU {
                    let mut buf = Vec::with_capacity(len);
                    core::ptr::copy_nonoverlapping(self.rx_buffers[rx_id], buf.as_mut_ptr(), len);
                    buf.set_len(len);

                    let desc = self.rx_des.add(rx_id * DESC_LEN + 7);
                    desc.write_volatile(0x80);

                    self.rx_id.store((rx_id + 1) % RX_BUFFERS_COUNT, Ordering::Relaxed);
                    return Some(buf);
                }
            }

            let desc = self.rx_des.add(rx_id * DESC_LEN + 7);
            desc.write_volatile(0x80);
            self.rx_id.store((rx_id + 1) % RX_BUFFERS_COUNT, Ordering::Relaxed);
        }

        None
    }

    fn transmit_inner(&self, data: &[u8]) -> Result<(), NetError> {
        if data.len() > MTU {
            return Err(NetError::BufferTooSmall);
        }

        let tx_id = self.tx_id.load(Ordering::Relaxed);

        unsafe {
            let desc = self.tx_des.add(tx_id * DESC_LEN + 7);
            let status = desc.read_volatile();

            if (status & (1 << DE_OWN)) != 0 {
                let mut timeout = 10000;
                while (self.tx_des.add(tx_id * DESC_LEN + 7).read_volatile() & (1 << DE_OWN)) != 0 {
                    core::hint::spin_loop();
                    timeout -= 1;
                    if timeout == 0 {
                        return Err(NetError::NotReady);
                    }
                }
            }

            core::ptr::copy_nonoverlapping(data.as_ptr(), self.tx_buffers[tx_id], data.len());

            let desc = self.tx_des.add(tx_id * DESC_LEN);
            let bcnt = (!(data.len() as u16)).wrapping_add(1) & 0x0FFF;
            desc.add(4).write((bcnt & 0xFF) as u8);
            desc.add(5).write(((bcnt >> 8) as u8) | 0xF0);
            desc.add(6).write(0);
            desc.add(7).write(0x83);

            self.tx_id.store((tx_id + 1) % TX_BUFFERS_COUNT, Ordering::Relaxed);

            let mut ports = self.ports.lock();
            let mut csr_0 = ports.read_csr(0);
            csr_0 |= 1 << CSR0_TDMD;
            ports.write_csr(0, csr_0);
        }

        Ok(())
    }
}

impl NetworkDevice for PcnetDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    fn link_up(&self) -> bool {
        let mut ports = self.ports.lock();
        let csr_4 = ports.read_csr(4);
        (csr_4 & 0x20) != 0
    }

    fn receive(&self, buf: &mut [u8]) -> Result<usize, NetError> {
        if let Some(packet) = self.receive_inner() {
            let len = core::cmp::min(packet.len(), buf.len());
            buf[..len].copy_from_slice(&packet[..len]);
            Ok(len)
        } else {
            Err(NetError::NoPacket)
        }
    }

    fn transmit(&self, data: &[u8]) -> Result<(), NetError> {
        self.transmit_inner(data)
    }
}

static PCNET_DEVICES: Mutex<Vec<Arc<PcnetDevice>>> = Mutex::new(Vec::new());

pub fn init() {
    log::info!("[PCnet] Scanning for PCnet devices...");

    let candidates = pci::probe_all(ProbeCriteria {
        vendor_id: Some(0x1022),
        device_id: None,
        class_code: Some(pci::class::NETWORK),
        subclass: Some(pci::net_subclass::ETHERNET),
        prog_if: None,
    });

    for pci_dev in candidates.into_iter() {
        if pci_dev.device_id != 0x2000 && pci_dev.device_id != 0x2001 {
            continue;
        }

        log::info!(
            "PCnet: Found device at {:?} (VEN:{:04x} DEV:{:04x})",
            pci_dev.address,
            pci_dev.vendor_id,
            pci_dev.device_id
        );

        pci_dev.enable_bus_master();

        match unsafe { PcnetDevice::new(pci_dev) } {
            Ok(device) => {
                let arc = Arc::new(device);
                PCNET_DEVICES.lock().push(arc.clone());
                let _iface = crate::hardware::nic::register_device(arc);
            }
            Err(e) => {
                log::warn!("PCnet: Failed to initialize device: {}", e);
            }
        }
    }

    log::info!("[PCnet] Found {} device(s)", PCNET_DEVICES.lock().len());
}
