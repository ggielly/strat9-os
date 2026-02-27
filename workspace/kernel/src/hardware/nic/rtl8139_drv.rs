// RTL8139 Ethernet Controller Driver
// Reference: RTL8139/RTL8100 Series Data Sheet

use crate::{
    arch::x86_64::pci::{self, Bar, ProbeCriteria},
    hardware::nic::NetworkDevice,
    memory::{allocate_dma_frame, phys_to_virt},
};
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::string::String;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

use crate::hardware::nic::NetError;

const RX_BUFFER_SIZE: usize = 8192;
const RX_BUFFER_PAD: usize = 16;
const TX_BUFFER_SIZE: usize = 2048;
const TX_BUFFERS_COUNT: usize = 4;
const MTU: usize = 1536;

const CR_RST: u8 = 1 << 4;
const CR_RE: u8 = 1 << 3;
const CR_TE: u8 = 1 << 2;
const CR_BUFE: u8 = 1 << 0;

const RCR_WRAP: u32 = 1 << 7;
const RCR_AB: u32 = 1 << 3;
const RCR_AM: u32 = 1 << 2;
const RCR_APM: u32 = 1 << 1;
const RCR_AAP: u32 = 1 << 0;
const RCR_RBLEN: u32 = 0 << 11;

const TCR_IFG: u32 = 3 << 24;
const TCR_MXDMA: u32 = 7 << 8;

const ISR_ROK: u16 = 1 << 0;
const ISR_TOK: u16 = 1 << 2;

const TOK: u32 = 1 << 15;
const OWN: u32 = 1 << 13;

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
    fn read16(&self, offset: u16) -> u16 {
        unsafe { x86_64::instructions::port::Port::new(self.io_base + offset).read() }
    }

    #[inline]
    fn write16(&mut self, offset: u16, value: u16) {
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

pub struct Rtl8139Device {
    ports: Mutex<Ports>,
    rx_buffer: *mut u8,
    rx_phys: u64,
    rx_offset: usize,
    tx_buffers: [*mut u8; TX_BUFFERS_COUNT],
    tx_phys: [u64; TX_BUFFERS_COUNT],
    tx_id: AtomicUsize,
    mac: [u8; 6],
    name: String,
}

unsafe impl Send for Rtl8139Device {}
unsafe impl Sync for Rtl8139Device {}

impl Rtl8139Device {
    pub unsafe fn new(pci_dev: pci::PciDevice) -> Result<Self, &'static str> {
        let io_base = match pci_dev.read_bar(0) {
            Some(Bar::Io(addr)) => addr as u16,
            _ => return Err("Invalid BAR"),
        };

        let mut ports = Ports::new(io_base);
        let mac = ports.mac();
        let name = format!("rtl8139_{:02x}{:02x}{:02x}", mac[3], mac[4], mac[5]);

        let rx_frame = allocate_dma_frame().ok_or("Failed to allocate RX buffer")?;
        let rx_phys = rx_frame.start_address();
        let rx_buffer = phys_to_virt(rx_phys) as *mut u8;
        core::ptr::write_bytes(rx_buffer, 0, RX_BUFFER_SIZE + RX_BUFFER_PAD + MTU);

        let mut tx_buffers = [core::ptr::null_mut(); TX_BUFFERS_COUNT];
        let mut tx_phys = [0u64; TX_BUFFERS_COUNT];
        for i in 0..TX_BUFFERS_COUNT {
            let frame = allocate_dma_frame().ok_or("Failed to allocate TX buffer")?;
            tx_phys[i] = frame.start_address();
            tx_buffers[i] = phys_to_virt(tx_phys[i]) as *mut u8;
            core::ptr::write_bytes(tx_buffers[i], 0, TX_BUFFER_SIZE);
        }

        let mut device = Self {
            ports: Mutex::new(ports),
            rx_buffer,
            rx_phys,
            rx_offset: 0,
            tx_buffers,
            tx_phys,
            tx_id: AtomicUsize::new(TX_BUFFERS_COUNT - 1),
            mac,
            name,
        };

        device.init();
        Ok(device)
    }

    fn init(&mut self) {
        let mut ports = self.ports.lock();

        ports.write8(0x37, CR_RST);
        core::hint::spin_loop();

        for _ in 0..1000 {
            if (ports.read8(0x37) & CR_RST) == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        ports.write32(0x44, RCR_WRAP | RCR_AB | RCR_AM | RCR_APM | RCR_AAP | RCR_RBLEN);
        ports.write32(0x40, TCR_IFG | TCR_MXDMA);
        ports.write32(0x30, self.rx_phys as u32);

        for i in 0..TX_BUFFERS_COUNT {
            ports.write32(0x20 + (i as u16) * 4, self.tx_phys[i] as u32);
        }

        ports.write16(0x3C, ISR_ROK | ISR_TOK);
        ports.write8(0x37, CR_RE | CR_TE | CR_BUFE);

        log::info!(
            "RTL8139: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.mac[0], self.mac[1], self.mac[2],
            self.mac[3], self.mac[4], self.mac[5]
        );
    }

    fn receive(&self) -> Option<Vec<u8>> {
        let ports = self.ports.lock();

        let status = unsafe {
            (self.rx_buffer.add(self.rx_offset) as *const u32).read_volatile()
        };

        if (status & OWN) != 0 {
            return None;
        }

        if (status & 0x0001) == 0 {
            let length = ((status >> 16) & 0x1FFF) as usize - 4;
            if length <= MTU {
                let packet_start = unsafe { self.rx_buffer.add(self.rx_offset + 4) };
                let mut buf = Vec::with_capacity(length);
                unsafe {
                    core::ptr::copy_nonoverlapping(packet_start, buf.as_mut_ptr(), length);
                    buf.set_len(length);
                }

                let new_offset = ((self.rx_offset + length + 4 + RX_BUFFER_PAD) & !(RX_BUFFER_PAD - 1)) % RX_BUFFER_SIZE;
                self.rx_offset = new_offset;
                ports.write16(0x38, (new_offset - RX_BUFFER_PAD) as u16);

                return Some(buf);
            }
        }

        ports.write8(0x37, CR_RE | CR_TE);
        self.rx_offset = 0;
        None
    }

    fn transmit(&self, data: &[u8]) -> Result<(), NetError> {
        if data.len() > MTU {
            return Err(NetError::BufferTooLarge);
        }

        let id = self.tx_id.fetch_add(1, Ordering::SeqCst) % TX_BUFFERS_COUNT;
        let ports = self.ports.lock();

        let tx_status = ports.read32(0x10 + (id as u16) * 4);
        if (tx_status & OWN) != 0 {
            let mut timeout = 10000;
            while (ports.read32(0x10 + (id as u16) * 4) & OWN) != 0 {
                core::hint::spin_loop();
                timeout -= 1;
                if timeout == 0 {
                    return Err(NetError::Timeout);
                }
            }
        }

        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), self.tx_buffers[id], data.len());
        }

        let tx_cmd = (data.len() as u32) | TOK | OWN;
        ports.write32(0x10 + (id as u16) * 4, tx_cmd);

        Ok(())
    }
}

impl NetworkDevice for Rtl8139Device {
    fn name(&self) -> &str {
        &self.name
    }

    fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    fn link_up(&self) -> bool {
        let ports = self.ports.lock();
        (ports.read8(0x58) & 0x80) != 0
    }

    fn recv(&self) -> Option<Vec<u8>> {
        self.receive()
    }

    fn send(&self, data: &[u8]) -> Result<(), NetError> {
        self.transmit(data)
    }
}

static RTL8139_DEVICES: Mutex<Vec<Arc<Rtl8139Device>>> = Mutex::new(Vec::new());

pub fn init() {
    log::info!("[RTL8139] Scanning for RTL8139 devices...");

    let candidates = pci::probe_all(ProbeCriteria {
        vendor_id: Some(0x10EC),
        device_id: None,
        class_code: Some(pci::class::NETWORK),
        subclass: Some(pci::net_subclass::ETHERNET),
        prog_if: None,
    });

    for pci_dev in candidates.into_iter() {
        if pci_dev.device_id != 0x8139 {
            continue;
        }

        log::info!(
            "RTL8139: Found device at {:?} (VEN:{:04x} DEV:{:04x})",
            pci_dev.address,
            pci_dev.vendor_id,
            pci_dev.device_id
        );

        pci_dev.enable_bus_master();

        match unsafe { Rtl8139Device::new(pci_dev) } {
            Ok(device) => {
                let arc = Arc::new(device);
                RTL8139_DEVICES.lock().push(arc.clone());
                let _iface = crate::hardware::nic::register_device(arc);
            }
            Err(e) => {
                log::warn!("RTL8139: Failed to initialize device: {}", e);
            }
        }
    }

    log::info!("[RTL8139] Found {} device(s)", RTL8139_DEVICES.lock().len());
}
