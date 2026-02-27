// VirtIO Console Driver
// Reference: VirtIO spec v1.2, Section 5.3 (Console Device)

use crate::{
    arch::x86_64::pci::{self, Bar, ProbeCriteria},
    memory::{allocate_dma_frame, phys_to_virt},
};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::{Mutex, Once};

const VIRTIO_RING_SIZE: usize = 8;
const VIRTIO_CONSOLE_PORT_SIZE: usize = 256;

pub struct VirtioConsole {
    device: VirtioDevice,
    ports: Mutex<Vec<VirtioConsolePort>>,
}

struct VirtioDevice {
    mmio: usize,
}

struct VirtioConsolePort {
    id: u16,
    rx_queue: Virtqueue,
    tx_queue: Virtqueue,
    open: bool,
}

struct Virtqueue {
    desc: *mut VirtqDesc,
    avail: *mut VirtqAvail,
    used: *mut VirtqUsed,
    desc_phys: u64,
    avail_phys: u64,
    used_phys: u64,
    buffer_phys: u64,
    buffer_virt: *mut u8,
    free: Vec<u16>,
    last_used_idx: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C)]
struct VirtqAvail {
    flags: u16,
    idx: u16,
    ring: [u16; VIRTIO_RING_SIZE],
}

#[repr(C)]
struct VirtqUsed {
    flags: u16,
    idx: u16,
    ring: [VirtqUsedElem; VIRTIO_RING_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtqUsedElem {
    id: u32,
    len: u32,
}

const VIRTIO_F_VERSION_1: u64 = 1 << 32;
const VIRTIO_CONSOLE_F_MULTIPORT: u32 = 1;

const VIRTIO_STATUS_RESET: u8 = 0;
const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;

impl VirtioConsole {
    pub unsafe fn new(pci_dev: pci::PciDevice) -> Result<Self, &'static str> {
        let bar = match pci_dev.read_bar(0) {
            Some(Bar::Memory64(addr)) => addr,
            _ => return Err("Invalid BAR"),
        };

        let mmio = phys_to_virt(bar) as usize;
        let mut device = VirtioDevice { mmio };

        device.reset();
        device.add_status(VIRTIO_STATUS_ACKNOWLEDGE);
        device.add_status(VIRTIO_STATUS_DRIVER);

        let features = device.read_features();
        let mut guest_features = VIRTIO_F_VERSION_1;
        if (features & (1 << VIRTIO_CONSOLE_F_MULTIPORT)) != 0 {
            guest_features |= 1 << VIRTIO_CONSOLE_F_MULTIPORT;
        }
        device.write_features(guest_features);
        device.add_status(VIRTIO_STATUS_FEATURES_OK);

        if (device.read_status() & VIRTIO_STATUS_FEATURES_OK) == 0 {
            return Err("Features negotiation failed");
        }

        let mut ports = Vec::new();
        let rx_queue = Virtqueue::new(&mut device, 0)?;
        let tx_queue = Virtqueue::new(&mut device, 1)?;

        ports.push(VirtioConsolePort {
            id: 0,
            rx_queue,
            tx_queue,
            open: true,
        });

        device.add_status(VIRTIO_STATUS_DRIVER_OK);

        Ok(Self {
            device,
            ports: Mutex::new(ports),
        })
    }

    pub fn write(&self, data: &[u8]) -> Result<usize, &'static str> {
        let ports = self.ports.lock();
        let port = ports.first().ok_or("No console port")?;

        for chunk in data.chunks(VIRTIO_CONSOLE_PORT_SIZE) {
            port.tx_queue.write(chunk)?;
            self.device.notify_queue(1);

            loop {
                if port.tx_queue.poll_used() {
                    break;
                }
                core::hint::spin_loop();
            }
        }

        Ok(data.len())
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, &'static str> {
        let ports = self.ports.lock();
        let port = ports.first().ok_or("No console port")?;
        port.rx_queue.read(buf)
    }
}

impl VirtioDevice {
    fn reset(&mut self) {
        unsafe {
            (self.mmio as *mut u32).write_volatile(0);
        }
        core::hint::spin_loop();
    }

    fn add_status(&mut self, status: u8) {
        unsafe {
            let current = (self.mmio.add(0x14) as *const u8).read_volatile();
            (self.mmio.add(0x14) as *mut u8).write_volatile(current | status);
        }
    }

    fn read_status(&self) -> u8 {
        unsafe { (self.mmio.add(0x14) as *const u8).read_volatile() }
    }

    fn read_features(&self) -> u64 {
        unsafe {
            let lo = (self.mmio as *const u32).read_volatile() as u64;
            let hi = (self.mmio.add(4) as *const u32).read_volatile() as u64;
            (hi << 32) | lo
        }
    }

    fn write_features(&mut self, features: u64) {
        unsafe {
            (self.mmio as *mut u32).write_volatile((features & 0xFFFFFFFF) as u32);
            (self.mmio.add(4) as *mut u32).write_volatile(((features >> 32) & 0xFFFFFFFF) as u32);
        }
    }

    fn notify_queue(&self, queue: u16) {
        unsafe {
            let offset = (self.mmio.add(0x20) as *const u16).read_volatile() as usize;
            let queue_notify = self.mmio.add(0x50 + offset * 4);
            (queue_notify as *mut u32).write_volatile(queue as u32);
        }
    }
}

impl Virtqueue {
    fn new(device: &mut VirtioDevice, queue_idx: u16) -> Result<Self, &'static str> {
        unsafe {
            (device.mmio.add(0x16) as *mut u16).write_volatile(queue_idx);
            let max_size = (device.mmio.add(0x18) as *const u16).read_volatile();
            if max_size < VIRTIO_RING_SIZE as u16 {
                return Err("Queue size too small");
            }
            (device.mmio.add(0x16) as *mut u16).write_volatile(VIRTIO_RING_SIZE as u16);

            let desc_frame = allocate_dma_frame().ok_or("Failed to allocate desc")?;
            let avail_frame = allocate_dma_frame().ok_or("Failed to allocate avail")?;
            let used_frame = allocate_dma_frame().ok_or("Failed to allocate used")?;

            let desc_phys = desc_frame.start_address();
            let avail_phys = avail_frame.start_address();
            let used_phys = used_frame.start_address();

            let desc_virt = phys_to_virt(desc_phys) as *mut VirtqDesc;
            let avail_virt = phys_to_virt(avail_phys) as *mut VirtqAvail;
            let used_virt = phys_to_virt(used_phys) as *mut VirtqUsed;

            core::ptr::write_bytes(desc_virt, 0, VIRTIO_RING_SIZE * core::mem::size_of::<VirtqDesc>());
            core::ptr::write_bytes(avail_virt, 0, core::mem::size_of::<VirtqAvail>());
            core::ptr::write_bytes(used_virt, 0, core::mem::size_of::<VirtqUsed>());

            (device.mmio.add(0x10) as *mut u32).write_volatile((desc_phys & 0xFFFFFFFF) as u32);
            (device.mmio.add(0x1A) as *mut u16).write_volatile(0xFFFF);

            let buffer_frame = allocate_dma_frame().ok_or("Failed to allocate buffer")?;
            let buffer_phys = buffer_frame.start_address();
            let buffer_virt = phys_to_virt(buffer_phys) as *mut u8;
            core::ptr::write_bytes(buffer_virt, 0, 4096);

            let mut free = Vec::with_capacity(VIRTIO_RING_SIZE);
            for i in 0..VIRTIO_RING_SIZE {
                free.push(i as u16);
            }

            Ok(Self {
                desc: desc_virt,
                avail: avail_virt,
                used: used_virt,
                desc_phys,
                avail_phys,
                used_phys,
                buffer_phys,
                buffer_virt,
                free,
                last_used_idx: 0,
            })
        }
    }

    fn write(&self, data: &[u8]) -> Result<(), &'static str> {
        unsafe {
            if self.free.is_empty() {
                return Err("No free descriptors");
            }
            let desc_idx = self.free.pop().unwrap();

            let desc = &mut *self.desc.add(desc_idx as usize);
            core::ptr::copy_nonoverlapping(data.as_ptr(), self.buffer_virt, data.len());
            desc.addr = self.buffer_phys;
            desc.len = data.len() as u32;
            desc.flags = 2;
            desc.next = 0;

            let avail = &mut *self.avail;
            let idx = avail.idx as usize % VIRTIO_RING_SIZE;
            avail.ring[idx] = desc_idx;
            avail.idx = avail.idx.wrapping_add(1);
        }
        Ok(())
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, &'static str> {
        unsafe {
            if self.last_used_idx == (*self.used).idx {
                return Ok(0);
            }

            let idx = self.last_used_idx as usize % VIRTIO_RING_SIZE;
            let elem = (*self.used).ring[idx];

            let len = core::cmp::min(elem.len as usize, buf.len());
            core::ptr::copy_nonoverlapping(self.buffer_virt, buf.as_mut_ptr(), len);

            self.last_used_idx = self.last_used_idx.wrapping_add(1);
            Ok(len)
        }
    }

    fn poll_used(&self) -> bool {
        unsafe { self.last_used_idx != (*self.used).idx }
    }
}

static CONSOLE_INSTANCE: Once<Arc<VirtioConsole>> = Once::new();
static CONSOLE_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init() {
    log::info!("[VirtIO-Console] Scanning for VirtIO Console devices...");

    let candidates = pci::probe_all(ProbeCriteria {
        vendor_id: Some(pci::vendor::VIRTIO),
        device_id: Some(pci::device::VIRTIO_CONSOLE),
        class_code: None,
        subclass: None,
        prog_if: None,
    });

    for pci_dev in candidates.into_iter() {
        log::info!(
            "VirtIO-Console: Found device at {:?} (VEN:{:04x} DEV:{:04x})",
            pci_dev.address,
            pci_dev.vendor_id,
            pci_dev.device_id
        );

        pci_dev.enable_bus_master();

        match unsafe { VirtioConsole::new(pci_dev) } {
            Ok(console) => {
                let arc = Arc::new(console);
                CONSOLE_INSTANCE.call_once(|| arc.clone());
                CONSOLE_INITIALIZED.store(true, Ordering::SeqCst);
                log::info!("[VirtIO-Console] Initialized");
                return;
            }
            Err(e) => {
                log::warn!("VirtIO-Console: Failed to initialize device: {}", e);
            }
        }
    }

    log::info!("[VirtIO-Console] No device found");
}

pub fn write(data: &[u8]) -> Result<usize, &'static str> {
    CONSOLE_INSTANCE
        .get()
        .ok_or("Console not initialized")?
        .write(data)
}

pub fn read(buf: &mut [u8]) -> Result<usize, &'static str> {
    CONSOLE_INSTANCE
        .get()
        .ok_or("Console not initialized")?
        .read(buf)
}

pub fn is_available() -> bool {
    CONSOLE_INITIALIZED.load(Ordering::Relaxed)
}
