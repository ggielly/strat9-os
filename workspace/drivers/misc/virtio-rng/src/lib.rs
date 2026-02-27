// VirtIO Random Number Generator Driver
// Reference: VirtIO spec v1.2, Section 5.6 (Entropy Device)

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

const VIRTIO_RING_SIZE: usize = 4;

pub struct VirtioRng {
    device: VirtioDevice,
    queue: Mutex<Virtqueue>,
}

struct VirtioDevice {
    mmio: usize,
}

struct Virtqueue {
    desc: *mut VirtqDesc,
    avail: *mut VirtqAvail,
    used: *mut VirtqUsed,
    entropy_virt: *mut u8,
    entropy_phys: u64,
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

const VIRTIO_STATUS_RESET: u8 = 0;
const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;

impl VirtioRng {
    pub unsafe fn new(pci_dev: crate::arch::x86_64::pci::PciDevice) -> Result<Self, &'static str> {
        let bar = match pci_dev.read_bar(0) {
            Some(crate::arch::x86_64::pci::Bar::Memory64(addr)) => addr,
            _ => return Err("Invalid BAR"),
        };

        let mmio = crate::memory::phys_to_virt(bar) as usize;

        let mut device = VirtioDevice { mmio };

        device.reset();
        device.add_status(VIRTIO_STATUS_ACKNOWLEDGE);
        device.add_status(VIRTIO_STATUS_DRIVER);

        let features = device.read_features();
        device.write_features(features & VIRTIO_F_VERSION_1);
        device.add_status(VIRTIO_STATUS_FEATURES_OK);

        if (device.read_status() & VIRTIO_STATUS_FEATURES_OK) == 0 {
            return Err("Features negotiation failed");
        }

        let queue = Virtqueue::new(&mut device, 0, VIRTIO_RING_SIZE)?;

        device.add_status(VIRTIO_STATUS_DRIVER_OK);

        Ok(Self {
            device,
            queue: Mutex::new(queue),
        })
    }

    pub fn read_entropy(&self, buf: &mut [u8]) -> Result<usize, &'static str> {
        let mut queue = self.queue.lock();

        if queue.free.is_empty() {
            return Err("No free descriptors");
        }
        let desc_idx = queue.free.pop().unwrap();

        unsafe {
            let desc = &mut *queue.desc.add(desc_idx as usize);
            desc.addr = queue.entropy_phys;
            desc.len = buf.len() as u32;
            desc.flags = 1;
            desc.next = 0;

            let avail = &mut *queue.avail;
            let idx = avail.idx as usize % VIRTIO_RING_SIZE;
            avail.ring[idx] = desc_idx;
            avail.idx = avail.idx.wrapping_add(1);
        }

        self.device.notify_queue(0);

        loop {
            unsafe {
                let used = &*queue.used;
                if queue.last_used_idx != used.idx {
                    let idx = queue.last_used_idx as usize % VIRTIO_RING_SIZE;
                    let elem = used.ring[idx];

                    if elem.len as usize <= buf.len() {
                        core::ptr::copy_nonoverlapping(
                            queue.entropy_virt,
                            buf.as_mut_ptr(),
                            elem.len as usize,
                        );
                        queue.free.push(desc_idx);
                        queue.last_used_idx = queue.last_used_idx.wrapping_add(1);
                        return Ok(elem.len as usize);
                    }

                    queue.free.push(desc_idx);
                    queue.last_used_idx = queue.last_used_idx.wrapping_add(1);
                    return Err("Invalid entropy length");
                }
            }
            core::hint::spin_loop();
        }
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
    fn new(device: &mut VirtioDevice, queue_idx: u16, size: usize) -> Result<Self, &'static str> {
        unsafe {
            (device.mmio.add(0x16) as *mut u16).write_volatile(queue_idx);
            let max_size = (device.mmio.add(0x18) as *const u16).read_volatile();
            if max_size < size as u16 {
                return Err("Queue size too large");
            }
            (device.mmio.add(0x16) as *mut u16).write_volatile(size as u16);

            let desc_frame = crate::memory::allocate_dma_frame().ok_or("Failed to allocate desc")?;
            let avail_frame = crate::memory::allocate_dma_frame().ok_or("Failed to allocate avail")?;
            let used_frame = crate::memory::allocate_dma_frame().ok_or("Failed to allocate used")?;

            let desc_phys = desc_frame.start_address();
            let avail_phys = avail_frame.start_address();
            let used_phys = used_frame.start_address();

            let desc_virt = crate::memory::phys_to_virt(desc_phys) as *mut VirtqDesc;
            let avail_virt = crate::memory::phys_to_virt(avail_phys) as *mut VirtqAvail;
            let used_virt = crate::memory::phys_to_virt(used_phys) as *mut VirtqUsed;

            core::ptr::write_bytes(desc_virt, 0, size * core::mem::size_of::<VirtqDesc>());
            core::ptr::write_bytes(avail_virt, 0, core::mem::size_of::<VirtqAvail>());
            core::ptr::write_bytes(used_virt, 0, core::mem::size_of::<VirtqUsed>());

            (device.mmio.add(0x10) as *mut u32).write_volatile((desc_phys & 0xFFFFFFFF) as u32);

            (device.mmio.add(0x1A) as *mut u16).write_volatile(0xFFFF);

            let entropy_frame = crate::memory::allocate_dma_frame().ok_or("Failed to allocate entropy buffer")?;
            let entropy_phys = entropy_frame.start_address();
            let entropy_virt = crate::memory::phys_to_virt(entropy_phys) as *mut u8;
            core::ptr::write_bytes(entropy_virt, 0, 4096);

            let mut free = Vec::with_capacity(size);
            for i in 0..size {
                free.push(i as u16);
            }

            Ok(Self {
                desc: desc_virt,
                avail: avail_virt,
                used: used_virt,
                entropy_virt,
                entropy_phys,
                free,
                last_used_idx: 0,
            })
        }
    }
}

static RNG_INSTANCE: Mutex<Option<VirtioRng>> = Mutex::new(None);
static RNG_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init() {
    log::info!("[VirtIO-RNG] Scanning for VirtIO RNG devices...");

    let candidates = crate::arch::x86_64::pci::probe_all(crate::arch::x86_64::pci::ProbeCriteria {
        vendor_id: Some(crate::arch::x86_64::pci::vendor::VIRTIO),
        device_id: Some(crate::arch::x86_64::pci::device::VIRTIO_RNG),
        class_code: None,
        subclass: None,
        prog_if: None,
    });

    for pci_dev in candidates.into_iter() {
        log::info!(
            "VirtIO-RNG: Found device at {:?} (VEN:{:04x} DEV:{:04x})",
            pci_dev.address,
            pci_dev.vendor_id,
            pci_dev.device_id
        );

        pci_dev.enable_bus_master();

        match unsafe { VirtioRng::new(pci_dev) } {
            Ok(rng) => {
                *RNG_INSTANCE.lock() = Some(rng);
                RNG_INITIALIZED.store(true, Ordering::SeqCst);
                log::info!("[VirtIO-RNG] Initialized");
                return;
            }
            Err(e) => {
                log::warn!("VirtIO-RNG: Failed to initialize device: {}", e);
            }
        }
    }

    log::info!("[VirtIO-RNG] No device found");
}

pub fn read_entropy(buf: &mut [u8]) -> Result<usize, &'static str> {
    let rng = RNG_INSTANCE.lock();
    match rng.as_ref() {
        Some(rng) => rng.read_entropy(buf),
        None => Err("RNG not initialized"),
    }
}

pub fn is_available() -> bool {
    RNG_INITIALIZED.load(Ordering::Relaxed)
}
