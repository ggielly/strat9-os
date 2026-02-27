// VirtIO GPU Driver
// Reference: VirtIO spec v1.2, Section 5.4 (GPU Device)

use crate::{
    arch::x86_64::pci::{self, Bar, ProbeCriteria},
    memory::{allocate_dma_frame, phys_to_virt},
};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::{Mutex, Once};

const VIRTIO_RING_SIZE: usize = 8;

pub struct VirtioGpu {
    device: VirtioDevice,
    ctrl_queue: Mutex<Virtqueue>,
    cursor_queue: Mutex<Virtqueue>,
    info: GpuInfo,
}

struct VirtioDevice {
    mmio: usize,
}

struct Virtqueue {
    desc: *mut VirtqDesc,
    avail: *mut VirtqAvail,
    used: *mut VirtqUsed,
    desc_phys: u64,
    avail_phys: u64,
    used_phys: u64,
    free: Vec<u16>,
    last_used_idx: u16,
}

unsafe impl Send for Virtqueue {}

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

#[derive(Clone, Copy)]
pub struct GpuInfo {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub framebuffer_phys: u64,
    pub framebuffer_virt: *mut u8,
}

unsafe impl Send for GpuInfo {}
unsafe impl Sync for GpuInfo {}

const VIRTIO_F_VERSION_1: u64 = 1 << 32;
const VIRTIO_GPU_F_VIRGL: u32 = 0;
const VIRTIO_GPU_F_EDID: u32 = 1;

const VIRTIO_STATUS_RESET: u8 = 0;
const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;

// VirtIO GPU commands
const VIRTIO_GPU_CMD_GET_DISPLAY_INFO: u32 = 0x0100;
const VIRTIO_GPU_CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
const VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0104;
const VIRTIO_GPU_CMD_SET_SCANOUT: u32 = 0x0103;
const VIRTIO_GPU_CMD_SET_FRAMEBUFFER: u32 = 0x0105;
const VIRTIO_GPU_CMD_RESOURCE_FLUSH: u32 = 0x0106;

// VirtIO GPU formats
const VIRTIO_GPU_FORMAT_X8R8G8B8: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct GpuRect {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CtrlHeader {
    cmd_and_flags: u32,
    fence_id: u64,
    ctx_id: u32,
    _padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CmdGetDisplayInfo {
    hdr: CtrlHeader,
    scanout_id: u32,
    _padding: [u32; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RespDisplayInfo {
    hdr: CtrlHeader,
    rect: GpuRect,
    enabled: u32,
    _padding: [u32; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CmdResourceCreate2d {
    hdr: CtrlHeader,
    resource_id: u32,
    format: u32,
    width: u32,
    height: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CmdResourceAttachBacking {
    hdr: CtrlHeader,
    resource_id: u32,
    nr_entries: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MemEntry {
    addr: u64,
    length: u32,
    _padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CmdSetScanout {
    hdr: CtrlHeader,
    rect: GpuRect,
    scanout_id: u32,
    resource_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CmdSetFramebuffer {
    hdr: CtrlHeader,
    resource_id: u32,
    scanout_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CmdResourceFlush {
    hdr: CtrlHeader,
    rect: GpuRect,
    resource_id: u32,
    _padding: u32,
}

impl VirtioGpu {
    pub unsafe fn new(pci_dev: pci::PciDevice) -> Result<Self, &'static str> {
        let bar = match pci_dev.read_bar(0) {
            Some(Bar::Memory64 { addr, .. }) => addr,
            _ => return Err("Invalid BAR"),
        };

        let mmio = phys_to_virt(bar) as usize;
        let mut device = VirtioDevice { mmio };

        device.reset();
        device.add_status(VIRTIO_STATUS_ACKNOWLEDGE);
        device.add_status(VIRTIO_STATUS_DRIVER);

        let features = device.read_features();
        let mut guest_features = VIRTIO_F_VERSION_1;
        if (features & (1 << VIRTIO_GPU_F_EDID)) != 0 {
            guest_features |= 1 << VIRTIO_GPU_F_EDID;
        }
        device.write_features(guest_features);
        device.add_status(VIRTIO_STATUS_FEATURES_OK);

        if (device.read_status() & VIRTIO_STATUS_FEATURES_OK) == 0 {
            return Err("Features negotiation failed");
        }

        let ctrl_queue = Virtqueue::new(&mut device, 0)?;
        let cursor_queue = Virtqueue::new(&mut device, 1)?;

        device.add_status(VIRTIO_STATUS_DRIVER_OK);

        let mut gpu = Self {
            device,
            ctrl_queue: Mutex::new(ctrl_queue),
            cursor_queue: Mutex::new(cursor_queue),
            info: GpuInfo {
                width: 1024,
                height: 768,
                stride: 1024 * 4,
                framebuffer_phys: 0,
                framebuffer_virt: core::ptr::null_mut(),
            },
        };

        gpu.init_display()?;
        Ok(gpu)
    }

    fn init_display(&mut self) -> Result<(), &'static str> {
        self.get_display_info()?;

        let framebuffer_size = self.info.stride as usize * self.info.height as usize;
        let framebuffer_pages = (framebuffer_size + 4095) / 4096;

        let mut framebuffer_phys = 0u64;
        let mut framebuffer_virt = core::ptr::null_mut::<u8>();

        for i in 0..framebuffer_pages {
            let frame = allocate_dma_frame().ok_or("Failed to allocate framebuffer")?;
            let page_phys = frame.start_address.as_u64();
            let page_virt = phys_to_virt(page_phys) as *mut u8;

            if i == 0 {
                framebuffer_phys = page_phys;
                framebuffer_virt = page_virt;
            }

            unsafe {
                core::ptr::write_bytes(page_virt, 0, 4096);
            }
        }

        self.info.framebuffer_phys = framebuffer_phys;
        self.info.framebuffer_virt = framebuffer_virt;

        let resource_id = 1;
        self.resource_create_2d(resource_id, self.info.width, self.info.height)?;
        self.resource_attach_backing(resource_id, framebuffer_phys, framebuffer_size as u32)?;
        self.set_scanout(0, resource_id)?;
        self.set_framebuffer(resource_id, 0)?;

        log::info!(
            "VirtIO GPU: {}x{} @ {} bpp, framebuffer at 0x{:x}",
            self.info.width,
            self.info.height,
            32,
            framebuffer_phys
        );

        Ok(())
    }

    fn get_display_info(&mut self) -> Result<(), &'static str> {
        let cmd = CmdGetDisplayInfo {
            hdr: CtrlHeader {
                cmd_and_flags: VIRTIO_GPU_CMD_GET_DISPLAY_INFO,
                fence_id: 0,
                ctx_id: 0,
                _padding: 0,
            },
            scanout_id: 0,
            _padding: [0; 3],
        };

        let response = self.send_command(&cmd, core::mem::size_of::<CmdGetDisplayInfo>())?;
        let resp = unsafe { &*(response as *const RespDisplayInfo) };

        if resp.enabled != 0 {
            self.info.width = resp.rect.width;
            self.info.height = resp.rect.height;
            self.info.stride = resp.rect.width * 4;
        }

        Ok(())
    }

    fn resource_create_2d(&self, resource_id: u32, width: u32, height: u32) -> Result<(), &'static str> {
        let cmd = CmdResourceCreate2d {
            hdr: CtrlHeader {
                cmd_and_flags: VIRTIO_GPU_CMD_RESOURCE_CREATE_2D,
                fence_id: 0,
                ctx_id: 0,
                _padding: 0,
            },
            resource_id,
            format: VIRTIO_GPU_FORMAT_X8R8G8B8,
            width,
            height,
        };

        self.send_command(&cmd, core::mem::size_of::<CmdResourceCreate2d>())?;
        Ok(())
    }

    fn resource_attach_backing(&self, resource_id: u32, addr: u64, length: u32) -> Result<(), &'static str> {
        let cmd = CmdResourceAttachBacking {
            hdr: CtrlHeader {
                cmd_and_flags: VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING,
                fence_id: 0,
                ctx_id: 0,
                _padding: 0,
            },
            resource_id,
            nr_entries: 1,
        };

        let entry = MemEntry {
            addr,
            length,
            _padding: 0,
        };

        self.send_command_with_data(&cmd, core::mem::size_of::<CmdResourceAttachBacking>(), &entry, core::mem::size_of::<MemEntry>())?;
        Ok(())
    }

    fn set_scanout(&self, scanout_id: u32, resource_id: u32) -> Result<(), &'static str> {
        let cmd = CmdSetScanout {
            hdr: CtrlHeader {
                cmd_and_flags: VIRTIO_GPU_CMD_SET_SCANOUT,
                fence_id: 0,
                ctx_id: 0,
                _padding: 0,
            },
            rect: GpuRect {
                x: 0,
                y: 0,
                width: self.info.width,
                height: self.info.height,
            },
            scanout_id,
            resource_id,
        };

        self.send_command(&cmd, core::mem::size_of::<CmdSetScanout>())?;
        Ok(())
    }

    fn set_framebuffer(&self, resource_id: u32, scanout_id: u32) -> Result<(), &'static str> {
        let cmd = CmdSetFramebuffer {
            hdr: CtrlHeader {
                cmd_and_flags: VIRTIO_GPU_CMD_SET_FRAMEBUFFER,
                fence_id: 0,
                ctx_id: 0,
                _padding: 0,
            },
            resource_id,
            scanout_id,
        };

        self.send_command(&cmd, core::mem::size_of::<CmdSetFramebuffer>())?;
        Ok(())
    }

    fn send_command<T: Copy>(&self, cmd: &T, cmd_size: usize) -> Result<*mut u8, &'static str> {
        let mut ctrl_queue = self.ctrl_queue.lock();

        if ctrl_queue.free.is_empty() {
            return Err("No free descriptors");
        }
        let desc_idx = ctrl_queue.free.pop().unwrap();

        let cmd_frame = allocate_dma_frame().ok_or("Failed to allocate command buffer")?;
        let cmd_phys = cmd_frame.start_address.as_u64();
        let cmd_virt = phys_to_virt(cmd_phys) as *mut u8;

        unsafe {
            core::ptr::copy_nonoverlapping(cmd as *const _ as *const u8, cmd_virt, cmd_size);

            let desc = &mut *ctrl_queue.desc.add(desc_idx as usize);
            desc.addr = cmd_phys;
            desc.len = cmd_size as u32;
            desc.flags = 1;
            desc.next = 0;

            let avail = &mut *ctrl_queue.avail;
            let idx = avail.idx as usize % VIRTIO_RING_SIZE;
            avail.ring[idx] = desc_idx;
            avail.idx = avail.idx.wrapping_add(1);
        }

        self.device.notify_queue(0);

        loop {
            unsafe {
                let used = &*ctrl_queue.used;
                if ctrl_queue.last_used_idx != used.idx {
                    let idx = ctrl_queue.last_used_idx as usize % VIRTIO_RING_SIZE;
                    let elem = used.ring[idx];

                    ctrl_queue.free.push(desc_idx);
                    ctrl_queue.last_used_idx = ctrl_queue.last_used_idx.wrapping_add(1);

                    return Ok(cmd_virt);
                }
            }
            core::hint::spin_loop();
        }
    }

    fn send_command_with_data<T: Copy, U: Copy>(
        &self,
        cmd: &T,
        cmd_size: usize,
        data: &U,
        data_size: usize,
    ) -> Result<(), &'static str> {
        let mut ctrl_queue = self.ctrl_queue.lock();

        if ctrl_queue.free.len() < 2 {
            return Err("Not enough free descriptors");
        }
        let cmd_desc_idx = ctrl_queue.free.pop().unwrap();
        let data_desc_idx = ctrl_queue.free.pop().unwrap();

        let cmd_frame = allocate_dma_frame().ok_or("Failed to allocate command buffer")?;
        let cmd_phys = cmd_frame.start_address.as_u64();
        let cmd_virt = phys_to_virt(cmd_phys) as *mut u8;

        let data_frame = allocate_dma_frame().ok_or("Failed to allocate data buffer")?;
        let data_phys = data_frame.start_address.as_u64();
        let data_virt = phys_to_virt(data_phys) as *mut u8;

        unsafe {
            core::ptr::copy_nonoverlapping(cmd as *const _ as *const u8, cmd_virt, cmd_size);
            core::ptr::copy_nonoverlapping(data as *const _ as *const u8, data_virt, data_size);

            let cmd_desc = &mut *ctrl_queue.desc.add(cmd_desc_idx as usize);
            cmd_desc.addr = cmd_phys;
            cmd_desc.len = cmd_size as u32;
            cmd_desc.flags = 1 | 2;
            cmd_desc.next = data_desc_idx;

            let data_desc = &mut *ctrl_queue.desc.add(data_desc_idx as usize);
            data_desc.addr = data_phys;
            data_desc.len = data_size as u32;
            data_desc.flags = 1 | 2;
            data_desc.next = 0;

            let avail = &mut *ctrl_queue.avail;
            let idx = avail.idx as usize % VIRTIO_RING_SIZE;
            avail.ring[idx] = cmd_desc_idx;
            avail.idx = avail.idx.wrapping_add(1);
        }

        self.device.notify_queue(0);

        loop {
            unsafe {
                let used = &*ctrl_queue.used;
                if ctrl_queue.last_used_idx != used.idx {
                    ctrl_queue.free.push(cmd_desc_idx);
                    ctrl_queue.free.push(data_desc_idx);
                    ctrl_queue.last_used_idx = ctrl_queue.last_used_idx.wrapping_add(1);
                    return Ok(());
                }
            }
            core::hint::spin_loop();
        }
    }

    pub fn info(&self) -> GpuInfo {
        self.info
    }

    pub fn flush(&self, x: u32, y: u32, width: u32, height: u32) {
        let cmd = CmdResourceFlush {
            hdr: CtrlHeader {
                cmd_and_flags: VIRTIO_GPU_CMD_RESOURCE_FLUSH,
                fence_id: 0,
                ctx_id: 0,
                _padding: 0,
            },
            rect: GpuRect { x, y, width, height },
            resource_id: 1,
            _padding: 0,
        };

        let _ = self.send_command(&cmd, core::mem::size_of::<CmdResourceFlush>());
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
            let current = ((self.mmio + 0x14) as *const u8).read_volatile();
            ((self.mmio + 0x14) as *mut u8).write_volatile(current | status);
        }
    }

    fn read_status(&self) -> u8 {
        unsafe { ((self.mmio + 0x14) as *const u8).read_volatile() }
    }

    fn read_features(&self) -> u64 {
        unsafe {
            let lo = (self.mmio as *const u32).read_volatile() as u64;
            let hi = ((self.mmio + 4) as *const u32).read_volatile() as u64;
            (hi << 32) | lo
        }
    }

    fn write_features(&mut self, features: u64) {
        unsafe {
            (self.mmio as *mut u32).write_volatile((features & 0xFFFFFFFF) as u32);
            ((self.mmio + 4) as *mut u32).write_volatile(((features >> 32) & 0xFFFFFFFF) as u32);
        }
    }

    fn notify_queue(&self, queue: u16) {
        unsafe {
            let offset = ((self.mmio + 0x20) as *const u16).read_volatile() as usize;
            let queue_notify = self.mmio + 0x50 + offset * 4;
            (queue_notify as *mut u32).write_volatile(queue as u32);
        }
    }
}

impl Virtqueue {
    fn new(device: &mut VirtioDevice, queue_idx: u16) -> Result<Self, &'static str> {
        unsafe {
            ((device.mmio + 0x16) as *mut u16).write_volatile(queue_idx);
            let max_size = ((device.mmio + 0x18) as *const u16).read_volatile();
            if max_size < VIRTIO_RING_SIZE as u16 {
                return Err("Queue size too small");
            }
            ((device.mmio + 0x16) as *mut u16).write_volatile(VIRTIO_RING_SIZE as u16);

            let desc_frame = allocate_dma_frame().ok_or("Failed to allocate desc")?;
            let avail_frame = allocate_dma_frame().ok_or("Failed to allocate avail")?;
            let used_frame = allocate_dma_frame().ok_or("Failed to allocate used")?;

            let desc_phys = desc_frame.start_address.as_u64();
            let avail_phys = avail_frame.start_address.as_u64();
            let used_phys = used_frame.start_address.as_u64();

            let desc_virt = phys_to_virt(desc_phys) as *mut VirtqDesc;
            let avail_virt = phys_to_virt(avail_phys) as *mut VirtqAvail;
            let used_virt = phys_to_virt(used_phys) as *mut VirtqUsed;

            core::ptr::write_bytes(desc_virt, 0, VIRTIO_RING_SIZE * core::mem::size_of::<VirtqDesc>());
            core::ptr::write_bytes(avail_virt, 0, core::mem::size_of::<VirtqAvail>());
            core::ptr::write_bytes(used_virt, 0, core::mem::size_of::<VirtqUsed>());

            ((device.mmio + 0x10) as *mut u32).write_volatile((desc_phys & 0xFFFFFFFF) as u32);
            ((device.mmio + 0x1A) as *mut u16).write_volatile(0xFFFF);

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
                free,
                last_used_idx: 0,
            })
        }
    }
}

static GPU_INSTANCE: Once<Arc<VirtioGpu>> = Once::new();
static GPU_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init() {
    log::info!("[VirtIO-GPU] Scanning for VirtIO GPU devices...");

    let candidates = pci::probe_all(ProbeCriteria {
        vendor_id: Some(pci::vendor::VIRTIO),
        device_id: Some(pci::device::VIRTIO_GPU),
        class_code: None,
        subclass: None,
        prog_if: None,
    });

    for pci_dev in candidates.into_iter() {
        log::info!(
            "VirtIO-GPU: Found device at {:?} (VEN:{:04x} DEV:{:04x})",
            pci_dev.address,
            pci_dev.vendor_id,
            pci_dev.device_id
        );

        pci_dev.enable_bus_master();

        match unsafe { VirtioGpu::new(pci_dev) } {
            Ok(gpu) => {
                let arc = Arc::new(gpu);
                GPU_INSTANCE.call_once(|| arc.clone());
                GPU_INITIALIZED.store(true, Ordering::SeqCst);

                let info = arc.info();
                log::info!(
                    "[VirtIO-GPU] Initialized: {}x{} @ 32bpp",
                    info.width,
                    info.height
                );
                return;
            }
            Err(e) => {
                log::warn!("VirtIO-GPU: Failed to initialize device: {}", e);
            }
        }
    }

    log::info!("[VirtIO-GPU] No device found");
}

pub fn get_gpu() -> Option<Arc<VirtioGpu>> {
    GPU_INSTANCE.get().cloned()
}

pub fn is_available() -> bool {
    GPU_INITIALIZED.load(Ordering::Relaxed)
}

pub fn get_framebuffer_info() -> Option<GpuInfo> {
    GPU_INSTANCE.get().map(|gpu| gpu.info())
}
