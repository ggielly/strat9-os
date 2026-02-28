// VirtIO GPU Driver
// Reference: VirtIO spec v1.2, Section 5.4 (GPU Device)

use crate::{
    arch::x86_64::pci::{self, Bar, ProbeCriteria},
    memory::{allocate_dma_frame, get_allocator, phys_to_virt, FrameAllocator, PhysFrame},
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
    framebuffer_allocation: Option<(PhysFrame, u8)>,
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
const VIRTIO_GPU_CMD_SET_SCANOUT: u32 = 0x0103;
const VIRTIO_GPU_CMD_RESOURCE_FLUSH: u32 = 0x0104;
const VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
const VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;

// VirtIO GPU responses
const VIRTIO_GPU_RESP_OK_NODATA: u32 = 0x1100;
const VIRTIO_GPU_RESP_OK_DISPLAY_INFO: u32 = 0x1101;

// Virtqueue descriptor flags
const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

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
struct CmdResourceFlush {
    hdr: CtrlHeader,
    rect: GpuRect,
    resource_id: u32,
    _padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CmdTransferToHost2d {
    hdr: CtrlHeader,
    rect: GpuRect,
    offset: u64,
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
            framebuffer_allocation: None,
        };

        gpu.init_display()?;
        Ok(gpu)
    }

    fn init_display(&mut self) -> Result<(), &'static str> {
        self.get_display_info()?;

        let framebuffer_size = self.info.stride as usize * self.info.height as usize;
        if framebuffer_size == 0 {
            return Err("Display reports zero-sized framebuffer");
        }
        let framebuffer_pages = (framebuffer_size + 4095) / 4096;
        let framebuffer_order = framebuffer_pages
            .next_power_of_two()
            .trailing_zeros() as u8;

        let framebuffer_frame = {
            let mut alloc_guard = get_allocator().lock();
            let allocator = alloc_guard
                .as_mut()
                .ok_or("Allocator unavailable for framebuffer")?;
            allocator
                .alloc(framebuffer_order)
                .map_err(|_| "Failed to allocate contiguous framebuffer")?
        };
        let framebuffer_phys = framebuffer_frame.start_address.as_u64();
        let framebuffer_virt = phys_to_virt(framebuffer_phys) as *mut u8;

        // SAFETY: `framebuffer_virt` points to a freshly allocated DMA buffer
        // that we own for at least `framebuffer_size` bytes.
        unsafe {
            core::ptr::write_bytes(framebuffer_virt, 0, framebuffer_size);
        }

        self.info.framebuffer_phys = framebuffer_phys;
        self.info.framebuffer_virt = framebuffer_virt;
        self.framebuffer_allocation = Some((framebuffer_frame, framebuffer_order));

        let resource_id = 1;
        self.resource_create_2d(resource_id, self.info.width, self.info.height)?;
        self.resource_attach_backing(resource_id, framebuffer_phys, framebuffer_size as u32)?;
        self.set_scanout(0, resource_id)?;
        self.transfer_to_host_2d(resource_id, 0, 0, self.info.width, self.info.height)?;
        self.resource_flush(resource_id, 0, 0, self.info.width, self.info.height)?;

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

        let resp: RespDisplayInfo = self.send_command(&cmd)?;
        if resp.hdr.cmd_and_flags != VIRTIO_GPU_RESP_OK_DISPLAY_INFO {
            return Err("GET_DISPLAY_INFO failed");
        }

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

        let resp: CtrlHeader = self.send_command(&cmd)?;
        if resp.cmd_and_flags != VIRTIO_GPU_RESP_OK_NODATA {
            return Err("RESOURCE_CREATE_2D failed");
        }
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

        let entry_bytes = unsafe {
            // SAFETY: `entry` is a POD `#[repr(C)]` struct and we convert it to
            // a byte view for DMA submission.
            core::slice::from_raw_parts(
                (&entry as *const MemEntry) as *const u8,
                core::mem::size_of::<MemEntry>(),
            )
        };
        let resp: CtrlHeader = self.send_command_with_payload(&cmd, Some(entry_bytes))?;
        if resp.cmd_and_flags != VIRTIO_GPU_RESP_OK_NODATA {
            return Err("RESOURCE_ATTACH_BACKING failed");
        }
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

        let resp: CtrlHeader = self.send_command(&cmd)?;
        if resp.cmd_and_flags != VIRTIO_GPU_RESP_OK_NODATA {
            return Err("SET_SCANOUT failed");
        }
        Ok(())
    }

    fn transfer_to_host_2d(
        &self,
        resource_id: u32,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
    ) -> Result<(), &'static str> {
        let cmd = CmdTransferToHost2d {
            hdr: CtrlHeader {
                cmd_and_flags: VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D,
                fence_id: 0,
                ctx_id: 0,
                _padding: 0,
            },
            rect: GpuRect {
                x,
                y,
                width,
                height,
            },
            offset: 0,
            resource_id,
            _padding: 0,
        };

        let resp: CtrlHeader = self.send_command(&cmd)?;
        if resp.cmd_and_flags != VIRTIO_GPU_RESP_OK_NODATA {
            return Err("TRANSFER_TO_HOST_2D failed");
        }
        Ok(())
    }

    fn resource_flush(
        &self,
        resource_id: u32,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
    ) -> Result<(), &'static str> {
        let cmd = CmdResourceFlush {
            hdr: CtrlHeader {
                cmd_and_flags: VIRTIO_GPU_CMD_RESOURCE_FLUSH,
                fence_id: 0,
                ctx_id: 0,
                _padding: 0,
            },
            rect: GpuRect {
                x,
                y,
                width,
                height,
            },
            resource_id,
            _padding: 0,
        };

        let resp: CtrlHeader = self.send_command(&cmd)?;
        if resp.cmd_and_flags != VIRTIO_GPU_RESP_OK_NODATA {
            return Err("RESOURCE_FLUSH failed");
        }
        Ok(())
    }

    fn send_command<T: Copy, R: Copy>(&self, cmd: &T) -> Result<R, &'static str> {
        self.send_command_with_payload::<T, R>(cmd, None)
    }

    fn send_command_with_payload<T: Copy, R: Copy>(
        &self,
        cmd: &T,
        payload: Option<&[u8]>,
    ) -> Result<R, &'static str> {
        let cmd_size = core::mem::size_of::<T>();
        let resp_size = core::mem::size_of::<R>();

        if cmd_size > 4096 || resp_size > 4096 {
            return Err("Command or response too large");
        }
        if payload.map(|p| p.len()).unwrap_or(0) > 4096 {
            return Err("Payload too large");
        }

        let cmd_frame = allocate_dma_frame().ok_or("Failed to allocate command buffer")?;
        let payload_frame = if payload.is_some() {
            Some(allocate_dma_frame().ok_or("Failed to allocate payload buffer")?)
        } else {
            None
        };
        let resp_frame = allocate_dma_frame().ok_or("Failed to allocate response buffer")?;

        let cmd_phys = cmd_frame.start_address.as_u64();
        let cmd_virt = phys_to_virt(cmd_phys) as *mut u8;
        let payload_phys = payload_frame
            .as_ref()
            .map(|f| f.start_address.as_u64())
            .unwrap_or(0);
        let payload_virt = if payload.is_some() {
            Some(phys_to_virt(payload_phys) as *mut u8)
        } else {
            None
        };
        let resp_phys = resp_frame.start_address.as_u64();
        let resp_virt = phys_to_virt(resp_phys) as *mut u8;

        let mut ctrl_queue = self.ctrl_queue.lock();
        let needed_desc = if payload.is_some() { 3 } else { 2 };
        if ctrl_queue.free.len() < needed_desc {
            drop(ctrl_queue);
            self.free_dma_frame(cmd_frame);
            if let Some(frame) = payload_frame {
                self.free_dma_frame(frame);
            }
            self.free_dma_frame(resp_frame);
            return Err("Not enough free descriptors");
        }

        let head_idx = ctrl_queue.free.pop().ok_or("Missing descriptor")?;
        let middle_idx = if payload.is_some() {
            Some(ctrl_queue.free.pop().ok_or("Missing payload descriptor")?)
        } else {
            None
        };
        let resp_idx = ctrl_queue.free.pop().ok_or("Missing response descriptor")?;

        unsafe {
            // SAFETY: DMA command/response buffers are freshly allocated and
            // valid for the copied sizes.
            core::ptr::copy_nonoverlapping(cmd as *const _ as *const u8, cmd_virt, cmd_size);
            if let (Some(data), Some(data_virt)) = (payload, payload_virt) {
                core::ptr::copy_nonoverlapping(data.as_ptr(), data_virt, data.len());
            }

            let head_desc = &mut *ctrl_queue.desc.add(head_idx as usize);
            head_desc.addr = cmd_phys;
            head_desc.len = cmd_size as u32;
            head_desc.flags = VIRTQ_DESC_F_NEXT;
            head_desc.next = middle_idx.unwrap_or(resp_idx);

            if let Some(middle) = middle_idx {
                let data = payload.expect("payload descriptor without payload");
                let data_desc = &mut *ctrl_queue.desc.add(middle as usize);
                data_desc.addr = payload_phys;
                data_desc.len = data.len() as u32;
                data_desc.flags = VIRTQ_DESC_F_NEXT;
                data_desc.next = resp_idx;
            }

            let resp_desc = &mut *ctrl_queue.desc.add(resp_idx as usize);
            resp_desc.addr = resp_phys;
            resp_desc.len = resp_size as u32;
            resp_desc.flags = VIRTQ_DESC_F_WRITE;
            resp_desc.next = 0;

            let avail = &mut *ctrl_queue.avail;
            let ring_idx = avail.idx as usize % VIRTIO_RING_SIZE;
            avail.ring[ring_idx] = head_idx;
            avail.idx = avail.idx.wrapping_add(1);
        }

        self.device.notify_queue(0);

        let mut completed = false;
        while !completed {
            unsafe {
                // SAFETY: `ctrl_queue.used` points to a valid shared vring page.
                let used = &*ctrl_queue.used;
                if ctrl_queue.last_used_idx != used.idx {
                    let idx = ctrl_queue.last_used_idx as usize % VIRTIO_RING_SIZE;
                    let elem = used.ring[idx];
                    ctrl_queue.last_used_idx = ctrl_queue.last_used_idx.wrapping_add(1);
                    completed = elem.id as u16 == head_idx;
                }
            }
            if !completed {
                core::hint::spin_loop();
            }
        }

        let response = unsafe {
            // SAFETY: The device has completed the command and wrote `resp_size`
            // bytes in `resp_virt`. Reading as `R` is valid by construction.
            core::ptr::read_unaligned(resp_virt as *const R)
        };

        ctrl_queue.free.push(head_idx);
        if let Some(middle) = middle_idx {
            ctrl_queue.free.push(middle);
        }
        ctrl_queue.free.push(resp_idx);
        drop(ctrl_queue);

        self.free_dma_frame(cmd_frame);
        if let Some(frame) = payload_frame {
            self.free_dma_frame(frame);
        }
        self.free_dma_frame(resp_frame);

        Ok(response)
    }

    fn free_dma_frame(&self, frame: PhysFrame) {
        let mut alloc_guard = get_allocator().lock();
        if let Some(allocator) = alloc_guard.as_mut() {
            allocator.free(frame, 0);
        }
    }

    pub fn info(&self) -> GpuInfo {
        self.info
    }

    pub fn flush(&self, x: u32, y: u32, width: u32, height: u32) {
        let _ = self.transfer_to_host_2d(1, x, y, width, height);
        let _ = self.resource_flush(1, x, y, width, height);
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
