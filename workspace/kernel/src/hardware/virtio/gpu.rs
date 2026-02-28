// VirtIO GPU driver
// Reference: VirtIO spec v1.2, Section 5.4 (GPU Device)

use crate::{
    arch::x86_64::pci::{self, Bar, ProbeCriteria},
    memory::{allocate_dma_frame, get_allocator, phys_to_virt, FrameAllocator, PhysFrame},
};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::{Mutex, Once};

const VIRTIO_RING_SIZE: usize = 64;
const PAGE_SIZE: usize = 4096;
const VIRTQ_PAYLOAD_ORDER: u8 = 6;
const FLUSH_OPS_THRESHOLD: u32 = 64;

pub struct VirtioGpu {
    ctrl_queue: Mutex<Virtqueue>,
    _cursor_queue: Mutex<Option<Virtqueue>>,
    info: GpuInfo,
    _framebuffer_pages: Vec<PhysFrame>,
    framebuffer_segments: Vec<FramebufferSegment>,
    framebuffer_size: usize,
    dirty: Mutex<DirtyRect>,
}

struct VirtioDevice {
    mmio: usize,
    queue_notify_addr: usize,
}

struct Virtqueue {
    desc: *mut VirtqDesc,
    avail: *mut VirtqAvail,
    used: *mut VirtqUsed,
    queue_idx: u16,
    queue_size: u16,
    notify_addr: usize,
    free_stack: [u16; VIRTIO_RING_SIZE],
    free_len: usize,
    last_used_idx: u16,
    cmd_phys: u64,
    cmd_virt: *mut u8,
    payload_phys: u64,
    payload_virt: *mut u8,
    payload_capacity: usize,
    resp_phys: u64,
    resp_virt: *mut u8,
}

unsafe impl Send for Virtqueue {}

#[derive(Clone, Copy)]
struct FramebufferSegment {
    virt: *mut u8,
    len: usize,
}

unsafe impl Send for FramebufferSegment {}
unsafe impl Sync for FramebufferSegment {}

#[derive(Clone, Copy)]
struct DirtyRect {
    valid: bool,
    x0: u32,
    y0: u32,
    x1: u32,
    y1: u32,
    pending_ops: u32,
}

impl DirtyRect {
    const fn empty() -> Self {
        Self {
            valid: false,
            x0: 0,
            y0: 0,
            x1: 0,
            y1: 0,
            pending_ops: 0,
        }
    }

    fn include(&mut self, x: u32, y: u32, width: u32, height: u32) {
        if width == 0 || height == 0 {
            return;
        }
        let x1 = x.saturating_add(width);
        let y1 = y.saturating_add(height);
        if !self.valid {
            self.valid = true;
            self.x0 = x;
            self.y0 = y;
            self.x1 = x1;
            self.y1 = y1;
        } else {
            self.x0 = self.x0.min(x);
            self.y0 = self.y0.min(y);
            self.x1 = self.x1.max(x1);
            self.y1 = self.y1.max(y1);
        }
        self.pending_ops = self.pending_ops.saturating_add(1);
    }
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
const VIRTIO_GPU_F_EDID: u32 = 1;

const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;

const VIRTIO_GPU_CMD_GET_DISPLAY_INFO: u32 = 0x0100;
const VIRTIO_GPU_CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
const VIRTIO_GPU_CMD_SET_SCANOUT: u32 = 0x0103;
const VIRTIO_GPU_CMD_RESOURCE_FLUSH: u32 = 0x0104;
const VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
const VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;

const VIRTIO_GPU_RESP_OK_NODATA: u32 = 0x1100;
const VIRTIO_GPU_RESP_OK_DISPLAY_INFO: u32 = 0x1101;

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

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
        let notify_mult = unsafe { ((mmio + 0x20) as *const u16).read_volatile() as usize };
        let queue_notify_addr = mmio + 0x50 + notify_mult * 4;
        let mut device = VirtioDevice {
            mmio,
            queue_notify_addr,
        };

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

        device.add_status(VIRTIO_STATUS_DRIVER_OK);

        let mut gpu = Self {
            ctrl_queue: Mutex::new(ctrl_queue),
            _cursor_queue: Mutex::new(None),
            info: GpuInfo {
                width: 1024,
                height: 768,
                stride: 1024 * 4,
                framebuffer_phys: 0,
                framebuffer_virt: core::ptr::null_mut(),
            },
            _framebuffer_pages: Vec::new(),
            framebuffer_segments: Vec::new(),
            framebuffer_size: 0,
            dirty: Mutex::new(DirtyRect::empty()),
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
        let page_count = (framebuffer_size + PAGE_SIZE - 1) / PAGE_SIZE;
        let mut pages = Vec::with_capacity(page_count);
        let mut entries = Vec::with_capacity(page_count);
        let mut segments = Vec::with_capacity(page_count);

        for _ in 0..page_count {
            let frame = allocate_dma_frame().ok_or("Failed to allocate framebuffer page")?;
            let phys = frame.start_address.as_u64();
            pages.push(frame);
            entries.push(MemEntry {
                addr: phys,
                length: PAGE_SIZE as u32,
                _padding: 0,
            });
            segments.push(FramebufferSegment {
                virt: phys_to_virt(phys) as *mut u8,
                len: PAGE_SIZE,
            });
        }

        if let Some(last) = entries.last_mut() {
            let rem = framebuffer_size % PAGE_SIZE;
            if rem != 0 {
                last.length = rem as u32;
            }
        }
        if let Some(last) = segments.last_mut() {
            let rem = framebuffer_size % PAGE_SIZE;
            if rem != 0 {
                last.len = rem;
            }
        }

        self.info.framebuffer_phys = entries.first().map(|e| e.addr).unwrap_or(0);
        self.info.framebuffer_virt = segments
            .first()
            .map(|s| s.virt)
            .unwrap_or(core::ptr::null_mut());
        self.framebuffer_size = framebuffer_size;
        self._framebuffer_pages = pages;
        self.framebuffer_segments = segments;

        let resource_id = 1;
        self.resource_create_2d(resource_id, self.info.width, self.info.height)?;
        self.resource_attach_backing(resource_id, &entries)?;
        self.set_scanout(0, resource_id)?;
        self.transfer_to_host_2d(resource_id, 0, 0, self.info.width, self.info.height)?;
        self.resource_flush(resource_id, 0, 0, self.info.width, self.info.height)?;

        log::info!(
            "VirtIO GPU: {}x{} @ {} bpp, framebuffer {} pages",
            self.info.width,
            self.info.height,
            32,
            page_count
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

    fn resource_create_2d(
        &self,
        resource_id: u32,
        width: u32,
        height: u32,
    ) -> Result<(), &'static str> {
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

    fn resource_attach_backing(
        &self,
        resource_id: u32,
        entries: &[MemEntry],
    ) -> Result<(), &'static str> {
        if entries.is_empty() {
            return Err("No backing entries");
        }
        let cmd = CmdResourceAttachBacking {
            hdr: CtrlHeader {
                cmd_and_flags: VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING,
                fence_id: 0,
                ctx_id: 0,
                _padding: 0,
            },
            resource_id,
            nr_entries: entries.len() as u32,
        };

        let payload = unsafe {
            core::slice::from_raw_parts(
                entries.as_ptr() as *const u8,
                entries.len() * core::mem::size_of::<MemEntry>(),
            )
        };
        let resp: CtrlHeader = self.send_command_with_payload(&cmd, Some(payload))?;
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
        if cmd_size > PAGE_SIZE || resp_size > PAGE_SIZE {
            return Err("Command or response too large");
        }

        let payload_len = payload.map_or(0, |p| p.len());
        let mut ctrl_queue = self.ctrl_queue.lock();
        if payload_len > ctrl_queue.payload_capacity {
            return Err("Payload too large");
        }

        let needed_desc = if payload_len > 0 { 3 } else { 2 };
        if ctrl_queue.free_len < needed_desc {
            return Err("Not enough free descriptors");
        }

        let head_idx = ctrl_queue.pop_desc().ok_or("Missing descriptor")?;
        let middle_idx = if payload_len > 0 {
            Some(ctrl_queue.pop_desc().ok_or("Missing payload descriptor")?)
        } else {
            None
        };
        let resp_idx = ctrl_queue.pop_desc().ok_or("Missing response descriptor")?;

        unsafe {
            core::ptr::copy_nonoverlapping(
                cmd as *const _ as *const u8,
                ctrl_queue.cmd_virt,
                cmd_size,
            );
            if let Some(data) = payload {
                core::ptr::copy_nonoverlapping(data.as_ptr(), ctrl_queue.payload_virt, data.len());
            }

            let head_desc = &mut *ctrl_queue.desc.add(head_idx as usize);
            head_desc.addr = ctrl_queue.cmd_phys;
            head_desc.len = cmd_size as u32;
            head_desc.flags = VIRTQ_DESC_F_NEXT;
            head_desc.next = middle_idx.unwrap_or(resp_idx);

            if let Some(mid) = middle_idx {
                let data_desc = &mut *ctrl_queue.desc.add(mid as usize);
                data_desc.addr = ctrl_queue.payload_phys;
                data_desc.len = payload_len as u32;
                data_desc.flags = VIRTQ_DESC_F_NEXT;
                data_desc.next = resp_idx;
            }

            let resp_desc = &mut *ctrl_queue.desc.add(resp_idx as usize);
            resp_desc.addr = ctrl_queue.resp_phys;
            resp_desc.len = resp_size as u32;
            resp_desc.flags = VIRTQ_DESC_F_WRITE;
            resp_desc.next = 0;

            let avail = &mut *ctrl_queue.avail;
            let ring_idx = (avail.idx as usize) % (ctrl_queue.queue_size as usize);
            avail.ring[ring_idx] = head_idx;
            avail.idx = avail.idx.wrapping_add(1);
        }

        unsafe {
            (ctrl_queue.notify_addr as *mut u32).write_volatile(ctrl_queue.queue_idx as u32);
        }

        let mut spins: u32 = 0;
        loop {
            unsafe {
                let used = &*ctrl_queue.used;
                if ctrl_queue.last_used_idx != used.idx {
                    let idx =
                        (ctrl_queue.last_used_idx as usize) % (ctrl_queue.queue_size as usize);
                    let elem = used.ring[idx];
                    ctrl_queue.last_used_idx = ctrl_queue.last_used_idx.wrapping_add(1);
                    if elem.id as u16 == head_idx {
                        break;
                    }
                }
            }

            spins = spins.wrapping_add(1);
            if (spins & 0x3ff) == 0 {
                crate::process::yield_task();
            } else {
                core::hint::spin_loop();
            }
        }

        let response = unsafe { core::ptr::read_unaligned(ctrl_queue.resp_virt as *const R) };

        ctrl_queue.push_desc(head_idx);
        if let Some(mid) = middle_idx {
            ctrl_queue.push_desc(mid);
        }
        ctrl_queue.push_desc(resp_idx);

        Ok(response)
    }

    fn copy_to_backing(
        &self,
        mut src: *const u8,
        mut dst_offset: usize,
        mut len: usize,
    ) -> Result<(), &'static str> {
        let end = dst_offset.checked_add(len).ok_or("Copy overflow")?;
        if end > self.framebuffer_size {
            return Err("Copy out of bounds");
        }
        while len > 0 {
            let seg_idx = dst_offset / PAGE_SIZE;
            let seg_off = dst_offset % PAGE_SIZE;
            let seg = self
                .framebuffer_segments
                .get(seg_idx)
                .ok_or("Segment out of bounds")?;
            if seg_off >= seg.len {
                return Err("Segment offset out of bounds");
            }
            let chunk = core::cmp::min(len, seg.len - seg_off);
            unsafe {
                core::ptr::copy_nonoverlapping(src, seg.virt.add(seg_off), chunk);
            }
            unsafe {
                src = src.add(chunk);
            }
            dst_offset += chunk;
            len -= chunk;
        }
        Ok(())
    }

    pub fn present_from_linear(
        &self,
        src: *const u8,
        src_stride: u32,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
    ) -> Result<(), &'static str> {
        if src.is_null() {
            return Err("Invalid source pointer");
        }
        if width == 0 || height == 0 {
            return Ok(());
        }
        if x >= self.info.width || y >= self.info.height {
            return Ok(());
        }

        let width = width.min(self.info.width - x);
        let height = height.min(self.info.height - y);
        let src_stride = src_stride as usize;
        let dst_stride = self.info.stride as usize;
        let row_bytes = (width as usize).checked_mul(4).ok_or("Row overflow")?;

        for row in 0..height as usize {
            let src_off = (y as usize + row)
                .checked_mul(src_stride)
                .and_then(|o| o.checked_add(x as usize * 4))
                .ok_or("Source offset overflow")?;
            let dst_off = (y as usize + row)
                .checked_mul(dst_stride)
                .and_then(|o| o.checked_add(x as usize * 4))
                .ok_or("Destination offset overflow")?;
            let src_row = unsafe { src.add(src_off) };
            self.copy_to_backing(src_row, dst_off, row_bytes)?;
        }

        self.transfer_to_host_2d(1, x, y, width, height)?;
        self.resource_flush(1, x, y, width, height)?;
        Ok(())
    }

    pub fn info(&self) -> GpuInfo {
        self.info
    }

    pub fn flush(&self, x: u32, y: u32, width: u32, height: u32) {
        if width == 0 || height == 0 {
            return;
        }
        let mut dirty = self.dirty.lock();
        dirty.include(x, y, width, height);
        if dirty.pending_ops < FLUSH_OPS_THRESHOLD {
            return;
        }
        let x0 = dirty.x0;
        let y0 = dirty.y0;
        let w = dirty.x1.saturating_sub(dirty.x0);
        let h = dirty.y1.saturating_sub(dirty.y0);
        *dirty = DirtyRect::empty();
        drop(dirty);
        let _ = self.transfer_to_host_2d(1, x0, y0, w, h);
        let _ = self.resource_flush(1, x0, y0, w, h);
    }

    pub fn flush_now(&self) {
        let (x0, y0, w, h) = {
            let mut dirty = self.dirty.lock();
            if !dirty.valid {
                return;
            }
            let x0 = dirty.x0;
            let y0 = dirty.y0;
            let w = dirty.x1.saturating_sub(dirty.x0);
            let h = dirty.y1.saturating_sub(dirty.y0);
            *dirty = DirtyRect::empty();
            (x0, y0, w, h)
        };
        let _ = self.transfer_to_host_2d(1, x0, y0, w, h);
        let _ = self.resource_flush(1, x0, y0, w, h);
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
            (self.mmio as *mut u32).write_volatile((features & 0xFFFF_FFFF) as u32);
            ((self.mmio + 4) as *mut u32).write_volatile(((features >> 32) & 0xFFFF_FFFF) as u32);
        }
    }
}

impl Virtqueue {
    fn new(device: &mut VirtioDevice, queue_idx: u16) -> Result<Self, &'static str> {
        unsafe {
            ((device.mmio + 0x16) as *mut u16).write_volatile(queue_idx);
            let max_size = ((device.mmio + 0x18) as *const u16).read_volatile() as usize;
            if max_size == 0 {
                return Err("Queue size is zero");
            }

            let queue_size = core::cmp::min(max_size, VIRTIO_RING_SIZE) as u16;
            ((device.mmio + 0x16) as *mut u16).write_volatile(queue_size);

            let desc_frame = allocate_dma_frame().ok_or("Failed to allocate desc")?;
            let avail_frame = allocate_dma_frame().ok_or("Failed to allocate avail")?;
            let used_frame = allocate_dma_frame().ok_or("Failed to allocate used")?;
            let cmd_frame = allocate_dma_frame().ok_or("Failed to allocate command buffer")?;
            let resp_frame = allocate_dma_frame().ok_or("Failed to allocate response buffer")?;

            let payload_frame = {
                let mut alloc_guard = get_allocator().lock();
                let allocator = alloc_guard
                    .as_mut()
                    .ok_or("Allocator unavailable for payload buffer")?;
                allocator
                    .alloc(VIRTQ_PAYLOAD_ORDER)
                    .map_err(|_| "Failed to allocate payload buffer")?
            };

            let desc_phys = desc_frame.start_address.as_u64();
            let avail_phys = avail_frame.start_address.as_u64();
            let used_phys = used_frame.start_address.as_u64();
            let cmd_phys = cmd_frame.start_address.as_u64();
            let payload_phys = payload_frame.start_address.as_u64();
            let resp_phys = resp_frame.start_address.as_u64();

            let desc_virt = phys_to_virt(desc_phys) as *mut VirtqDesc;
            let avail_virt = phys_to_virt(avail_phys) as *mut VirtqAvail;
            let used_virt = phys_to_virt(used_phys) as *mut VirtqUsed;
            let cmd_virt = phys_to_virt(cmd_phys) as *mut u8;
            let payload_virt = phys_to_virt(payload_phys) as *mut u8;
            let resp_virt = phys_to_virt(resp_phys) as *mut u8;

            core::ptr::write_bytes(
                desc_virt as *mut u8,
                0,
                core::mem::size_of::<VirtqDesc>() * VIRTIO_RING_SIZE,
            );
            core::ptr::write_bytes(avail_virt as *mut u8, 0, core::mem::size_of::<VirtqAvail>());
            core::ptr::write_bytes(used_virt as *mut u8, 0, core::mem::size_of::<VirtqUsed>());
            core::ptr::write_bytes(payload_virt, 0, PAGE_SIZE << (VIRTQ_PAYLOAD_ORDER as usize));

            ((device.mmio + 0x10) as *mut u32).write_volatile((desc_phys & 0xFFFF_FFFF) as u32);
            ((device.mmio + 0x1A) as *mut u16).write_volatile(0xFFFF);

            let mut free_stack = [0u16; VIRTIO_RING_SIZE];
            for i in 0..(queue_size as usize) {
                free_stack[i] = i as u16;
            }

            Ok(Self {
                desc: desc_virt,
                avail: avail_virt,
                used: used_virt,
                queue_idx,
                queue_size,
                notify_addr: device.queue_notify_addr,
                free_stack,
                free_len: queue_size as usize,
                last_used_idx: 0,
                cmd_phys,
                cmd_virt,
                payload_phys,
                payload_virt,
                payload_capacity: PAGE_SIZE << (VIRTQ_PAYLOAD_ORDER as usize),
                resp_phys,
                resp_virt,
            })
        }
    }

    fn pop_desc(&mut self) -> Option<u16> {
        if self.free_len == 0 {
            None
        } else {
            self.free_len -= 1;
            Some(self.free_stack[self.free_len])
        }
    }

    fn push_desc(&mut self, idx: u16) {
        if self.free_len < self.free_stack.len() {
            self.free_stack[self.free_len] = idx;
            self.free_len += 1;
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
