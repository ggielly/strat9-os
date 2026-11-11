/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! s9vm — virtio block device (pure model, MMIO transport).
//!
//! Single request queue (`0`): each request is a descriptor chain made of
//!
//! 1. a 16-byte header (`type: u32`, `reserved: u32`, `sector: u64`);
//! 2. zero or more data buffers (device-readable for `OUT`, device-writable
//!    for `IN`);
//! 3. one writable status byte (0 = ok, 1 = I/O error, 2 = unsupported).
//!
//! The disk itself is a plain byte vector owned by the model. A real world
//! will back it with a block scheme through policy; the interface is already
//! the right one (512-byte sectors), so the storage layer can be swapped
//! without touching the transport or the request parser.

use alloc::{vec, vec::Vec};

use super::virtio::{
    DeviceFeatures, QueueMemory, QueueNotify, QueueState, SplitQueue, apply_status,
};

// ---------------------------------------------------------------------------
// Transport registers (virtio-mmio, version 2).
// ---------------------------------------------------------------------------

/// Transport signature.
pub const MAGIC: u32 = 0x7472_6976;
/// Transport version implemented here.
pub const VERSION: u32 = 2;
/// Device identifier of a block device.
pub const DEVICE_ID: u32 = 2;
/// Transport vendor identifier (strat9).
pub const VENDOR_ID: u32 = 0x5354;
/// Highest queue size advertised by the device.
pub const QUEUE_NUM_MAX: u16 = 256;
/// Sector size of the virtio block protocol.
pub const SECTOR_SIZE: usize = 512;

/// Offsets of the transport registers.
pub mod reg {
    pub const MAGIC: u32 = 0x000;
    pub const VERSION: u32 = 0x004;
    pub const DEVICE_ID: u32 = 0x008;
    pub const VENDOR_ID: u32 = 0x00C;
    pub const DEVICE_FEATURES: u32 = 0x010;
    pub const DEVICE_FEATURES_SEL: u32 = 0x014;
    pub const DRIVER_FEATURES: u32 = 0x020;
    pub const DRIVER_FEATURES_SEL: u32 = 0x024;
    pub const QUEUE_SEL: u32 = 0x030;
    pub const QUEUE_NUM_MAX: u32 = 0x034;
    pub const QUEUE_NUM: u32 = 0x038;
    pub const QUEUE_READY: u32 = 0x044;
    pub const QUEUE_NOTIFY: u32 = 0x050;
    pub const INTERRUPT_STATUS: u32 = 0x060;
    pub const INTERRUPT_ACK: u32 = 0x064;
    pub const STATUS: u32 = 0x070;
    pub const QUEUE_DESC_LOW: u32 = 0x080;
    pub const QUEUE_DESC_HIGH: u32 = 0x084;
    pub const QUEUE_AVAIL_LOW: u32 = 0x090;
    pub const QUEUE_AVAIL_HIGH: u32 = 0x094;
    pub const QUEUE_USED_LOW: u32 = 0x0A0;
    pub const QUEUE_USED_HIGH: u32 = 0x0A4;
    pub const CONFIG_GENERATION: u32 = 0x0FC;
    /// Device configuration space: `capacity` in 512-byte sectors, 64 bits.
    pub const CONFIG: u32 = 0x100;
}

/// Device status bits.
pub mod status {
    pub const ACKNOWLEDGE: u32 = 1;
    pub const DRIVER: u32 = 2;
    pub const DRIVER_OK: u32 = 4;
    pub const FEATURES_OK: u32 = 8;
    pub const NEEDS_RESET: u32 = 64;
    pub const FAILED: u32 = 128;
}

/// Interrupt status bits.
pub mod interrupt {
    pub const USED_RING: u32 = 1;
    pub const CONFIG: u32 = 2;
}

/// Feature bits (low word).
pub mod feature_lo {
    /// The device is read-only.
    pub const RO: u32 = 1 << 5;
    /// The device supports `FLUSH` requests.
    pub const FLUSH: u32 = 1 << 9;
}

/// Feature bits (high word).
pub mod feature_hi {
    /// Modern (version 1) virtio interface.
    pub const VERSION_1: u32 = 1;
}

/// Request types.
pub mod request {
    /// Read from the device into guest memory.
    pub const IN: u32 = 0;
    /// Write from guest memory to the device.
    pub const OUT: u32 = 1;
    /// Flush the device cache.
    pub const FLUSH: u32 = 4;
}

/// Status byte written back to the guest.
pub mod request_status {
    pub const OK: u8 = 0;
    pub const IO_ERROR: u8 = 1;
    pub const UNSUPPORTED: u8 = 2;
}

/// Request queue index.
pub const QUEUE_REQUEST: u32 = 0;
/// Size of the request header.
pub const HEADER_SIZE: usize = 16;

/// virtio block device.
#[derive(Debug)]
pub struct VirtioBlk {
    status: u32,
    features: DeviceFeatures,
    feature_select: u32,
    queue_select: u32,
    interrupt_status: u32,
    config_generation: u32,
    queue: QueueState,
    queue_view: Option<SplitQueue>,
    disk: Vec<u8>,
    read_only: bool,
    completed: u32,
    last_status: u8,
}

impl VirtioBlk {
    /// Creates a writable zeroed disk of `capacity` bytes (rounded up to a
    /// sector).
    pub fn new(capacity: usize) -> Self {
        Self::with_mode(capacity, false)
    }

    /// Creates a read-only zeroed disk of `capacity` bytes.
    ///
    /// The `VIRTIO_BLK_F_RO` feature is offered so the driver knows the disk
    /// cannot be written; write requests are rejected without touching it.
    pub fn new_read_only(capacity: usize) -> Self {
        Self::with_mode(capacity, true)
    }

    /// Shared constructor for both access modes.
    fn with_mode(capacity: usize, read_only: bool) -> Self {
        let sectors = capacity.div_ceil(SECTOR_SIZE);
        let mut device_features =
            (u64::from(feature_hi::VERSION_1) << 32) | u64::from(feature_lo::FLUSH);
        if read_only {
            device_features |= u64::from(feature_lo::RO);
        }
        Self {
            status: 0,
            features: DeviceFeatures::new(device_features),
            feature_select: 0,
            queue_select: 0,
            interrupt_status: 0,
            config_generation: 0,
            queue: QueueState::default(),
            queue_view: None,
            disk: vec![0u8; sectors * SECTOR_SIZE],
            read_only,
            completed: 0,
            last_status: request_status::OK,
        }
    }

    /// True if the device rejects write requests.
    pub const fn read_only(&self) -> bool {
        self.read_only
    }

    /// Switches the device access mode.
    ///
    /// The offered feature set is fixed at construction; this is meant for a
    /// privileged kernel toggle after the guest has been stopped.
    pub fn set_read_only(&mut self, read_only: bool) {
        self.read_only = read_only;
    }

    /// Number of 512-byte sectors.
    pub fn sectors(&self) -> u64 {
        (self.disk.len() / SECTOR_SIZE) as u64
    }

    /// Mutable disk bytes (privileged kernel side: population/inspection).
    pub fn disk_mut(&mut self) -> &mut [u8] {
        &mut self.disk
    }

    /// Writes `data` at `sector`, zero-padding the last partial sector.
    pub fn write_sector(&mut self, sector: u64, data: &[u8]) -> bool {
        let start = (sector as usize) * SECTOR_SIZE;
        let Some(end) = start.checked_add(SECTOR_SIZE) else {
            return false;
        };
        if end > self.disk.len() {
            return false;
        }
        let length = core::cmp::min(data.len(), SECTOR_SIZE);
        self.disk[start..start + length].copy_from_slice(&data[..length]);
        true
    }

    /// Device status register.
    pub const fn status(&self) -> u32 {
        self.status
    }

    /// Driver feature bits requested so far (raw mask).
    pub const fn driver_features(&self) -> u64 {
        self.features.driver()
    }

    /// Feature mask committed when the driver accepted `FEATURES_OK`.
    pub const fn negotiated_features(&self) -> u64 {
        self.features.negotiated()
    }

    /// True once `FEATURES_OK` was accepted and the device is not failed.
    pub const fn features_ok(&self) -> bool {
        self.status & status::FEATURES_OK != 0 && self.status & status::FAILED == 0
    }

    /// Interrupt status register.
    pub const fn interrupt_status(&self) -> u32 {
        self.interrupt_status
    }

    /// True once the driver set `DRIVER_OK` on a non-failed device.
    pub const fn ready(&self) -> bool {
        self.status & status::DRIVER_OK != 0 && self.status & status::FAILED == 0
    }

    /// Number of completed requests (diagnostics).
    pub const fn completed(&self) -> u32 {
        self.completed
    }

    /// Status byte of the last request.
    pub const fn last_status(&self) -> u8 {
        self.last_status
    }

    /// True if the request queue is programmed and enabled.
    pub const fn queue_ready(&self) -> bool {
        self.queue_view.is_some()
    }

    /// Reads a 32-bit transport register (or config word).
    pub fn read(&self, offset: u32) -> u32 {
        let capacity = self.sectors();
        match offset {
            reg::MAGIC => MAGIC,
            reg::VERSION => VERSION,
            reg::DEVICE_ID => DEVICE_ID,
            reg::VENDOR_ID => VENDOR_ID,
            reg::DEVICE_FEATURES => self.features.read_device_word(self.feature_select),
            reg::DRIVER_FEATURES => self.features.read_driver_word(self.feature_select),
            reg::QUEUE_SEL => self.queue_select,
            reg::QUEUE_NUM_MAX => u32::from(QUEUE_NUM_MAX),
            reg::QUEUE_NUM => u32::from(self.queue.num),
            reg::QUEUE_READY => u32::from(self.queue.ready),
            reg::INTERRUPT_STATUS => self.interrupt_status,
            reg::STATUS => self.status,
            reg::QUEUE_DESC_LOW => self.queue.desc as u32,
            reg::QUEUE_DESC_HIGH => (self.queue.desc >> 32) as u32,
            reg::QUEUE_AVAIL_LOW => self.queue.avail as u32,
            reg::QUEUE_AVAIL_HIGH => (self.queue.avail >> 32) as u32,
            reg::QUEUE_USED_LOW => self.queue.used as u32,
            reg::QUEUE_USED_HIGH => (self.queue.used >> 32) as u32,
            reg::CONFIG_GENERATION => self.config_generation,
            reg::CONFIG => capacity as u32,
            // Second config word (capacity high half) at CONFIG + 4.
            offset if offset == reg::CONFIG + 4 => (capacity >> 32) as u32,
            _ => 0,
        }
    }

    /// Writes a 32-bit transport register.
    pub fn write<M: QueueMemory + ?Sized>(&mut self, offset: u32, value: u32, memory: &mut M) {
        match offset {
            reg::DEVICE_FEATURES_SEL | reg::DRIVER_FEATURES_SEL => self.feature_select = value & 1,
            reg::DRIVER_FEATURES => self.features.write_driver_word(self.feature_select, value),
            reg::QUEUE_SEL => self.queue_select = value & 1,
            reg::QUEUE_NUM => {
                let num = value as u16;
                if num <= QUEUE_NUM_MAX && self.queue.set_num(num).is_ok() {
                    self.refresh_queue();
                } else {
                    self.status |= status::FAILED;
                }
            }
            reg::QUEUE_READY => {
                self.queue.ready = value & 1 != 0;
                self.refresh_queue();
            }
            reg::QUEUE_DESC_LOW => {
                self.queue.desc = (self.queue.desc & !0xFFFF_FFFF) | u64::from(value);
            }
            reg::QUEUE_DESC_HIGH => {
                self.queue.desc = (self.queue.desc & 0xFFFF_FFFF) | (u64::from(value) << 32);
            }
            reg::QUEUE_AVAIL_LOW => {
                self.queue.avail = (self.queue.avail & !0xFFFF_FFFF) | u64::from(value);
            }
            reg::QUEUE_AVAIL_HIGH => {
                self.queue.avail = (self.queue.avail & 0xFFFF_FFFF) | (u64::from(value) << 32);
            }
            reg::QUEUE_USED_LOW => {
                self.queue.used = (self.queue.used & !0xFFFF_FFFF) | u64::from(value);
            }
            reg::QUEUE_USED_HIGH => {
                self.queue.used = (self.queue.used & 0xFFFF_FFFF) | (u64::from(value) << 32);
            }
            reg::QUEUE_NOTIFY => self.notify(value, memory),
            reg::INTERRUPT_ACK => self.interrupt_status &= !value,
            reg::STATUS => self.write_status(value),
            _ => {}
        }
    }

    /// Handles a device-status write.
    fn write_status(&mut self, value: u32) {
        if value == 0 {
            // Device reset (virtio specification): the transport, the feature
            // negotiation and the queue state return to their initial values,
            // but the **backing store is persistent**. A real block device
            // does not erase its medium when the driver resets it, and the
            // policy provisions the disk with `SYS_VMM_LOAD_DISK` before the
            // guest runs: wiping it here made the guest read zeros after its
            // own handshake (observed as the block driver's label mismatch).
            let sectors = self.sectors();
            let read_only = self.read_only;
            let disk = core::mem::take(&mut self.disk);
            *self = Self::with_mode(sectors as usize * SECTOR_SIZE, read_only);
            self.disk = disk;
            return;
        }
        self.status = apply_status(self.status, value, &mut self.features);
    }

    /// Rebuilds the split-queue view after a queue register changed.
    fn refresh_queue(&mut self) {
        self.queue_view = self.queue.split().ok();
    }

    /// Processes a queue notification.
    fn notify<M: QueueMemory + ?Sized>(&mut self, queue: u32, memory: &mut M) {
        if !self.ready() {
            return;
        }
        let Ok(notify) = QueueNotify::new(queue, 1) else {
            return;
        };
        if notify.is(QUEUE_REQUEST) {
            self.service_requests(memory);
        }
    }

    /// Serves the requests published by the driver.
    ///
    /// Returns the number of requests completed.
    pub fn service_requests<M: QueueMemory + ?Sized>(&mut self, memory: &mut M) -> u32 {
        if !self.ready() {
            return 0;
        }
        let Some(mut queue) = self.queue_view else {
            return 0;
        };
        let mut completed = 0u32;
        while completed < 32 {
            let Ok(Some(head)) = queue.pop_available(memory) else {
                break;
            };
            let Ok(chain) = queue.chain(memory, head) else {
                break;
            };
            let written = self.execute(memory, &chain);
            if queue.push_used(memory, head, written).is_err() {
                break;
            }
            self.completed = self.completed.wrapping_add(1);
            completed += 1;
            if !queue.no_interrupt_requested(memory).unwrap_or(false) {
                self.interrupt_status |= interrupt::USED_RING;
            }
        }
        self.queue_view = Some(queue);
        completed
    }

    /// Executes one descriptor chain. Returns the number of bytes written.
    fn execute<M: QueueMemory + ?Sized>(
        &mut self,
        memory: &mut M,
        chain: &[super::virtio::Descriptor],
    ) -> u32 {
        if chain.len() < 2 {
            self.last_status = request_status::IO_ERROR;
            return 0;
        }
        // Header is the first descriptor and must be device-readable.
        let header = chain[0];
        if header.writable() || header.len < HEADER_SIZE as u32 {
            self.last_status = request_status::IO_ERROR;
            return 0;
        }
        let mut header_bytes = [0u8; HEADER_SIZE];
        if !memory.read_gpa(header.addr, &mut header_bytes) {
            self.last_status = request_status::IO_ERROR;
            return 0;
        }
        let request_type = u32::from_le_bytes([
            header_bytes[0],
            header_bytes[1],
            header_bytes[2],
            header_bytes[3],
        ]);
        let sector = u64::from_le_bytes([
            header_bytes[8],
            header_bytes[9],
            header_bytes[10],
            header_bytes[11],
            header_bytes[12],
            header_bytes[13],
            header_bytes[14],
            header_bytes[15],
        ]);

        // The status byte is the last descriptor of the chain (virtio block
        // protocol: header, data..., status). It must be device-writable.
        let status_descriptor = chain[chain.len() - 1];
        if !status_descriptor.writable() || status_descriptor.len < 1 {
            self.last_status = request_status::IO_ERROR;
            return 0;
        }

        // Read-only mode: a write request is rejected without inspecting the
        // data buffers and without touching the disk. The status byte is still
        // published so the driver can complete the request.
        if self.read_only && request_type == request::OUT {
            let _ = memory.write_gpa(status_descriptor.addr, &[request_status::IO_ERROR]);
            self.last_status = request_status::IO_ERROR;
            return 0;
        }

        // Data descriptors are the ones between the header and the status.
        let data_end = chain.len() - 1;
        let mut written = 0u32;
        let mut offset = (sector as usize) * SECTOR_SIZE;
        let mut ok = true;
        for descriptor in &chain[1..data_end] {
            if descriptor.len == 0 {
                continue;
            }
            let length = descriptor.len as usize;
            match request_type {
                request::IN => {
                    if !descriptor.writable() {
                        ok = false;
                        break;
                    }
                    if offset >= self.disk.len() {
                        // The request starts past the end of the disk.
                        ok = false;
                        break;
                    }
                    let available = self.disk.len() - offset;
                    let count = core::cmp::min(length, available);
                    let mut buffer = vec![0u8; count];
                    buffer.copy_from_slice(&self.disk[offset..offset + count]);
                    if !memory.write_gpa(descriptor.addr, &buffer) {
                        ok = false;
                        break;
                    }
                    offset += count;
                    written += count as u32;
                }
                request::OUT => {
                    let mut buffer = vec![0u8; length];
                    if !memory.read_gpa(descriptor.addr, &mut buffer) {
                        ok = false;
                        break;
                    }
                    let available = self.disk.len().saturating_sub(offset);
                    let count = core::cmp::min(length, available);
                    if count != length {
                        ok = false;
                        break;
                    }
                    self.disk[offset..offset + count].copy_from_slice(&buffer);
                    offset += count;
                }
                request::FLUSH => {}
                _ => {
                    ok = false;
                    break;
                }
            }
        }

        // A request that runs past the end of the disk is an I/O error.
        if offset > self.disk.len() {
            ok = false;
        }
        let status_byte = if ok {
            request_status::OK
        } else if request_type != request::IN
            && request_type != request::OUT
            && request_type != request::FLUSH
        {
            request_status::UNSUPPORTED
        } else {
            request_status::IO_ERROR
        };
        let _ = memory.write_gpa(status_descriptor.addr, &[status_byte]);
        self.last_status = status_byte;
        written
    }
}

impl Default for VirtioBlk {
    fn default() -> Self {
        Self::new(64 * 1024)
    }
}
