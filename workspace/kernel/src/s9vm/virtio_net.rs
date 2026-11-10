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

//! s9vm — virtio network device (pure model, MMIO transport).
//!
//! Two split queues (`0` = receive, `1` = transmit). Every buffer starts with
//! the `virtio_net_hdr` (10 bytes in the modern interface); the device strips
//! it on transmit and prepends a zeroed one on receive, which is the "no
//! offload" configuration every driver supports.
//!
//! The device has no host networking of its own: transmitted frames are
//! collected in a byte buffer that the kernel drains (and can forward to a
//! network scheme), and received frames are pushed by the kernel with
//! [`VirtioNet::push_frame`]. This keeps the model pure, testable and
//! independent of the network stack.

use alloc::{collections::VecDeque, vec, vec::Vec};

use super::virtio::{
    apply_status, DeviceFeatures, QueueMemory, QueueNotify, QueueState, SplitQueue,
};

// ---------------------------------------------------------------------------
// Transport registers (virtio-mmio, version 2).
// ---------------------------------------------------------------------------

/// Transport signature.
pub const MAGIC: u32 = 0x7472_6976;
/// Transport version implemented here.
pub const VERSION: u32 = 2;
/// Device identifier of a network device.
pub const DEVICE_ID: u32 = 1;
/// Transport vendor identifier (strat9).
pub const VENDOR_ID: u32 = 0x5354;
/// Highest queue size advertised by the device.
pub const QUEUE_NUM_MAX: u16 = 256;

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
    /// Device configuration space: the MAC address, then link status.
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
    /// The device exposes a MAC address in its configuration space.
    pub const MAC: u32 = 1 << 5;
    /// The device reports link status changes.
    pub const STATUS: u32 = 1 << 16;
}

/// Feature bits (high word).
pub mod feature_hi {
    /// Modern (version 1) interface.
    pub const VERSION_1: u32 = 1;
}

/// Receive queue index.
pub const QUEUE_RX: u32 = 0;
/// Transmit queue index.
pub const QUEUE_TX: u32 = 1;
/// Size of the `virtio_net_hdr` in the modern interface.
pub const NET_HDR_SIZE: usize = 10;
/// MAC address of the device (locally administered).
pub const MAC: [u8; 6] = [0x52, 0x54, 0x39, 0x00, 0x00, 0x01];
/// Maximum bytes processed by one queue notification.
pub const BUDGET: usize = 8192;
/// Maximum number of transmitted bytes buffered for the kernel.
pub const OUTPUT_CAPACITY: usize = 128 * 1024;
/// Maximum number of transmitted frames kept with their boundaries.
pub const MAX_OUTPUT_FRAMES: usize = 256;
/// Maximum number of received frames buffered for the driver.
pub const INPUT_CAPACITY: usize = 256;

/// virtio network device.
#[derive(Debug)]
pub struct VirtioNet {
    status: u32,
    features: DeviceFeatures,
    feature_select: u32,
    queue_select: u32,
    interrupt_status: u32,
    config_generation: u32,
    rx: QueueState,
    tx: QueueState,
    rx_queue: Option<SplitQueue>,
    tx_queue: Option<SplitQueue>,
    input: VecDeque<Vec<u8>>,
    output: Vec<u8>,
    output_frames: VecDeque<Vec<u8>>,
    frames_sent: u32,
    frames_received: u32,
    link_up: bool,
}

impl VirtioNet {
    /// Creates a device with no driver attached.
    pub fn new() -> Self {
        Self {
            status: 0,
            features: DeviceFeatures::new(
                u64::from(feature_lo::MAC)
                    | u64::from(feature_lo::STATUS)
                    | (u64::from(feature_hi::VERSION_1) << 32),
            ),
            feature_select: 0,
            queue_select: 0,
            interrupt_status: 0,
            config_generation: 0,
            rx: QueueState::default(),
            tx: QueueState::default(),
            rx_queue: None,
            tx_queue: None,
            input: VecDeque::new(),
            output: Vec::new(),
            output_frames: VecDeque::new(),
            frames_sent: 0,
            frames_received: 0,
            link_up: true,
        }
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

    /// True if `VIRTIO_NET_F_MAC` was negotiated: the config space carries a
    /// valid MAC address.
    pub const fn mac_negotiated(&self) -> bool {
        self.features.negotiated() & (feature_lo::MAC as u64) != 0
    }

    /// True if `VIRTIO_NET_F_STATUS` was negotiated: the link-status byte in
    /// the config space is meaningful.
    pub const fn link_status_negotiated(&self) -> bool {
        self.features.negotiated() & (feature_lo::STATUS as u64) != 0
    }

    /// True when the emulated link is up.
    pub const fn link_up(&self) -> bool {
        self.link_up
    }

    /// Sets the emulated link state.
    ///
    /// When the link is down, receive frames stay queued (they are never
    /// delivered to the driver) while transmit requests still complete, which
    /// matches the observable behaviour of a real NIC whose link is down.
    pub fn set_link_up(&mut self, link_up: bool) {
        if self.link_up != link_up {
            self.link_up = link_up;
            self.interrupt_status |= interrupt::CONFIG;
        }
    }

    /// Link-status byte reported in the config space (`VIRTIO_NET_S_LINK_UP`).
    pub const fn link_status(&self) -> u8 {
        if self.link_up {
            1
        } else {
            0
        }
    }

    /// Interrupt status register.
    pub const fn interrupt_status(&self) -> u32 {
        self.interrupt_status
    }

    /// True once the driver set `DRIVER_OK` on a non-failed device.
    pub const fn ready(&self) -> bool {
        self.status & status::DRIVER_OK != 0 && self.status & status::FAILED == 0
    }

    /// Number of frames the driver transmitted (diagnostics).
    pub const fn frames_sent(&self) -> u32 {
        self.frames_sent
    }

    /// Number of frames handed to the driver (diagnostics).
    pub const fn frames_received(&self) -> u32 {
        self.frames_received
    }

    /// Bytes transmitted by the driver and not yet drained.
    pub fn output(&self) -> &[u8] {
        &self.output
    }

    /// Takes the transmitted bytes.
    pub fn drain_output(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.output)
    }

    /// Takes the individual frames the guest transmitted (no virtio header).
    ///
    /// The flat [`Self::drain_output`] accessor loses frame boundaries; this
    /// one is used by the network front-end, which needs packet boundaries.
    pub fn drain_frames(&mut self) -> Vec<Vec<u8>> {
        self.output_frames.drain(..).collect()
    }

    /// Queues a frame for the receive path.
    pub fn push_frame(&mut self, frame: &[u8]) {
        if self.input.len() >= INPUT_CAPACITY {
            return;
        }
        self.input.push_back(frame.to_vec());
        self.interrupt_status |= interrupt::CONFIG;
    }

    /// Number of frames waiting for the driver.
    pub fn pending_frames(&self) -> usize {
        self.input.len()
    }

    /// True if the receive queue is programmed and enabled.
    pub const fn rx_ready(&self) -> bool {
        self.rx_queue.is_some()
    }

    /// True if the transmit queue is programmed and enabled.
    pub const fn tx_ready(&self) -> bool {
        self.tx_queue.is_some()
    }

    /// Reads a 32-bit transport register (or config word).
    pub fn read(&self, offset: u32) -> u32 {
        match offset {
            reg::MAGIC => MAGIC,
            reg::VERSION => VERSION,
            reg::DEVICE_ID => DEVICE_ID,
            reg::VENDOR_ID => VENDOR_ID,
            reg::DEVICE_FEATURES => self.features.read_device_word(self.feature_select),
            reg::DRIVER_FEATURES => self.features.read_driver_word(self.feature_select),
            reg::QUEUE_SEL => self.queue_select,
            reg::QUEUE_NUM_MAX => u32::from(QUEUE_NUM_MAX),
            reg::QUEUE_NUM => u32::from(self.queue_state().num),
            reg::QUEUE_READY => u32::from(self.queue_state().ready),
            reg::INTERRUPT_STATUS => self.interrupt_status,
            reg::STATUS => self.status,
            reg::QUEUE_DESC_LOW => self.queue_state().desc as u32,
            reg::QUEUE_DESC_HIGH => (self.queue_state().desc >> 32) as u32,
            reg::QUEUE_AVAIL_LOW => self.queue_state().avail as u32,
            reg::QUEUE_AVAIL_HIGH => (self.queue_state().avail >> 32) as u32,
            reg::QUEUE_USED_LOW => self.queue_state().used as u32,
            reg::QUEUE_USED_HIGH => (self.queue_state().used >> 32) as u32,
            reg::CONFIG_GENERATION => self.config_generation,
            // MAC address: first word = bytes 0..4, second word = bytes 4..6.
            reg::CONFIG => u32::from_le_bytes([MAC[0], MAC[1], MAC[2], MAC[3]]),
            offset if offset == reg::CONFIG + 4 => u32::from_le_bytes([MAC[4], MAC[5], 0, 0]),
            // Link status byte: bit 0 = link up, bit 1 = announce.
            offset if offset == reg::CONFIG + 8 => u32::from(self.link_status()),
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
                if num <= QUEUE_NUM_MAX && self.queue_state_mut().set_num(num).is_ok() {
                    self.refresh_queue();
                } else {
                    self.status |= status::FAILED;
                }
            }
            reg::QUEUE_READY => {
                self.queue_state_mut().ready = value & 1 != 0;
                self.refresh_queue();
            }
            reg::QUEUE_DESC_LOW => {
                let queue = self.queue_state_mut();
                queue.desc = (queue.desc & !0xFFFF_FFFF) | u64::from(value);
            }
            reg::QUEUE_DESC_HIGH => {
                let queue = self.queue_state_mut();
                queue.desc = (queue.desc & 0xFFFF_FFFF) | (u64::from(value) << 32);
            }
            reg::QUEUE_AVAIL_LOW => {
                let queue = self.queue_state_mut();
                queue.avail = (queue.avail & !0xFFFF_FFFF) | u64::from(value);
            }
            reg::QUEUE_AVAIL_HIGH => {
                let queue = self.queue_state_mut();
                queue.avail = (queue.avail & 0xFFFF_FFFF) | (u64::from(value) << 32);
            }
            reg::QUEUE_USED_LOW => {
                let queue = self.queue_state_mut();
                queue.used = (queue.used & !0xFFFF_FFFF) | u64::from(value);
            }
            reg::QUEUE_USED_HIGH => {
                let queue = self.queue_state_mut();
                queue.used = (queue.used & 0xFFFF_FFFF) | (u64::from(value) << 32);
            }
            reg::QUEUE_NOTIFY => self.notify(value, memory),
            reg::INTERRUPT_ACK => self.interrupt_status &= !value,
            reg::STATUS => self.write_status(value, memory),
            _ => {}
        }
    }

    /// Handles a device-status write.
    fn write_status<M: QueueMemory + ?Sized>(&mut self, value: u32, memory: &mut M) {
        if value == 0 {
            *self = Self::new();
            return;
        }
        let next = apply_status(self.status, value, &mut self.features);
        self.status = next;
        if next & status::FAILED != 0 {
            return;
        }
        if value & status::DRIVER_OK != 0 {
            self.service_rx(memory);
        }
    }

    /// State of the queue selected by `QUEUE_SEL`.
    const fn queue_state(&self) -> &QueueState {
        if self.queue_select == QUEUE_TX {
            &self.tx
        } else {
            &self.rx
        }
    }

    /// Mutable state of the queue selected by `QUEUE_SEL`.
    fn queue_state_mut(&mut self) -> &mut QueueState {
        if self.queue_select == QUEUE_TX {
            &mut self.tx
        } else {
            &mut self.rx
        }
    }

    /// Rebuilds the split-queue views after a queue register changed.
    fn refresh_queue(&mut self) {
        let split = self.queue_state().split().ok();
        if self.queue_select == QUEUE_TX {
            self.tx_queue = split;
        } else {
            self.rx_queue = split;
        }
    }

    /// Processes a queue notification.
    fn notify<M: QueueMemory + ?Sized>(&mut self, queue: u32, memory: &mut M) {
        if !self.ready() {
            return;
        }
        let Ok(notify) = QueueNotify::new(queue, 2) else {
            return;
        };
        match notify.index() {
            QUEUE_RX => {
                self.service_rx(memory);
            }
            QUEUE_TX => {
                self.service_tx(memory);
            }
            _ => {}
        }
    }

    /// Hands pending frames to the driver's receive buffers.
    ///
    /// Returns the number of frames delivered.
    pub fn service_rx<M: QueueMemory + ?Sized>(&mut self, memory: &mut M) -> u32 {
        // A down link never delivers: frames stay queued and the driver sees
        // no used-ring entry, exactly as with a real NIC.
        if !self.ready() || !self.link_up || self.input.is_empty() {
            return 0;
        }
        let Some(mut queue) = self.rx_queue else {
            return 0;
        };
        let mut delivered = 0u32;
        while !self.input.is_empty() {
            let Ok(Some(head)) = queue.pop_available(memory) else {
                break;
            };
            let Ok(chain) = queue.chain(memory, head) else {
                break;
            };
            let Some(frame) = self.input.pop_front() else {
                break;
            };
            // The packet is a zeroed virtio_net_hdr followed by the frame.
            // It is split across the writable descriptors of the chain; a
            // buffer that does not fit is truncated (the driver observes a
            // short used length).
            let mut packet = vec![0u8; NET_HDR_SIZE + frame.len()];
            packet[NET_HDR_SIZE..].copy_from_slice(&frame);
            let mut written = 0u32;
            let mut offset = 0usize;
            for descriptor in &chain {
                if !descriptor.writable() || descriptor.len == 0 {
                    continue;
                }
                let count = core::cmp::min(descriptor.len as usize, packet.len() - offset);
                if count == 0 {
                    break;
                }
                if !memory.write_gpa(descriptor.addr, &packet[offset..offset + count]) {
                    break;
                }
                offset += count;
                written += count as u32;
                if offset == packet.len() {
                    break;
                }
            }
            if queue.push_used(memory, head, written).is_err() {
                break;
            }
            self.frames_received = self.frames_received.wrapping_add(1);
            if !queue.no_interrupt_requested(memory).unwrap_or(false) {
                self.interrupt_status |= interrupt::USED_RING;
            }
            delivered += 1;
        }
        self.rx_queue = Some(queue);
        delivered
    }

    /// Collects the frames the driver transmitted.
    ///
    /// Returns the number of bytes appended to [`Self::output`] (headers are
    /// stripped).
    pub fn service_tx<M: QueueMemory + ?Sized>(&mut self, memory: &mut M) -> usize {
        if !self.ready() || self.output.len() >= OUTPUT_CAPACITY {
            return 0;
        }
        let Some(mut queue) = self.tx_queue else {
            return 0;
        };
        let mut total = 0usize;
        while total < BUDGET && self.output.len() < OUTPUT_CAPACITY {
            let Ok(Some(head)) = queue.pop_available(memory) else {
                break;
            };
            let Ok(chain) = queue.chain(memory, head) else {
                break;
            };
            let mut packet = Vec::new();
            let mut written = 0u32;
            for descriptor in &chain {
                if descriptor.writable() || descriptor.len == 0 {
                    continue;
                }
                let mut buffer = vec![0u8; descriptor.len as usize];
                if !memory.read_gpa(descriptor.addr, &mut buffer) {
                    break;
                }
                packet.extend_from_slice(&buffer);
                written += descriptor.len;
            }
            if packet.len() > NET_HDR_SIZE {
                let payload = &packet[NET_HDR_SIZE..];
                let count = core::cmp::min(payload.len(), OUTPUT_CAPACITY - self.output.len());
                self.output.extend_from_slice(&payload[..count]);
                if self.output_frames.len() >= MAX_OUTPUT_FRAMES {
                    self.output_frames.pop_front();
                }
                self.output_frames.push_back(payload[..count].to_vec());
                total += count;
                self.frames_sent = self.frames_sent.wrapping_add(1);
            }
            if queue.push_used(memory, head, written).is_err() {
                break;
            }
            if !queue.no_interrupt_requested(memory).unwrap_or(false) {
                self.interrupt_status |= interrupt::USED_RING;
            }
        }
        self.tx_queue = Some(queue);
        total
    }
}

impl Default for VirtioNet {
    fn default() -> Self {
        Self::new()
    }
}
