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

//! s9vm — virtio console device (pure model, MMIO transport).
//!
//! The device exposes the modern virtio-mmio register file (version 2) for a
//! console: two split queues (`0` = receive, `1` = transmit), a small config
//! space (`cols`, `rows`), feature negotiation and device status. Output bytes
//! are collected in [`VirtioConsole::output`] and drained by the kernel (they
//! are written to the kernel log); input bytes are pushed by the kernel with
//! [`VirtioConsole::push_input`] and delivered to the driver's receive
//! buffers.
//!
//! Everything here is transport-agnostic and host-tested: the only external
//! dependency is [`QueueMemory`], the guest-physical accessor of the queue
//! core.

use alloc::{collections::VecDeque, vec::Vec};

use super::virtio::{QueueMemory, SplitQueue};

// ---------------------------------------------------------------------------
// Transport registers (virtio-mmio, version 2).
// ---------------------------------------------------------------------------

/// The four-byte ASCII signature of a virtio-MMIO transport.
pub const MAGIC: u32 = 0x7472_6976;
/// Transport version implemented here.
pub const VERSION: u32 = 2;
/// Device identifier of a console.
pub const DEVICE_ID: u32 = 3;
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
    /// Start of the device-specific configuration space.
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
    /// A queue published a used-ring entry.
    pub const USED_RING: u32 = 1;
    /// The configuration space changed.
    pub const CONFIG: u32 = 2;
}

/// Feature bits (low word).
pub mod feature_lo {
    /// The device reports `cols`/`rows` in its config space.
    pub const CONSOLE_SIZE: u32 = 1;
}

/// Feature bits (high word).
pub mod feature_hi {
    /// Modern (version 1) virtio interface.
    pub const VERSION_1: u32 = 1;
}

/// Receive queue index.
pub const QUEUE_RX: u32 = 0;
/// Transmit queue index.
pub const QUEUE_TX: u32 = 1;
/// Console width reported in the config space.
pub const COLS: u16 = 80;
/// Console height reported in the config space.
pub const ROWS: u16 = 25;
/// Maximum number of bytes processed by one queue notification.
pub const BUDGET: usize = 4096;
/// Maximum number of input bytes buffered for the driver.
pub const INPUT_CAPACITY: usize = 64 * 1024;
/// Maximum number of output bytes buffered for the kernel.
pub const OUTPUT_CAPACITY: usize = 64 * 1024;

/// Programmed state of one split queue.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct QueueState {
    num: u16,
    desc: u64,
    avail: u64,
    used: u64,
    ready: bool,
}

impl QueueState {
    /// Rebuilds the split-queue view from the programmed addresses.
    fn split(self) -> Result<SplitQueue, super::virtio::QueueError> {
        SplitQueue::new(self.num, self.desc, self.avail, self.used)
    }
}

/// virtio console device.
#[derive(Debug)]
pub struct VirtioConsole {
    status: u32,
    device_features: u64,
    driver_features: u64,
    feature_select: u32,
    queue_select: u32,
    interrupt_status: u32,
    config_generation: u32,
    rx: QueueState,
    tx: QueueState,
    rx_queue: Option<SplitQueue>,
    tx_queue: Option<SplitQueue>,
    input: VecDeque<u8>,
    output: Vec<u8>,
}

impl VirtioConsole {
    /// Creates a device with no driver attached.
    pub fn new() -> Self {
        Self {
            status: 0,
            device_features: u64::from(feature_lo::CONSOLE_SIZE)
                | (u64::from(feature_hi::VERSION_1) << 32),
            driver_features: 0,
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
        }
    }

    /// Device status register.
    pub const fn status(&self) -> u32 {
        self.status
    }

    /// Negotiated driver feature bits.
    pub const fn driver_features(&self) -> u64 {
        self.driver_features
    }

    /// Interrupt status register.
    pub const fn interrupt_status(&self) -> u32 {
        self.interrupt_status
    }

    /// True once the driver set `DRIVER_OK`.
    pub const fn ready(&self) -> bool {
        self.status & status::DRIVER_OK != 0
    }

    /// Bytes produced by the transmit queue and not yet drained.
    pub fn output(&self) -> &[u8] {
        &self.output
    }

    /// Takes the pending output bytes.
    pub fn drain_output(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.output)
    }

    /// Queues input bytes for the receive queue.
    pub fn push_input(&mut self, bytes: &[u8]) {
        for byte in bytes {
            if self.input.len() >= INPUT_CAPACITY {
                break;
            }
            self.input.push_back(*byte);
        }
        self.interrupt_status |= interrupt::CONFIG;
    }

    /// Number of input bytes waiting for the driver.
    pub fn pending_input(&self) -> usize {
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
            reg::DEVICE_FEATURES => self.feature_word(self.device_features),
            reg::DRIVER_FEATURES => self.feature_word(self.driver_features),
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
            // Config space: `cols` then `rows`, 16 bits each.
            reg::CONFIG => u32::from(COLS) | (u32::from(ROWS) << 16),
            _ => 0,
        }
    }

    /// Low or high half of a feature word, depending on `DEVICE_FEATURES_SEL`.
    const fn feature_word(&self, features: u64) -> u32 {
        if self.feature_select == 0 {
            features as u32
        } else {
            (features >> 32) as u32
        }
    }

    /// Writes a 32-bit transport register.
    ///
    /// Writes that need queue processing (`QUEUE_NOTIFY`, `STATUS`) go through
    /// `memory`, the guest-physical accessor of the queue core.
    pub fn write<M: QueueMemory + ?Sized>(&mut self, offset: u32, value: u32, memory: &mut M) {
        match offset {
            reg::DEVICE_FEATURES_SEL | reg::DRIVER_FEATURES_SEL => self.feature_select = value & 1,
            reg::DRIVER_FEATURES => {
                if self.feature_select == 0 {
                    self.driver_features =
                        (self.driver_features & 0xFFFF_FFFF_0000_0000) | u64::from(value);
                } else {
                    self.driver_features =
                        (self.driver_features & 0xFFFF_FFFF) | (u64::from(value) << 32);
                }
            }
            reg::QUEUE_SEL => self.queue_select = value & 1,
            reg::QUEUE_NUM => {
                let num = value as u16;
                if num != 0 && num.is_power_of_two() && num <= QUEUE_NUM_MAX {
                    self.queue_state_mut().num = num;
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
                let state = self.queue_state_mut();
                state.desc = (state.desc & !0xFFFF_FFFF) | u64::from(value);
            }
            reg::QUEUE_DESC_HIGH => {
                let state = self.queue_state_mut();
                state.desc = (state.desc & 0xFFFF_FFFF) | (u64::from(value) << 32);
            }
            reg::QUEUE_AVAIL_LOW => {
                let state = self.queue_state_mut();
                state.avail = (state.avail & !0xFFFF_FFFF) | u64::from(value);
            }
            reg::QUEUE_AVAIL_HIGH => {
                let state = self.queue_state_mut();
                state.avail = (state.avail & 0xFFFF_FFFF) | (u64::from(value) << 32);
            }
            reg::QUEUE_USED_LOW => {
                let state = self.queue_state_mut();
                state.used = (state.used & !0xFFFF_FFFF) | u64::from(value);
            }
            reg::QUEUE_USED_HIGH => {
                let state = self.queue_state_mut();
                state.used = (state.used & 0xFFFF_FFFF) | (u64::from(value) << 32);
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
            // Device reset: the driver must reprogram the queues.
            *self = Self::new();
            return;
        }
        self.status = value & !status::NEEDS_RESET;
        if value & status::FAILED != 0 {
            self.status |= status::FAILED;
            return;
        }
        if value & status::DRIVER_OK != 0 {
            // Deliver input the kernel queued before the driver was ready.
            self.service_rx(memory);
        }
    }

    /// Rebuilds the split-queue views after a queue register changed.
    fn refresh_queue(&mut self) {
        let state = *self.queue_state();
        let split = if state.ready {
            state.split().ok()
        } else {
            None
        };
        if self.queue_select == QUEUE_TX {
            self.tx_queue = split;
        } else {
            self.rx_queue = split;
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

    /// Processes a `QUEUE_NOTIFY` write.
    fn notify<M: QueueMemory + ?Sized>(&mut self, queue: u32, memory: &mut M) {
        if !self.ready() {
            return;
        }
        match queue {
            QUEUE_RX => {
                self.service_rx(memory);
            }
            QUEUE_TX => {
                self.service_tx(memory);
            }
            _ => {}
        }
    }

    /// Moves pending input bytes into the driver's receive buffers.
    ///
    /// Returns the number of bytes handed to the driver.
    pub fn service_rx<M: QueueMemory + ?Sized>(&mut self, memory: &mut M) -> usize {
        if !self.ready() || self.input.is_empty() {
            return 0;
        }
        let Some(mut queue) = self.rx_queue else {
            return 0;
        };
        let mut total = 0usize;
        while !self.input.is_empty() && total < BUDGET {
            let Ok(Some(head)) = queue.pop_available(memory) else {
                break;
            };
            let Ok(chain) = queue.chain(memory, head) else {
                break;
            };
            let mut written = 0u32;
            for descriptor in &chain {
                if !descriptor.writable() || descriptor.len == 0 || self.input.is_empty() {
                    continue;
                }
                let capacity = descriptor.len as usize;
                let count = core::cmp::min(capacity, self.input.len());
                let mut buffer = Vec::with_capacity(count);
                for _ in 0..count {
                    match self.input.pop_front() {
                        Some(byte) => buffer.push(byte),
                        None => break,
                    }
                }
                if !memory.write_gpa(descriptor.addr, &buffer) {
                    // The buffer is not accessible: put the bytes back.
                    for byte in buffer.into_iter().rev() {
                        self.input.push_front(byte);
                    }
                    break;
                }
                written += count as u32;
                total += count;
            }
            if queue.push_used(memory, head, written).is_err() {
                break;
            }
            self.interrupt_status |= interrupt::USED_RING;
        }
        self.rx_queue = Some(queue);
        total
    }

    /// Collects the bytes the driver wrote into the transmit queue.
    ///
    /// Returns the number of bytes appended to [`Self::output`].
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
            let mut written = 0u32;
            for descriptor in &chain {
                if descriptor.writable() || descriptor.len == 0 {
                    continue;
                }
                let capacity = descriptor.len as usize;
                let count = core::cmp::min(capacity, BUDGET - total);
                let mut buffer = alloc::vec![0u8; count];
                if !memory.read_gpa(descriptor.addr, &mut buffer) {
                    break;
                }
                self.output.extend_from_slice(&buffer);
                written += count as u32;
                total += count;
                if self.output.len() >= OUTPUT_CAPACITY {
                    break;
                }
            }
            if queue.push_used(memory, head, written).is_err() {
                break;
            }
            self.interrupt_status |= interrupt::USED_RING;
        }
        self.tx_queue = Some(queue);
        total
    }
}

impl Default for VirtioConsole {
    fn default() -> Self {
        Self::new()
    }
}
