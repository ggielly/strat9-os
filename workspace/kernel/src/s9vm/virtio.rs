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

//! s9vm — virtio split-queue core (pure).
//!
//! A virtio device exchanges buffers with its driver through a *split
//! virtqueue*: a descriptor table, an available ring (driver → device) and a
//! used ring (device → driver). The layout is transport-independent, which is
//! why this module is a pure model: it only needs guest-physical memory
//! access, and the transport layer (MMIO page or PCI BAR) is a thin register
//! file on top.
//!
//! Implemented here:
//!
//! - descriptor encoding/decoding (16 bytes: `addr`, `len`, `flags`, `next`);
//! - available-ring consumption (`idx` and `ring[]`) with wrap-around;
//! - chain walking, including one level of *indirect* descriptor tables;
//! - used-ring completion (`id` + written length), with wrap-around.
//!
//! Out of scope (deliberately): feature negotiation, interrupt suppression
//! (`VIRTQ_AVAIL_F_NO_INTERRUPT`), and the "event" index. They are transport
//! concerns and can be added without changing this core.

use alloc::vec::Vec;

/// Size of one descriptor in the table.
pub const DESCRIPTOR_SIZE: u64 = 16;
/// Descriptor flag: the chain continues in `next`.
pub const DESC_F_NEXT: u16 = 1;
/// Descriptor flag: the buffer is written by the device.
pub const DESC_F_WRITE: u16 = 2;
/// Descriptor flag: `addr` points to an indirect descriptor table.
pub const DESC_F_INDIRECT: u16 = 4;
/// Highest queue size accepted by the legacy interface.
pub const MAX_QUEUE_SIZE: u16 = 32768;

/// Queue configuration or access error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    /// The size is zero, not a power of two, or above [`MAX_QUEUE_SIZE`].
    BadSize,
    /// A table address is misaligned for its element size.
    BadAddress,
    /// A descriptor index is outside the table.
    BadDescriptor,
    /// A chain loops, is too long, or contains an invalid indirect table.
    BadChain,
    /// Guest memory could not be read or written.
    Memory,
}

/// Guest physical memory access for the queue.
pub trait QueueMemory {
    /// Copies `out.len()` bytes from the guest-physical address `gpa`.
    fn read_gpa(&mut self, gpa: u64, out: &mut [u8]) -> bool;
    /// Copies `bytes` to the guest-physical address `gpa`.
    fn write_gpa(&mut self, gpa: u64, bytes: &[u8]) -> bool;

    /// Reads a little-endian 16-bit value.
    fn read_u16(&mut self, gpa: u64) -> Option<u16> {
        let mut bytes = [0u8; 2];
        if self.read_gpa(gpa, &mut bytes) {
            Some(u16::from_le_bytes(bytes))
        } else {
            None
        }
    }

    /// Writes a little-endian 16-bit value.
    fn write_u16(&mut self, gpa: u64, value: u16) -> bool {
        self.write_gpa(gpa, &value.to_le_bytes())
    }

    /// Reads a little-endian 32-bit value.
    fn read_u32(&mut self, gpa: u64) -> Option<u32> {
        let mut bytes = [0u8; 4];
        if self.read_gpa(gpa, &mut bytes) {
            Some(u32::from_le_bytes(bytes))
        } else {
            None
        }
    }

    /// Writes a little-endian 32-bit value.
    fn write_u32(&mut self, gpa: u64, value: u32) -> bool {
        self.write_gpa(gpa, &value.to_le_bytes())
    }
}

/// One split-queue descriptor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Descriptor {
    /// Guest-physical address of the buffer (or of an indirect table).
    pub addr: u64,
    /// Buffer length in bytes.
    pub len: u32,
    /// [`DESC_F_NEXT`], [`DESC_F_WRITE`], [`DESC_F_INDIRECT`].
    pub flags: u16,
    /// Index of the next descriptor when [`DESC_F_NEXT`] is set.
    pub next: u16,
}

impl Descriptor {
    /// Decodes a descriptor from its 16-byte representation.
    pub fn decode(bytes: &[u8; 16]) -> Self {
        Self {
            addr: u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            len: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            flags: u16::from_le_bytes([bytes[12], bytes[13]]),
            next: u16::from_le_bytes([bytes[14], bytes[15]]),
        }
    }

    /// Encodes the descriptor into its 16-byte representation.
    pub fn encode(self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&self.addr.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.len.to_le_bytes());
        bytes[12..14].copy_from_slice(&self.flags.to_le_bytes());
        bytes[14..].copy_from_slice(&self.next.to_le_bytes());
        bytes
    }

    /// True if the device writes this buffer (it is read-only for the driver).
    pub const fn writable(self) -> bool {
        self.flags & DESC_F_WRITE != 0
    }

    /// True if the chain continues in [`Self::next`].
    pub const fn has_next(self) -> bool {
        self.flags & DESC_F_NEXT != 0
    }

    /// True if [`Self::addr`] points to an indirect descriptor table.
    pub const fn indirect(self) -> bool {
        self.flags & DESC_F_INDIRECT != 0
    }
}

/// One split virtqueue.
///
/// All addresses are guest-physical; `avail` points to the available-ring
/// header and `used` to the used-ring header (the `ring[]` arrays follow their
/// headers, as defined by the virtio specification).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SplitQueue {
    size: u16,
    desc: u64,
    avail: u64,
    used: u64,
    last_avail: u16,
    last_used: u16,
}

impl SplitQueue {
    /// Creates a queue from the three table addresses programmed by the
    /// driver.
    pub fn new(size: u16, desc: u64, avail: u64, used: u64) -> Result<Self, QueueError> {
        if size == 0 || size > MAX_QUEUE_SIZE || !size.is_power_of_two() {
            return Err(QueueError::BadSize);
        }
        if desc % DESCRIPTOR_SIZE != 0 || avail % 2 != 0 || used % 4 != 0 {
            return Err(QueueError::BadAddress);
        }
        Ok(Self {
            size,
            desc,
            avail,
            used,
            last_avail: 0,
            last_used: 0,
        })
    }

    /// Queue size (number of descriptors).
    pub const fn size(self) -> u16 {
        self.size
    }

    /// Guest-physical address of descriptor `index`.
    pub fn descriptor_gpa(self, index: u16) -> Option<u64> {
        if index >= self.size {
            return None;
        }
        Some(self.desc + u64::from(index) * DESCRIPTOR_SIZE)
    }

    /// Reads one descriptor.
    pub fn read_descriptor<M: QueueMemory + ?Sized>(
        self,
        memory: &mut M,
        index: u16,
    ) -> Result<Descriptor, QueueError> {
        let gpa = self.descriptor_gpa(index).ok_or(QueueError::BadDescriptor)?;
        let mut bytes = [0u8; 16];
        if !memory.read_gpa(gpa, &mut bytes) {
            return Err(QueueError::Memory);
        }
        Ok(Descriptor::decode(&bytes))
    }

    /// Pops the next available chain head, or `None` when the driver has not
    /// published anything new. The available index is advanced only when a
    /// descriptor is actually returned.
    pub fn pop_available<M: QueueMemory + ?Sized>(
        &mut self,
        memory: &mut M,
    ) -> Result<Option<u16>, QueueError> {
        let produced = memory
            .read_u16(self.avail + 2)
            .ok_or(QueueError::Memory)?;
        if produced == self.last_avail {
            return Ok(None);
        }
        let slot = u64::from(self.last_avail % self.size);
        let head = memory
            .read_u16(self.avail + 4 + slot * 2)
            .ok_or(QueueError::Memory)?;
        if head >= self.size {
            return Err(QueueError::BadDescriptor);
        }
        self.last_avail = self.last_avail.wrapping_add(1);
        Ok(Some(head))
    }

    /// Walks the chain starting at `head`.
    ///
    /// One level of indirect descriptors is supported: their table is expanded
    /// in place and the outer `NEXT` flag then continues the chain.
    pub fn chain<M: QueueMemory + ?Sized>(
        self,
        memory: &mut M,
        head: u16,
    ) -> Result<Vec<Descriptor>, QueueError> {
        let mut chain = Vec::new();
        let mut index = head;
        let mut hops = 0u32;
        // A well-formed chain cannot be longer than the descriptor table.
        let limit = u32::from(self.size) + 1;
        loop {
            if index >= self.size {
                return Err(QueueError::BadDescriptor);
            }
            hops += 1;
            if hops > limit {
                return Err(QueueError::BadChain);
            }
            let descriptor = self.read_descriptor(memory, index)?;
            if descriptor.indirect() {
                self.expand_indirect(memory, descriptor, &mut chain)?;
            } else {
                chain.push(descriptor);
            }
            if !descriptor.has_next() {
                return Ok(chain);
            }
            index = descriptor.next;
        }
    }

    /// Expands an indirect descriptor table into `chain`.
    fn expand_indirect<M: QueueMemory + ?Sized>(
        self,
        memory: &mut M,
        indirect: Descriptor,
        chain: &mut Vec<Descriptor>,
    ) -> Result<(), QueueError> {
        if indirect.len == 0 || indirect.len % DESCRIPTOR_SIZE as u32 != 0 {
            return Err(QueueError::BadChain);
        }
        let count = indirect.len / DESCRIPTOR_SIZE as u32;
        if count > u32::from(self.size) {
            return Err(QueueError::BadChain);
        }
        let mut index = 0u32;
        let mut hops = 0u32;
        loop {
            if index >= count {
                return Ok(());
            }
            hops += 1;
            if hops > count {
                return Err(QueueError::BadChain);
            }
            let gpa = indirect.addr + u64::from(index) * DESCRIPTOR_SIZE;
            let mut bytes = [0u8; 16];
            if !memory.read_gpa(gpa, &mut bytes) {
                return Err(QueueError::Memory);
            }
            let descriptor = Descriptor::decode(&bytes);
            if descriptor.indirect() {
                return Err(QueueError::BadChain);
            }
            chain.push(descriptor);
            if !descriptor.has_next() {
                return Ok(());
            }
            index = u32::from(descriptor.next);
        }
    }

    /// Publishes a completed chain in the used ring.
    ///
    /// `written` is the number of bytes the device wrote into the chain, which
    /// the driver reads after the used-ring entry becomes visible.
    pub fn push_used<M: QueueMemory + ?Sized>(
        &mut self,
        memory: &mut M,
        head: u16,
        written: u32,
    ) -> Result<(), QueueError> {
        if head >= self.size {
            return Err(QueueError::BadDescriptor);
        }
        let slot = u64::from(self.last_used % self.size);
        let entry = self.used + 4 + slot * 8;
        if !memory.write_u32(entry, u32::from(head)) {
            return Err(QueueError::Memory);
        }
        if !memory.write_u32(entry + 4, written) {
            return Err(QueueError::Memory);
        }
        let next = self.last_used.wrapping_add(1);
        if !memory.write_u16(self.used + 2, next) {
            return Err(QueueError::Memory);
        }
        self.last_used = next;
        Ok(())
    }
}
