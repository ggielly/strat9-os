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

//! Virtio-console transmit driver (virtio-mmio v2, one split queue).
//!
//! The engine models a virtio-console device at the transport base published
//! in the `S9VMBP` boot-parameter block (`console_mmio_base`). A [`Console`]
//! performs the handshake once, then sends any number of messages through the
//! same transmit queue:
//!
//! 1. probe the transport and `device_id = 3` (console) through [`virtio`];
//! 2. run the status machine and negotiate `VIRTIO_F_VERSION_1`;
//! 3. program the transmit queue (`queue 1`) in `.bss` buffers (identity
//!    mapped, so their virtual addresses are their guest-physical addresses);
//! 4. publish one device-readable descriptor per message, request no
//!    interrupt, notify the queue and poll the used ring until the device
//!    reports the buffer as consumed.
//!
//! Interrupts stay disabled: the available ring sets
//! `VIRTQ_AVAIL_F_NO_INTERRUPT` and the driver polls, so the guest never needs
//! an ISR for console output.

use core::ptr::{addr_of, addr_of_mut, read_volatile};

use crate::virtio::{self, Bus, AVAIL_F_NO_INTERRUPT};

/// Device id of a console.
pub const DEVICE_ID: u32 = 3;
/// Transmit queue index of a console.
const QUEUE_TX: u32 = 1;
/// Queue size used by this driver (power of two, at most `QUEUE_NUM_MAX`).
const QUEUE_SIZE: u16 = 8;
/// Number of bytes one message can carry.
pub const MAX_MESSAGE: usize = 128;
/// Bounded number of used-ring polls after a notify.
const USED_POLLS: u32 = 64;

/// Descriptor table: `QUEUE_SIZE` entries of 16 bytes.
#[repr(C, align(16))]
struct DescriptorTable([u8; 16 * QUEUE_SIZE as usize]);
/// Available ring: `flags`, `idx`, `ring[QUEUE_SIZE]` (the optional
/// `used_event` word is unused and stays zero).
#[repr(C, align(16))]
struct AvailRing([u8; 4 + 2 * QUEUE_SIZE as usize]);
/// Used ring: `flags`, `idx`, `ring[QUEUE_SIZE]` of `{ id: u32, len: u32 }`.
#[repr(C, align(16))]
struct UsedRing([u8; 4 + 8 * QUEUE_SIZE as usize]);

static mut DESCRIPTORS: DescriptorTable = DescriptorTable([0; 16 * QUEUE_SIZE as usize]);
static mut AVAILABLE: AvailRing = AvailRing([0; 4 + 2 * QUEUE_SIZE as usize]);
static mut USED: UsedRing = UsedRing([0; 4 + 8 * QUEUE_SIZE as usize]);
static mut MESSAGE: [u8; MAX_MESSAGE] = [0; MAX_MESSAGE];

/// An initialized virtio-console transmit path.
pub struct Console {
    bus: Bus,
    /// Number of messages already consumed by the device.
    sent: u16,
}

impl Console {
    /// Initializes the console transport, its status machine, feature
    /// negotiation and the transmit queue.
    ///
    /// Returns `None` when the device is absent, is not a console, rejects
    /// `VIRTIO_F_VERSION_1` or cannot program the queue.
    ///
    /// # Safety
    ///
    /// `base` must be the guest-physical address of the console transport page,
    /// mapped readable and writable by the active guest page tables.
    pub unsafe fn init(base: u64) -> Option<Self> {
        let bus = Bus::at(base);
        // SAFETY: caller contract.
        unsafe {
            if !virtio::probe(bus, DEVICE_ID) {
                return None;
            }
            virtio::begin(bus);
            if !virtio::negotiate_version_1(bus) {
                return None;
            }
            let desc_gpa = addr_of!(DESCRIPTORS) as u64;
            let avail_gpa = addr_of!(AVAILABLE) as u64;
            let used_gpa = addr_of!(USED) as u64;
            if !virtio::setup_queue(bus, QUEUE_TX, QUEUE_SIZE, desc_gpa, avail_gpa, used_gpa) {
                return None;
            }
            core::ptr::write_bytes(
                addr_of_mut!(DESCRIPTORS).cast::<u8>(),
                0,
                16 * QUEUE_SIZE as usize,
            );
            core::ptr::write_bytes(
                addr_of_mut!(AVAILABLE).cast::<u8>(),
                0,
                4 + 2 * QUEUE_SIZE as usize,
            );
            core::ptr::write_bytes(
                addr_of_mut!(USED).cast::<u8>(),
                0,
                4 + 8 * QUEUE_SIZE as usize,
            );
            if !virtio::driver_ok(bus) {
                return None;
            }
        }
        Some(Self { bus, sent: 0 })
    }

    /// Sends one message and waits (bounded) for the device to consume it.
    ///
    /// Returns `false` when the message is empty/oversized, the device status
    /// failed or the used ring did not advance within the poll budget.
    ///
    /// # Safety
    ///
    /// The console transport page and the queue buffers must stay mapped for
    /// the device model to read them.
    pub unsafe fn send(&mut self, bytes: &[u8]) -> bool {
        if bytes.is_empty() || bytes.len() > MAX_MESSAGE {
            return false;
        }
        // SAFETY: `MESSAGE` is `MAX_MESSAGE` bytes and the length was checked.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                addr_of_mut!(MESSAGE).cast::<u8>(),
                bytes.len(),
            );
        }
        let descriptor = self.sent % QUEUE_SIZE;
        let slot = self.sent % QUEUE_SIZE;
        let message_gpa = addr_of!(MESSAGE) as u64;
        // SAFETY: the tables are `.bss` buffers of the sizes used here; the
        // queue indices stay below `QUEUE_SIZE`.
        unsafe {
            let desc = addr_of_mut!(DESCRIPTORS).cast::<u8>();
            virtio::write_u64(desc, descriptor as usize * 16, message_gpa);
            virtio::write_u32(desc, descriptor as usize * 16 + 8, bytes.len() as u32);
            virtio::write_u16(desc, descriptor as usize * 16 + 12, 0); // device-readable
            virtio::write_u16(desc, descriptor as usize * 16 + 14, 0); // no chain

            let avail = addr_of_mut!(AVAILABLE).cast::<u8>();
            virtio::write_u16(avail, 0, AVAIL_F_NO_INTERRUPT);
            virtio::write_u16(avail, 4 + slot as usize * 2, descriptor);
            virtio::write_u16(avail, 2, self.sent.wrapping_add(1));

            virtio::notify(self.bus, QUEUE_TX);

            let want = self.sent.wrapping_add(1);
            let used = addr_of!(USED).cast::<u8>();
            let mut polls = 0u32;
            while polls < USED_POLLS {
                if read_volatile(used.add(2).cast::<u16>()) == want {
                    self.sent = want;
                    return true;
                }
                core::hint::spin_loop();
                polls += 1;
            }
        }
        false
    }
}
