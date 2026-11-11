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

use crate::virtio::{self, Bus, Transport, AVAIL_F_NO_INTERRUPT};

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

/// Failure reasons of [`Console::init`] and [`Console::send`], published on the
/// debug port right after the non-fatal `c` marker (small binary codes, never
/// an ASCII marker, so the marker stream stays unambiguous).
pub mod failure {
    /// The transport does not report the console device id.
    pub const DEVICE_ID: u8 = 1;
    /// `VIRTIO_F_VERSION_1` could not be negotiated.
    pub const FEATURES: u8 = 2;
    /// The transmit queue could not be programmed.
    pub const QUEUE: u8 = 3;
    /// The device rejected the `DRIVER_OK` status.
    pub const DRIVER_OK: u8 = 4;
    /// The message is empty or larger than [`MAX_MESSAGE`].
    pub const MESSAGE_SIZE: u8 = 5;
    /// The device never consumed the message (used ring unchanged).
    pub const COMPLETION: u8 = 6;
}

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
static mut MESSAGE: virtio::Aligned<MAX_MESSAGE> = virtio::Aligned([0; MAX_MESSAGE]);

/// An initialized virtio-console transmit path.
pub struct Console<T: Transport> {
    bus: T,
    /// Number of messages already consumed by the device.
    sent: u16,
}

impl Console<Bus> {
    /// Initializes the console transport of the device page at `base`.
    ///
    /// # Safety
    ///
    /// `base` must be the guest-physical address of the console transport page,
    /// mapped readable and writable by the active guest page tables.
    pub unsafe fn init(base: u64) -> Result<Self, u8> {
        Self::init_with(Bus::at(base))
    }
}

impl<T: Transport> Console<T> {
    /// Initializes the console transport, its status machine, feature
    /// negotiation and the transmit queue on an already constructed transport.
    ///
    /// Returns the [`failure`] code of the step that failed when the device is
    /// absent, is not a console, rejects `VIRTIO_F_VERSION_1` or cannot program
    /// the queue.
    pub fn init_with(bus: T) -> Result<Self, u8> {
        if !virtio::probe(&bus, DEVICE_ID) {
            return Err(failure::DEVICE_ID);
        }
        virtio::begin(&bus);
        if !virtio::negotiate_version_1(&bus) {
            return Err(failure::FEATURES);
        }
        let desc_gpa = addr_of!(DESCRIPTORS) as u64;
        let avail_gpa = addr_of!(AVAILABLE) as u64;
        let used_gpa = addr_of!(USED) as u64;
        // SAFETY: the tables are page-aligned `.bss` buffers the device model
        // can address (identity mapped in the guest).
        if !unsafe { virtio::setup_queue(&bus, QUEUE_TX, QUEUE_SIZE, desc_gpa, avail_gpa, used_gpa) }
        {
            return Err(failure::QUEUE);
        }
        // SAFETY: the three tables are `.bss` objects of exactly the sizes
        // written here.
        unsafe {
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
        }
        if !virtio::driver_ok(&bus) {
            return Err(failure::DRIVER_OK);
        }
        Ok(Self { bus, sent: 0 })
    }

    /// Sends one message and waits (bounded) for the device to consume it.
    ///
    /// Returns the [`failure`] code of the step that failed (oversized or empty
    /// message, device status failed, used ring unchanged within the poll
    /// budget).
    pub fn send(&mut self, bytes: &[u8]) -> Result<(), u8> {
        if bytes.is_empty() || bytes.len() > MAX_MESSAGE {
            return Err(failure::MESSAGE_SIZE);
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
        }
        virtio::notify(&self.bus, QUEUE_TX);

        let want = self.sent.wrapping_add(1);
        // SAFETY: `USED` is a `.bss` buffer of the size read here.
        unsafe {
            let used = addr_of!(USED).cast::<u8>();
            let mut polls = 0u32;
            while polls < USED_POLLS {
                if read_volatile(used.add(2).cast::<u16>()) == want {
                    self.sent = want;
                    return Ok(());
                }
                core::hint::spin_loop();
                polls += 1;
            }
        }
        Err(failure::COMPLETION)
    }
}

