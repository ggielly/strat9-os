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
//! in the `S9VMBP` boot-parameter block (`console_mmio_base`). This driver
//! performs the smallest complete handshake a kernel needs for real text
//! output:
//!
//! 1. probe the transport and `device_id = 3` (console) through [`virtio`];
//! 2. run the status machine and negotiate `VIRTIO_F_VERSION_1`;
//! 3. program the transmit queue (`queue 1`) in `.bss` buffers (identity
//!    mapped, so their virtual addresses are their guest-physical addresses);
//! 4. publish one device-readable descriptor pointing at the message, request
//!    no interrupt, notify the queue and poll the used ring until the device
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
/// Number of bytes the transmit buffer can hold.
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

/// Transmits `bytes` through the virtio-console transmit queue.
///
/// Returns `true` only when the device acknowledged the handshake and the used
/// ring reports the buffer as consumed. A device that is absent, not a console,
/// rejects `VIRTIO_F_VERSION_1` or never consumes the buffer yields `false`
/// (the caller publishes a non-fatal marker).
///
/// # Safety
///
/// `base` must be the guest-physical address of the console transport page,
/// mapped readable and writable by the active guest page tables.
pub unsafe fn transmit(base: u64, bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.len() > MAX_MESSAGE {
        return false;
    }
    let bus = Bus::at(base);

    // 1. Transport and device identity.
    // SAFETY: caller contract.
    if !unsafe { virtio::probe(bus, DEVICE_ID) } {
        return false;
    }

    // 2. Status machine and feature negotiation.
    // SAFETY: caller contract.
    unsafe {
        virtio::begin(bus);
        if !virtio::negotiate_version_1(bus) {
            return false;
        }
    }

    // 3. Transmit queue: descriptor table, available ring and used ring.
    let desc_gpa = addr_of!(DESCRIPTORS) as u64;
    let avail_gpa = addr_of!(AVAILABLE) as u64;
    let used_gpa = addr_of!(USED) as u64;
    // SAFETY: caller contract; the tables are page-aligned `.bss` buffers with
    // the alignment the transport requires.
    if !unsafe { virtio::setup_queue(bus, QUEUE_TX, QUEUE_SIZE, desc_gpa, avail_gpa, used_gpa) } {
        return false;
    }

    // 4. One device-readable descriptor carrying the message.
    // SAFETY: the tables are `.bss` buffers of exactly the sizes zeroed here,
    // `MESSAGE` is large enough (checked above) and the descriptor fields are
    // the split-virtqueue layout.
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
        core::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            addr_of_mut!(MESSAGE).cast::<u8>(),
            bytes.len(),
        );
        let message_gpa = addr_of!(MESSAGE) as u64;
        let desc = addr_of_mut!(DESCRIPTORS).cast::<u8>();
        virtio::write_u64(desc, 0, message_gpa);
        virtio::write_u32(desc, 8, bytes.len() as u32);
        virtio::write_u16(desc, 12, 0); // device-readable, no chain
        virtio::write_u16(desc, 14, 0);
        let avail = addr_of_mut!(AVAILABLE).cast::<u8>();
        virtio::write_u16(avail, 0, AVAIL_F_NO_INTERRUPT);
        virtio::write_u16(avail, 2, 1);
        virtio::write_u16(avail, 4, 0);
    }

    // 5. DRIVER_OK, notify queue 1, poll the used ring.
    // SAFETY: caller contract.
    unsafe {
        if !virtio::driver_ok(bus) {
            return false;
        }
        virtio::notify(bus, QUEUE_TX);
        let used = addr_of!(USED).cast::<u8>();
        let mut polls = 0u32;
        while polls < USED_POLLS {
            if read_volatile(used.add(2).cast::<u16>()) != 0 {
                return true;
            }
            core::hint::spin_loop();
            polls += 1;
        }
    }
    false
}
