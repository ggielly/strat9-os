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

//! Virtio-block read driver (virtio-mmio v2, request queue).
//!
//! The engine models a virtio-block device at the block transport page (the
//! console base plus one 4 KiB page, by device-model convention) and the
//! userspace policy provisions its content with `SYS_VMM_LOAD_DISK`. This
//! driver reads sector 0 and validates the `S9VMDISK` label the policy writes,
//! which proves the full path guest request -> split queue -> device model ->
//! backing image:
//!
//! 1. probe the transport and `device_id = 2` (block) through [`virtio`];
//! 2. run the status machine and negotiate `VIRTIO_F_VERSION_1`;
//! 3. program the request queue (`queue 0`) in `.bss` buffers;
//! 4. publish the virtio-block request chain — 16-byte header (`type = IN`,
//!    `sector`), one 512-byte device-writable data descriptor and one status
//!    byte — request no interrupt, notify and poll the used ring;
//! 5. accept the read only when the status byte is `OK` and the data starts
//!    with the `S9VMDISK` magic.
//!
//! Interrupts stay disabled (no ISR): the driver polls the used ring.

use core::ptr::{addr_of, addr_of_mut, read_volatile};

use crate::virtio::{self, Bus, AVAIL_F_NO_INTERRUPT, DESC_F_NEXT, DESC_F_WRITE};

/// Device id of a block device.
pub const DEVICE_ID: u32 = 2;
/// Consecutive transport pages: console, block, network (engine convention).
pub const BASE_OFFSET_FROM_CONSOLE: u64 = 0x1000;
/// Request queue index.
const QUEUE_REQUEST: u32 = 0;
/// Queue size used by this driver (power of two, at most `QUEUE_NUM_MAX`).
const QUEUE_SIZE: u16 = 8;
/// Size of one virtio-block sector.
pub const SECTOR_SIZE: usize = 512;
/// Virtio-block request type `IN` (read).
const REQUEST_IN: u32 = 0;
/// Virtio-block request status `OK`.
const STATUS_OK: u8 = 0;
/// `S9VMDISK` label magic written by the userspace policy.
const DISK_MAGIC: [u8; 8] = *b"S9VMDISK";
/// Bounded number of used-ring polls after a notify.
const USED_POLLS: u32 = 64;

/// Descriptor table: `QUEUE_SIZE` entries of 16 bytes.
#[repr(C, align(16))]
struct DescriptorTable([u8; 16 * QUEUE_SIZE as usize]);
/// Available ring: `flags`, `idx`, `ring[QUEUE_SIZE]`.
#[repr(C, align(16))]
struct AvailRing([u8; 4 + 2 * QUEUE_SIZE as usize]);
/// Used ring: `flags`, `idx`, `ring[QUEUE_SIZE]` of `{ id: u32, len: u32 }`.
#[repr(C, align(16))]
struct UsedRing([u8; 4 + 8 * QUEUE_SIZE as usize]);

static mut DESCRIPTORS: DescriptorTable = DescriptorTable([0; 16 * QUEUE_SIZE as usize]);
static mut AVAILABLE: AvailRing = AvailRing([0; 4 + 2 * QUEUE_SIZE as usize]);
static mut USED: UsedRing = UsedRing([0; 4 + 8 * QUEUE_SIZE as usize]);
/// Request header: `type: u32`, `reserved: u32`, `sector: u64`.
static mut HEADER: [u8; 16] = [0; 16];
/// Data buffer of the read request.
static mut DATA: [u8; SECTOR_SIZE] = [0; SECTOR_SIZE];
/// Request status byte written back by the device.
static mut REQUEST_STATUS: [u8; 1] = [0; 1];

/// Reads sector 0 and validates the `S9VMDISK` label.
///
/// Returns `true` only when the device acknowledged the handshake, completed
/// the request with status `OK` and the sector starts with the label magic.
///
/// # Safety
///
/// `base` must be the guest-physical address of the block transport page,
/// mapped readable and writable by the active guest page tables.
pub unsafe fn read_disk_label(base: u64) -> bool {
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

    // 3. Request queue tables.
    let desc_gpa = addr_of!(DESCRIPTORS) as u64;
    let avail_gpa = addr_of!(AVAILABLE) as u64;
    let used_gpa = addr_of!(USED) as u64;
    // SAFETY: caller contract; the tables are page-aligned `.bss` buffers with
    // the alignment the transport requires.
    if !unsafe {
        virtio::setup_queue(
            bus,
            QUEUE_REQUEST,
            QUEUE_SIZE,
            desc_gpa,
            avail_gpa,
            used_gpa,
        )
    } {
        return false;
    }

    // 4. Request chain: header (readable) -> data (writable) -> status
    //    (writable), with the NEXT flag on the first two descriptors.
    // SAFETY: the tables and buffers are `.bss` objects of exactly the sizes
    // used here; the device model reads and writes them through guest physical
    // addresses (identity mapped).
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
        core::ptr::write_bytes(addr_of_mut!(HEADER).cast::<u8>(), 0, 16);
        core::ptr::write_bytes(addr_of_mut!(DATA).cast::<u8>(), 0, SECTOR_SIZE);
        *addr_of_mut!(REQUEST_STATUS).cast::<u8>() = 0xFF;

        // Header: read sector 0.
        let header = addr_of_mut!(HEADER).cast::<u8>();
        virtio::write_u32(header, 0, REQUEST_IN);
        virtio::write_u32(header, 4, 0);
        virtio::write_u64(header, 8, 0);

        // Descriptor chain.
        let desc = addr_of_mut!(DESCRIPTORS).cast::<u8>();
        virtio::write_u64(desc, 0, addr_of!(HEADER) as u64);
        virtio::write_u32(desc, 8, 16);
        virtio::write_u16(desc, 12, DESC_F_NEXT);
        virtio::write_u16(desc, 14, 1);

        virtio::write_u64(desc, 16, addr_of!(DATA) as u64);
        virtio::write_u32(desc, 24, SECTOR_SIZE as u32);
        virtio::write_u16(desc, 28, DESC_F_NEXT | DESC_F_WRITE);
        virtio::write_u16(desc, 30, 2);

        virtio::write_u64(desc, 32, addr_of!(REQUEST_STATUS) as u64);
        virtio::write_u32(desc, 40, 1);
        virtio::write_u16(desc, 44, DESC_F_WRITE);
        virtio::write_u16(desc, 46, 0);

        // Available ring: no interrupt, publish head descriptor 0.
        let avail = addr_of_mut!(AVAILABLE).cast::<u8>();
        virtio::write_u16(avail, 0, AVAIL_F_NO_INTERRUPT);
        virtio::write_u16(avail, 2, 1);
        virtio::write_u16(avail, 4, 0);
    }

    // 5. DRIVER_OK, notify queue 0, poll the used ring.
    // SAFETY: caller contract.
    unsafe {
        if !virtio::driver_ok(bus) {
            return false;
        }
        virtio::notify(bus, QUEUE_REQUEST);
        let used = addr_of!(USED).cast::<u8>();
        let mut polls = 0u32;
        while polls < USED_POLLS {
            if read_volatile(used.add(2).cast::<u16>()) != 0 {
                break;
            }
            core::hint::spin_loop();
            polls += 1;
        }
        if polls == USED_POLLS {
            return false;
        }
        // The device wrote the completion status and the sector data.
        if *addr_of!(REQUEST_STATUS).cast::<u8>() != STATUS_OK {
            return false;
        }
        let data = addr_of!(DATA).cast::<u8>();
        let mut index = 0usize;
        while index < DISK_MAGIC.len() {
            if read_volatile(data.add(index)) != DISK_MAGIC[index] {
                return false;
            }
            index += 1;
        }
    }
    true
}
