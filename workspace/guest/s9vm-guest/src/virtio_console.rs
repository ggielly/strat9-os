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

//! Minimal virtio-mmio v2 console transmit driver.
//!
//! The engine models a virtio-console device at the transport base published
//! in the `S9VMBP` boot-parameter block (`console_mmio_base`). This driver does
//! the smallest complete virtio handshake a kernel needs to produce real text
//! output:
//!
//! 1. probe `magic`, `version = 2` and `device_id = 3` (console);
//! 2. drive the status machine `ACKNOWLEDGE` -> `DRIVER` -> `FEATURES_OK`
//!    (validated by reading the status back) -> `DRIVER_OK`;
//! 3. negotiate `VIRTIO_F_VERSION_1` (bit 0 of the feature word 1), the only
//!    feature a modern transport requires;
//! 4. program the transmit queue (`queue 1`): descriptor table, available ring
//!    and used ring, all in page-aligned `.bss` buffers (identity mapped, so
//!    their virtual addresses are their guest-physical addresses);
//! 5. publish one device-readable descriptor that points at the message,
//!    notify the queue and poll the used ring until the device reports the
//!    buffer as consumed.
//!
//! No interrupt is used: the available ring sets `VIRTQ_AVAIL_F_NO_INTERRUPT`
//! and the driver polls the used ring, so the guest never needs an ISR.
//!
//! The module is `core`-only and allocation-free; it is exercised on hardware
//! (the engine has no VT-x under TCG), while every malformed device answer is
//! turned into a `false` return instead of a fault.

use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

/// virtio-mmio transport register offsets (modern, version 2).
const REG_MAGIC: u64 = 0x000;
const REG_VERSION: u64 = 0x004;
const REG_DEVICE_ID: u64 = 0x008;
const REG_DEVICE_FEATURES: u64 = 0x010;
const REG_DEVICE_FEATURES_SEL: u64 = 0x014;
const REG_DRIVER_FEATURES: u64 = 0x020;
const REG_DRIVER_FEATURES_SEL: u64 = 0x024;
const REG_QUEUE_SEL: u64 = 0x030;
const REG_QUEUE_NUM_MAX: u64 = 0x034;
const REG_QUEUE_NUM: u64 = 0x038;
const REG_QUEUE_READY: u64 = 0x044;
const REG_QUEUE_NOTIFY: u64 = 0x050;
const REG_STATUS: u64 = 0x070;
const REG_QUEUE_DESC_LOW: u64 = 0x080;
const REG_QUEUE_DESC_HIGH: u64 = 0x084;
const REG_QUEUE_AVAIL_LOW: u64 = 0x090;
const REG_QUEUE_AVAIL_HIGH: u64 = 0x094;
const REG_QUEUE_USED_LOW: u64 = 0x0A0;
const REG_QUEUE_USED_HIGH: u64 = 0x0A4;

/// Transport magic: `"virt"` in little endian.
const MAGIC_VALUE: u32 = 0x7472_6976;
/// Transport version implemented by the engine.
const VERSION_VALUE: u32 = 2;
/// Device id of a console.
const DEVICE_ID_CONSOLE: u32 = 3;

/// Device status bits.
const STATUS_ACKNOWLEDGE: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_DRIVER_OK: u32 = 4;
const STATUS_FEATURES_OK: u32 = 8;
const STATUS_FAILED: u32 = 128;

/// Feature word 1, bit 0: the modern (`VIRTIO_F_VERSION_1`) interface.
const FEATURE_HI_VERSION_1: u32 = 1;

/// Transmit queue index of a console.
const QUEUE_TX: u32 = 1;
/// Queue size used by this driver (power of two, at most `QUEUE_NUM_MAX`).
const QUEUE_SIZE: u16 = 8;
/// Number of bytes the transmit buffer can hold.
pub const MAX_MESSAGE: usize = 64;
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

/// One virtio-mmio transport.
#[derive(Clone, Copy)]
struct Bus {
    base: u64,
}

impl Bus {
    /// Reads a 32-bit transport register.
    ///
    /// # Safety
    ///
    /// `base` must be the mapped console transport page.
    unsafe fn read(self, offset: u64) -> u32 {
        // SAFETY: the caller validated the device base and the register
        // offsets are inside the 4 KiB transport page.
        unsafe { read_volatile((self.base + offset) as *const u32) }
    }

    /// Writes a 32-bit transport register.
    ///
    /// # Safety
    ///
    /// `base` must be the mapped console transport page.
    unsafe fn write(self, offset: u64, value: u32) {
        // SAFETY: same contract as `read`.
        unsafe { write_volatile((self.base + offset) as *mut u32, value) };
    }
}

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
    let bus = Bus { base };

    // 1. Probe the transport and the device identity.
    // SAFETY: caller contract.
    unsafe {
        if bus.read(REG_MAGIC) != MAGIC_VALUE
            || bus.read(REG_VERSION) != VERSION_VALUE
            || bus.read(REG_DEVICE_ID) != DEVICE_ID_CONSOLE
        {
            return false;
        }
    }

    // 2. Status machine. Every write is cumulative, as the specification
    //    requires; `FEATURES_OK` is validated by reading the status back.
    // SAFETY: caller contract.
    unsafe {
        bus.write(REG_STATUS, 0);
        let mut status = STATUS_ACKNOWLEDGE;
        bus.write(REG_STATUS, status);
        status |= STATUS_DRIVER;
        bus.write(REG_STATUS, status);

        // 3. Features: request VIRTIO_F_VERSION_1 (word 1, bit 0) when offered.
        bus.write(REG_DEVICE_FEATURES_SEL, 1);
        let offered = bus.read(REG_DEVICE_FEATURES);
        if offered & FEATURE_HI_VERSION_1 == 0 {
            return false;
        }
        bus.write(REG_DRIVER_FEATURES_SEL, 1);
        bus.write(REG_DRIVER_FEATURES, FEATURE_HI_VERSION_1);
        bus.write(REG_DRIVER_FEATURES_SEL, 0);
        bus.write(REG_DRIVER_FEATURES, 0);
        bus.write(REG_DEVICE_FEATURES_SEL, 0);

        status |= STATUS_FEATURES_OK;
        bus.write(REG_STATUS, status);
        if bus.read(REG_STATUS) & STATUS_FEATURES_OK == 0 {
            return false;
        }
    }

    // 4. Program the transmit queue.
    let desc_gpa = addr_of!(DESCRIPTORS) as u64;
    let avail_gpa = addr_of!(AVAILABLE) as u64;
    let used_gpa = addr_of!(USED) as u64;
    // SAFETY: caller contract; the queue tables are `.bss` buffers, identity
    // mapped and aligned for the transport requirements (16 / 2 / 4 bytes).
    unsafe {
        bus.write(REG_QUEUE_SEL, QUEUE_TX);
        if bus.read(REG_QUEUE_NUM_MAX) < u32::from(QUEUE_SIZE) {
            return false;
        }
        bus.write(REG_QUEUE_NUM, u32::from(QUEUE_SIZE));
        bus.write(REG_QUEUE_DESC_LOW, desc_gpa as u32);
        bus.write(REG_QUEUE_DESC_HIGH, (desc_gpa >> 32) as u32);
        bus.write(REG_QUEUE_AVAIL_LOW, avail_gpa as u32);
        bus.write(REG_QUEUE_AVAIL_HIGH, (avail_gpa >> 32) as u32);
        bus.write(REG_QUEUE_USED_LOW, used_gpa as u32);
        bus.write(REG_QUEUE_USED_HIGH, (used_gpa >> 32) as u32);
        bus.write(REG_QUEUE_READY, 1);
    }

    // 5. Publish one device-readable descriptor and the available-ring entry.
    // SAFETY: the three tables are `.bss` buffers of exactly the sizes written
    // here, and `MESSAGE` is large enough (checked above).
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
    }
    let message_gpa = addr_of!(MESSAGE) as u64;
    let desc = addr_of_mut!(DESCRIPTORS).cast::<u8>();
    let avail = addr_of_mut!(AVAILABLE).cast::<u8>();
    // SAFETY: descriptor 0 is inside the table; the fields are little-endian
    // 64/32/16-bit values as defined by the split-virtqueue format.
    unsafe {
        write_volatile(desc as *mut u64, message_gpa);
        write_volatile(desc.add(8) as *mut u32, bytes.len() as u32);
        write_volatile(desc.add(12) as *mut u16, 0); // device-readable
        write_volatile(desc.add(14) as *mut u16, 0); // no next descriptor
                                                     // Available ring: request no interrupt and publish descriptor 0.
        write_volatile(avail as *mut u16, 1); // VIRTQ_AVAIL_F_NO_INTERRUPT
        write_volatile(avail.add(2) as *mut u16, 1); // idx
        write_volatile(avail.add(4) as *mut u16, 0); // ring[0] = descriptor 0
    }

    // 6. Set DRIVER_OK, notify the transmit queue and poll the used ring.
    // SAFETY: caller contract.
    unsafe {
        let status = STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK;
        bus.write(REG_STATUS, status);
        if bus.read(REG_STATUS) & STATUS_FAILED != 0 {
            return false;
        }
        bus.write(REG_QUEUE_NOTIFY, QUEUE_TX);

        let used = addr_of!(USED).cast::<u8>();
        let mut polls = 0u32;
        while polls < USED_POLLS {
            if read_volatile(used.add(2) as *const u16) != 0 {
                return true;
            }
            core::hint::spin_loop();
            polls += 1;
        }
    }
    false
}
