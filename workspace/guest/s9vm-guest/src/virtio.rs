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

//! Shared virtio-mmio v2 transport helpers.
//!
//! Both guest drivers (console and block) speak the same transport: the
//! register file offsets, the magic/version probe, the device-status machine
//! (`ACKNOWLEDGE` -> `DRIVER` -> `FEATURES_OK` -> `DRIVER_OK`), the
//! `VIRTIO_F_VERSION_1` negotiation and the split-queue programming are
//! identical. This module keeps that single implementation; the drivers only
//! own their queue tables and request format.
//!
//! Everything here is `core`-only, allocation-free and total: a device that is
//! absent, not the expected kind or not modern yields `false` instead of a
//! fault.

use core::ptr::{read_volatile, write_volatile};

/// Transport register offsets (virtio-mmio, version 2).
pub const REG_MAGIC: u64 = 0x000;
pub const REG_VERSION: u64 = 0x004;
pub const REG_DEVICE_ID: u64 = 0x008;
pub const REG_DEVICE_FEATURES: u64 = 0x010;
pub const REG_DEVICE_FEATURES_SEL: u64 = 0x014;
pub const REG_DRIVER_FEATURES: u64 = 0x020;
pub const REG_DRIVER_FEATURES_SEL: u64 = 0x024;
pub const REG_QUEUE_SEL: u64 = 0x030;
pub const REG_QUEUE_NUM_MAX: u64 = 0x034;
pub const REG_QUEUE_NUM: u64 = 0x038;
pub const REG_QUEUE_READY: u64 = 0x044;
pub const REG_QUEUE_NOTIFY: u64 = 0x050;
pub const REG_STATUS: u64 = 0x070;
pub const REG_QUEUE_DESC_LOW: u64 = 0x080;
pub const REG_QUEUE_DESC_HIGH: u64 = 0x084;
pub const REG_QUEUE_AVAIL_LOW: u64 = 0x090;
pub const REG_QUEUE_AVAIL_HIGH: u64 = 0x094;
pub const REG_QUEUE_USED_LOW: u64 = 0x0A0;
pub const REG_QUEUE_USED_HIGH: u64 = 0x0A4;

/// Transport magic: `"virt"` little-endian.
pub const MAGIC_VALUE: u32 = 0x7472_6976;
/// Transport version this driver implements.
pub const VERSION_VALUE: u32 = 2;

/// Device status bits.
pub const STATUS_ACKNOWLEDGE: u32 = 1;
pub const STATUS_DRIVER: u32 = 2;
pub const STATUS_DRIVER_OK: u32 = 4;
pub const STATUS_FEATURES_OK: u32 = 8;
pub const STATUS_FAILED: u32 = 128;

/// Feature word 1, bit 0: the modern (`VIRTIO_F_VERSION_1`) interface.
pub const FEATURE_HI_VERSION_1: u32 = 1;

/// Available-ring flag: the driver does not want used-ring interrupts.
pub const AVAIL_F_NO_INTERRUPT: u16 = 1;

/// Descriptor flag: the next descriptor continues the chain.
pub const DESC_F_NEXT: u16 = 1;
/// Descriptor flag: the buffer is device-writable.
pub const DESC_F_WRITE: u16 = 2;

/// One mapped virtio-mmio transport.
#[derive(Clone, Copy)]
pub struct Bus {
    base: u64,
}

impl Bus {
    /// Creates a transport handle for the page at `base`.
    pub const fn at(base: u64) -> Self {
        Self { base }
    }

    /// Reads a 32-bit transport register.
    ///
    /// # Safety
    ///
    /// `base` must be mapped readable by the active page tables.
    pub unsafe fn read(self, offset: u64) -> u32 {
        // SAFETY: caller guarantees the mapping; every offset used by the
        // drivers is inside the 4 KiB transport page.
        unsafe { read_volatile((self.base + offset) as *const u32) }
    }

    /// Writes a 32-bit transport register.
    ///
    /// # Safety
    ///
    /// `base` must be mapped writable by the active page tables.
    pub unsafe fn write(self, offset: u64, value: u32) {
        // SAFETY: same contract as `read`.
        unsafe { write_volatile((self.base + offset) as *mut u32, value) };
    }
}

/// Probes the transport magic/version and the expected device id.
///
/// # Safety
///
/// The transport page must be mapped.
pub unsafe fn probe(bus: Bus, device_id: u32) -> bool {
    // SAFETY: caller contract.
    unsafe {
        bus.read(REG_MAGIC) == MAGIC_VALUE
            && bus.read(REG_VERSION) == VERSION_VALUE
            && bus.read(REG_DEVICE_ID) == device_id
    }
}

/// Starts the device-status machine: `ACKNOWLEDGE`, then `DRIVER`.
///
/// # Safety
///
/// The transport page must be mapped writable.
pub unsafe fn begin(bus: Bus) {
    // SAFETY: caller contract.
    unsafe {
        bus.write(REG_STATUS, 0);
        bus.write(REG_STATUS, STATUS_ACKNOWLEDGE);
        bus.write(REG_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
    }
}

/// Negotiates the modern interface plus the requested low-word feature bits.
///
/// The requested bits are masked with the device-offered mask, so a driver can
/// pass the optional features it understands without probing the device
/// itself. Returns `false` when the device does not offer
/// [`FEATURE_HI_VERSION_1`] or rejects `FEATURES_OK`.
///
/// # Safety
///
/// The transport page must be mapped writable.
pub unsafe fn negotiate(bus: Bus, low_features: u32) -> bool {
    // SAFETY: caller contract.
    unsafe {
        bus.write(REG_DEVICE_FEATURES_SEL, 0);
        let offered_low = bus.read(REG_DEVICE_FEATURES);
        bus.write(REG_DEVICE_FEATURES_SEL, 1);
        let offered_high = bus.read(REG_DEVICE_FEATURES);
        if offered_high & FEATURE_HI_VERSION_1 == 0 {
            return false;
        }
        bus.write(REG_DRIVER_FEATURES_SEL, 0);
        bus.write(REG_DRIVER_FEATURES, low_features & offered_low);
        bus.write(REG_DRIVER_FEATURES_SEL, 1);
        bus.write(REG_DRIVER_FEATURES, FEATURE_HI_VERSION_1);
        bus.write(REG_DRIVER_FEATURES_SEL, 0);
        bus.write(REG_DEVICE_FEATURES_SEL, 0);
        bus.write(
            REG_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
        );
        bus.read(REG_STATUS) & STATUS_FEATURES_OK != 0
    }
}

/// Negotiates `VIRTIO_F_VERSION_1` and validates `FEATURES_OK`.
///
/// Returns `false` when the device does not offer the modern interface or
/// rejects the feature request.
///
/// # Safety
///
/// The transport page must be mapped writable.
pub unsafe fn negotiate_version_1(bus: Bus) -> bool {
    // SAFETY: caller contract.
    unsafe { negotiate(bus, 0) }
}

/// Programs one split queue (`index`, `size` entries) and marks it ready.
///
/// The three table addresses are guest-physical; the caller owns the buffers
/// and must keep them aligned (16 bytes for the descriptor table, 2 for the
/// available ring, 4 for the used ring) and zeroed before first use.
///
/// # Safety
///
/// The transport page must be mapped writable and the queue tables must be
/// mapped for the device model to read and write them.
pub unsafe fn setup_queue(
    bus: Bus,
    index: u32,
    size: u16,
    desc: u64,
    avail: u64,
    used: u64,
) -> bool {
    // SAFETY: caller contract.
    unsafe {
        bus.write(REG_QUEUE_SEL, index);
        if bus.read(REG_QUEUE_NUM_MAX) < u32::from(size) {
            return false;
        }
        bus.write(REG_QUEUE_NUM, u32::from(size));
        bus.write(REG_QUEUE_DESC_LOW, desc as u32);
        bus.write(REG_QUEUE_DESC_HIGH, (desc >> 32) as u32);
        bus.write(REG_QUEUE_AVAIL_LOW, avail as u32);
        bus.write(REG_QUEUE_AVAIL_HIGH, (avail >> 32) as u32);
        bus.write(REG_QUEUE_USED_LOW, used as u32);
        bus.write(REG_QUEUE_USED_HIGH, (used >> 32) as u32);
        bus.write(REG_QUEUE_READY, 1);
        true
    }
}

/// Sets `DRIVER_OK` and checks that the device did not fail.
///
/// # Safety
///
/// The transport page must be mapped writable.
pub unsafe fn driver_ok(bus: Bus) -> bool {
    // SAFETY: caller contract.
    unsafe {
        bus.write(
            REG_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
        );
        bus.read(REG_STATUS) & STATUS_FAILED == 0
    }
}

/// Notifies the device that a queue has new entries.
///
/// # Safety
///
/// The transport page must be mapped writable.
pub unsafe fn notify(bus: Bus, index: u32) {
    // SAFETY: caller contract.
    unsafe {
        bus.write(REG_QUEUE_NOTIFY, index);
    }
}

/// Writes a little-endian `u64` at `offset` inside `base`.
///
/// # Safety
///
/// `base + offset .. base + offset + 8` must be mapped writable.
pub unsafe fn write_u64(base: *mut u8, offset: usize, value: u64) {
    // SAFETY: caller contract.
    unsafe { write_volatile(base.add(offset).cast::<u64>(), value) };
}

/// Writes a little-endian `u32` at `offset` inside `base`.
///
/// # Safety
///
/// `base + offset .. base + offset + 4` must be mapped writable.
pub unsafe fn write_u32(base: *mut u8, offset: usize, value: u32) {
    // SAFETY: caller contract.
    unsafe { write_volatile(base.add(offset).cast::<u32>(), value) };
}

/// Writes a little-endian `u16` at `offset` inside `base`.
///
/// # Safety
///
/// `base + offset .. base + offset + 2` must be mapped writable.
pub unsafe fn write_u16(base: *mut u8, offset: usize, value: u16) {
    // SAFETY: caller contract.
    unsafe { write_volatile(base.add(offset).cast::<u16>(), value) };
}
