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

//! Virtio-network transmit driver (virtio-mmio v2, transmit queue).
//!
//! The engine models a virtio-net device at the network transport page (the
//! console base plus two 4 KiB pages, by device-model convention). The device
//! has two split queues; this driver only uses the transmit one and sends one
//! minimal Ethernet frame, which proves the full path guest -> split queue ->
//! device model -> kernel network collector:
//!
//! 1. probe the transport and `device_id = 1` (network) through [`virtio`];
//! 2. run the status machine and negotiate `VIRTIO_F_VERSION_1`, plus
//!    `VIRTIO_NET_F_MAC` when the device offers it (the configuration space
//!    then carries the device address used as the frame destination);
//! 3. program the transmit queue (`queue 1`) in `.bss` buffers;
//! 4. publish one device-readable descriptor holding the modern
//!    `virtio_net_hdr` (10 zeroed bytes) followed by a 60-byte Ethernet frame,
//!    request no interrupt, notify the queue and poll the used ring;
//! 5. accept the transmit only when the used ring advanced with a non-zero
//!    length, i.e. the device consumed the whole packet.
//!
//! Interrupts stay disabled in this driver: the available ring sets
//! `VIRTQ_AVAIL_F_NO_INTERRUPT` and the used ring is polled.

use core::ptr::{addr_of, addr_of_mut, read_volatile};

use crate::virtio::{self, Bus, AVAIL_F_NO_INTERRUPT};

/// Device id of a network device.
pub const DEVICE_ID: u32 = 1;
/// Consecutive transport pages: console, block, network (engine convention).
pub const BASE_OFFSET_FROM_CONSOLE: u64 = 0x2000;
/// Transmit queue index.
const QUEUE_TX: u32 = 1;
/// Queue size used by this driver (power of two, at most `QUEUE_NUM_MAX`).
const QUEUE_SIZE: u16 = 8;
/// Feature low-word bit 5: `VIRTIO_NET_F_MAC` (configuration space MAC).
const FEATURE_MAC: u32 = 1 << 5;
/// Configuration-space offset of the device MAC address.
const REG_CONFIG: u64 = 0x100;
/// Size of the modern `virtio_net_hdr` (no offload fields are used).
const NET_HEADER_SIZE: usize = 10;
/// Size of the transmitted Ethernet frame (minimum frame size).
const FRAME_SIZE: usize = 60;
/// Total buffer published to the device: header followed by the frame.
const PACKET_SIZE: usize = NET_HEADER_SIZE + FRAME_SIZE;
/// Destination MAC used when the device does not advertise one.
const FALLBACK_MAC: [u8; 6] = [0x52, 0x54, 0x39, 0x00, 0x00, 0x01];
/// Local source MAC of the guest interface.
const SOURCE_MAC: [u8; 6] = [0x52, 0x54, 0x39, 0x00, 0x00, 0x02];
/// EtherType of the transmitted frame (IPv4).
const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];
/// Payload carried by the frame (the rest of the frame is zero padding).
const PAYLOAD: &[u8] = b"s9vm-guest: virtio-net tx";
/// Bounded number of used-ring polls after a notify.
const USED_POLLS: u32 = 64;

/// Failure reasons of [`transmit`], published on the debug port right after the
/// non-fatal `x` marker (small binary codes, never an ASCII marker, so the
/// marker stream stays unambiguous).
pub mod failure {
    /// The transport does not report the network device id.
    pub const DEVICE_ID: u8 = 1;
    /// Feature negotiation failed.
    pub const FEATURES: u8 = 2;
    /// The transmit queue could not be programmed.
    pub const QUEUE: u8 = 3;
    /// The device rejected the `DRIVER_OK` status.
    pub const DRIVER_OK: u8 = 4;
    /// The device never consumed the descriptor (used ring unchanged).
    pub const COMPLETION: u8 = 5;
    /// The device reported a used length different from the packet size.
    pub const LENGTH: u8 = 6;
}

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
/// One packet: zeroed network header then the Ethernet frame.
static mut PACKET: [u8; PACKET_SIZE] = [0; PACKET_SIZE];

/// Transmits one Ethernet frame through the virtio-net transmit queue.
///
/// Returns `Ok(())` only when the device acknowledged the handshake, consumed
/// the descriptor and reported the expected used length; otherwise returns the
/// [`failure`] code of the step that failed.
///
/// # Safety
///
/// `base` must be the guest-physical address of the network transport page,
/// mapped readable and writable by the active guest page tables.
pub unsafe fn transmit(base: u64) -> Result<(), u8> {
    let bus = Bus::at(base);

    // 1. Transport and device identity.
    // SAFETY: caller contract.
    if !unsafe { virtio::probe(bus, DEVICE_ID) } {
        return Err(failure::DEVICE_ID);
    }

    // 2. Status machine and feature negotiation. The MAC feature is optional:
    //    when offered it is negotiated and the configuration space supplies the
    //    destination address, otherwise the driver falls back to the address
    //    the engine model advertises.
    // SAFETY: caller contract.
    unsafe {
        virtio::begin(bus);
        if !virtio::negotiate(bus, FEATURE_MAC) {
            return Err(failure::FEATURES);
        }
    }

    // 3. Transmit queue tables.
    let desc_gpa = addr_of!(DESCRIPTORS) as u64;
    let avail_gpa = addr_of!(AVAILABLE) as u64;
    let used_gpa = addr_of!(USED) as u64;
    // SAFETY: caller contract; the tables are page-aligned `.bss` buffers.
    if !unsafe { virtio::setup_queue(bus, QUEUE_TX, QUEUE_SIZE, desc_gpa, avail_gpa, used_gpa) } {
        return Err(failure::QUEUE);
    }

    // 4. Build the packet and publish it.
    // SAFETY: the tables and the packet are `.bss` objects of exactly the
    // sizes used here; the device model reads them through guest physical
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

        // Device MAC from the configuration space (feature negotiated above).
        let low = bus.read(REG_CONFIG);
        let high = bus.read(REG_CONFIG + 4);
        let mut destination = FALLBACK_MAC;
        if low != 0 || high != 0 {
            destination[0] = low as u8;
            destination[1] = (low >> 8) as u8;
            destination[2] = (low >> 16) as u8;
            destination[3] = (low >> 24) as u8;
            destination[4] = high as u8;
            destination[5] = (high >> 8) as u8;
        }
        build_frame(&destination);

        // Descriptor 0: whole packet, device-readable and unchained.
        let desc = addr_of_mut!(DESCRIPTORS).cast::<u8>();
        virtio::write_u64(desc, 0, addr_of!(PACKET) as u64);
        virtio::write_u32(desc, 8, PACKET_SIZE as u32);
        virtio::write_u16(desc, 12, 0); // device-readable
        virtio::write_u16(desc, 14, 0); // no chain

        // Available ring: no interrupt, one published descriptor.
        let avail = addr_of_mut!(AVAILABLE).cast::<u8>();
        virtio::write_u16(avail, 0, AVAIL_F_NO_INTERRUPT);
        virtio::write_u16(avail, 2, 1);
        virtio::write_u16(avail, 4, 0);
    }

    // 5. DRIVER_OK, notify queue 1, poll the used ring.
    // SAFETY: caller contract.
    unsafe {
        if !virtio::driver_ok(bus) {
            return Err(failure::DRIVER_OK);
        }
        virtio::notify(bus, QUEUE_TX);
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
            return Err(failure::COMPLETION);
        }
        // The device completed the descriptor; a non-zero length means it
        // collected the whole packet (header stripped on the device side).
        // Used-ring layout: flags (0), idx (2), entry id (4), entry len (8).
        if read_volatile(used.add(8).cast::<u32>()) != PACKET_SIZE as u32 {
            return Err(failure::LENGTH);
        }
    }
    Ok(())
}

/// Fills [`PACKET`] with a zeroed network header followed by a minimal
/// Ethernet frame addressed to `destination`.
///
/// # Safety
///
/// `PACKET` is a `.bss` buffer of exactly [`PACKET_SIZE`] bytes.
unsafe fn build_frame(destination: &[u8; 6]) {
    // SAFETY: the write ranges below are inside `PACKET`.
    unsafe {
        let packet = addr_of_mut!(PACKET).cast::<u8>();
        core::ptr::write_bytes(packet, 0, PACKET_SIZE);
        // The modern virtio_net_hdr stays zero: no checksum or segmentation
        // offload is requested, the configuration every driver supports.
        let frame = packet.add(NET_HEADER_SIZE);
        let mut index = 0usize;
        while index < destination.len() {
            *frame.add(index) = destination[index];
            index += 1;
        }
        while index < destination.len() + SOURCE_MAC.len() {
            *frame.add(index) = SOURCE_MAC[index - destination.len()];
            index += 1;
        }
        *frame.add(index) = ETHERTYPE_IPV4[0];
        *frame.add(index + 1) = ETHERTYPE_IPV4[1];
        index += 2;
        let mut payload = 0usize;
        while payload < PAYLOAD.len() && index + payload < FRAME_SIZE {
            *frame.add(index + payload) = PAYLOAD[payload];
            payload += 1;
        }
    }
}
