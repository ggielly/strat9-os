//! L1 — Intel 8254x descriptor layouts + generic ring logic (nic-queues).
//!
//! Descriptor byte layouts are pinned against the Intel 8254x SDM
//! (§3.2.3 RX legacy, §3.3.3 TX legacy): the hardware reads these bytes
//! directly — any padding/offset drift breaks DMA silently.

use intel_ethernet::regs::*;
use intel_ethernet::rx_errors;
use intel_ethernet::rx_status;
use intel_ethernet::tx_status;
use intel_ethernet::{LegacyRxDesc, LegacyTxDesc};
use nic_queues::{RxDescriptor, RxRing, TxDescriptor};

// ===========================================================================
// Wire layouts (hardware contract)
// ===========================================================================

#[test]
fn legacy_descriptor_sizes_are_16_bytes() {
    // Both legacy descriptors are exactly two 8-byte words on the wire.
    assert_eq!(core::mem::size_of::<LegacyRxDesc>(), 16);
    assert_eq!(core::mem::size_of::<LegacyTxDesc>(), 16);
}

#[test]
fn legacy_rx_desc_field_offsets_match_sdm() {
    let d = LegacyRxDesc {
        addr: 0x1234_5678_9ABC_DEF0,
        length: 0x0200,
        checksum: 0xFFFF,
        status: rx_status::DD | rx_status::EOP,
        errors: 0,
        special: 0,
    };
    let base = &d as *const _ as usize;
    assert_eq!(&d.addr as *const _ as usize - base, 0); // addr @0..8
    assert_eq!(&d.length as *const _ as usize - base, 8); // length @8
    assert_eq!(&d.checksum as *const _ as usize - base, 10);
    assert_eq!(&d.status as *const _ as usize - base, 12);
    assert_eq!(&d.errors as *const _ as usize - base, 13);
    assert_eq!(&d.special as *const _ as usize - base, 14);
}

#[test]
fn rx_status_and_error_bits_are_pinned() {
    assert_eq!(rx_status::DD, 1 << 0);
    assert_eq!(rx_status::EOP, 1 << 1);
    assert_eq!(rx_status::IXSM, 1 << 3);
    assert_eq!(rx_status::UDP, 1 << 4);
    assert_eq!(rx_status::TCP, 1 << 5);
    assert_eq!(rx_status::IPCS, 1 << 6);
    assert_eq!(rx_status::PIF, 1 << 7);

    assert_eq!(rx_errors::CE, 1 << 0);
    assert_eq!(rx_errors::SE, 1 << 1);
    assert_eq!(rx_errors::SEQ, 1 << 3);
    assert_eq!(rx_errors::CPRS, 1 << 4);
    assert_eq!(rx_errors::TCPE, 1 << 5);
    assert_eq!(rx_errors::IPE, 1 << 6);

    assert_eq!(tx_status::DD, 1 << 0);
}

#[test]
fn tx_cmd_bits_eop_ifcs_rs_are_pinned() {
    // Via trait behaviour: set_eop_ifcs_rs must produce EOP|IFCS|RS.
    let mut d = LegacyTxDesc::default();
    d.set_eop_ifcs_rs();
    const EOP: u8 = 1 << 0;
    const IFCS: u8 = 1 << 1;
    const RS: u8 = 1 << 3;
    assert_eq!(d.cmd, EOP | IFCS | RS);
}

#[test]
fn register_offsets_match_intel_sdm() {
    assert_eq!(CTRL, 0x0000);
    assert_eq!(STATUS, 0x0008);
    assert_eq!(ICR, 0x00C0);
    assert_eq!(RCTL, 0x0100);
    assert_eq!(TCTL, 0x0400);
    assert_eq!(RDBAL, 0x2800);
    assert_eq!(RDBAH, 0x2804);
    assert_eq!(RDLEN, 0x2808);
    assert_eq!(RDH, 0x2810);
    assert_eq!(RDT, 0x2818);
    assert_eq!(TDBAL, 0x3800);
    assert_eq!(TDLEN, 0x3808);
    assert_eq!(TDH, 0x3810);
    assert_eq!(TDT, 0x3818);
    assert_eq!(RAL0, 0x5400);
    // Multicast filter table and VLAN ETHERTYPE live at fixed addresses too.
    assert_eq!(VET, 0x0008);
    assert_eq!(VFTA, 0x5200);
}

// ===========================================================================
// RxRing polling logic (generic over descriptors)
// ===========================================================================

/// Allocates a zeroed ring of `count` descriptors.
fn make_rx_ring(count: usize) -> Box<[LegacyRxDesc]> {
    let mut v: Box<[LegacyRxDesc]> = vec![LegacyRxDesc::default(); count].into_boxed_slice();
    for (i, d) in v.iter_mut().enumerate() {
        d.addr = 0x1000 + i as u64; // distinct buffer addresses
    }
    v
}

#[test]
fn rx_ring_poll_returns_none_when_not_done() {
    let mut ring_mem = make_rx_ring(4);
    let ring = unsafe { RxRing::new(ring_mem.as_mut_ptr(), 4) };
    assert_eq!(ring.count(), 4);
    assert_eq!(ring.tail(), 3); // tail starts at count-1
    assert!(ring.poll().is_none());
}

#[test]
fn rx_ring_poll_returns_done_descriptor_with_length() {
    let mut ring_mem = make_rx_ring(4);
    ring_mem[0].status |= 1; // DD
    ring_mem[0].length = 512;

    let ring = unsafe { RxRing::new(ring_mem.as_mut_ptr(), 4) };
    let polled = ring.poll().expect("descriptor 0 marked done");
    assert_eq!(polled.0, 0);
    assert_eq!(polled.1, 512);
}

#[test]
fn rx_ring_advance_wraps_modulo_count() {
    let mut ring_mem = make_rx_ring(4);
    ring_mem[0].status |= 1;

    let mut ring = unsafe { RxRing::new(ring_mem.as_mut_ptr(), 4) };
    assert!(ring.poll().is_some());
    ring.advance();
    assert_eq!(ring.tail(), 0);

    // Wrap around the end of the ring.
    ring.advance(); // 1
    ring.advance(); // 2
    ring.advance(); // 3
    assert_eq!(ring.tail(), 3);
    ring.advance();
    assert_eq!(ring.tail(), 0);
}

#[test]
fn tx_descriptor_set_and_clear() {
    let mut d = LegacyTxDesc::default();
    d.set_buffer(0xDEAD_BEEF, 1514);
    assert_eq!(d.addr, 0xDEAD_BEEF);
    assert_eq!(d.length, 1514);
    d.set_eop_ifcs_rs();
    assert!(d.is_done() == false); // TX_DD not set yet
    d.status |= tx_status::DD;
    assert!(d.is_done());
    d.clear();
    assert_eq!(d.addr, 0);
    assert_eq!(d.length, 0);
    assert_eq!(d.cmd, 0);
    assert_eq!(d.status, 0);
}

// ===========================================================================
// net-core constants
// ===========================================================================

#[test]
fn mtu_is_classic_ethernet_frame_size() {
    assert_eq!(net_core::MTU, 1514); // 1500 payload + 14 Ethernet header
}
