// USB Bluetooth (HCI over USB) transport
// Reference: Bluetooth Core Specification, Vol 4, Part B (HCI USB transport)
//
// Phase 1 skeleton. This file owns the *transport* only:
// - HCI interface discovery (bInterfaceClass=0xE0, subclass 0x01, protocol 0x01)
// - Endpoint configuration through xHCI (bulk IN, bulk OUT, optional int IN)
// - H4 framing (0x01 command, 0x02 ACL, 0x04 event)
// - Fixed-capacity RX/TX queues, safe to touch from interrupt context
//
// The HCI command/event protocol (initialisation, firmware download, L2CAP)
// lives in userspace; it reaches the controller through /dev/bt/hci0.
//
// Notes:
// - No allocation happens on the IRQ path (`on_transfer` / `fill_bulk_out`).
// - Single controller (index 0) and a single Bluetooth device are supported.
// - Firmware download, SCO and hubs are not implemented in this phase.

#![allow(dead_code)]

use crate::{hardware::usb::xhci, sync::SpinLock, syscall::error::SyscallError};
use alloc::string::String;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

/// H4 packet indicator: HCI command packet.
pub const H4_COMMAND: u8 = 0x01;
/// H4 packet indicator: ACL data packet.
pub const H4_ACL: u8 = 0x02;
/// H4 packet indicator: SCO data packet (not supported yet).
pub const H4_SCO: u8 = 0x03;
/// H4 packet indicator: HCI event packet.
pub const H4_EVENT: u8 = 0x04;

/// bInterfaceClass for wireless controllers.
const USB_CLASS_WIRELESS: u8 = 0xE0;
/// bInterfaceSubClass for radio frequency controllers.
const USB_SUBCLASS_RF: u8 = 0x01;
/// bInterfaceProtocol for Bluetooth.
const USB_PROTO_BLUETOOTH: u8 = 0x01;

/// Largest configuration descriptor we fetch (descriptors can be longer,
/// in which case the extra interfaces are ignored).
const MAX_CONFIG_DESC: usize = 256;

/// Capacity of the HCI event ring (one or more complete H4 packets).
const RX_EVENT_RING: usize = 2048;
/// Capacity of the ACL receive ring.
const RX_ACL_RING: usize = 8192;
/// Byte capacity of the command/ACL transmit ring.
const TX_RING_BYTES: usize = 4096;
/// Number of packets the transmit ring may hold at once.
const TX_RING_PACKETS: usize = 8;

/// Receive buffer size used for a bulk IN endpoint.
const BULK_IN_BUF_LEN: usize = 1024;
/// Largest H4 packet accepted for transmission (matches the bulk OUT buffer).
pub const BULK_OUT_MAX: usize = 1024;

/// xHCI endpoint types used when configuring the HCI endpoints.
const EP_TYPE_BULK_OUT: u32 = 2;
const EP_TYPE_BULK_IN: u32 = 6;
const EP_TYPE_INTR_IN: u32 = 7;

// ============================================================================
// H4 framing helpers
// ============================================================================

/// Returns the total H4 packet length implied by a leading packet indicator.
///
/// `packet` must contain at least the packet header, otherwise `None` is
/// returned. The result may be larger than `packet.len()`: callers use it to
/// detect partial transfers.
pub fn h4_total_len(packet: &[u8]) -> Option<usize> {
    let ty = *packet.first()?;
    let (header_len, payload_len) = match ty {
        H4_COMMAND => {
            if packet.len() < 4 {
                return None;
            }
            (4, packet[3] as usize)
        }
        H4_ACL | H4_SCO => {
            if packet.len() < 5 {
                return None;
            }
            (5, u16::from_le_bytes([packet[3], packet[4]]) as usize)
        }
        H4_EVENT => {
            if packet.len() < 3 {
                return None;
            }
            (3, packet[2] as usize)
        }
        _ => return None,
    };
    Some(header_len + payload_len)
}

/// Computes the H4 packet length from a fixed 5-byte header window.
///
/// Used by the rings, which may not be able to hand out a contiguous slice
/// across the wrap point.
fn h4_len_from_window(ty: u8, header: &[u8; 5]) -> Option<(usize, usize)> {
    match ty {
        H4_COMMAND => Some((4, header[3] as usize)),
        H4_ACL | H4_SCO => Some((5, u16::from_le_bytes([header[3], header[4]]) as usize)),
        H4_EVENT => Some((3, header[2] as usize)),
        _ => None,
    }
}

/// Reason a ring operation did not produce a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingError {
    /// No complete packet is queued.
    Empty,
    /// The caller's buffer is smaller than the packet; nothing was consumed.
    Truncated,
    /// The queued bytes do not form a valid H4 packet; they were discarded.
    Corrupt,
}

// ============================================================================
// Fixed-capacity packet ring (byte oriented, one H4 packet at a time)
// ============================================================================

/// Byte ring that preserves H4 packet boundaries.
///
/// Each entry is a complete H4 packet, so a reader never observes half a
/// packet unless the producer queued one as-is (which `push` rejects).
struct PacketRing<const N: usize> {
    buf: [u8; N],
    /// Offset of the oldest byte.
    head: usize,
    /// Number of valid bytes in the ring.
    used: usize,
    /// Packets rejected because the ring was full or the frame was invalid.
    dropped: u32,
    /// Bytes discarded together with those packets.
    dropped_bytes: u32,
}

impl<const N: usize> PacketRing<N> {
    const fn new() -> Self {
        Self {
            buf: [0; N],
            head: 0,
            used: 0,
            dropped: 0,
            dropped_bytes: 0,
        }
    }

    fn byte_at(&self, index: usize) -> Option<u8> {
        if index < self.used {
            Some(self.buf[(self.head + index) % N])
        } else {
            None
        }
    }

    /// Length of the packet at the head, if the header is readable.
    fn packet_len(&self) -> Option<usize> {
        let ty = self.byte_at(0)?;
        let header_len = match ty {
            H4_COMMAND => 4,
            H4_ACL | H4_SCO => 5,
            H4_EVENT => 3,
            _ => return None,
        };
        if self.used < header_len {
            return None;
        }
        let mut header = [0u8; 5];
        for (i, slot) in header.iter_mut().enumerate() {
            *slot = self.byte_at(i).unwrap_or(0);
        }
        h4_len_from_window(ty, &header).map(|(header_len, payload_len)| header_len + payload_len)
    }

    /// Queues one complete packet. Returns `false` if it was dropped.
    fn push(&mut self, packet: &[u8]) -> bool {
        let total = match h4_total_len(packet) {
            Some(total) if total == packet.len() => total,
            _ => {
                self.dropped = self.dropped.saturating_add(1);
                self.dropped_bytes = self.dropped_bytes.saturating_add(packet.len() as u32);
                return false;
            }
        };
        if total > N || N - self.used < total {
            self.dropped = self.dropped.saturating_add(1);
            self.dropped_bytes = self.dropped_bytes.saturating_add(total as u32);
            return false;
        }
        let tail = (self.head + self.used) % N;
        for (i, byte) in packet.iter().enumerate() {
            self.buf[(tail + i) % N] = *byte;
        }
        self.used += total;
        true
    }

    /// Copies the head packet into `out` without consuming it.
    fn peek(&self, out: &mut [u8]) -> Result<usize, RingError> {
        if self.used == 0 {
            return Err(RingError::Empty);
        }
        let total = self.packet_len().ok_or(RingError::Corrupt)?;
        if total > self.used {
            return Err(RingError::Corrupt);
        }
        if out.len() < total {
            return Err(RingError::Truncated);
        }
        for (i, slot) in out.iter_mut().take(total).enumerate() {
            *slot = self.buf[(self.head + i) % N];
        }
        Ok(total)
    }

    /// Removes the head packet and copies it into `out`.
    ///
    /// Nothing is consumed when the destination is too small.
    fn pop(&mut self, out: &mut [u8]) -> Result<usize, RingError> {
        if self.used == 0 {
            return Err(RingError::Empty);
        }
        let total = match self.packet_len() {
            Some(total) if total <= self.used => total,
            _ => {
                // Unrecoverable framing error: drop the queued bytes.
                self.dropped = self.dropped.saturating_add(1);
                self.dropped_bytes = self.dropped_bytes.saturating_add(self.used as u32);
                self.head = 0;
                self.used = 0;
                return Err(RingError::Corrupt);
            }
        };
        if out.len() < total {
            return Err(RingError::Truncated);
        }
        for (i, slot) in out.iter_mut().take(total).enumerate() {
            *slot = self.buf[(self.head + i) % N];
        }
        self.head = (self.head + total) % N;
        self.used -= total;
        Ok(total)
    }

    fn discard_all(&mut self) {
        self.head = 0;
        self.used = 0;
    }
}

// ============================================================================
// Fixed-capacity TX queue (H4 packets)
// ============================================================================

/// Multi-packet transmit queue backed by a byte ring plus a length queue.
struct TxQueue<const N: usize, const S: usize> {
    buf: [u8; N],
    lens: [usize; S],
    /// Index of the oldest packet in `lens`.
    head: usize,
    /// Offset of the oldest byte in `buf`.
    head_off: usize,
    count: usize,
    used: usize,
    dropped: u32,
}

impl<const N: usize, const S: usize> TxQueue<N, S> {
    const fn new() -> Self {
        Self {
            buf: [0; N],
            lens: [0; S],
            head: 0,
            head_off: 0,
            count: 0,
            used: 0,
            dropped: 0,
        }
    }

    fn push(&mut self, packet: &[u8]) -> bool {
        let total = match h4_total_len(packet) {
            Some(total) if total == packet.len() => total,
            _ => {
                self.dropped = self.dropped.saturating_add(1);
                return false;
            }
        };
        if self.count == S || total > N || N - self.used < total {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        let tail = (self.head_off + self.used) % N;
        for (i, byte) in packet.iter().enumerate() {
            self.buf[(tail + i) % N] = *byte;
        }
        self.lens[(self.head + self.count) % S] = total;
        self.count += 1;
        self.used += total;
        true
    }

    fn peek(&self, out: &mut [u8]) -> Result<usize, RingError> {
        if self.count == 0 {
            return Err(RingError::Empty);
        }
        let total = self.lens[self.head];
        if out.len() < total {
            return Err(RingError::Truncated);
        }
        for (i, slot) in out.iter_mut().take(total).enumerate() {
            *slot = self.buf[(self.head_off + i) % N];
        }
        Ok(total)
    }

    fn pop(&mut self) -> Option<usize> {
        if self.count == 0 {
            return None;
        }
        let total = self.lens[self.head];
        self.head_off = (self.head_off + total) % N;
        self.used -= total;
        self.head = (self.head + 1) % S;
        self.count -= 1;
        Some(total)
    }

    fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ============================================================================
// USB descriptor parsing
// ============================================================================

/// One USB endpoint described by an endpoint descriptor.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// bEndpointAddress, direction encoded in bit 7.
    pub addr: u8,
    /// wMaxPacketSize.
    pub max_packet: u16,
    /// bInterval (poll interval, meaningful for interrupt endpoints).
    pub interval: u8,
}

impl Endpoint {
    fn number(self) -> u8 {
        self.addr & 0x0F
    }

    fn is_in(self) -> bool {
        self.addr & 0x80 != 0
    }
}

/// HCI transport endpoints selected from a configuration descriptor.
#[derive(Clone, Copy, Default, Debug)]
pub struct HciEndpoints {
    pub interface: u8,
    pub alternate: u8,
    pub bulk_in: Endpoint,
    pub bulk_out: Endpoint,
    /// Interrupt IN endpoint, if the dongle exposes one. When absent, HCI
    /// events arrive on `bulk_in`.
    pub intr_in: Option<Endpoint>,
}

#[derive(Clone, Copy, Default)]
struct Candidate {
    interface: u8,
    alternate: u8,
    bulk_in: Endpoint,
    bulk_out: Endpoint,
    intr_in: Option<Endpoint>,
}

impl Candidate {
    fn complete(&self) -> bool {
        self.bulk_in.addr != 0 && self.bulk_out.addr != 0
    }

    fn score(&self) -> u32 {
        // Prefer alternate settings that also provide an interrupt endpoint.
        1 + self.intr_in.is_some() as u32
    }
}

/// Scans a configuration descriptor for an HCI-over-USB interface.
///
/// The parser tolerates multiple interfaces and alternate settings: every
/// interface that advertises class 0xE0 / subclass 0x01 / protocol 0x01 is
/// considered, and the best endpoint set wins. Endpoint descriptors are tied
/// to the interface descriptor that immediately precedes them.
pub fn parse_hci_config(config: &[u8], total_len: usize) -> Option<HciEndpoints> {
    let end = total_len.min(config.len());
    if end < 9 {
        return None;
    }

    let mut best: Option<HciEndpoints> = None;
    let mut best_score = 0u32;
    let mut current: Option<Candidate> = None;

    let mut offset = 9usize;
    while offset + 2 <= end {
        let length = config[offset] as usize;
        if length < 2 || offset + length > end {
            break;
        }
        let descriptor_type = config[offset + 1];

        match descriptor_type {
            4 if length >= 9 => {
                if let Some(candidate) = current.take() {
                    if candidate.complete() && candidate.score() > best_score {
                        best_score = candidate.score();
                        best = Some(HciEndpoints {
                            interface: candidate.interface,
                            alternate: candidate.alternate,
                            bulk_in: candidate.bulk_in,
                            bulk_out: candidate.bulk_out,
                            intr_in: candidate.intr_in,
                        });
                    }
                }

                let class = config[offset + 5];
                let subclass = config[offset + 6];
                let protocol = config[offset + 7];
                if class == USB_CLASS_WIRELESS
                    && subclass == USB_SUBCLASS_RF
                    && protocol == USB_PROTO_BLUETOOTH
                {
                    current = Some(Candidate {
                        interface: config[offset + 2],
                        alternate: config[offset + 3],
                        ..Candidate::default()
                    });
                }
            }
            5 if length >= 7 => {
                if let Some(candidate) = current.as_mut() {
                    let endpoint = Endpoint {
                        addr: config[offset + 2],
                        max_packet: u16::from_le_bytes([config[offset + 4], config[offset + 5]]),
                        interval: config[offset + 6],
                    };
                    let transfer_type = config[offset + 3] & 0x03;
                    match (transfer_type, endpoint.is_in()) {
                        (2, true) => candidate.bulk_in = endpoint,
                        (2, false) => candidate.bulk_out = endpoint,
                        (3, true) => candidate.intr_in = Some(endpoint),
                        _ => {}
                    }
                }
            }
            _ => {}
        }

        offset += length;
    }

    if let Some(candidate) = current.take() {
        if candidate.complete() && candidate.score() > best_score {
            best = Some(HciEndpoints {
                interface: candidate.interface,
                alternate: candidate.alternate,
                bulk_in: candidate.bulk_in,
                bulk_out: candidate.bulk_out,
                intr_in: candidate.intr_in,
            });
        }
    }

    best
}

// ============================================================================
// Driver state
// ============================================================================

struct BtState {
    present: bool,
    slot_id: u8,
    vendor_id: u16,
    product_id: u16,
    ep_in: Endpoint,
    ep_out: Endpoint,
    /// Endpoint that carries HCI events (interrupt IN, else bulk IN).
    ep_evt: Endpoint,
    events_on_bulk: bool,
    rx_event_ring: PacketRing<RX_EVENT_RING>,
    rx_acl_ring: PacketRing<RX_ACL_RING>,
    /// H4 reassembly across USB transfers (events arrive on a 16-byte
    /// interrupt endpoint, so a 22-byte LE Connection Complete spans two).
    evt_reasm: [u8; 260],
    evt_reasm_len: usize,
    acl_reasm: [u8; 1100],
    acl_reasm_len: usize,
    tx: TxQueue<TX_RING_BYTES, TX_RING_PACKETS>,
    /// Length of the packet popped by `next_tx_packet` and awaiting completion.
    in_flight: Option<usize>,
    rx_events: u32,
    rx_acl: u32,
    tx_packets: u32,
    tx_bytes: u32,
    rx_dropped: u32,
    tx_dropped: u32,
}

impl BtState {
    const fn new() -> Self {
        Self {
            present: false,
            slot_id: 0,
            vendor_id: 0,
            product_id: 0,
            ep_in: Endpoint {
                addr: 0,
                max_packet: 0,
                interval: 0,
            },
            ep_out: Endpoint {
                addr: 0,
                max_packet: 0,
                interval: 0,
            },
            ep_evt: Endpoint {
                addr: 0,
                max_packet: 0,
                interval: 0,
            },
            events_on_bulk: false,
            rx_event_ring: PacketRing::new(),
            rx_acl_ring: PacketRing::new(),
            evt_reasm: [0; 260],
            evt_reasm_len: 0,
            acl_reasm: [0; 1100],
            acl_reasm_len: 0,
            tx: TxQueue::new(),
            in_flight: None,
            rx_events: 0,
            rx_acl: 0,
            tx_packets: 0,
            tx_bytes: 0,
            rx_dropped: 0,
            tx_dropped: 0,
        }
    }

    fn reset(&mut self) {
        let dropped = self.rx_dropped.saturating_add(self.rx_event_ring.dropped);
        let tx_dropped = self.tx_dropped.saturating_add(self.tx.dropped);
        *self = Self::new();
        self.rx_dropped = dropped;
        self.tx_dropped = tx_dropped;
    }
}

static STATE: SpinLock<BtState> = SpinLock::new(BtState::new());

/// Slot owning the Bluetooth device, `0xFF` when absent.
///
/// Lock-free so the interrupt handler can route transfers without taking the
/// state lock.
static BT_SLOT: AtomicU8 = AtomicU8::new(0xFF);
/// Raw bEndpointAddress of the bulk OUT endpoint (direction bit set to 0).
static BULK_OUT_ADDR: AtomicU8 = AtomicU8::new(0);
/// Incremented when the IRQ path cannot take the state lock.
static IRQ_DROPS: AtomicU32 = AtomicU32::new(0);
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Returns true when `ep_id` denotes `endpoint`.
///
/// Both numbering conventions are accepted because the xHCI driver and the
/// HID driver historically used different values here: the endpoint number
/// (1..15) and the xHCI device context index (`2*n + direction`).
fn endpoint_matches(endpoint: Endpoint, ep_id: u8) -> bool {
    let number = endpoint.number();
    if number == 0 {
        return false;
    }
    let dci = (number << 1) | endpoint.is_in() as u8;
    ep_id == number || ep_id == dci
}

/// Initializes the transport. Idempotent; called from `hardware::usb::init()`.
pub fn init() {
    if INITIALIZED.swap(true, Ordering::AcqRel) {
        return;
    }
    if is_present() {
        log::info!("[USB-BT] HCI-over-USB transport ready (device attached)");
    } else {
        log::info!(
            "[USB-BT] no HCI interface on any xHCI device (QEMU has no emulated \
             Bluetooth dongle; on real hardware check root port + xHCI)"
        );
    }
}

/// True when an HCI interface is configured.
pub fn is_present() -> bool {
    BT_SLOT.load(Ordering::Acquire) != 0xFF
}

/// True when `slot_id`/`ep_id` belong to the Bluetooth device.
///
/// Used by the xHCI interrupt path to route transfer events. Lock-free and
/// safe to call from interrupt context.
pub fn owns_endpoint(slot_id: u8, ep_id: u8) -> bool {
    // DCI 1 is EP0: never route control-transfer completions to the HCI rings.
    ep_id >= 2 && slot_id != 0xFF && slot_id == BT_SLOT.load(Ordering::Acquire)
}

/// True when `ep_id` is the bulk OUT endpoint.
///
/// The xHCI completion loop must not blindly re-arm this endpoint: a new TRB
/// is only queued when a packet is waiting in the TX ring.
pub fn is_bulk_out(slot_id: u8, ep_id: u8) -> bool {
    if slot_id != BT_SLOT.load(Ordering::Acquire) {
        return false;
    }
    let addr = BULK_OUT_ADDR.load(Ordering::Acquire);
    if addr == 0 {
        return false;
    }
    endpoint_matches(
        Endpoint {
            addr,
            max_packet: 0,
            interval: 0,
        },
        ep_id,
    )
}

// ============================================================================
// Enumeration
// ============================================================================

fn configure_endpoint(
    controller: &mut xhci::XhciController,
    slot_id: u8,
    endpoint: Endpoint,
    ep_type: u32,
    buffer_len: usize,
) -> bool {
    let number = endpoint.number();
    if number == 0 {
        return false;
    }
    let interval = if ep_type == EP_TYPE_INTR_IN {
        endpoint.interval.max(1) as u32
    } else {
        0
    };
    if controller
        .setup_endpoint(
            slot_id,
            number,
            endpoint.max_packet as u32,
            ep_type,
            interval,
            0,
        )
        .is_err()
    {
        log::warn!(
            "[USB-BT] Endpoint setup failed: slot={} ep={:02x} type={}",
            slot_id,
            endpoint.addr,
            ep_type
        );
        return false;
    }
    if controller
        .alloc_interrupt_buffer(slot_id, number, buffer_len)
        .is_err()
    {
        log::warn!(
            "[USB-BT] Endpoint buffer allocation failed: slot={} ep={:02x}",
            slot_id,
            endpoint.addr
        );
        return false;
    }
    true
}

/// Probes a newly enumerated device for an HCI-over-USB interface.
///
/// Many Bluetooth dongles report `bDeviceClass = 0x00`, so the decision is
/// made from the configuration descriptor, never from the device descriptor
/// alone. The function is a no-op for devices without an HCI interface.
pub fn enumerate_device(
    controller: &mut xhci::XhciController,
    port: usize,
    slot_id: u8,
    dev_desc: &[u8; 18],
) {
    // Correct device descriptor offsets: idVendor @ 8..10, idProduct @ 10..12.
    let vendor_id = u16::from_le_bytes([dev_desc[8], dev_desc[9]]);
    let product_id = u16::from_le_bytes([dev_desc[10], dev_desc[11]]);
    log::info!(
        "[USB-BT] Probing port={} slot={} vid={:04x} pid={:04x}",
        port,
        slot_id,
        vendor_id,
        product_id
    );

    let mut config_desc = [0u8; MAX_CONFIG_DESC];
    if controller
        .get_configuration_descriptor(slot_id, 0, &mut config_desc, 9)
        .is_err()
    {
        log::warn!(
            "[USB-BT] Cannot read configuration descriptor header: slot={}",
            slot_id
        );
        return;
    }

    let total_len = u16::from_le_bytes([config_desc[2], config_desc[3]]) as usize;
    if total_len < 9 || total_len > MAX_CONFIG_DESC {
        log::warn!(
            "[USB-BT] Unsupported configuration length {}: slot={}",
            total_len,
            slot_id
        );
        return;
    }
    if total_len > 9
        && controller
            .get_configuration_descriptor(slot_id, 0, &mut config_desc, total_len)
            .is_err()
    {
        log::warn!(
            "[USB-BT] Cannot read full configuration: slot={}",
            slot_id
        );
        return;
    }

    let Some(hci) = parse_hci_config(&config_desc, total_len) else {
        log::info!(
            "[USB-BT] No HCI interface on port={} slot={} vid={:04x} pid={:04x}",
            port,
            slot_id,
            vendor_id,
            product_id
        );
        return;
    };

    if hci.bulk_in.number() == hci.bulk_out.number() {
        log::warn!(
            "[USB-BT] Endpoint number collision (ep{:x} used for bulk IN and OUT), skipping",
            hci.bulk_in.number()
        );
        return;
    }

    let events_on_bulk = hci.intr_in.is_none();
    let ep_evt = hci.intr_in.unwrap_or(hci.bulk_in);
    log::info!(
        "[USB-BT] HCI interface: slot={} iface={} alt={} bulk_in={:02x} bulk_out={:02x} evt={:02x}{}",
        slot_id,
        hci.interface,
        hci.alternate,
        hci.bulk_in.addr,
        hci.bulk_out.addr,
        ep_evt.addr,
        if events_on_bulk {
            " (events on bulk IN)"
        } else {
            ""
        }
    );

    let in_len = BULK_IN_BUF_LEN.min(4096);
    if !configure_endpoint(
        controller,
        slot_id,
        hci.bulk_in,
        EP_TYPE_BULK_IN,
        in_len,
    ) {
        return;
    }
    if !configure_endpoint(
        controller,
        slot_id,
        hci.bulk_out,
        EP_TYPE_BULK_OUT,
        BULK_OUT_MAX,
    ) {
        return;
    }
    if let Some(intr) = hci.intr_in {
        let intr_len = (intr.max_packet as usize).max(16).min(BULK_IN_BUF_LEN);
        if !configure_endpoint(controller, slot_id, intr, EP_TYPE_INTR_IN, intr_len) {
            return;
        }
    }

    // Match the HID driver's ordering: endpoints first, then SET_CONFIGURATION.
    if controller.set_configuration(slot_id, 1).is_err() {
        log::warn!("[USB-BT] SET_CONFIGURATION(1) failed: slot={}", slot_id);
        return;
    }

    // Arm the receive paths.
    controller
        .submit_interrupt_transfer(slot_id, hci.bulk_in.number())
        .ok();
    if let Some(intr) = hci.intr_in {
        if intr.number() != hci.bulk_in.number() {
            controller
                .submit_interrupt_transfer(slot_id, intr.number())
                .ok();
        }
    }

    {
        let mut state = STATE.lock();
        state.reset();
        state.present = true;
        state.slot_id = slot_id;
        state.vendor_id = vendor_id;
        state.product_id = product_id;
        state.ep_in = hci.bulk_in;
        state.ep_out = hci.bulk_out;
        state.ep_evt = ep_evt;
        state.events_on_bulk = events_on_bulk;
    }

    BT_SLOT.store(slot_id, Ordering::Release);
    BULK_OUT_ADDR.store(hci.bulk_out.addr & 0x7F, Ordering::Release);

    log::info!(
        "[USB-BT] Attached vid={:04x} pid={:04x} slot={}",
        vendor_id,
        product_id,
        slot_id
    );

    // Expose /dev/bt. The VFS mount may not exist yet at hardware-init time;
    // `init_bt_scheme()` is idempotent and retried by `vfs::init()`.
    crate::vfs::bt_scheme::init_bt_scheme();

    // The HCI state machine (including HCI_Reset) belongs to `strate-bt`; the
    // kernel only moves bytes. Keeping it out of enumeration also avoids mixing
    // the kernel's own events into the userspace event stream.
}

// ============================================================================
// Interrupt-side receive path
// ============================================================================

fn queue_packet(state: &mut BtState, packet: &[u8]) -> bool {
    match packet[0] {
        H4_EVENT => {
            if state.rx_event_ring.push(packet) {
                state.rx_events = state.rx_events.saturating_add(1);
                true
            } else {
                false
            }
        }
        H4_ACL => {
            if state.rx_acl_ring.push(packet) {
                state.rx_acl = state.rx_acl.saturating_add(1);
                true
            } else {
                false
            }
        }
        // SCO is not supported in this phase.
        _ => false,
    }
}

/// Appends bytes to the reassembly buffer; returns true on overflow.
fn append_reasm(state: &mut BtState, use_evt: bool, data: &[u8]) -> bool {
    let (buf_len, len) = if use_evt {
        (state.evt_reasm.len(), state.evt_reasm_len)
    } else {
        (state.acl_reasm.len(), state.acl_reasm_len)
    };
    let n = core::cmp::min(buf_len.saturating_sub(len), data.len());
    if use_evt {
        state.evt_reasm[len..len + n].copy_from_slice(&data[..n]);
        state.evt_reasm_len = len + n;
    } else {
        state.acl_reasm[len..len + n].copy_from_slice(&data[..n]);
        state.acl_reasm_len = len + n;
    }
    n < data.len()
}

/// Drops `n` bytes from the front of the reassembly buffer.
fn drop_reasm_prefix(state: &mut BtState, use_evt: bool, n: usize) {
    if use_evt {
        let len = state.evt_reasm_len;
        let n = n.min(len);
        state.evt_reasm.copy_within(n..len, 0);
        state.evt_reasm_len = len - n;
    } else {
        let len = state.acl_reasm_len;
        let n = n.min(len);
        state.acl_reasm.copy_within(n..len, 0);
        state.acl_reasm_len = len - n;
    }
}

/// Copies the head packet into `out`.
///
/// `None` means "wait for more bytes"; `Some(0)` means a malformed header that
/// the caller must resync by dropping one byte.
fn peek_reasm(state: &BtState, use_evt: bool, out: &mut [u8; 1100]) -> Option<usize> {
    let src = if use_evt {
        &state.evt_reasm[..state.evt_reasm_len]
    } else {
        &state.acl_reasm[..state.acl_reasm_len]
    };
    if src.is_empty() {
        return None;
    }
    match h4_total_len(src) {
        // Larger than any packet we can buffer: malformed, resync.
        Some(t) if t > out.len() => Some(0),
        Some(t) if t <= src.len() => {
            out[..t].copy_from_slice(&src[..t]);
            Some(t)
        }
        // Valid header, wait for the rest.
        Some(_) => None,
        None => Some(0),
    }
}

/// Called by the xHCI completion handler with a completed IN transfer.
///
/// Runs in interrupt context: only `try_lock` is used, and no allocation is
/// performed. HCI events arriving on a 16-byte interrupt endpoint (and large
/// ACL packets on bulk IN) may span several USB transfers, so bytes are
/// reassembled per endpoint before complete H4 packets are queued.
pub fn on_transfer(slot_id: u8, ep_id: u8, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let Some(mut state) = STATE.try_lock() else {
        IRQ_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    };

    if !state.present || state.slot_id != slot_id {
        state.rx_dropped = state.rx_dropped.saturating_add(1);
        return;
    }

    // Bulk OUT completions are acknowledgements, not data.
    if endpoint_matches(state.ep_out, ep_id) {
        return;
    }
    let is_in = endpoint_matches(state.ep_in, ep_id);
    let is_evt = endpoint_matches(state.ep_evt, ep_id);
    if !is_in && !is_evt {
        state.rx_dropped = state.rx_dropped.saturating_add(1);
        return;
    }

    // Events get their own small buffer unless they share the bulk endpoint.
    let use_evt = is_evt && !is_in;

    if append_reasm(&mut state, use_evt, data) {
        state.rx_dropped = state.rx_dropped.saturating_add(1);
    }

    let mut packet = [0u8; 1100];
    loop {
        match peek_reasm(&state, use_evt, &mut packet) {
            None => break,
            Some(0) => {
                drop_reasm_prefix(&mut state, use_evt, 1);
                state.rx_dropped = state.rx_dropped.saturating_add(1);
            }
            Some(total) => {
                if !queue_packet(&mut state, &packet[..total]) {
                    state.rx_dropped = state.rx_dropped.saturating_add(1);
                }
                drop_reasm_prefix(&mut state, use_evt, total);
            }
        }
    }
}

// ============================================================================
// Transmit path
// ============================================================================

/// Validates and enqueues one H4 packet.
///
/// Does not submit the transfer; call [`kick_tx`] afterwards (the scheme does
/// this once per write, after all packets have been queued).
pub fn send_h4(packet: &[u8]) -> Result<(), SyscallError> {
    let total = h4_total_len(packet).ok_or(SyscallError::InvalidArgument)?;
    if total != packet.len() {
        return Err(SyscallError::InvalidArgument);
    }
    if total > BULK_OUT_MAX {
        return Err(SyscallError::MessageSize);
    }

    let mut state = STATE.lock();
    if !state.present {
        return Err(SyscallError::Again);
    }
    if !state.tx.push(packet) {
        return Err(SyscallError::QueueFull);
    }
    Ok(())
}

/// Pops the next packet for transmission into `buf`.
///
/// Only one packet may be in flight at a time. Returns `None` when no packet
/// is queued, another packet is still in flight, or the state lock is busy.
pub fn next_tx_packet(buf: &mut [u8]) -> Option<usize> {
    let mut state = STATE.try_lock()?;
    if !state.present || state.in_flight.is_some() {
        return None;
    }
    match state.tx.peek(buf) {
        Ok(len) => {
            state.tx.pop();
            state.in_flight = Some(len);
            Some(len)
        }
        Err(_) => {
            // A queued packet that cannot be copied indicates a size bug in
            // the queue; drop it instead of stalling the endpoint forever.
            state.tx.pop();
            state.tx_dropped = state.tx_dropped.saturating_add(1);
            None
        }
    }
}

/// Copies the next TX packet directly into an xHCI endpoint buffer.
///
/// # Safety
///
/// `dst` must point to `cap` writable bytes owned by the xHCI endpoint buffer.
pub unsafe fn fill_bulk_out(dst: *mut u8, cap: usize) -> Option<usize> {
    if dst.is_null() || cap == 0 {
        return None;
    }
    let out = unsafe { core::slice::from_raw_parts_mut(dst, cap) };
    next_tx_packet(out)
}

/// Marks the in-flight bulk OUT packet as completed.
///
/// Called by the xHCI completion handler when the bulk OUT endpoint reports a
/// successful transfer (or an error, in which case the packet is simply
/// accounted as sent and retry policy is left to userspace).
pub fn tx_complete(ep_id: u8, len: usize) {
    let Some(mut state) = STATE.try_lock() else {
        IRQ_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    };
    if !state.present || !endpoint_matches(state.ep_out, ep_id) {
        return;
    }
    if state.in_flight.take().is_some() {
        state.tx_packets = state.tx_packets.saturating_add(1);
        state.tx_bytes = state.tx_bytes.saturating_add(len as u32);
    } else {
        state.tx_dropped = state.tx_dropped.saturating_add(1);
    }
}

/// Submits queued packets to the bulk OUT endpoint when it is idle.
///
/// No-op when the transport is absent or the endpoint already has a transfer
/// in flight (its completion re-arms it).
pub fn kick_tx() {
    let (slot_id, endpoint) = {
        let Some(state) = STATE.try_lock() else {
            return;
        };
        if !state.present {
            return;
        }
        (state.slot_id, state.ep_out.number())
    };

    if let Some(controller_arc) = xhci::get_controller(0) {
        let mut controller = controller_arc.lock();
        if let Err(error) = controller.submit_bulk_out(slot_id, endpoint) {
            log::warn!(
                "[USB-BT] Bulk OUT submit failed: slot={} ep={} ({})",
                slot_id,
                endpoint,
                error
            );
        }
    }
}

// ============================================================================
// Scheme-facing helpers
// ============================================================================

/// Reads one complete H4 packet.
///
/// Events are returned before ACL data. `Err(Again)` means both rings are
/// empty; `Err(MessageSize)` means `buf` cannot hold the head packet (nothing
/// is consumed in that case, so the caller can retry with a larger buffer).
pub fn read_packet(buf: &mut [u8]) -> Result<usize, SyscallError> {
    if buf.is_empty() {
        return Err(SyscallError::InvalidArgument);
    }

    let mut state = STATE.lock();
    if !state.present {
        return Err(SyscallError::Again);
    }

    match state.rx_event_ring.pop(buf) {
        Ok(len) => return Ok(len),
        Err(RingError::Empty) => {}
        Err(RingError::Truncated) => return Err(SyscallError::MessageSize),
        Err(RingError::Corrupt) => {
            state.rx_dropped = state.rx_dropped.saturating_add(1);
        }
    }

    match state.rx_acl_ring.pop(buf) {
        Ok(len) => Ok(len),
        Err(RingError::Empty) => Err(SyscallError::Again),
        Err(RingError::Truncated) => Err(SyscallError::MessageSize),
        Err(RingError::Corrupt) => {
            state.rx_dropped = state.rx_dropped.saturating_add(1);
            Err(SyscallError::Again)
        }
    }
}

/// Human-readable transport statistics for `/dev/bt/stats`.
pub fn stats_text() -> String {
    let state = STATE.lock();
    alloc::format!(
        "present={} slot={} vid={:04x} pid={:04x} ep_in={:02x} ep_out={:02x} ep_evt={:02x} events_on_bulk={} rx_events={} rx_acl={} rx_dropped={} tx_packets={} tx_bytes={} tx_dropped={} tx_queued={} irq_drops={}\n",
        state.present,
        state.slot_id,
        state.vendor_id,
        state.product_id,
        state.ep_in.addr,
        state.ep_out.addr,
        state.ep_evt.addr,
        state.events_on_bulk,
        state.rx_events,
        state.rx_acl,
        state.rx_dropped
            .saturating_add(state.rx_event_ring.dropped)
            .saturating_add(state.rx_acl_ring.dropped),
        state.tx_packets,
        state.tx_bytes,
        state.tx_dropped.saturating_add(state.tx.dropped),
        !state.tx.is_empty(),
        IRQ_DROPS.load(Ordering::Relaxed),
    )
}
