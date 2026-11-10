//! L2: virtio network device model (rx/tx queues, virtio_net_hdr).

extern crate alloc;

#[path = "../../kernel/src/s9vm/virtio.rs"]
mod virtio;
#[path = "../../kernel/src/s9vm/virtio_net.rs"]
mod virtio_net;

use alloc::vec::Vec;
use virtio::{
    Descriptor, QueueMemory, DESCRIPTOR_SIZE, DESC_F_NEXT, DESC_F_WRITE, VIRTQ_AVAIL_F_NO_INTERRUPT,
};
use virtio_net::{
    reg, status, VirtioNet, DEVICE_ID, MAC, MAGIC, NET_HDR_SIZE, QUEUE_NUM_MAX, VERSION,
};

struct Memory {
    bytes: Vec<u8>,
}

impl Memory {
    fn new() -> Self {
        Self {
            bytes: alloc::vec![0u8; 0x8000],
        }
    }

    fn write_bytes(&mut self, gpa: u64, bytes: &[u8]) {
        self.write_gpa(gpa, bytes);
    }

    fn slice(&self, gpa: u64, len: usize) -> &[u8] {
        &self.bytes[gpa as usize..gpa as usize + len]
    }
}

impl QueueMemory for Memory {
    fn read_gpa(&mut self, gpa: u64, out: &mut [u8]) -> bool {
        let start = gpa as usize;
        let Some(slice) = self.bytes.get(start..start + out.len()) else {
            return false;
        };
        out.copy_from_slice(slice);
        true
    }

    fn write_gpa(&mut self, gpa: u64, bytes: &[u8]) -> bool {
        let start = gpa as usize;
        let Some(slice) = self.bytes.get_mut(start..start + bytes.len()) else {
            return false;
        };
        slice.copy_from_slice(bytes);
        true
    }
}

const DESC: u64 = 0x1000;
const AVAIL: u64 = 0x2000;
const USED: u64 = 0x3000;
const BUFFERS: u64 = 0x4000;
const QUEUE_SIZE: u16 = 8;

fn write_descriptor(memory: &mut Memory, index: u16, descriptor: Descriptor) {
    memory.write_bytes(
        DESC + u64::from(index) * DESCRIPTOR_SIZE,
        &descriptor.encode(),
    );
}

fn publish(memory: &mut Memory, count: u16) {
    memory.write_u16(AVAIL + 2, count);
}

fn used_entry(memory: &Memory, index: u16) -> (u32, u32) {
    let gpa = USED + 4 + u64::from(index) * 8;
    let id = u32::from_le_bytes(memory.slice(gpa, 4).try_into().unwrap());
    let len = u32::from_le_bytes(memory.slice(gpa + 4, 4).try_into().unwrap());
    (id, len)
}

fn used_count(memory: &Memory) -> u16 {
    u16::from_le_bytes(memory.slice(USED + 2, 2).try_into().unwrap())
}

/// Programs one queue and marks the device ready.
fn setup(memory: &mut Memory, device: &mut VirtioNet, queue: u32) {
    device.write(reg::QUEUE_SEL, queue, memory);
    device.write(reg::QUEUE_NUM, u32::from(QUEUE_SIZE), memory);
    device.write(reg::QUEUE_DESC_LOW, DESC as u32, memory);
    device.write(reg::QUEUE_AVAIL_LOW, AVAIL as u32, memory);
    device.write(reg::QUEUE_USED_LOW, USED as u32, memory);
    device.write(reg::QUEUE_READY, 1, memory);
}

fn ready_device(memory: &mut Memory) -> VirtioNet {
    let mut device = VirtioNet::new();
    setup(memory, &mut device, virtio_net::QUEUE_RX);
    setup(memory, &mut device, virtio_net::QUEUE_TX);
    device.write(
        reg::STATUS,
        status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK,
        memory,
    );
    device
}

#[test]
fn transport_identity_is_advertised() {
    let device = VirtioNet::new();
    assert_eq!(device.read(reg::MAGIC), MAGIC);
    assert_eq!(device.read(reg::VERSION), VERSION);
    assert_eq!(device.read(reg::DEVICE_ID), DEVICE_ID);
    assert_eq!(device.read(reg::QUEUE_NUM_MAX), u32::from(QUEUE_NUM_MAX));
}

#[test]
fn mac_address_is_exposed_in_the_config_space() {
    let device = VirtioNet::new();
    let first = device.read(reg::CONFIG).to_le_bytes();
    let second = device.read(reg::CONFIG + 4).to_le_bytes();
    assert_eq!(
        [first[0], first[1], first[2], first[3], second[0], second[1]],
        MAC
    );
}

#[test]
fn link_is_reported_up() {
    let device = VirtioNet::new();
    assert_eq!(device.read(reg::CONFIG + 8) & 1, 1);
}

#[test]
fn transmit_strips_the_network_header() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    // Packet: 10-byte header then the frame payload.
    let mut packet = alloc::vec![0u8; NET_HDR_SIZE];
    packet.extend_from_slice(b"frame");
    memory.write_bytes(BUFFERS, &packet);
    write_descriptor(
        &mut memory,
        0,
        Descriptor {
            addr: BUFFERS,
            len: packet.len() as u32,
            flags: 0,
            next: 0,
        },
    );
    memory.write_u16(AVAIL + 4, 0);
    publish(&mut memory, 1);
    device.write(reg::QUEUE_NOTIFY, virtio_net::QUEUE_TX, &mut memory);
    assert_eq!(device.output(), b"frame");
    assert_eq!(device.frames_sent(), 1);
    assert_eq!(used_entry(&memory, 0), (0, (NET_HDR_SIZE + 5) as u32));
}

#[test]
fn transmit_collects_a_descriptor_chain() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    memory.write_bytes(BUFFERS, &[0u8; NET_HDR_SIZE]);
    memory.write_bytes(BUFFERS + NET_HDR_SIZE as u64, b"seg1");
    memory.write_bytes(BUFFERS + NET_HDR_SIZE as u64 + 4, b"seg2");
    write_descriptor(
        &mut memory,
        0,
        Descriptor {
            addr: BUFFERS,
            len: NET_HDR_SIZE as u32,
            flags: DESC_F_NEXT,
            next: 1,
        },
    );
    write_descriptor(
        &mut memory,
        1,
        Descriptor {
            addr: BUFFERS + NET_HDR_SIZE as u64,
            len: 8,
            flags: 0,
            next: 0,
        },
    );
    memory.write_u16(AVAIL + 4, 0);
    publish(&mut memory, 1);
    device.write(reg::QUEUE_NOTIFY, virtio_net::QUEUE_TX, &mut memory);
    assert_eq!(device.output(), b"seg1seg2");
}

#[test]
fn transmit_is_ignored_before_driver_ok() {
    let mut memory = Memory::new();
    let mut device = VirtioNet::new();
    setup(&mut memory, &mut device, virtio_net::QUEUE_TX);
    memory.write_bytes(BUFFERS, b"ignored");
    write_descriptor(
        &mut memory,
        0,
        Descriptor {
            addr: BUFFERS,
            len: 7,
            flags: 0,
            next: 0,
        },
    );
    memory.write_u16(AVAIL + 4, 0);
    publish(&mut memory, 1);
    device.write(reg::QUEUE_NOTIFY, virtio_net::QUEUE_TX, &mut memory);
    assert!(device.output().is_empty());
}

#[test]
fn receive_prepends_the_network_header() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    write_descriptor(
        &mut memory,
        0,
        Descriptor {
            addr: BUFFERS,
            len: 64,
            flags: DESC_F_WRITE,
            next: 0,
        },
    );
    memory.write_u16(AVAIL + 4, 0);
    publish(&mut memory, 1);
    device.push_frame(b"ping");
    device.write(reg::QUEUE_NOTIFY, virtio_net::QUEUE_RX, &mut memory);
    assert_eq!(memory.slice(BUFFERS, NET_HDR_SIZE), &[0u8; NET_HDR_SIZE]);
    assert_eq!(memory.slice(BUFFERS + NET_HDR_SIZE as u64, 4), b"ping");
    assert_eq!(used_entry(&memory, 0), (0, (NET_HDR_SIZE + 4) as u32));
    assert_eq!(device.frames_received(), 1);
}

#[test]
fn receive_splits_a_frame_across_descriptors() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    write_descriptor(
        &mut memory,
        0,
        Descriptor {
            addr: BUFFERS,
            len: 12,
            flags: DESC_F_NEXT | DESC_F_WRITE,
            next: 1,
        },
    );
    write_descriptor(
        &mut memory,
        1,
        Descriptor {
            addr: BUFFERS + 12,
            len: 64,
            flags: DESC_F_WRITE,
            next: 0,
        },
    );
    memory.write_u16(AVAIL + 4, 0);
    publish(&mut memory, 1);
    device.push_frame(b"abcdef");
    device.write(reg::QUEUE_NOTIFY, virtio_net::QUEUE_RX, &mut memory);
    // Header (10) + 2 bytes in the first descriptor, then the rest.
    assert_eq!(memory.slice(BUFFERS + 10, 2), b"ab");
    assert_eq!(memory.slice(BUFFERS + 12, 4), b"cdef");
}

#[test]
fn receive_keeps_frames_without_buffers_pending() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    device.push_frame(b"nowhere");
    device.write(reg::QUEUE_NOTIFY, virtio_net::QUEUE_RX, &mut memory);
    assert_eq!(device.pending_frames(), 1);
}

#[test]
fn interrupt_status_is_acknowledged() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    device.push_frame(b"x");
    assert_ne!(device.interrupt_status(), 0);
    let value = device.interrupt_status();
    device.write(reg::INTERRUPT_ACK, value, &mut memory);
    assert_eq!(device.interrupt_status(), 0);
}

#[test]
fn reset_clears_the_device() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    device.write(reg::STATUS, 0, &mut memory);
    assert!(!device.ready());
    assert!(!device.rx_ready());
    assert!(!device.tx_ready());
}

#[test]
fn invalid_queue_size_marks_the_device_failed() {
    let mut memory = Memory::new();
    let mut device = VirtioNet::new();
    device.write(reg::QUEUE_SEL, 0, &mut memory);
    device.write(reg::QUEUE_NUM, 3, &mut memory);
    assert_ne!(device.status() & status::FAILED, 0);
}

// ---------------------------------------------------------------------------
// MAC/STATUS features and link state.
// ---------------------------------------------------------------------------

#[test]
fn mac_and_link_status_features_are_negotiated() {
    let mut memory = Memory::new();
    let mut device = VirtioNet::new();
    device.write(reg::DRIVER_FEATURES_SEL, 0, &mut memory);
    device.write(
        reg::DRIVER_FEATURES,
        virtio_net::feature_lo::MAC | virtio_net::feature_lo::STATUS,
        &mut memory,
    );
    device.write(reg::DRIVER_FEATURES_SEL, 1, &mut memory);
    device.write(
        reg::DRIVER_FEATURES,
        virtio_net::feature_hi::VERSION_1,
        &mut memory,
    );
    device.write(
        reg::STATUS,
        status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK,
        &mut memory,
    );
    assert!(device.features_ok());
    assert!(device.mac_negotiated());
    assert!(device.link_status_negotiated());
    assert_eq!(
        device.negotiated_features(),
        u64::from(virtio_net::feature_lo::MAC)
            | u64::from(virtio_net::feature_lo::STATUS)
            | (u64::from(virtio_net::feature_hi::VERSION_1) << 32)
    );
}

#[test]
fn link_status_byte_reflects_the_link_state() {
    let mut device = VirtioNet::new();
    assert!(device.link_up());
    assert_eq!(device.read(reg::CONFIG + 8) & 1, 1);
    device.set_link_up(false);
    assert!(!device.link_up());
    assert_eq!(device.read(reg::CONFIG + 8), 0);
    assert_ne!(device.interrupt_status(), 0);
    device.set_link_up(true);
    assert_eq!(device.read(reg::CONFIG + 8) & 1, 1);
}

#[test]
fn link_down_blocks_rx_delivery() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    write_descriptor(
        &mut memory,
        0,
        Descriptor {
            addr: BUFFERS,
            len: 64,
            flags: DESC_F_WRITE,
            next: 0,
        },
    );
    memory.write_u16(AVAIL + 4, 0);
    publish(&mut memory, 1);
    device.push_frame(b"dropped");
    device.set_link_up(false);
    device.write(reg::QUEUE_NOTIFY, virtio_net::QUEUE_RX, &mut memory);
    assert_eq!(device.frames_received(), 0);
    assert_eq!(device.pending_frames(), 1);
    assert_eq!(used_count(&memory), 0);
    assert_eq!(device.service_rx(&mut memory), 0);
}

#[test]
fn link_down_still_completes_transmit() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    device.set_link_up(false);
    let mut packet = alloc::vec![0u8; NET_HDR_SIZE];
    packet.extend_from_slice(b"frame");
    memory.write_bytes(BUFFERS, &packet);
    write_descriptor(
        &mut memory,
        0,
        Descriptor {
            addr: BUFFERS,
            len: packet.len() as u32,
            flags: 0,
            next: 0,
        },
    );
    memory.write_u16(AVAIL + 4, 0);
    publish(&mut memory, 1);
    device.write(reg::QUEUE_NOTIFY, virtio_net::QUEUE_TX, &mut memory);
    assert_eq!(device.output(), b"frame");
    assert_eq!(device.frames_sent(), 1);
    assert_eq!(used_count(&memory), 1);
}

#[test]
fn missing_version_1_fails_feature_negotiation() {
    let mut memory = Memory::new();
    let mut device = VirtioNet::new();
    device.write(reg::DRIVER_FEATURES_SEL, 0, &mut memory);
    device.write(
        reg::DRIVER_FEATURES,
        virtio_net::feature_lo::MAC,
        &mut memory,
    );
    device.write(
        reg::STATUS,
        status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK,
        &mut memory,
    );
    assert_ne!(device.status() & status::FAILED, 0);
    assert!(!device.features_ok());
}

#[test]
fn no_interrupt_flag_suppresses_the_rx_interrupt() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    write_descriptor(
        &mut memory,
        0,
        Descriptor {
            addr: BUFFERS,
            len: 64,
            flags: DESC_F_WRITE,
            next: 0,
        },
    );
    memory.write_u16(AVAIL + 4, 0);
    memory.write_u16(AVAIL, VIRTQ_AVAIL_F_NO_INTERRUPT);
    publish(&mut memory, 1);
    device.push_frame(b"quiet");
    device.write(reg::QUEUE_NOTIFY, virtio_net::QUEUE_RX, &mut memory);
    assert_eq!(device.frames_received(), 1);
    assert_ne!(device.interrupt_status() & virtio_net::interrupt::CONFIG, 0);
    assert_eq!(
        device.interrupt_status() & virtio_net::interrupt::USED_RING,
        0
    );
}
