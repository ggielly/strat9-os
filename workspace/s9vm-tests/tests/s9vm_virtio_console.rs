//! L2: virtio console device model (MMIO registers, TX/RX split queues).

extern crate alloc;

#[path = "../../kernel/src/s9vm/virtio.rs"]
mod virtio;
#[path = "../../kernel/src/s9vm/virtio_console.rs"]
mod virtio_console;

use alloc::vec::Vec;
use virtio::{Descriptor, QueueMemory, DESC_F_NEXT, DESC_F_WRITE, DESCRIPTOR_SIZE};
use virtio_console::{reg, status, VirtioConsole, DEVICE_ID, MAGIC, QUEUE_NUM_MAX, VERSION};

/// Identity-mapped guest memory backed by a byte vector.
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

    fn read_bytes(&self, gpa: u64, len: usize) -> &[u8] {
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
    memory.write_bytes(DESC + u64::from(index) * DESCRIPTOR_SIZE, &descriptor.encode());
}

fn publish(memory: &mut Memory, count: u16) {
    memory.write_u16(AVAIL + 2, count);
}

fn used_entry(memory: &Memory, index: u16) -> (u32, u32) {
    let gpa = USED + 4 + u64::from(index) * 8;
    let id = u32::from_le_bytes(memory.read_bytes(gpa, 4).try_into().unwrap());
    let len = u32::from_le_bytes(memory.read_bytes(gpa + 4, 4).try_into().unwrap());
    (id, len)
}

/// Programs one queue and marks the device ready.
fn setup(memory: &mut Memory, device: &mut VirtioConsole, queue: u32) {
    device.write(reg::QUEUE_SEL, queue, memory);
    device.write(reg::QUEUE_NUM, u32::from(QUEUE_SIZE), memory);
    device.write(reg::QUEUE_DESC_LOW, DESC as u32, memory);
    device.write(reg::QUEUE_DESC_HIGH, 0, memory);
    device.write(reg::QUEUE_AVAIL_LOW, AVAIL as u32, memory);
    device.write(reg::QUEUE_AVAIL_HIGH, 0, memory);
    device.write(reg::QUEUE_USED_LOW, USED as u32, memory);
    device.write(reg::QUEUE_USED_HIGH, 0, memory);
    device.write(reg::QUEUE_READY, 1, memory);
}

fn ready_device(memory: &mut Memory) -> VirtioConsole {
    let mut device = VirtioConsole::new();
    setup(memory, &mut device, virtio_console::QUEUE_RX);
    setup(memory, &mut device, virtio_console::QUEUE_TX);
    device.write(
        reg::STATUS,
        status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK,
        memory,
    );
    device
}

#[test]
fn transport_identity_is_advertised() {
    let mut memory = Memory::new();
    let device = VirtioConsole::new();
    assert_eq!(device.read(reg::MAGIC), MAGIC);
    assert_eq!(device.read(reg::VERSION), VERSION);
    assert_eq!(device.read(reg::DEVICE_ID), DEVICE_ID);
    assert_eq!(device.read(reg::QUEUE_NUM_MAX), u32::from(QUEUE_NUM_MAX));
    let _ = &mut memory;
}

#[test]
fn feature_negotiation_uses_the_selector() {
    let mut memory = Memory::new();
    let mut device = VirtioConsole::new();
    let low = device.read(reg::DEVICE_FEATURES);
    assert_eq!(low & 1, 1); // console size
    device.write(reg::DEVICE_FEATURES_SEL, 1, &mut memory);
    let high = device.read(reg::DEVICE_FEATURES);
    assert_eq!(high & 1, 1); // version 1
    device.write(reg::DRIVER_FEATURES_SEL, 0, &mut memory);
    device.write(reg::DRIVER_FEATURES, low, &mut memory);
    assert_eq!(device.driver_features() as u32, low);
}

#[test]
fn queue_registers_are_visible() {
    let mut memory = Memory::new();
    let mut device = VirtioConsole::new();
    setup(&mut memory, &mut device, virtio_console::QUEUE_TX);
    assert_eq!(device.read(reg::QUEUE_SEL), virtio_console::QUEUE_TX);
    assert_eq!(device.read(reg::QUEUE_NUM), u32::from(QUEUE_SIZE));
    assert_eq!(device.read(reg::QUEUE_READY), 1);
    assert_eq!(device.read(reg::QUEUE_DESC_LOW), DESC as u32);
    assert_eq!(device.read(reg::QUEUE_AVAIL_LOW), AVAIL as u32);
    assert_eq!(device.read(reg::QUEUE_USED_LOW), USED as u32);
    assert!(device.tx_ready());
    assert!(!device.rx_ready());
}

#[test]
fn invalid_queue_size_marks_the_device_failed() {
    let mut memory = Memory::new();
    let mut device = VirtioConsole::new();
    device.write(reg::QUEUE_SEL, 0, &mut memory);
    device.write(reg::QUEUE_NUM, 3, &mut memory);
    assert_ne!(device.status() & status::FAILED, 0);
}

#[test]
fn transmit_publishes_the_buffer_to_the_output() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    memory.write_bytes(BUFFERS, b"hello");
    write_descriptor(
        &mut memory,
        0,
        Descriptor {
            addr: BUFFERS,
            len: 5,
            flags: 0,
            next: 0,
        },
    );
    memory.write_u16(AVAIL + 4, 0); // ring[0] = descriptor 0
    publish(&mut memory, 1);
    device.write(reg::QUEUE_NOTIFY, virtio_console::QUEUE_TX, &mut memory);
    assert_eq!(device.output(), b"hello");
    assert_eq!(used_entry(&memory, 0), (0, 5));
    assert_ne!(device.interrupt_status() & virtio_console::interrupt::USED_RING, 0);
}

#[test]
fn transmit_concatenates_a_descriptor_chain() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    memory.write_bytes(BUFFERS, b"abc");
    memory.write_bytes(BUFFERS + 3, b"defg");
    write_descriptor(
        &mut memory,
        0,
        Descriptor {
            addr: BUFFERS,
            len: 3,
            flags: DESC_F_NEXT,
            next: 1,
        },
    );
    write_descriptor(
        &mut memory,
        1,
        Descriptor {
            addr: BUFFERS + 3,
            len: 4,
            flags: 0,
            next: 0,
        },
    );
    memory.write_u16(AVAIL + 4, 0);
    publish(&mut memory, 1);
    device.write(reg::QUEUE_NOTIFY, virtio_console::QUEUE_TX, &mut memory);
    assert_eq!(device.output(), b"abcdefg");
}

#[test]
fn transmit_is_ignored_before_driver_ok() {
    let mut memory = Memory::new();
    let mut device = VirtioConsole::new();
    setup(&mut memory, &mut device, virtio_console::QUEUE_TX);
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
    device.write(reg::QUEUE_NOTIFY, virtio_console::QUEUE_TX, &mut memory);
    assert!(device.output().is_empty());
}

#[test]
fn receive_delivers_input_to_writable_buffers() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    write_descriptor(
        &mut memory,
        0,
        Descriptor {
            addr: BUFFERS,
            len: 16,
            flags: DESC_F_WRITE,
            next: 0,
        },
    );
    memory.write_u16(AVAIL + 4, 0);
    publish(&mut memory, 1);
    device.push_input(b"typed");
    device.write(reg::QUEUE_NOTIFY, virtio_console::QUEUE_RX, &mut memory);
    assert_eq!(memory.read_bytes(BUFFERS, 5), b"typed");
    assert_eq!(used_entry(&memory, 0), (0, 5));
    assert_eq!(device.pending_input(), 0);
}

#[test]
fn receive_keeps_input_that_does_not_fit() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    write_descriptor(
        &mut memory,
        0,
        Descriptor {
            addr: BUFFERS,
            len: 4,
            flags: DESC_F_WRITE,
            next: 0,
        },
    );
    memory.write_u16(AVAIL + 4, 0);
    publish(&mut memory, 1);
    device.push_input(b"0123456789");
    device.write(reg::QUEUE_NOTIFY, virtio_console::QUEUE_RX, &mut memory);
    assert_eq!(memory.read_bytes(BUFFERS, 4), b"0123");
    assert_eq!(used_entry(&memory, 0), (0, 4));
    assert_eq!(device.pending_input(), 6);
}

#[test]
fn receive_completes_a_chain_without_writable_buffer() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    write_descriptor(
        &mut memory,
        0,
        Descriptor {
            addr: BUFFERS,
            len: 8,
            flags: 0, // read-only for the device: not a receive buffer
            next: 0,
        },
    );
    memory.write_u16(AVAIL + 4, 0);
    publish(&mut memory, 1);
    device.push_input(b"x");
    device.write(reg::QUEUE_NOTIFY, virtio_console::QUEUE_RX, &mut memory);
    assert_eq!(used_entry(&memory, 0), (0, 0));
    assert_eq!(device.pending_input(), 1);
}

#[test]
fn config_space_reports_the_console_size() {
    let device = VirtioConsole::new();
    let config = device.read(reg::CONFIG);
    assert_eq!(config & 0xFFFF, u32::from(virtio_console::COLS));
    assert_eq!(config >> 16, u32::from(virtio_console::ROWS));
}

#[test]
fn interrupt_status_is_acknowledged() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    device.push_input(b"x");
    assert_ne!(device.interrupt_status() & virtio_console::interrupt::CONFIG, 0);
    device.write(
        reg::INTERRUPT_ACK,
        virtio_console::interrupt::CONFIG,
        &mut memory,
    );
    assert_eq!(device.interrupt_status() & virtio_console::interrupt::CONFIG, 0);
}

#[test]
fn reset_clears_the_device() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    assert!(device.ready());
    device.write(reg::STATUS, 0, &mut memory);
    assert_eq!(device.status(), 0);
    assert!(!device.ready());
    assert!(!device.tx_ready());
    assert!(!device.rx_ready());
}

#[test]
fn output_can_be_drained() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    memory.write_bytes(BUFFERS, b"drain me");
    write_descriptor(
        &mut memory,
        0,
        Descriptor {
            addr: BUFFERS,
            len: 8,
            flags: 0,
            next: 0,
        },
    );
    memory.write_u16(AVAIL + 4, 0);
    publish(&mut memory, 1);
    device.write(reg::QUEUE_NOTIFY, virtio_console::QUEUE_TX, &mut memory);
    assert_eq!(device.drain_output(), b"drain me");
    assert!(device.output().is_empty());
}
