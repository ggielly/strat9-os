//! L2: virtio block device model (request queue, read/write/flush).

extern crate alloc;

#[path = "../../kernel/src/s9vm/virtio.rs"]
mod virtio;
#[path = "../../kernel/src/s9vm/virtio_blk.rs"]
mod virtio_blk;

use alloc::vec::Vec;
use virtio::{DESC_F_WRITE, DESCRIPTOR_SIZE, Descriptor, QueueMemory, VIRTQ_AVAIL_F_NO_INTERRUPT};
use virtio_blk::{
    DEVICE_ID, MAGIC, QUEUE_NUM_MAX, SECTOR_SIZE, VERSION, VirtioBlk, reg, request, request_status,
    status,
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
const HEADER: u64 = 0x4000;
const DATA: u64 = 0x5000;
const STATUS_BYTE: u64 = 0x6000;
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

fn ready_with(memory: &mut Memory, mut device: VirtioBlk) -> VirtioBlk {
    device.write(reg::QUEUE_SEL, 0, memory);
    device.write(reg::QUEUE_NUM, u32::from(QUEUE_SIZE), memory);
    device.write(reg::QUEUE_DESC_LOW, DESC as u32, memory);
    device.write(reg::QUEUE_AVAIL_LOW, AVAIL as u32, memory);
    device.write(reg::QUEUE_USED_LOW, USED as u32, memory);
    device.write(reg::QUEUE_READY, 1, memory);
    device.write(
        reg::STATUS,
        status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK,
        memory,
    );
    device
}

fn ready_device(memory: &mut Memory) -> VirtioBlk {
    ready_with(memory, VirtioBlk::new(16 * SECTOR_SIZE))
}

/// Builds a chain: header, one data descriptor, status byte.
fn build_request(
    memory: &mut Memory,
    request_type: u32,
    sector: u64,
    data_len: u32,
    data_writable: bool,
) {
    let mut header = [0u8; 16];
    header[..4].copy_from_slice(&request_type.to_le_bytes());
    header[8..].copy_from_slice(&sector.to_le_bytes());
    memory.write_bytes(HEADER, &header);

    write_descriptor(
        memory,
        0,
        Descriptor {
            addr: HEADER,
            len: 16,
            flags: virtio::DESC_F_NEXT,
            next: 1,
        },
    );
    write_descriptor(
        memory,
        1,
        Descriptor {
            addr: DATA,
            len: data_len,
            flags: virtio::DESC_F_NEXT | if data_writable { DESC_F_WRITE } else { 0 },
            next: 2,
        },
    );
    write_descriptor(
        memory,
        2,
        Descriptor {
            addr: STATUS_BYTE,
            len: 1,
            flags: DESC_F_WRITE,
            next: 0,
        },
    );
    memory.write_u16(AVAIL + 4, 0);
    publish(memory, 1);
}

#[test]
fn transport_identity_is_advertised() {
    let device = VirtioBlk::new(1024);
    assert_eq!(device.read(reg::MAGIC), MAGIC);
    assert_eq!(device.read(reg::VERSION), VERSION);
    assert_eq!(device.read(reg::DEVICE_ID), DEVICE_ID);
    assert_eq!(device.read(reg::QUEUE_NUM_MAX), u32::from(QUEUE_NUM_MAX));
}

#[test]
fn config_space_reports_the_capacity() {
    let device = VirtioBlk::new(16 * SECTOR_SIZE);
    assert_eq!(device.sectors(), 16);
    assert_eq!(device.read(reg::CONFIG), 16);
    assert_eq!(device.read(reg::CONFIG + 4), 0);
}

#[test]
fn read_request_copies_a_sector_into_guest_memory() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    device.write_sector(0, b"DISK DATA");
    build_request(&mut memory, request::IN, 0, SECTOR_SIZE as u32, true);
    device.write(reg::QUEUE_NOTIFY, 0, &mut memory);
    assert_eq!(memory.slice(DATA, 9), b"DISK DATA");
    assert_eq!(memory.slice(STATUS_BYTE, 1)[0], request_status::OK);
    assert_eq!(used_entry(&memory, 0).0, 0);
    assert_eq!(device.completed(), 1);
    assert_ne!(
        device.interrupt_status() & virtio_blk::interrupt::USED_RING,
        0
    );
}

#[test]
fn write_request_updates_the_disk() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    memory.write_bytes(DATA, b"NEW DATA");
    build_request(&mut memory, request::OUT, 0, 8, false);
    device.write(reg::QUEUE_NOTIFY, 0, &mut memory);
    assert_eq!(memory.slice(STATUS_BYTE, 1)[0], request_status::OK);
    assert_eq!(&device.disk_mut()[..8], b"NEW DATA");
}

#[test]
fn read_request_beyond_the_disk_reports_an_io_error() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    build_request(&mut memory, request::IN, 1_000_000, 16, true);
    device.write(reg::QUEUE_NOTIFY, 0, &mut memory);
    assert_eq!(memory.slice(STATUS_BYTE, 1)[0], request_status::IO_ERROR);
    assert_eq!(device.last_status(), request_status::IO_ERROR);
}

#[test]
fn unknown_request_type_reports_unsupported() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    build_request(&mut memory, 42, 0, 8, true);
    device.write(reg::QUEUE_NOTIFY, 0, &mut memory);
    assert_eq!(memory.slice(STATUS_BYTE, 1)[0], request_status::UNSUPPORTED);
}

#[test]
fn flush_request_succeeds_without_data() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    // Chain: header + status only.
    let mut header = [0u8; 16];
    header[..4].copy_from_slice(&request::FLUSH.to_le_bytes());
    memory.write_bytes(HEADER, &header);
    write_descriptor(
        &mut memory,
        0,
        Descriptor {
            addr: HEADER,
            len: 16,
            flags: virtio::DESC_F_NEXT,
            next: 1,
        },
    );
    write_descriptor(
        &mut memory,
        1,
        Descriptor {
            addr: STATUS_BYTE,
            len: 1,
            flags: DESC_F_WRITE,
            next: 0,
        },
    );
    memory.write_u16(AVAIL + 4, 0);
    publish(&mut memory, 1);
    device.write(reg::QUEUE_NOTIFY, 0, &mut memory);
    assert_eq!(memory.slice(STATUS_BYTE, 1)[0], request_status::OK);
}

#[test]
fn queue_notification_is_ignored_before_driver_ok() {
    let mut memory = Memory::new();
    let mut device = VirtioBlk::new(16 * SECTOR_SIZE);
    device.write(reg::QUEUE_SEL, 0, &mut memory);
    device.write(reg::QUEUE_NUM, u32::from(QUEUE_SIZE), &mut memory);
    device.write(reg::QUEUE_DESC_LOW, DESC as u32, &mut memory);
    device.write(reg::QUEUE_AVAIL_LOW, AVAIL as u32, &mut memory);
    device.write(reg::QUEUE_USED_LOW, USED as u32, &mut memory);
    device.write(reg::QUEUE_READY, 1, &mut memory);
    build_request(&mut memory, request::IN, 0, 16, true);
    device.write(reg::QUEUE_NOTIFY, 0, &mut memory);
    assert_eq!(device.completed(), 0);
}

#[test]
fn features_use_the_selector() {
    let mut memory = Memory::new();
    let mut device = VirtioBlk::new(1024);
    device.write(reg::DEVICE_FEATURES_SEL, 1, &mut memory);
    assert_eq!(device.read(reg::DEVICE_FEATURES) & 1, 1);
    device.write(reg::DRIVER_FEATURES_SEL, 1, &mut memory);
    device.write(reg::DRIVER_FEATURES, 1, &mut memory);
    assert_eq!(device.read(reg::DRIVER_FEATURES), 1);
}

#[test]
fn interrupt_status_is_acknowledged() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    build_request(&mut memory, request::IN, 0, 16, true);
    device.write(reg::QUEUE_NOTIFY, 0, &mut memory);
    assert_ne!(device.interrupt_status(), 0);
    device.write(reg::INTERRUPT_ACK, device.interrupt_status(), &mut memory);
    assert_eq!(device.interrupt_status(), 0);
}

#[test]
fn reset_clears_the_device() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    assert!(device.ready());
    device.write(reg::STATUS, 0, &mut memory);
    assert_eq!(device.status(), 0);
    assert!(!device.ready());
    assert!(!device.queue_ready());
}

#[test]
fn invalid_queue_size_marks_the_device_failed() {
    let mut memory = Memory::new();
    let mut device = VirtioBlk::new(1024);
    device.write(reg::QUEUE_SEL, 0, &mut memory);
    device.write(reg::QUEUE_NUM, 3, &mut memory);
    assert_ne!(device.status() & status::FAILED, 0);
}

// ---------------------------------------------------------------------------
// FLUSH/RO features, config capacity and read-only behaviour.
// ---------------------------------------------------------------------------

#[test]
fn flush_and_read_only_features_are_offered() {
    let mut memory = Memory::new();
    let mut device = VirtioBlk::new(1024);
    let low = device.read(reg::DEVICE_FEATURES);
    assert_ne!(low & virtio_blk::feature_lo::FLUSH, 0);
    assert_eq!(low & virtio_blk::feature_lo::RO, 0);
    device.write(reg::DEVICE_FEATURES_SEL, 1, &mut memory);
    assert_eq!(
        device.read(reg::DEVICE_FEATURES),
        virtio_blk::feature_hi::VERSION_1
    );

    let mut read_only = VirtioBlk::new_read_only(1024);
    assert!(read_only.read_only());
    assert_ne!(
        read_only.read(reg::DEVICE_FEATURES) & virtio_blk::feature_lo::RO,
        0
    );
}

#[test]
fn capacity_is_reported_in_512_byte_sectors() {
    let device = VirtioBlk::new(3 * SECTOR_SIZE - 1);
    assert_eq!(device.sectors(), 3);
    assert_eq!(device.read(reg::CONFIG), 3);
    assert_eq!(device.read(reg::CONFIG + 4), 0);
    let big = VirtioBlk::new(2 * 1024);
    assert_eq!(big.sectors(), 4);
    assert_eq!(big.read(reg::CONFIG), 4);
}

#[test]
fn read_only_device_rejects_out_requests_without_touching_the_disk() {
    let mut memory = Memory::new();
    let mut device = ready_with(&mut memory, VirtioBlk::new_read_only(16 * SECTOR_SIZE));
    device.write_sector(0, b"SAFE");
    memory.write_bytes(DATA, b"HACK");
    build_request(&mut memory, request::OUT, 0, 4, false);
    device.write(reg::QUEUE_NOTIFY, 0, &mut memory);
    assert_eq!(memory.slice(STATUS_BYTE, 1)[0], request_status::IO_ERROR);
    assert_eq!(device.last_status(), request_status::IO_ERROR);
    assert_eq!(&device.disk_mut()[..4], b"SAFE");
    assert_eq!(device.completed(), 1);
}

#[test]
fn read_only_device_still_serves_read_requests() {
    let mut memory = Memory::new();
    let mut device = ready_with(&mut memory, VirtioBlk::new_read_only(16 * SECTOR_SIZE));
    device.write_sector(0, b"DATA");
    build_request(&mut memory, request::IN, 0, 4, true);
    device.write(reg::QUEUE_NOTIFY, 0, &mut memory);
    assert_eq!(memory.slice(DATA, 4), b"DATA");
    assert_eq!(memory.slice(STATUS_BYTE, 1)[0], request_status::OK);
}

#[test]
fn missing_version_1_fails_feature_negotiation() {
    let mut memory = Memory::new();
    let mut device = VirtioBlk::new(1024);
    device.write(reg::DRIVER_FEATURES_SEL, 0, &mut memory);
    device.write(
        reg::DRIVER_FEATURES,
        virtio_blk::feature_lo::FLUSH,
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
fn no_interrupt_flag_suppresses_the_completion_interrupt() {
    let mut memory = Memory::new();
    let mut device = ready_device(&mut memory);
    device.write_sector(0, b"QUIET");
    build_request(&mut memory, request::IN, 0, 8, true);
    memory.write_u16(AVAIL, VIRTQ_AVAIL_F_NO_INTERRUPT);
    device.write(reg::QUEUE_NOTIFY, 0, &mut memory);
    assert_eq!(memory.slice(STATUS_BYTE, 1)[0], request_status::OK);
    assert_eq!(device.completed(), 1);
    assert_eq!(used_count(&memory), 1);
    assert_eq!(
        device.interrupt_status() & virtio_blk::interrupt::USED_RING,
        0
    );
}

// ---------------------------------------------------------------------------
// Disk replacement primitives used by `SYS_VMM_LOAD_DISK`
//
// The capacity policy (grow-only, 128 KiB floor, 16 MiB bound) lives in
// `s9vm::vm::load_disk`, which is not host-includable because it depends on
// the world registry. These tests exercise the device-level primitives that
// function uses: zero-filling the disk, copying a shorter image over it, and
// rebuilding a zeroed device when the image grows it.
// ---------------------------------------------------------------------------

/// Mirror of the in-place branch of `vm::load_disk`: capacity unchanged,
/// zero-fill then copy the image.
fn replace_in_place(device: &mut VirtioBlk, image: &[u8]) {
    let disk = device.disk_mut();
    assert!(image.len() <= disk.len());
    disk.fill(0);
    disk[..image.len()].copy_from_slice(image);
}

/// Mirror of the growth branch of `vm::load_disk`: rebuild the device zeroed
/// at `capacity`, preserving the access mode, then copy the image.
fn replace_with_growth(device: &mut VirtioBlk, image: &[u8], capacity: usize) {
    assert!(image.len() <= capacity);
    let read_only = device.read_only();
    let mut fresh = if read_only {
        VirtioBlk::new_read_only(capacity)
    } else {
        VirtioBlk::new(capacity)
    };
    fresh.disk_mut()[..image.len()].copy_from_slice(image);
    *device = fresh;
}

#[test]
fn load_disk_shorter_image_zero_fills_the_tail() {
    let mut device = VirtioBlk::new(128 * 1024);
    // Old content must not survive a replacement.
    device.disk_mut().fill(0xAA);
    let image = [0x5Au8; 4 * SECTOR_SIZE];
    replace_in_place(&mut device, &image);
    assert_eq!(&device.disk_mut()[..image.len()], &image[..]);
    assert!(
        device.disk_mut()[image.len()..]
            .iter()
            .all(|byte| *byte == 0),
        "bytes after the image must be zero-filled"
    );
    assert_eq!(device.sectors(), 256);
}

#[test]
fn load_disk_growth_rebuilds_a_zeroed_device() {
    let mut device = VirtioBlk::new(64 * 1024);
    device.disk_mut().fill(0xAA);
    let image = [0x3Cu8; 8 * SECTOR_SIZE];
    replace_with_growth(&mut device, &image, 128 * 1024);
    assert_eq!(device.sectors(), 256);
    assert_eq!(&device.disk_mut()[..image.len()], &image[..]);
    assert!(
        device.disk_mut()[image.len()..]
            .iter()
            .all(|byte| *byte == 0),
        "the rebuilt device must be zeroed after the image"
    );
    // Device identity is preserved: it is still a virtio block device.
    let mut memory = Memory::new();
    let _ = ready_with(&mut memory, device);
}

#[test]
fn load_disk_growth_preserves_read_only_mode() {
    let mut device = VirtioBlk::new_read_only(64 * 1024);
    assert!(device.read_only());
    let image = [0x11u8; SECTOR_SIZE];
    replace_with_growth(&mut device, &image, 128 * 1024);
    assert!(device.read_only(), "the access mode must be preserved");
    assert_eq!(&device.disk_mut()[..image.len()], &image[..]);
}

#[test]
fn load_disk_image_writes_remain_visible_through_sectors() {
    // The raw `/dev/vmm/<id>/disk` view addresses the same bytes the guest
    // reads: a replacement is visible sector by sector. One read request of
    // two sectors covers both markers.
    let mut device = VirtioBlk::new(128 * 1024);
    let mut image = [0u8; 2 * SECTOR_SIZE];
    image[0] = 0xDE;
    image[SECTOR_SIZE] = 0xAD;
    replace_in_place(&mut device, &image);
    let mut memory = Memory::new();
    let mut device = ready_with(&mut memory, device);
    build_request(&mut memory, request::IN, 0, (2 * SECTOR_SIZE) as u32, true);
    device.write(reg::QUEUE_NOTIFY, 0, &mut memory);
    assert_eq!(memory.slice(STATUS_BYTE, 1)[0], request_status::OK);
    assert_eq!(memory.slice(DATA, 2 * SECTOR_SIZE), &image[..]);
}
