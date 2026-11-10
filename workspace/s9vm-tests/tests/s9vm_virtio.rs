//! L2: virtio split-queue core (descriptor chains, available/used rings).

extern crate alloc;

#[path = "../../kernel/src/s9vm/virtio.rs"]
mod virtio;

use alloc::vec::Vec;
use virtio::{
    Descriptor, QueueError, QueueMemory, SplitQueue, DESC_F_INDIRECT, DESC_F_NEXT, DESC_F_WRITE,
    DESCRIPTOR_SIZE, MAX_QUEUE_SIZE,
};

/// Identity-mapped guest memory backed by a byte vector.
struct Memory {
    bytes: Vec<u8>,
}

impl Memory {
    fn new(size: usize) -> Self {
        Self {
            bytes: alloc::vec![0u8; size],
        }
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

// Layout of the synthetic queue in guest memory.
const DESC_TABLE: u64 = 0x1000;
const AVAIL_RING: u64 = 0x2000;
const USED_RING: u64 = 0x3000;
const BUFFERS: u64 = 0x4000;
const QUEUE_SIZE: u16 = 8;
const MEMORY_SIZE: usize = 0x8000;

fn queue() -> SplitQueue {
    SplitQueue::new(QUEUE_SIZE, DESC_TABLE, AVAIL_RING, USED_RING).expect("valid queue")
}

fn memory() -> Memory {
    Memory::new(MEMORY_SIZE)
}

fn write_descriptor(memory: &mut Memory, index: u16, descriptor: Descriptor) {
    let gpa = DESC_TABLE + u64::from(index) * DESCRIPTOR_SIZE;
    memory.write_gpa(gpa, &descriptor.encode());
}

fn publish_available(memory: &mut Memory, index: u16) {
    // Producer index is the count of published buffers.
    memory.write_u16(AVAIL_RING + 2, index);
}

#[test]
fn queue_rejects_invalid_sizes() {
    assert_eq!(
        SplitQueue::new(0, DESC_TABLE, AVAIL_RING, USED_RING),
        Err(QueueError::BadSize)
    );
    assert_eq!(
        SplitQueue::new(3, DESC_TABLE, AVAIL_RING, USED_RING),
        Err(QueueError::BadSize)
    );
    assert_eq!(
        SplitQueue::new(MAX_QUEUE_SIZE - 1, DESC_TABLE, AVAIL_RING, USED_RING),
        Err(QueueError::BadSize)
    );
}

#[test]
fn queue_rejects_misaligned_tables() {
    assert_eq!(
        SplitQueue::new(QUEUE_SIZE, DESC_TABLE + 1, AVAIL_RING, USED_RING),
        Err(QueueError::BadAddress)
    );
    assert_eq!(
        SplitQueue::new(QUEUE_SIZE, DESC_TABLE, AVAIL_RING + 1, USED_RING),
        Err(QueueError::BadAddress)
    );
    assert_eq!(
        SplitQueue::new(QUEUE_SIZE, DESC_TABLE, AVAIL_RING, USED_RING + 2),
        Err(QueueError::BadAddress)
    );
}

#[test]
fn queue_accepts_a_maximum_size_queue() {
    assert!(SplitQueue::new(MAX_QUEUE_SIZE, DESC_TABLE, AVAIL_RING, USED_RING).is_ok());
}

#[test]
fn descriptor_encoding_round_trips() {
    let descriptor = Descriptor {
        addr: 0x1234_5678_9ABC,
        len: 0x0FFF_0000,
        flags: DESC_F_NEXT | DESC_F_WRITE,
        next: 0x1234,
    };
    assert_eq!(Descriptor::decode(&descriptor.encode()), descriptor);
}

#[test]
fn descriptor_flags_are_decoded() {
    let descriptor = Descriptor {
        addr: 0,
        len: 0,
        flags: DESC_F_WRITE | DESC_F_INDIRECT,
        next: 0,
    };
    assert!(descriptor.writable());
    assert!(descriptor.indirect());
    assert!(!descriptor.has_next());
}

#[test]
fn pop_available_returns_none_on_an_empty_ring() {
    let mut memory = memory();
    let mut queue = queue();
    assert_eq!(queue.pop_available(&mut memory), Ok(None));
}

#[test]
fn pop_available_returns_published_heads() {
    let mut memory = memory();
    let mut queue = queue();
    memory.write_u16(AVAIL_RING + 4, 5); // ring[0] = descriptor 5
    publish_available(&mut memory, 1);
    assert_eq!(queue.pop_available(&mut memory), Ok(Some(5)));
    assert_eq!(queue.pop_available(&mut memory), Ok(None));
}

#[test]
fn pop_available_rejects_an_out_of_range_head() {
    let mut memory = memory();
    let mut queue = queue();
    memory.write_u16(AVAIL_RING + 4, QUEUE_SIZE);
    publish_available(&mut memory, 1);
    assert_eq!(queue.pop_available(&mut memory), Err(QueueError::BadDescriptor));
}

#[test]
fn available_ring_wraps_around() {
    let mut memory = memory();
    let mut queue = queue();
    // Publish more buffers than the queue size: the slot index must wrap.
    for round in 0..(QUEUE_SIZE * 2 + 1) {
        let slot = u64::from(round % QUEUE_SIZE);
        memory.write_u16(AVAIL_RING + 4 + slot * 2, round % QUEUE_SIZE);
        publish_available(&mut memory, round.wrapping_add(1));
        assert_eq!(
            queue.pop_available(&mut memory),
            Ok(Some(round % QUEUE_SIZE)),
            "round {round}"
        );
    }
}

#[test]
fn chain_walks_next_descriptors() {
    let mut memory = memory();
    let queue = queue();
    write_descriptor(
        &mut memory,
        0,
        Descriptor {
            addr: BUFFERS,
            len: 16,
            flags: DESC_F_NEXT,
            next: 1,
        },
    );
    write_descriptor(
        &mut memory,
        1,
        Descriptor {
            addr: BUFFERS + 16,
            len: 32,
            flags: DESC_F_WRITE,
            next: 0,
        },
    );
    let chain = queue.chain(&mut memory, 0).expect("valid chain");
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].len, 16);
    assert_eq!(chain[1].len, 32);
    assert!(chain[1].writable());
}

#[test]
fn chain_rejects_an_out_of_range_head() {
    let mut memory = memory();
    let queue = queue();
    assert_eq!(
        queue.chain(&mut memory, QUEUE_SIZE),
        Err(QueueError::BadDescriptor)
    );
}

#[test]
fn chain_rejects_a_loop() {
    let mut memory = memory();
    let queue = queue();
    write_descriptor(
        &mut memory,
        0,
        Descriptor {
            addr: BUFFERS,
            len: 8,
            flags: DESC_F_NEXT,
            next: 1,
        },
    );
    write_descriptor(
        &mut memory,
        1,
        Descriptor {
            addr: BUFFERS,
            len: 8,
            flags: DESC_F_NEXT,
            next: 0,
        },
    );
    assert_eq!(queue.chain(&mut memory, 0), Err(QueueError::BadChain));
}

#[test]
fn chain_expands_an_indirect_table() {
    let mut memory = memory();
    let queue = queue();
    write_descriptor(
        &mut memory,
        0,
        Descriptor {
            addr: BUFFERS,
            len: DESCRIPTOR_SIZE as u32 * 2,
            flags: DESC_F_INDIRECT,
            next: 0,
        },
    );
    // Indirect table at BUFFERS: two entries, first continues to the second.
    memory.write_gpa(
        BUFFERS,
        &Descriptor {
            addr: BUFFERS + 64,
            len: 4,
            flags: DESC_F_NEXT,
            next: 1,
        }
        .encode(),
    );
    memory.write_gpa(
        BUFFERS + DESCRIPTOR_SIZE,
        &Descriptor {
            addr: BUFFERS + 68,
            len: 8,
            flags: DESC_F_WRITE,
            next: 0,
        }
        .encode(),
    );
    let chain = queue.chain(&mut memory, 0).expect("valid chain");
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].len, 4);
    assert_eq!(chain[1].len, 8);
}

#[test]
fn chain_rejects_an_indirect_table_of_wrong_length() {
    let mut memory = memory();
    let queue = queue();
    write_descriptor(
        &mut memory,
        0,
        Descriptor {
            addr: BUFFERS,
            len: 7, // not a multiple of the descriptor size
            flags: DESC_F_INDIRECT,
            next: 0,
        },
    );
    assert_eq!(queue.chain(&mut memory, 0), Err(QueueError::BadChain));
}

#[test]
fn chain_rejects_nested_indirect_tables() {
    let mut memory = memory();
    let queue = queue();
    write_descriptor(
        &mut memory,
        0,
        Descriptor {
            addr: BUFFERS,
            len: DESCRIPTOR_SIZE as u32,
            flags: DESC_F_INDIRECT,
            next: 0,
        },
    );
    memory.write_gpa(
        BUFFERS,
        &Descriptor {
            addr: BUFFERS + 128,
            len: DESCRIPTOR_SIZE as u32,
            flags: DESC_F_INDIRECT,
            next: 0,
        }
        .encode(),
    );
    assert_eq!(queue.chain(&mut memory, 0), Err(QueueError::BadChain));
}

#[test]
fn chain_reports_missing_memory() {
    let mut memory = memory();
    // Descriptor table index within the table but beyond the memory vector.
    let far = SplitQueue::new(
        QUEUE_SIZE,
        MEMORY_SIZE as u64, // aligned, but outside the vector
        AVAIL_RING,
        USED_RING,
    )
    .expect("valid layout");
    assert_eq!(far.chain(&mut memory, 0), Err(QueueError::Memory));
}

#[test]
fn push_used_publishes_the_completion() {
    let mut memory = memory();
    let mut queue = queue();
    queue.push_used(&mut memory, 3, 42).expect("published");
    assert_eq!(memory.read_u32(USED_RING + 4), Some(3));
    assert_eq!(memory.read_u32(USED_RING + 8), Some(42));
    assert_eq!(memory.read_u16(USED_RING + 2), Some(1));
}

#[test]
fn used_ring_wraps_around() {
    let mut memory = memory();
    let mut queue = queue();
    for round in 0..(u32::from(QUEUE_SIZE) + 2) {
        queue.push_used(&mut memory, (round % 8) as u16, round).expect("published");
    }
    let last = u32::from(QUEUE_SIZE) + 1;
    let slot = u64::from(last % u32::from(QUEUE_SIZE));
    assert_eq!(memory.read_u32(USED_RING + 4 + slot * 8), Some(last % 8));
    assert_eq!(memory.read_u32(USED_RING + 4 + slot * 8 + 4), Some(last));
}

#[test]
fn push_used_rejects_an_out_of_range_head() {
    let mut memory = memory();
    let mut queue = queue();
    assert_eq!(
        queue.push_used(&mut memory, QUEUE_SIZE, 0),
        Err(QueueError::BadDescriptor)
    );
}

#[test]
fn descriptor_addresses_follow_the_table_stride() {
    let queue = queue();
    assert_eq!(queue.descriptor_gpa(0), Some(DESC_TABLE));
    assert_eq!(
        queue.descriptor_gpa(3),
        Some(DESC_TABLE + 3 * DESCRIPTOR_SIZE)
    );
    assert_eq!(queue.descriptor_gpa(QUEUE_SIZE), None);
}
