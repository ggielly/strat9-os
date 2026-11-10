//! L2: guest boot information page (encoding, decoding, validation).

#[path = "../../kernel/src/s9vm/bootinfo.rs"]
mod bootinfo;

use bootinfo::{
    device_kind, flags, memory_kind, BootInfo, BootInfoError, DeviceEntry, MemoryEntry, MAGIC,
    MAX_DEVICE_ENTRIES, MAX_MEMORY_ENTRIES, SIZE, VERSION,
};

fn sample() -> BootInfo {
    let mut info = BootInfo::new();
    assert!(info.add_memory(0, 0x20_0000, memory_kind::RAM));
    assert!(info.add_memory(0xFFFF_0000, 0x1_0000, memory_kind::RESERVED));
    assert!(info.add_device(device_kind::CONSOLE, 16, 0xFEB0_0000, 0));
    assert!(info.add_device(
        device_kind::BLOCK,
        17,
        0xFEB0_1000,
        128
    ));
    info.flags = flags::COMPLETE | flags::HAS_CONSOLE | flags::HAS_BLOCK;
    info
}

fn encoded(info: &BootInfo) -> [u8; SIZE] {
    let mut page = [0u8; SIZE];
    info.encode(&mut page);
    page
}

#[test]
fn empty_page_has_magic_version_and_size() {
    let page = encoded(&BootInfo::new());
    assert_eq!(page.len(), SIZE);
    let magic = u64::from_le_bytes(page[..8].try_into().unwrap());
    assert_eq!(magic, MAGIC);
    assert_eq!(u32::from_le_bytes(page[8..12].try_into().unwrap()), VERSION);
    assert_eq!(
        u32::from_le_bytes(page[12..16].try_into().unwrap()),
        SIZE as u32
    );
    assert_eq!(u32::from_le_bytes(page[16..20].try_into().unwrap()), 0);
}

#[test]
fn round_trip_preserves_memory_and_devices() {
    let info = sample();
    let decoded = BootInfo::decode(&encoded(&info)).expect("valid page");
    assert_eq!(decoded.flags, info.flags);
    assert_eq!(decoded.memory_count, 2);
    assert_eq!(
        decoded.memory[0],
        MemoryEntry {
            base: 0,
            len: 0x20_0000,
            kind: memory_kind::RAM
        }
    );
    assert_eq!(
        decoded.memory[1],
        MemoryEntry {
            base: 0xFFFF_0000,
            len: 0x1_0000,
            kind: memory_kind::RESERVED
        }
    );
    assert_eq!(decoded.device_count, 2);
    assert_eq!(
        decoded.devices[0],
        DeviceEntry {
            kind: device_kind::CONSOLE,
            irq_line: 16,
            mmio_base: 0xFEB0_0000,
            config: 0
        }
    );
    assert_eq!(decoded.devices[1], info.devices[1]);
}

#[test]
fn decode_rejects_a_bad_magic() {
    let mut page = encoded(&BootInfo::new());
    page[0] ^= 0xFF;
    assert_eq!(BootInfo::decode(&page), Err(BootInfoError::BadMagic));
}

#[test]
fn decode_rejects_an_unknown_version() {
    let mut page = encoded(&BootInfo::new());
    page[8..12].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(BootInfo::decode(&page), Err(BootInfoError::BadVersion));
}

#[test]
fn decode_rejects_a_bad_size_field() {
    let mut page = encoded(&BootInfo::new());
    page[12..16].copy_from_slice(&64u32.to_le_bytes());
    assert_eq!(BootInfo::decode(&page), Err(BootInfoError::BadSize));
}

#[test]
fn decode_rejects_too_many_memory_entries() {
    let mut page = encoded(&BootInfo::new());
    page[0x14..0x18].copy_from_slice(&((MAX_MEMORY_ENTRIES + 1) as u32).to_le_bytes());
    assert_eq!(BootInfo::decode(&page), Err(BootInfoError::TooManyEntries));
}

#[test]
fn decode_rejects_too_many_device_entries() {
    let mut page = encoded(&BootInfo::new());
    page[0x18..0x1C].copy_from_slice(&((MAX_DEVICE_ENTRIES + 1) as u32).to_le_bytes());
    assert_eq!(BootInfo::decode(&page), Err(BootInfoError::TooManyEntries));
}

#[test]
fn decode_rejects_a_truncated_page() {
    let page = encoded(&BootInfo::new());
    assert_eq!(
        BootInfo::decode(&page[..SIZE - 1]),
        Err(BootInfoError::Truncated)
    );
}

#[test]
fn slot_arrays_are_bounded() {
    let mut info = BootInfo::new();
    for index in 0..MAX_MEMORY_ENTRIES {
        assert!(info.add_memory(index as u64 * 0x1000, 0x1000, memory_kind::RAM));
    }
    assert!(!info.add_memory(0, 0x1000, memory_kind::RAM));
    let mut info = BootInfo::new();
    for index in 0..MAX_DEVICE_ENTRIES {
        assert!(info.add_device(device_kind::CONSOLE, index as u32, 0, 0));
    }
    assert!(!info.add_device(device_kind::CONSOLE, 0, 0, 0));
}

#[test]
fn encoding_is_deterministic_and_page_bounded() {
    let info = sample();
    let first = encoded(&info);
    let second = encoded(&info);
    assert_eq!(first, second);
    let decoded = BootInfo::decode(&first).expect("valid page");
    assert!(decoded.memory_count <= MAX_MEMORY_ENTRIES as u8);
    assert!(decoded.device_count <= MAX_DEVICE_ENTRIES as u8);
}

#[test]
fn device_config_carries_capacity_and_mac() {
    let mut info = BootInfo::new();
    assert!(info.add_device(device_kind::BLOCK, 17, 0xFEB0_1000, 4096));
    assert!(info.add_device(device_kind::NETWORK, 18, 0xFEB0_2000, 0x0102_0304));
    let decoded = BootInfo::decode(&encoded(&info)).expect("valid page");
    assert_eq!(decoded.devices[0].config, 4096);
    assert_eq!(decoded.devices[1].config, 0x0102_0304);
}
