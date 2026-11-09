//! L2: s9vm guest memory map (real kernel code).

extern crate alloc;

#[path = "../../kernel/src/s9vm/memmap.rs"]
mod memmap;

use memmap::{perms_from_abi, GuestMap, MapError, MAX_REGIONS};

const PAGE: u64 = 4096;

fn map(quota_pages: u64) -> GuestMap {
    GuestMap::new(quota_pages)
}

#[test]
fn reserves_aligned_region() {
    let mut guest = map(64);
    let region = guest.reserve(0x10_0000, 3 * PAGE, 3, 0).expect("reserve");
    assert_eq!(region.gpa, 0x10_0000);
    assert_eq!(region.end(), 0x10_3000);
    assert_eq!(guest.pages(), 3);
    assert_eq!(guest.region_count(), 1);
}

#[test]
fn rejects_misaligned_or_empty_ranges() {
    let mut guest = map(64);
    assert_eq!(
        guest.reserve(0x1001, PAGE, 3, 0),
        Err(MapError::InvalidRange)
    );
    assert_eq!(
        guest.reserve(0x1000, PAGE + 1, 3, 0),
        Err(MapError::InvalidRange)
    );
    assert_eq!(guest.reserve(0x1000, 0, 3, 0), Err(MapError::InvalidRange));
}

#[test]
fn rejects_ranges_beyond_guest_physical_space() {
    let mut guest = map(1024);
    assert_eq!(
        guest.reserve((1u64 << 48) - PAGE, 2 * PAGE, 3, 0),
        Err(MapError::InvalidRange)
    );
}

#[test]
fn detects_overlap_before_inside_and_after() {
    let mut guest = map(64);
    guest.reserve(0x10_0000, 3 * PAGE, 3, 0).expect("first");
    // Overlap from the left.
    assert_eq!(
        guest.reserve(0x0FF000, 2 * PAGE, 3, 0),
        Err(MapError::Overlap)
    );
    // Exactly the same range.
    assert_eq!(
        guest.reserve(0x10_0000, 3 * PAGE, 3, 0),
        Err(MapError::Overlap)
    );
    // Inside.
    assert_eq!(
        guest.reserve(0x10_1000, PAGE, 3, 0),
        Err(MapError::Overlap)
    );
    // Overlap from the right.
    assert_eq!(
        guest.reserve(0x10_2000, 2 * PAGE, 3, 0),
        Err(MapError::Overlap)
    );
    // Adjacent: accepted.
    guest.reserve(0x10_3000, PAGE, 3, 0).expect("adjacent");
    assert_eq!(guest.pages(), 4);
}

#[test]
fn enforces_quota() {
    let mut guest = map(2);
    guest.reserve(0x0, 2 * PAGE, 3, 0).expect("within quota");
    assert_eq!(
        guest.reserve(0x2000, PAGE, 3, 0),
        Err(MapError::QuotaExceeded)
    );
    assert_eq!(guest.pages(), 2);
}

#[test]
fn removes_region_and_updates_pages() {
    let mut guest = map(16);
    guest.reserve(0x1000, 2 * PAGE, 3, 0).expect("reserve");
    assert!(guest.remove(0x1000).is_some());
    assert_eq!(guest.pages(), 0);
    assert_eq!(guest.region_count(), 0);
    assert!(guest.remove(0x1000).is_none());
    // The freed slot is reusable.
    guest.reserve(0x1000, 2 * PAGE, 3, 0).expect("re-reserve");
}

#[test]
fn finds_region_containing_address() {
    let mut guest = map(16);
    guest.reserve(0x2000, PAGE, 1, 0).expect("reserve");
    assert_eq!(guest.region_containing(0x2000).map(|r| r.gpa), Some(0x2000));
    assert_eq!(guest.region_containing(0x2FFF).map(|r| r.gpa), Some(0x2000));
    assert!(guest.region_containing(0x3000).is_none());
    assert!(guest.region_containing(0x1000).is_none());
}

#[test]
fn limits_region_count() {
    let mut guest = map(MAX_REGIONS as u64 * 2);
    for index in 0..MAX_REGIONS {
        guest
            .reserve(index as u64 * PAGE, PAGE, 3, 0)
            .expect("region within limit");
    }
    let extra = MAX_REGIONS as u64 * PAGE;
    assert_eq!(
        guest.reserve(extra, PAGE, 3, 0),
        Err(MapError::TooManyRegions)
    );
}

#[test]
fn clears_map() {
    let mut guest = map(16);
    guest.reserve(0x0, PAGE, 3, 0).expect("reserve");
    guest.clear();
    assert_eq!(guest.pages(), 0);
    assert_eq!(guest.region_count(), 0);
}

#[test]
fn converts_abi_permissions() {
    let read_write_execute = perms_from_abi(0b111);
    assert!(read_write_execute.read);
    assert!(read_write_execute.write);
    assert!(read_write_execute.execute);

    let read_only = perms_from_abi(0b001);
    assert!(read_only.read);
    assert!(!read_only.write);
    assert!(!read_only.execute);

    // 0 = implicit read (compatibility).
    let default = perms_from_abi(0);
    assert!(default.read);
    assert!(!default.write);
}
