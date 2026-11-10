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

//! L2: s9vm IOMMU model (device address translation, real kernel code).
//!
//! The model re-uses [`mmu::Perms`] for the leaf permissions, so both test
//! modules are compiled together, exactly like the kernel compiles them.

extern crate alloc;

#[path = "../../kernel/src/s9vm/iommu.rs"]
mod iommu;
#[path = "../../kernel/src/s9vm/mmu.rs"]
mod mmu;

use iommu::{
    DeviceId, DomainId, IommuEntry, IommuError, IommuModel, LARGE_PAGE_SIZE, LeafSize, MAX_ADDRESS,
    MAX_DOMAINS, MAX_ENTRIES_PER_DOMAIN, PAGE_SIZE,
};
use mmu::Perms;

const PAGE: u64 = PAGE_SIZE;
const TWO_M: u64 = LARGE_PAGE_SIZE;

fn model() -> IommuModel {
    IommuModel::new()
}

fn perms() -> Perms {
    Perms::read_write()
}

fn domain_of(model: &mut IommuModel) -> DomainId {
    model.create_domain().expect("create domain")
}

#[test]
fn creates_and_destroys_domains() {
    let mut iommu = model();
    assert_eq!(iommu.domain_count(), 0);
    let a = domain_of(&mut iommu);
    let b = domain_of(&mut iommu);
    assert_ne!(a, b);
    assert_eq!(iommu.domain_count(), 2);
    assert!(iommu.domain_exists(a));
    assert!(iommu.destroy_domain(a));
    assert!(!iommu.domain_exists(a));
    assert!(iommu.domain_exists(b));
    assert!(!iommu.destroy_domain(a));
    assert_eq!(iommu.domain_count(), 1);
}

#[test]
fn maps_identity_page_and_translates_offsets() {
    let mut iommu = model();
    let d = domain_of(&mut iommu);
    assert_eq!(iommu.map(d, 0x10_0000, 0x10_0000, PAGE, perms()), Ok(1));
    assert_eq!(iommu.translate(d, 0x10_0000), Some(0x10_0000));
    assert_eq!(iommu.translate(d, 0x10_0FFF), Some(0x10_0FFF));
    assert_eq!(iommu.mapped_pages(d), Some(1));
    assert_eq!(iommu.mapped_entries(d), Some(1));
    let stats = iommu.stats();
    assert_eq!(stats.mapped_pages, 1);
    assert_eq!(stats.translations, 2);
}

#[test]
fn maps_a_multi_page_range() {
    let mut iommu = model();
    let d = domain_of(&mut iommu);
    assert_eq!(iommu.map(d, 0x1000, 0x8000, 4 * PAGE, perms()), Ok(4));
    for page in 0..4 {
        assert_eq!(
            iommu.translate(d, 0x1000 + page * PAGE),
            Some(0x8000 + page * PAGE)
        );
    }
    assert_eq!(iommu.mapped_entries(d), Some(4));
    assert_eq!(iommu.mapped_pages(d), Some(4));
}

#[test]
fn rejects_remap_of_the_same_address() {
    let mut iommu = model();
    let d = domain_of(&mut iommu);
    iommu.map(d, 0x1000, 0x8000, PAGE, perms()).unwrap();
    assert_eq!(
        iommu.map(d, 0x1000, 0x9000, PAGE, perms()),
        Err(IommuError::Overlap)
    );
    // The first mapping is untouched.
    assert_eq!(iommu.translate(d, 0x1000), Some(0x8000));
    assert_eq!(iommu.mapped_pages(d), Some(1));
}

#[test]
fn rejects_partial_overlap() {
    let mut iommu = model();
    let d = domain_of(&mut iommu);
    iommu.map(d, 0x2000, 0x8000, 2 * PAGE, perms()).unwrap();
    // Head overlap.
    assert_eq!(
        iommu.map(d, 0x1000, 0x9000, 2 * PAGE, perms()),
        Err(IommuError::Overlap)
    );
    // Tail overlap.
    assert_eq!(
        iommu.map(d, 0x3000, 0x9000, 2 * PAGE, perms()),
        Err(IommuError::Overlap)
    );
    assert_eq!(iommu.mapped_entries(d), Some(2));
}

#[test]
fn adjacent_mappings_are_allowed() {
    let mut iommu = model();
    let d = domain_of(&mut iommu);
    iommu.map(d, 0x1000, 0x8000, PAGE, perms()).unwrap();
    assert_eq!(iommu.map(d, 0x2000, 0x9000, PAGE, perms()), Ok(1));
    assert_eq!(iommu.mapped_entries(d), Some(2));
}

#[test]
fn unmaps_a_range_and_refuses_double_unmap() {
    let mut iommu = model();
    let d = domain_of(&mut iommu);
    iommu.map(d, 0x1000, 0x8000, 2 * PAGE, perms()).unwrap();
    assert_eq!(iommu.unmap(d, 0x1000, 2 * PAGE), Ok(2));
    assert_eq!(iommu.translate(d, 0x1000), None);
    assert_eq!(iommu.translate(d, 0x2000), None);
    assert_eq!(iommu.mapped_entries(d), Some(0));
    assert_eq!(iommu.unmap(d, 0x1000, PAGE), Err(IommuError::NotMapped));
    assert_eq!(iommu.stats().unmapped_pages, 2);
}

#[test]
fn unmap_is_all_or_nothing() {
    let mut iommu = model();
    let d = domain_of(&mut iommu);
    iommu.map(d, 0x1000, 0x8000, PAGE, perms()).unwrap();
    // The range includes an unmapped page: nothing is removed.
    assert_eq!(iommu.unmap(d, 0x1000, 2 * PAGE), Err(IommuError::NotMapped));
    assert_eq!(iommu.translate(d, 0x1000), Some(0x8000));
    assert_eq!(iommu.mapped_entries(d), Some(1));
}

#[test]
fn translates_holes_to_none() {
    let mut iommu = model();
    let d = domain_of(&mut iommu);
    iommu.map(d, 0x1000, 0x8000, PAGE, perms()).unwrap();
    iommu.map(d, 0x3000, 0xA000, PAGE, perms()).unwrap();
    assert_eq!(iommu.translate(d, 0x2000), None);
    assert_eq!(iommu.translate(d, 0x4000), None);
    assert_eq!(iommu.translate(d, 0x0), None);
    assert_eq!(iommu.stats().faults, 3);
}

#[test]
fn maps_two_mib_leaves_and_translates_inside() {
    let mut iommu = model();
    let d = domain_of(&mut iommu);
    assert_eq!(
        iommu.map_2m(d, 0x200_0000, 0x4000_0000, TWO_M, perms()),
        Ok(512)
    );
    assert_eq!(iommu.mapped_entries(d), Some(1));
    assert_eq!(iommu.mapped_pages(d), Some(512));
    assert_eq!(iommu.translate(d, 0x200_0000), Some(0x4000_0000));
    assert_eq!(
        iommu.translate(d, 0x200_0000 + TWO_M - 1),
        Some(0x4000_0000 + TWO_M - 1)
    );
    let entry = iommu.translate_entry(d, 0x200_1234).expect("translation");
    assert_eq!(entry.size, LeafSize::Page2M);
    assert_eq!(entry.hpa, 0x4000_0000 + 0x1234);
}

#[test]
fn rejects_misaligned_two_mib_mappings() {
    let mut iommu = model();
    let d = domain_of(&mut iommu);
    assert_eq!(
        iommu.map_2m(d, 0x200_1000, 0x4000_0000, TWO_M, perms()),
        Err(IommuError::InvalidRange)
    );
    assert_eq!(
        iommu.map_2m(d, 0x200_0000, 0x4000_1000, TWO_M, perms()),
        Err(IommuError::InvalidRange)
    );
    assert_eq!(
        iommu.map_2m(d, 0x200_0000, 0x4000_0000, 3 * PAGE, perms()),
        Err(IommuError::InvalidRange)
    );
    assert_eq!(iommu.mapped_entries(d), Some(0));
}

#[test]
fn rejects_two_mib_overlapping_a_small_leaf() {
    let mut iommu = model();
    let d = domain_of(&mut iommu);
    iommu.map(d, 0x200_1000, 0x8000, PAGE, perms()).unwrap();
    assert_eq!(
        iommu.map_2m(d, 0x200_0000, 0x4000_0000, TWO_M, perms()),
        Err(IommuError::Overlap)
    );
    // The small leaf is untouched.
    assert_eq!(iommu.translate(d, 0x200_1000), Some(0x8000));
    assert_eq!(iommu.mapped_entries(d), Some(1));
}

#[test]
fn rejects_small_leaf_overlapping_a_two_mib_leaf() {
    let mut iommu = model();
    let d = domain_of(&mut iommu);
    iommu
        .map_2m(d, 0x200_0000, 0x4000_0000, TWO_M, perms())
        .unwrap();
    assert_eq!(
        iommu.map(d, 0x200_1000, 0x8000, PAGE, perms()),
        Err(IommuError::Overlap)
    );
}

#[test]
fn unmaps_two_mib_leaves_and_refuses_partial_small_unmap() {
    let mut iommu = model();
    let d = domain_of(&mut iommu);
    iommu
        .map_2m(d, 0x200_0000, 0x4000_0000, 2 * TWO_M, perms())
        .unwrap();
    assert_eq!(iommu.mapped_entries(d), Some(2));
    // A 4 KiB unmap cannot split a large leaf.
    assert_eq!(iommu.unmap(d, 0x200_0000, PAGE), Err(IommuError::NotMapped));
    assert_eq!(iommu.unmap_2m(d, 0x200_0000, TWO_M), Ok(512));
    assert_eq!(iommu.mapped_entries(d), Some(1));
    assert_eq!(iommu.translate(d, 0x200_0000), None);
    assert_eq!(iommu.translate(d, 0x220_0000), Some(0x4000_0000 + TWO_M));
}

#[test]
fn domains_are_isolated_for_the_same_device_address() {
    let mut iommu = model();
    let a = domain_of(&mut iommu);
    let b = domain_of(&mut iommu);
    iommu.map(a, 0x1000, 0x8000, PAGE, perms()).unwrap();
    iommu.map(b, 0x1000, 0xC000, PAGE, perms()).unwrap();
    assert_eq!(iommu.translate(a, 0x1000), Some(0x8000));
    assert_eq!(iommu.translate(b, 0x1000), Some(0xC000));
    // Unmapping one domain leaves the other untouched.
    iommu.unmap(a, 0x1000, PAGE).unwrap();
    assert_eq!(iommu.translate(a, 0x1000), None);
    assert_eq!(iommu.translate(b, 0x1000), Some(0xC000));
    // Destroying one domain never touches the other.
    iommu.destroy_domain(a);
    assert_eq!(iommu.translate(b, 0x1000), Some(0xC000));
}

#[test]
fn device_bindings_select_the_domain() {
    let mut iommu = model();
    let a = domain_of(&mut iommu);
    let b = domain_of(&mut iommu);
    iommu.map(a, 0x1000, 0x8000, PAGE, perms()).unwrap();
    iommu.map(b, 0x1000, 0xC000, PAGE, perms()).unwrap();
    let dev_a = DeviceId::from_u32(0x0000_0200);
    let dev_b = DeviceId::from_u32(0x0000_0300);
    iommu.bind_device(a, dev_a).unwrap();
    iommu.bind_device(b, dev_b).unwrap();
    assert_eq!(iommu.device_count(), 2);
    assert_eq!(iommu.domain_for_device(dev_a), Some(a));
    assert_eq!(iommu.translate_device(dev_a, 0x1000), Some(0x8000));
    assert_eq!(iommu.translate_device(dev_b, 0x1000), Some(0xC000));
    // An unbound device sees nothing.
    let unbound = DeviceId::from_u32(0x0000_0400);
    assert_eq!(iommu.translate_device(unbound, 0x1000), None);
    assert!(iommu.stats().faults >= 1);
    assert!(iommu.unbind_device(dev_a));
    assert!(!iommu.unbind_device(dev_a));
    assert_eq!(iommu.translate_device(dev_a, 0x1000), None);
}

#[test]
fn device_binding_bounds_and_lifecycle() {
    let mut iommu = model();
    let a = domain_of(&mut iommu);
    let unknown = DomainId::from_u32(0xFFFF);
    assert_eq!(
        iommu.bind_device(unknown, DeviceId::from_u32(1)),
        Err(IommuError::UnknownDomain)
    );
    iommu.bind_device(a, DeviceId::from_u32(1)).unwrap();
    assert_eq!(
        iommu.bind_device(a, DeviceId::from_u32(1)),
        Err(IommuError::AlreadyBound)
    );
    // Destroying the domain unbinds its devices.
    iommu.destroy_domain(a);
    assert_eq!(iommu.domain_for_device(DeviceId::from_u32(1)), None);
    assert_eq!(iommu.device_count(), 0);
}

#[test]
fn quota_is_enforced_per_domain() {
    let mut iommu = model();
    let d = domain_of(&mut iommu);
    let pages = MAX_ENTRIES_PER_DOMAIN as u64;
    assert_eq!(
        iommu.map(d, 0x100_0000, 0x100_0000, pages * PAGE, perms()),
        Ok(pages)
    );
    assert_eq!(iommu.mapped_entries(d), Some(MAX_ENTRIES_PER_DOMAIN));
    assert_eq!(
        iommu.map(d, 0x200_0000, 0x200_0000, PAGE, perms()),
        Err(IommuError::QuotaExceeded)
    );
    // The failed mapping left nothing behind.
    assert_eq!(iommu.mapped_entries(d), Some(MAX_ENTRIES_PER_DOMAIN));
    // Another domain has its own quota.
    let other = domain_of(&mut iommu);
    assert_eq!(iommu.map(other, 0x1000, 0x8000, PAGE, perms()), Ok(1));
}

#[test]
fn too_many_domains_is_refused() {
    let mut iommu = model();
    for _ in 0..MAX_DOMAINS {
        iommu.create_domain().expect("domain within the bound");
    }
    assert_eq!(iommu.domain_count(), MAX_DOMAINS);
    assert_eq!(iommu.create_domain(), Err(IommuError::TooManyDomains));
}

#[test]
fn adversarial_ranges_are_rejected_without_panic() {
    let mut iommu = model();
    let d = domain_of(&mut iommu);
    let cases = [
        (0u64, 0u64, 0u64),
        (0x1001, 0x8000, PAGE),
        (0x1000, 0x8001, PAGE),
        (0x1000, 0x8000, PAGE + 1),
        (MAX_ADDRESS - PAGE + 1, 0x8000, 2 * PAGE),
        (0x1000, MAX_ADDRESS - PAGE + 1, 2 * PAGE),
        (u64::MAX & !(PAGE - 1), 0, PAGE),
    ];
    for (gpa, hpa, len) in cases {
        assert_eq!(
            iommu.map(d, gpa, hpa, len, perms()),
            Err(IommuError::InvalidRange),
            "gpa={gpa:#x} hpa={hpa:#x} len={len:#x}"
        );
    }
    // Unknown domains never panic and report a typed error.
    let unknown = DomainId::from_u32(0xFFFF);
    assert_eq!(
        iommu.map(unknown, 0x1000, 0x8000, PAGE, perms()),
        Err(IommuError::UnknownDomain)
    );
    assert_eq!(iommu.translate(unknown, 0x1000), None);
    assert_eq!(
        iommu.unmap(unknown, 0x1000, PAGE),
        Err(IommuError::UnknownDomain)
    );
    assert_eq!(iommu.mapped_entries(unknown), None);
    assert_eq!(iommu.mapped_pages(unknown), None);
    assert!(iommu.entries(unknown).is_none());
}

#[test]
fn clear_keeps_domains_but_drops_mappings() {
    let mut iommu = model();
    let a = domain_of(&mut iommu);
    let b = domain_of(&mut iommu);
    iommu.map(a, 0x1000, 0x8000, PAGE, perms()).unwrap();
    iommu
        .map_2m(b, 0x200_0000, 0x4000_0000, TWO_M, perms())
        .unwrap();
    iommu.bind_device(a, DeviceId::from_u32(7)).unwrap();
    iommu.clear();
    assert_eq!(iommu.domain_count(), 2);
    assert_eq!(iommu.mapped_entries(a), Some(0));
    assert_eq!(iommu.mapped_pages(b), Some(0));
    assert_eq!(iommu.translate(a, 0x1000), None);
    // Device bindings survive `clear`.
    assert_eq!(iommu.domain_for_device(DeviceId::from_u32(7)), Some(a));
    // `destroy` resets everything.
    iommu.destroy();
    assert_eq!(iommu.domain_count(), 0);
    assert_eq!(iommu.device_count(), 0);
    assert_eq!(iommu.stats().mapped_pages, 0);
}

#[test]
fn entries_snapshot_is_sorted_and_deterministic() {
    fn feed(iommu: &mut IommuModel, d: DomainId) {
        // Deliberately out of order: the snapshot must be ascending because
        // the in-memory table is a BTreeMap.
        iommu.map(d, 0x5000, 0x9000, PAGE, perms()).unwrap();
        iommu.map(d, 0x1000, 0x8000, PAGE, perms()).unwrap();
        iommu
            .map_2m(d, 0x200_0000, 0x4000_0000, TWO_M, perms())
            .unwrap();
        iommu.map(d, 0x3000, 0xA000, PAGE, perms()).unwrap();
    }

    let mut first = model();
    let da = domain_of(&mut first);
    feed(&mut first, da);
    let mut second = model();
    let db = domain_of(&mut second);
    feed(&mut second, db);

    let a: Vec<IommuEntry> = first.entries(da).expect("entries");
    let b: Vec<IommuEntry> = second.entries(db).expect("entries");
    assert_eq!(a, b);
    assert_eq!(
        a.iter().map(|entry| entry.gpa).collect::<Vec<_>>(),
        vec![0x1000, 0x3000, 0x5000, 0x200_0000]
    );
    assert_eq!(a[0].hpa, 0x8000);
    assert_eq!(a[0].size, LeafSize::Page4K);
    assert_eq!(a[3].size, LeafSize::Page2M);
}

#[test]
fn permissions_are_preserved_and_reported() {
    let mut iommu = model();
    let d = domain_of(&mut iommu);
    let read_only = Perms::read_execute();
    iommu.map(d, 0x1000, 0x8000, PAGE, read_only).unwrap();
    let entry = iommu.translate_entry(d, 0x1000).expect("translation");
    assert_eq!(entry.perms, read_only);
    assert!(entry.perms.read);
    assert!(entry.perms.execute);
    assert!(!entry.perms.write);
    let snapshot = iommu.entries(d).expect("entries");
    assert_eq!(snapshot[0].perms, read_only);
}

#[test]
fn statistics_are_cumulative_and_saturating() {
    let mut iommu = model();
    let d = domain_of(&mut iommu);
    iommu.map(d, 0x1000, 0x8000, 3 * PAGE, perms()).unwrap();
    iommu
        .map_2m(d, 0x200_0000, 0x4000_0000, TWO_M, perms())
        .unwrap();
    iommu.translate(d, 0x1000);
    iommu.translate(d, 0x2000);
    iommu.translate(d, 0x9000);
    iommu.unmap(d, 0x1000, PAGE).unwrap();
    let stats = iommu.stats();
    assert_eq!(stats.mapped_pages, 3 + 512);
    assert_eq!(stats.unmapped_pages, 1);
    assert_eq!(stats.translations, 2);
    assert_eq!(stats.faults, 1);
    // The counters never decrease on destroy/clear.
    iommu.clear();
    assert_eq!(iommu.stats(), stats);
}
