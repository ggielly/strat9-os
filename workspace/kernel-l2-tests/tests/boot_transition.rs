//! Pure CPU/mapping-policy tests. No privileged instruction is executed.
#![allow(dead_code, unused_imports)]
#[path = "../../bootloader/src/boot_plan.rs"]
mod boot_plan;
#[path = "../../bootloader/src/cpu.rs"]
mod cpu;
#[path = "../../bootloader/src/elf.rs"]
mod elf;
#[path = "../../bootloader/src/memory_map.rs"]
mod memory_map;
#[path = "../../bootloader/src/page_tables.rs"]
mod page_tables;
#[path = "../../bootloader/src/paging.rs"]
mod paging;

use boot_plan::{DirectMapPlan, GIB, MAX_DIRECT_MAP};
use cpu::{validate_paging_mode, CpuFeatures};
use memory_map::{page_allocation_size, PageFrameCursor, PhysicalRange, PAGE_SIZE};

fn supported_cpu() -> CpuFeatures {
    CpuFeatures {
        standard_edx: (1 << 3)
            | (1 << 5)
            | (1 << 6)
            | (1 << 16)
            | (1 << 24)
            | (1 << 25)
            | (1 << 26),
        extended_edx: (1 << 20) | (1 << 29),
        physical_bits: 36,
    }
}

fn low_image() -> PhysicalRange {
    PhysicalRange {
        base: 0x100_0000,
        size: 0x40_0000,
    }
}

#[test]
fn cpu_without_one_gib_pages_is_supported() {
    let cpu = supported_cpu();
    assert_eq!(cpu.extended_edx & (1 << 26), 0);
    assert!(cpu.validate().is_ok());
}

#[test]
fn missing_msr_nx_pat_or_sse_prerequisites_are_rejected() {
    for bit in [3, 5, 6, 16, 24, 25, 26] {
        let mut cpu = supported_cpu();
        cpu.standard_edx &= !(1 << bit);
        assert!(cpu.validate().is_err());
    }
    for bit in [20, 29] {
        let mut cpu = supported_cpu();
        cpu.extended_edx &= !(1 << bit);
        assert!(cpu.validate().is_err());
    }
    for bits in [0, 31, 53, 64] {
        let mut cpu = supported_cpu();
        cpu.physical_bits = bits;
        assert!(cpu.validate().is_err());
    }
}

#[test]
fn active_paging_mode_must_match_the_four_level_handoff() {
    let cr0 = (1 << 31) | 1;
    let cr4 = 1 << 5;
    let efer = 1 << 10;
    assert!(validate_paging_mode(cr0, cr4, efer).is_ok());
    // PCID/global translations are normalized in the transition, so are accepted.
    assert!(validate_paging_mode(cr0, cr4 | (1 << 17) | (1 << 7), efer).is_ok());
    for bit in [12, 23] {
        assert!(validate_paging_mode(cr0, cr4 | (1 << bit), efer).is_err());
    }
    assert!(validate_paging_mode(1, cr4, efer).is_err());
    assert!(validate_paging_mode(cr0, 0, efer).is_err());
    assert!(validate_paging_mode(cr0, cr4, 0).is_err());
}

#[test]
fn efi_image_above_eight_gib_remains_in_the_identity_mapping() {
    let image = PhysicalRange {
        base: 12 * GIB - PAGE_SIZE,
        size: 3 * PAGE_SIZE,
    };
    let plan = DirectMapPlan::new(1 << 40, image).unwrap();
    assert_eq!(plan.end(), 13 * GIB);
    assert!(plan.covers(image));
}

#[test]
fn sparse_high_ram_is_included_before_any_kernel_allocation() {
    let mut plan = DirectMapPlan::new(1 << 40, low_image()).unwrap();
    let high_ram = PhysicalRange {
        base: 80 * GIB,
        size: GIB + PAGE_SIZE,
    };
    plan.include(high_ram).unwrap();
    assert_eq!(plan.end(), 82 * GIB);
    assert!(plan.covers(high_ram));
    // Even a single newly advertised page outside the prepared map is rejected.
    assert!(!plan.covers(PhysicalRange {
        base: plan.end(),
        size: PAGE_SIZE
    }));
}

#[test]
fn unsupported_physical_ranges_fail_before_wrapping_into_other_pml4_slots() {
    let mut plan = DirectMapPlan::new(1 << 40, low_image()).unwrap();
    assert!(plan
        .include(PhysicalRange {
            base: MAX_DIRECT_MAP - PAGE_SIZE,
            size: PAGE_SIZE
        })
        .is_ok());
    assert_eq!(plan.end(), MAX_DIRECT_MAP);
    assert!(plan
        .include(PhysicalRange {
            base: MAX_DIRECT_MAP,
            size: PAGE_SIZE
        })
        .is_err());
    assert!(plan
        .include(PhysicalRange {
            base: u64::MAX - PAGE_SIZE + 1,
            size: PAGE_SIZE
        })
        .is_err());
}

#[test]
fn mapping_never_sets_physical_address_bits_the_cpu_does_not_implement() {
    let mut plan = DirectMapPlan::new(1 << 32, low_image()).unwrap();
    assert_eq!(plan.end(), 4 * GIB);
    assert!(plan
        .include(PhysicalRange {
            base: 4 * GIB,
            size: PAGE_SIZE
        })
        .is_err());
}

#[test]
fn maximum_supported_layout_has_a_bounded_page_table_budget() {
    let mut plan = DirectMapPlan::new(1 << 40, low_image()).unwrap();
    plan.include(PhysicalRange {
        base: 0,
        size: MAX_DIRECT_MAP,
    })
    .unwrap();
    let mut kernel = elf::Elf64Info {
        entry: elf::KERNEL_VIRT_BASE,
        segments: [elf::Segment {
            phys_addr: 0,
            virt_addr: 0,
            mem_size: 0,
            file_size: 0,
            file_offset: 0,
            flags: 0,
        }; 16],
        segment_count: 1,
        phys_base: 0x20_0000,
        phys_end: 0x20_0000 + GIB,
    };
    kernel.segments[0] = elf::Segment {
        phys_addr: kernel.phys_base,
        virt_addr: elf::KERNEL_VIRT_BASE,
        mem_size: GIB,
        file_size: PAGE_SIZE,
        file_offset: PAGE_SIZE,
        flags: 5,
    };
    let wb = [PhysicalRange {
        base: 0,
        size: MAX_DIRECT_MAP,
    }];
    let mapping = page_tables::MappingPlan {
        direct_map: plan,
        kernel: &kernel,
        loader_image: PhysicalRange {
            base: 2 * GIB,
            size: PAGE_SIZE,
        },
        write_back: &wb,
        framebuffer: PhysicalRange { base: 0, size: 0 },
        environment: PhysicalRange { base: 0, size: 0 },
    };
    let pages = mapping.table_pages().unwrap();
    // Base topology (1541), 512 kernel PTs per physical alias, low memory
    // PT in each alias, and one additional identity PT for the EFI image.
    assert_eq!(pages, 2568);
    let area = PhysicalRange {
        base: PAGE_SIZE,
        size: page_allocation_size(pages * PAGE_SIZE).unwrap(),
    };
    let mut cursor = PageFrameCursor::new(area).unwrap();
    for _ in 0..pages {
        assert!(cursor.next_frame().is_ok());
    }
    assert!(cursor.next_frame().is_err());
    let oversized_kernel = elf::Elf64Info {
        entry: kernel.entry,
        segments: kernel.segments,
        segment_count: kernel.segment_count,
        phys_base: kernel.phys_base,
        phys_end: kernel.phys_end + PAGE_SIZE,
    };
    let oversized = page_tables::MappingPlan {
        kernel: &oversized_kernel,
        ..mapping
    };
    assert!(oversized.table_pages().is_err());
}

#[test]
fn pat_selectors_are_verified_without_reprogramming_other_entries() {
    assert!(cpu::validate_pat(0x0007_0406_0007_0406).is_ok());
    assert!(cpu::validate_pat(0x0101_0101_0000_0006).is_ok());
    assert!(cpu::validate_pat(0x0007_0406_0107_0406).is_err());
    assert!(cpu::validate_pat(0x0007_0406_0007_0400).is_err());
}
