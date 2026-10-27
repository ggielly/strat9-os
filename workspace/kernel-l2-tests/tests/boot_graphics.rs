//! Actual GOP geometry and page-table construction with synthetic physical
//! addresses. These tests do not execute firmware or privileged instructions.
#![allow(dead_code)]
#[path = "../../bootloader/src/boot_plan.rs"]
mod boot_plan;
#[path = "../../bootloader/src/elf.rs"]
mod elf;
#[path = "../../bootloader/src/graphics.rs"]
mod graphics;
#[path = "../../bootloader/src/memory_map.rs"]
mod memory_map;
#[path = "../../bootloader/src/page_tables.rs"]
mod page_tables;

use boot_plan::{DirectMapPlan, GIB};
use elf::{Elf64Info, Segment, KERNEL_VIRT_BASE};
use graphics::Framebuffer;
use memory_map::{PhysicalRange, PAGE_SIZE};
use page_tables::{
    build_page_tables, MappingPlan, ENVIRONMENT_BASE, FRAMEBUFFER_BASE, HHDM_OFFSET,
};

const NX: u64 = 1 << 63;
const UC: u64 = 0x18;
const ADDRESS: u64 = 0x000F_FFFF_FFFF_F000;
const ARENA: u64 = 0x2000_0000;
const EMPTY: PhysicalRange = PhysicalRange { base: 0, size: 0 };
const WB: [PhysicalRange; 1] = [PhysicalRange { base: 0, size: GIB }];

#[test]
fn console_modes_prefer_readable_resolution_with_firmware_fallbacks() {
    let mut modes = [
        (3840, 2160), (800, 600), (1920, 1080), (1600, 1200), (1280, 1024),
    ];
    modes.sort_by_key(|&(w, h)| {
        Framebuffer::geometry(w, h, w, false).unwrap().console_mode_rank()
    });
    assert_eq!(
        modes,
        [(1600, 1200), (1280, 1024), (800, 600), (1920, 1080), (3840, 2160)]
    );
}
const LOADER: PhysicalRange = PhysicalRange {
    base: 0x100_0000,
    size: 3 * PAGE_SIZE,
};

fn kernel() -> Elf64Info {
    let mut image = Elf64Info {
        entry: KERNEL_VIRT_BASE,
        segments: [Segment {
            phys_addr: 0,
            virt_addr: 0,
            mem_size: 0,
            file_size: 0,
            file_offset: 0,
            flags: 0,
        }; 16],
        segment_count: 3,
        phys_base: 0x400_0000,
        phys_end: 0x400_0000 + 6 * PAGE_SIZE,
    };
    for (i, offset, pages, flags) in [(0, 0, 2, 5), (1, 2, 1, 4), (2, 4, 2, 6)] {
        image.segments[i] = Segment {
            phys_addr: image.phys_base + offset * PAGE_SIZE,
            virt_addr: KERNEL_VIRT_BASE + offset * PAGE_SIZE,
            mem_size: pages * PAGE_SIZE,
            file_size: PAGE_SIZE,
            file_offset: (i as u64 + 1) * PAGE_SIZE,
            flags,
        };
    }
    image
}

fn plan(image: &Elf64Info) -> MappingPlan<'_> {
    MappingPlan {
        direct_map: DirectMapPlan::new(1 << 36, LOADER).unwrap(),
        kernel: image,
        loader_image: LOADER,
        write_back: &WB,
        framebuffer: EMPTY,
        environment: EMPTY,
    }
}

fn build(plan: &MappingPlan<'_>) -> Vec<u64> {
    let words = (plan.table_pages().unwrap() * PAGE_SIZE / 8) as usize;
    let mut storage = vec![0xA5A5_A5A5_A5A5_A5A5; words + 1024];
    assert_eq!(
        build_page_tables(&mut storage[512..512 + words], ARENA, plan),
        Ok(ARENA)
    );
    assert!(storage[..512]
        .iter()
        .chain(&storage[512 + words..])
        .all(|&v| v == 0xA5A5_A5A5_A5A5_A5A5));
    storage[512..512 + words].to_vec()
}

/// Walk the produced bytes, including huge leaves, independently of the builder.
fn walk(words: &[u64], address: u64) -> Option<(u64, u64, u64)> {
    let mut table = 0usize;
    for shift in [39, 30, 21, 12] {
        let entry = *words.get(table + ((address >> shift) & 511) as usize)?;
        if entry & 1 == 0 {
            return None;
        }
        if shift == 12 || entry & 128 != 0 {
            let span = 1u64 << shift;
            let phys = (entry & ADDRESS & !(span - 1)) | (address & (span - 1));
            return Some((phys, entry & !ADDRESS, span));
        }
        table = ((entry & ADDRESS).checked_sub(ARENA)? / 8) as usize;
    }
    None
}

#[test]
fn gop_rgb_and_bgr_follow_little_endian_byte_order() {
    for rgb in [true, false] {
        let fb = Framebuffer::geometry(800, 600, 832, rgb).unwrap();
        assert_eq!(fb.stride, 3328);
        let red = (0xFFu32 << fb.red_shift).to_le_bytes();
        let blue = (0xFFu32 << fb.blue_shift).to_le_bytes();
        assert_eq!(red, if rgb { [255, 0, 0, 0] } else { [0, 0, 255, 0] });
        assert_eq!(blue, if rgb { [0, 0, 255, 0] } else { [255, 0, 0, 0] });
    }
}

#[test]
fn invalid_geometry_and_short_apertures_are_rejected() {
    for (w, h, stride) in [
        (0, 1, 1),
        (1, 0, 1),
        (800, 600, 799),
        (1, 1, usize::MAX),
        (1, usize::MAX, 1),
    ] {
        assert!(Framebuffer::geometry(w, h, stride, true).is_none());
    }
    let fb = Framebuffer::geometry(1920, 1080, 1920, false).unwrap();
    assert!(fb.with_aperture(0, fb.visible_size()).is_none());
    assert!(fb
        .with_aperture(0xE000_0000, fb.visible_size() - 1)
        .is_none());
    assert!(fb.with_aperture(u64::MAX - 10, fb.visible_size()).is_none());
    assert!(fb.with_aperture(0xE000_0001, fb.visible_size()).is_none());
    assert!(fb.with_aperture(0xE000_0124, fb.visible_size()).is_some());
    assert!(fb.with_aperture(0xE000_0001, GIB).is_none());
}

#[test]
fn framebuffer_and_environment_are_contiguous_across_pt_boundaries() {
    let image = kernel();
    let mut layout = plan(&image);
    layout.framebuffer = PhysicalRange {
        base: 0xE000_0123,
        size: 9 * 1024 * 1024,
    };
    layout.environment = PhysicalRange {
        base: 0x300_0321,
        size: 3 * 1024 * 1024,
    };
    let words = build(&layout);
    for (window, range) in [
        (FRAMEBUFFER_BASE, layout.framebuffer),
        (ENVIRONMENT_BASE, layout.environment),
    ] {
        let start = range.base & !(PAGE_SIZE - 1);
        let span = page_tables::page_range(range).unwrap().size;
        for offset in (0..span).step_by(PAGE_SIZE as usize) {
            let (physical, flags, size) = walk(&words, window + offset).unwrap();
            assert_eq!(physical, start + offset);
            assert_eq!(size, PAGE_SIZE);
            assert_ne!(flags & NX, 0);
        }
        assert_eq!(
            walk(&words, window + (range.base - start)).unwrap().0,
            range.base
        );
        assert!(walk(&words, window + span).is_none());
    }
}

#[test]
fn kernel_permissions_apply_to_both_physical_aliases() {
    let image = kernel();
    let words = build(&plan(&image));
    for page in 0..6 {
        let displacement = page * PAGE_SIZE;
        let physical = image.phys_base + displacement;
        let expected = if page < 2 {
            1
        } else if page >= 4 {
            3 | NX
        } else {
            1 | NX
        };
        assert_eq!(
            walk(&words, KERNEL_VIRT_BASE + displacement).unwrap().1,
            expected
        );
        for offset in [0, HHDM_OFFSET] {
            let (actual, flags, span) = walk(&words, offset + physical).unwrap();
            assert_eq!(actual, physical);
            assert_eq!(flags, expected | NX);
            assert_eq!(span, PAGE_SIZE);
        }
    }
    assert!(walk(&words, KERNEL_VIRT_BASE + 6 * PAGE_SIZE).is_none());
}

#[test]
fn ram_and_mmio_are_nx_with_consistent_cache_selectors() {
    let image = kernel();
    let mut layout = plan(&image);
    // Deliberately inside WB-capable RAM, as with a stolen-memory framebuffer.
    layout.framebuffer = PhysicalRange {
        base: 0x220_0123,
        size: 5 * PAGE_SIZE,
    };
    let words = build(&layout);
    for physical in [0x8000, 0x800_0000, 0xFEE0_0000] {
        for offset in [0, HHDM_OFFSET] {
            let (_, flags, _) = walk(&words, offset + physical).unwrap();
            assert_eq!(
                flags & (3 | NX | UC),
                3 | NX | if physical >= GIB { UC } else { 0 }
            );
        }
    }
    let fb = page_tables::page_range(layout.framebuffer).unwrap();
    for displacement in (0..fb.size).step_by(PAGE_SIZE as usize) {
        let physical = fb.base + displacement;
        for virtual_addr in [
            physical,
            HHDM_OFFSET + physical,
            FRAMEBUFFER_BASE + displacement,
        ] {
            assert_eq!(walk(&words, virtual_addr).unwrap().1, 3 | NX | UC);
        }
    }
    // Adjacent WB RAM keeps its original policy; no entire 2 MiB region is retyped.
    assert_eq!(
        walk(&words, HHDM_OFFSET + fb.base - PAGE_SIZE).unwrap().1,
        3 | NX
    );
}

#[test]
fn only_the_efi_identity_alias_executes_during_transition() {
    let image = kernel();
    let words = build(&plan(&image));
    assert_eq!(walk(&words, LOADER.base).unwrap().1, 1);
    assert_eq!(
        walk(&words, HHDM_OFFSET + LOADER.base).unwrap().1 & (3 | NX),
        3 | NX
    );
    assert_eq!(walk(&words, 0x8000).unwrap().2, PAGE_SIZE);
    assert_ne!(walk(&words, 0x8000).unwrap().1 & NX, 0);
}

#[test]
fn undersized_arena_fails_without_touching_output() {
    let image = kernel();
    let layout = plan(&image);
    let len = (layout.table_pages().unwrap() * PAGE_SIZE / 8) as usize;
    let mut storage = vec![0xA5; len - 512];
    assert!(build_page_tables(&mut storage, ARENA, &layout).is_err());
    assert!(storage.iter().all(|&word| word == 0xA5));
}

#[test]
fn overlapping_images_and_oversized_windows_fail_before_mapping() {
    let image = kernel();
    let mut layout = plan(&image);
    layout.framebuffer = PhysicalRange {
        base: image.phys_base,
        size: PAGE_SIZE,
    };
    assert!(layout.table_pages().is_err());
    layout.framebuffer = PhysicalRange {
        base: 0xE000_0000,
        size: GIB + 1,
    };
    assert!(layout.table_pages().is_err());
    layout.framebuffer = EMPTY;
    layout.environment = PhysicalRange {
        base: 0x1000_0000,
        size: GIB + 1,
    };
    assert!(layout.table_pages().is_err());
}

#[test]
fn final_cache_map_may_split_ram_but_must_not_retype_it() {
    let image = kernel();
    let layout = plan(&image);
    let ram = PhysicalRange {
        base: 0x500_0000,
        size: PAGE_SIZE,
    };
    let mmio = PhysicalRange {
        base: 0xFEE0_0000,
        size: PAGE_SIZE,
    };
    assert!(layout.agrees_with_firmware(ram, true));
    assert!(!layout.agrees_with_firmware(ram, false));
    assert!(layout.agrees_with_firmware(mmio, false));
    assert!(!layout.agrees_with_firmware(mmio, true));
}
