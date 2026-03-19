//! Allocateur physique de boot pour les structures permanentes du noyau.

use crate::{
    boot::entry::{MemoryKind, MemoryRegion},
    memory::phys_to_virt,
    sync::SpinLock,
};
use x86_64::PhysAddr;

const PAGE_SIZE: u64 = 4096;
pub const MAX_BOOT_ALLOC_REGIONS: usize = 128;
pub const MAX_PROTECTED_RANGES: usize = 17;

#[derive(Clone, Copy)]
struct BootRegion {
    start: u64,
    end: u64,
}

impl BootRegion {
    const fn empty() -> Self {
        Self { start: 0, end: 0 }
    }

    #[inline]
    const fn is_empty(&self) -> bool {
        self.start >= self.end
    }
}

pub struct BootAllocator {
    regions: [BootRegion; MAX_BOOT_ALLOC_REGIONS],
    len: usize,
}

impl BootAllocator {
    pub const fn new() -> Self {
        Self {
            regions: [BootRegion::empty(); MAX_BOOT_ALLOC_REGIONS],
            len: 0,
        }
    }

    pub fn init(&mut self, regions: &[MemoryRegion]) {
        self.reset();

        for region in regions {
            if !matches!(region.kind, MemoryKind::Free | MemoryKind::Reclaim) {
                continue;
            }

            let start = align_up(region.base, PAGE_SIZE);
            let end = align_down(region.base.saturating_add(region.size), PAGE_SIZE);
            if start >= end {
                continue;
            }

            self.push_region(BootRegion { start, end });
        }

        for (base, size) in protected_module_ranges().into_iter().flatten() {
            if size == 0 {
                continue;
            }
            self.exclude_range(
                align_down(base, PAGE_SIZE),
                align_up(base.saturating_add(size), PAGE_SIZE),
            );
        }
    }

    pub fn alloc(&mut self, size: usize, align: usize) -> PhysAddr {
        self.try_alloc(size, align).unwrap_or_else(|| {
            panic!(
                "boot allocator: out of physical memory for size={} align={}",
                size, align
            )
        })
    }

    pub fn try_alloc(&mut self, size: usize, align: usize) -> Option<PhysAddr> {
        if size == 0 {
            return Some(PhysAddr::new(0));
        }

        let align = normalize_align(align) as u64;
        let size = align_up(size as u64, PAGE_SIZE);

        for idx in 0..self.len {
            let region = self.regions[idx];
            if region.is_empty() {
                continue;
            }

            let alloc_start = align_up(region.start, align);
            let alloc_end = alloc_start.checked_add(size)?;
            if alloc_end > region.end {
                continue;
            }

            self.consume_region(idx, alloc_start, alloc_end);
            return Some(PhysAddr::new(alloc_start));
        }

        None
    }

    pub fn snapshot_free_regions(&self, out: &mut [MemoryRegion]) -> usize {
        let count = core::cmp::min(self.len, out.len());
        for (dst, region) in out.iter_mut().zip(self.regions.iter()).take(count) {
            *dst = MemoryRegion {
                base: region.start,
                size: region.end.saturating_sub(region.start),
                kind: MemoryKind::Free,
            };
        }
        count
    }

    fn reset(&mut self) {
        self.regions = [BootRegion::empty(); MAX_BOOT_ALLOC_REGIONS];
        self.len = 0;
    }

    fn push_region(&mut self, region: BootRegion) {
        if region.is_empty() || self.len >= self.regions.len() {
            return;
        }
        self.regions[self.len] = region;
        self.len += 1;
    }

    fn exclude_range(&mut self, exclude_start: u64, exclude_end: u64) {
        if exclude_start >= exclude_end {
            return;
        }

        let mut idx = 0usize;
        while idx < self.len {
            let region = self.regions[idx];
            if exclude_end <= region.start || exclude_start >= region.end {
                idx += 1;
                continue;
            }

            if exclude_start <= region.start && exclude_end >= region.end {
                self.remove_region(idx);
                continue;
            }

            if exclude_start <= region.start {
                self.regions[idx].start = exclude_end.min(region.end);
                idx += 1;
                continue;
            }

            if exclude_end >= region.end {
                self.regions[idx].end = exclude_start.max(region.start);
                idx += 1;
                continue;
            }

            let right = BootRegion {
                start: exclude_end,
                end: region.end,
            };
            self.regions[idx].end = exclude_start;
            if self.len < self.regions.len() {
                self.insert_region(idx + 1, right);
            }
            idx += 2;
        }
    }

    fn consume_region(&mut self, idx: usize, alloc_start: u64, alloc_end: u64) {
        let region = self.regions[idx];

        if alloc_start <= region.start && alloc_end >= region.end {
            self.remove_region(idx);
            return;
        }

        if alloc_start <= region.start {
            self.regions[idx].start = alloc_end;
            return;
        }

        if alloc_end >= region.end {
            self.regions[idx].end = alloc_start;
            return;
        }

        let right = BootRegion {
            start: alloc_end,
            end: region.end,
        };
        self.regions[idx].end = alloc_start;
        if self.len < self.regions.len() {
            self.insert_region(idx + 1, right);
        }
    }

    fn insert_region(&mut self, idx: usize, region: BootRegion) {
        if region.is_empty() || self.len >= self.regions.len() {
            return;
        }

        for slot in (idx..self.len).rev() {
            self.regions[slot + 1] = self.regions[slot];
        }
        self.regions[idx] = region;
        self.len += 1;
    }

    fn remove_region(&mut self, idx: usize) {
        if idx >= self.len {
            return;
        }
        for slot in idx..self.len.saturating_sub(1) {
            self.regions[slot] = self.regions[slot + 1];
        }
        if self.len != 0 {
            self.len -= 1;
            self.regions[self.len] = BootRegion::empty();
        }
    }
}

static BOOT_ALLOCATOR: SpinLock<BootAllocator> = SpinLock::new(BootAllocator::new());

pub fn init_boot_allocator(regions: &[MemoryRegion]) {
    BOOT_ALLOCATOR.lock().init(regions);
}

pub fn get_boot_allocator() -> &'static SpinLock<BootAllocator> {
    &BOOT_ALLOCATOR
}

pub fn alloc_bytes(size: usize, align: usize) -> Option<PhysAddr> {
    BOOT_ALLOCATOR.lock().try_alloc(size, align)
}

pub fn snapshot_free_regions(out: &mut [MemoryRegion]) -> usize {
    BOOT_ALLOCATOR.lock().snapshot_free_regions(out)
}

/// Seal the boot allocator so no further allocations can be made from it.
///
/// Called immediately after the buddy allocator consumes the remaining free
/// regions via `snapshot_free_regions`. Any subsequent `alloc_stack` call
/// would otherwise double-allocate pages that are already tracked in the
/// buddy allocator's free lists.
pub fn seal() {
    BOOT_ALLOCATOR.lock().reset();
}

pub fn alloc_stack(size: usize) -> Option<u64> {
    let phys = alloc_bytes(size, PAGE_SIZE as usize)?;
    let span = align_up(size as u64, PAGE_SIZE);
    Some(phys_to_virt(phys.as_u64()).saturating_add(span))
}

pub(crate) fn protected_module_ranges() -> [Option<(u64, u64)>; MAX_PROTECTED_RANGES] {
    [
        crate::boot::limine::fs_ext4_module(),
        crate::boot::limine::strate_fs_ramfs_module(),
        crate::boot::limine::init_module(),
        crate::boot::limine::console_admin_module(),
        crate::boot::limine::strate_net_module(),
        crate::boot::limine::strate_bus_module(),
        crate::boot::limine::dhcp_client_module(),
        crate::boot::limine::ping_module(),
        crate::boot::limine::telnetd_module(),
        crate::boot::limine::udp_tool_module(),
        crate::boot::limine::strate_wasm_module(),
        crate::boot::limine::strate_webrtc_module(),
        crate::boot::limine::hello_wasm_module(),
        crate::boot::limine::wasm_test_toml_module(),
        crate::boot::limine::test_syscalls_module(),
        crate::boot::limine::test_mem_module(),
        crate::boot::limine::test_mem_stressed_module(),
    ]
}

#[inline]
const fn normalize_align(align: usize) -> usize {
    let align = if align == 0 { 1 } else { align };
    let align = if align < PAGE_SIZE as usize {
        PAGE_SIZE as usize
    } else {
        align
    };
    if align.is_power_of_two() {
        align
    } else {
        align.next_power_of_two()
    }
}

#[inline]
const fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

#[inline]
const fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}
