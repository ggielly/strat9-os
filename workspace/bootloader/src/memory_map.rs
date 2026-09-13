//! Pure, bounded conversion of firmware regions and boot-owned reservations.

use strat9_abi::boot::{MemoryKind, MemoryRegion};

pub const PAGE_SIZE: u64 = 4096;
pub use strat9_abi::boot::MAX_BOOT_MEMORY_REGIONS as MAX_MEMORY_REGIONS;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PhysicalRange {
    pub base: u64,
    pub size: u64,
}

impl PhysicalRange {
    pub fn end(self) -> Result<u64, &'static str> {
        self.base
            .checked_add(self.size)
            .ok_or("physical range overflow")
    }
}

pub fn page_allocation_size(size: u64) -> Result<u64, &'static str> {
    if size == 0 {
        return Err("zero-sized boot allocation");
    }
    size.checked_add(PAGE_SIZE - 1)
        .map(|end| end & !(PAGE_SIZE - 1))
        .ok_or("boot allocation size overflow")
}

/// Bounded cursor over a page allocation; obtaining a frame never writes memory.
pub struct PageFrameCursor {
    next: u64,
    end: u64,
}

impl PageFrameCursor {
    pub fn new(range: PhysicalRange) -> Result<Self, &'static str> {
        if range.base == 0
            || range.base % PAGE_SIZE != 0
            || range.size == 0
            || range.size % PAGE_SIZE != 0
        {
            return Err("invalid page-table arena");
        }
        Ok(Self {
            next: range.base,
            end: range.end()?,
        })
    }

    pub fn next_frame(&mut self) -> Result<u64, &'static str> {
        let next = self
            .next
            .checked_add(PAGE_SIZE)
            .ok_or("page-table cursor overflow")?;
        if next > self.end {
            return Err("page-table arena exhausted");
        }
        let frame = self.next;
        self.next = next;
        Ok(frame)
    }
}

/// Reservations must be sorted, non-overlapping, page-aligned allocations.
/// No heap allocation or firmware operation is performed by this builder.
pub struct MemoryMapBuilder<'a> {
    output: &'a mut [MemoryRegion],
    reservations: &'a [PhysicalRange],
    len: usize,
}

impl<'a> MemoryMapBuilder<'a> {
    pub fn new(
        output: &'a mut [MemoryRegion],
        reservations: &'a [PhysicalRange],
    ) -> Result<Self, &'static str> {
        let mut previous_end = 0;
        for range in reservations {
            if range.size == 0
                || range.base % PAGE_SIZE != 0
                || range.size % PAGE_SIZE != 0
                || range.base < previous_end
            {
                return Err("invalid boot reservation");
            }
            previous_end = range.end()?;
        }
        Ok(Self {
            output,
            reservations,
            len: 0,
        })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn push(&mut self, region: MemoryRegion) -> Result<(), &'static str> {
        if region.size == 0 {
            return Ok(());
        }
        let end = region
            .base
            .checked_add(region.size)
            .ok_or("memory descriptor overflow")?;
        if !matches!(region.kind, MemoryKind::Free | MemoryKind::Reclaim) {
            return self.emit(region.base, end, region.kind);
        }

        let mut cursor = region.base;
        for index in 0..self.reservations.len() {
            let range = self.reservations[index];
            let range_end = range.end()?;
            if range_end <= cursor {
                continue;
            }
            if range.base >= end {
                break;
            }
            let start = range.base.max(cursor);
            let stop = range_end.min(end);
            self.emit(cursor, start, region.kind)?;
            self.emit(start, stop, MemoryKind::Reserved)?;
            cursor = stop;
            if cursor == end {
                break;
            }
        }
        self.emit(cursor, end, region.kind)
    }

    fn emit(&mut self, base: u64, end: u64, kind: MemoryKind) -> Result<(), &'static str> {
        if base == end {
            return Ok(());
        }
        let size = end.checked_sub(base).ok_or("inverted memory region")?;
        if self.len > 0 {
            let previous = &mut self.output[self.len - 1];
            if previous.kind == kind && previous.base.checked_add(previous.size) == Some(base) {
                previous.size = end - previous.base;
                return Ok(());
            }
        }
        let slot = self
            .output
            .get_mut(self.len)
            .ok_or("boot memory map capacity exceeded")?;
        *slot = MemoryRegion { base, size, kind };
        self.len += 1;
        Ok(())
    }
}
