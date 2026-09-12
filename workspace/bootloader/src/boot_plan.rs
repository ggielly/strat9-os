//! Pure planning of the initial direct map, before any page-table writes.
use crate::memory_map::PhysicalRange;

pub const GIB: u64 = 1 << 30;
pub const INITIAL_ALLOCATION_LIMIT: u64 = 8 * GIB;
// One PML4 slot for the HHDM, with a separate low identity slot.
pub const MAX_DIRECT_MAP: u64 = 512 * GIB;

#[derive(Clone, Copy, Debug)]
pub struct DirectMapPlan {
    end: u64,
    limit: u64,
}

impl DirectMapPlan {
    pub fn new(physical_limit: u64, loader_image: PhysicalRange) -> Result<Self, &'static str> {
        if physical_limit < GIB
            || !physical_limit.is_power_of_two()
            || loader_image.base == 0
            || loader_image.size == 0
        {
            return Err("invalid CPU limit or loaded EFI image");
        }
        let mut plan = Self {
            end: INITIAL_ALLOCATION_LIMIT.min(physical_limit),
            limit: MAX_DIRECT_MAP.min(physical_limit),
        };
        plan.include(loader_image)?;
        Ok(plan)
    }

    pub fn include(&mut self, range: PhysicalRange) -> Result<(), &'static str> {
        if range.size == 0 {
            return Ok(());
        }
        let end = range.end()?;
        if end > self.limit {
            return Err("required RAM or EFI image exceeds the initial HHDM window");
        }
        let rounded = end.checked_add(GIB - 1).ok_or("direct map size overflow")? & !(GIB - 1);
        self.end = self.end.max(rounded);
        Ok(())
    }

    pub fn end(self) -> u64 {
        self.end
    }

    /// Recheck the final firmware map so no newly advertised allocatable page
    /// can escape the mappings prepared before ExitBootServices.
    pub fn covers(self, range: PhysicalRange) -> bool {
        range.end().is_ok_and(|end| end <= self.end)
    }
}
