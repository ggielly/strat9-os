use core::sync::atomic::{AtomicU64, Ordering};

const PAGE_SIZE: u64 = 4096;
const MEGAPAGE_SIZE: u64 = 2 * 1024 * 1024;
const ROOT_TABLE_COUNT: usize = 8;
const LEVEL0_PER_ROOT: usize = 512;
const LEVEL0_COUNT: usize = ROOT_TABLE_COUNT * LEVEL0_PER_ROOT;
const PTE_VALID: u64 = 1 << 0;
const PTE_READ: u64 = 1 << 1;
const PTE_WRITE: u64 = 1 << 2;
const PTE_EXECUTE: u64 = 1 << 3;
const PTE_ACCESSED: u64 = 1 << 6;
const PTE_DIRTY: u64 = 1 << 7;
const SV39_MODE: u64 = 8 << 60;
const RAM_LEAF_FLAGS: u64 =
    PTE_VALID | PTE_READ | PTE_WRITE | PTE_EXECUTE | PTE_ACCESSED | PTE_DIRTY;
const MMIO_LEAF_FLAGS: u64 = PTE_VALID | PTE_READ | PTE_WRITE | PTE_ACCESSED | PTE_DIRTY;

#[repr(C, align(4096))]
#[derive(Clone, Copy)]
struct PageTable {
    entries: [u64; 512],
}

impl PageTable {
    const fn new() -> Self {
        Self { entries: [0; 512] }
    }
}

static mut ROOT: PageTable = PageTable::new();
static mut LEVEL1: [PageTable; ROOT_TABLE_COUNT] = [const { PageTable::new() }; ROOT_TABLE_COUNT];
static mut LEVEL0: [PageTable; LEVEL0_COUNT] = [const { PageTable::new() }; LEVEL0_COUNT];
static PAGING_ROOT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    Unaligned,
    SizeOverflow,
    UnsupportedRoot(usize),
    InvalidLevel1(usize),
    TooManyRegions,
}

pub struct Sv39Mapper {
    root: *mut PageTable,
    level1: *mut PageTable,
    level0: *mut PageTable,
}

impl Sv39Mapper {
    pub fn new() -> Self {
        let root = core::ptr::addr_of_mut!(ROOT);
        let level1 = core::ptr::addr_of_mut!(LEVEL1).cast::<PageTable>();
        let level0 = core::ptr::addr_of_mut!(LEVEL0).cast::<PageTable>();
        unsafe {
            (*root).entries.fill(0);
            for index in 0..ROOT_TABLE_COUNT {
                (*level1.add(index)).entries.fill(0);
            }
            for index in 0..LEVEL0_COUNT {
                (*level0.add(index)).entries.fill(0);
            }
        }
        PAGING_ROOT.store(root as u64, Ordering::Release);
        Self {
            root,
            level1,
            level0,
        }
    }

    pub fn root_physical_address(&self) -> u64 {
        self.root as u64
    }

    pub fn map_ram(&mut self, base: u64, size: u64) -> Result<usize, MapError> {
        if base % MEGAPAGE_SIZE != 0 || size % MEGAPAGE_SIZE != 0 {
            return Err(MapError::Unaligned);
        }
        let pages = (size / MEGAPAGE_SIZE) as usize;
        for page in 0..pages {
            let virt = base + page as u64 * MEGAPAGE_SIZE;
            self.map_2mib(virt, virt, RAM_LEAF_FLAGS)?;
        }
        Ok(pages)
    }

    pub fn map_mmio(&mut self, base: u64, size: u64) -> Result<usize, MapError> {
        if size == 0 {
            return Ok(0);
        }
        let end = base
            .checked_add(size)
            .ok_or(MapError::SizeOverflow)?
            .checked_add(PAGE_SIZE - 1)
            .ok_or(MapError::SizeOverflow)?
            & !(PAGE_SIZE - 1);
        let start = base & !(PAGE_SIZE - 1);
        if end <= start {
            return Err(MapError::SizeOverflow);
        }

        if start % MEGAPAGE_SIZE == 0 && end % MEGAPAGE_SIZE == 0 {
            let pages = ((end - start) / MEGAPAGE_SIZE) as usize;
            for page in 0..pages {
                self.map_2mib(
                    start + page as u64 * MEGAPAGE_SIZE,
                    start + page as u64 * MEGAPAGE_SIZE,
                    MMIO_LEAF_FLAGS,
                )?;
            }
            return Ok(pages);
        }

        let pages = ((end - start) / PAGE_SIZE) as usize;
        for page in 0..pages {
            let virt = start + page as u64 * PAGE_SIZE;
            self.map_4k(virt, virt)?;
        }
        Ok(pages)
    }

    pub fn translate(&self, virt: u64) -> Option<u64> {
        let root_index = ((virt >> 30) & 0x1ff) as usize;
        let level1_index = ((virt >> 21) & 0x1ff) as usize;
        if root_index >= ROOT_TABLE_COUNT || level1_index >= LEVEL0_PER_ROOT {
            return None;
        }
        let table_index = root_index * LEVEL0_PER_ROOT + level1_index;
        let level0_index = ((virt >> 12) & 0x1ff) as usize;
        unsafe {
            let level1_entry = (*self.level1.add(root_index)).entries[level1_index];
            if level1_entry & PTE_VALID == 0 {
                return None;
            }
            if level1_entry & (PTE_READ | PTE_WRITE | PTE_EXECUTE) != 0 {
                return Some(((level1_entry >> 10) << 12) + (virt & (MEGAPAGE_SIZE - 1)));
            }
            let leaf = (*self.level0.add(table_index)).entries[level0_index];
            if leaf & PTE_VALID != 0 {
                return Some(((leaf >> 10) << 12) + (virt & (PAGE_SIZE - 1)));
            }
            let megapage = (*self.level0.add(table_index)).entries[0];
            if megapage & PTE_VALID != 0 {
                return Some(((megapage >> 10) << 12) + (virt & (MEGAPAGE_SIZE - 1)));
            }
        }
        None
    }

    pub unsafe fn activate(&self) {
        let satp = SV39_MODE | (self.root as u64 >> 12);
        core::arch::asm!("csrw satp, {0}", in(reg) satp, options(nostack));
        core::arch::asm!("sfence.vma", options(nostack));
    }

    fn map_2mib(&mut self, virt: u64, phys: u64, flags: u64) -> Result<(), MapError> {
        if virt % MEGAPAGE_SIZE != 0 || phys % MEGAPAGE_SIZE != 0 {
            return Err(MapError::Unaligned);
        }
        let root_index = ((virt >> 30) & 0x1ff) as usize;
        if root_index >= ROOT_TABLE_COUNT {
            return Err(MapError::UnsupportedRoot(root_index));
        }
        let level1_index = ((virt >> 21) & 0x1ff) as usize;
        if level1_index >= LEVEL0_PER_ROOT {
            return Err(MapError::InvalidLevel1(level1_index));
        }
        let level1_phys = (self.level1 as u64) + (root_index as u64) * 0x1000;
        unsafe {
            (*self.root).entries[root_index] = ((level1_phys >> 12) << 10) | PTE_VALID;
            (*self.level1.add(root_index)).entries[level1_index] = ((phys >> 12) << 10) | flags;
        }
        Ok(())
    }

    fn map_4k(&mut self, virt: u64, phys: u64) -> Result<(), MapError> {
        if virt % PAGE_SIZE != 0 || phys % PAGE_SIZE != 0 {
            return Err(MapError::Unaligned);
        }
        let root_index = ((virt >> 30) & 0x1ff) as usize;
        if root_index >= ROOT_TABLE_COUNT {
            return Err(MapError::UnsupportedRoot(root_index));
        }
        let level1_index = ((virt >> 21) & 0x1ff) as usize;
        if level1_index >= LEVEL0_PER_ROOT {
            return Err(MapError::InvalidLevel1(level1_index));
        }
        let level0_index = ((virt >> 12) & 0x1ff) as usize;
        let table_index = root_index * LEVEL0_PER_ROOT + level1_index;
        let level1_phys = (self.level1 as u64) + (root_index as u64) * 0x1000;
        let level0_phys = (self.level0 as u64) + (table_index as u64) * 0x1000;
        unsafe {
            (*self.root).entries[root_index] = ((level1_phys >> 12) << 10) | PTE_VALID;
            (*self.level1.add(root_index)).entries[level1_index] =
                ((level0_phys >> 12) << 10) | PTE_VALID;
            (*self.level0.add(table_index)).entries[level0_index] =
                ((phys >> 12) << 10) | MMIO_LEAF_FLAGS;
        }
        Ok(())
    }
}

pub fn root_physical_address() -> u64 {
    PAGING_ROOT.load(Ordering::Acquire)
}
