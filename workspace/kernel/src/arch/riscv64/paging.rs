use core::sync::atomic::{AtomicU64, Ordering};

const MEGAPAGE_SIZE: u64 = 2 * 1024 * 1024;
const LEVEL0_COUNT: usize = 256;
const PTE_VALID: u64 = 1 << 0;
const PTE_READ: u64 = 1 << 1;
const PTE_WRITE: u64 = 1 << 2;
const PTE_EXECUTE: u64 = 1 << 3;
const PTE_ACCESSED: u64 = 1 << 6;
const PTE_DIRTY: u64 = 1 << 7;
const SV39_MODE: u64 = 8 << 60;

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
static mut LEVEL1: PageTable = PageTable::new();
static mut LEVEL0: [PageTable; LEVEL0_COUNT] = [const { PageTable::new() }; LEVEL0_COUNT];
static PAGING_ROOT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    Unaligned,
    UnsupportedRoot(usize),
    InvalidLevel1(usize),
}

pub struct Sv39Mapper {
    root: *mut PageTable,
    level1: *mut PageTable,
    level0: *mut PageTable,
}

impl Sv39Mapper {
    pub fn new() -> Self {
        let root = core::ptr::addr_of_mut!(ROOT);
        let level1 = core::ptr::addr_of_mut!(LEVEL1);
        let level0 = core::ptr::addr_of_mut!(LEVEL0).cast::<PageTable>();
        unsafe {
            (*root).entries.fill(0);
            (*level1).entries.fill(0);
            for index in 0..LEVEL0_COUNT {
                (*level0.add(index)).entries.fill(0);
            }
        }
        let root_phys = root as u64;
        PAGING_ROOT.store(root_phys, Ordering::Release);
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
            self.map_2mib(virt, virt)?;
        }
        Ok(pages)
    }

    pub fn translate(&self, virt: u64) -> Option<u64> {
        let root_index = ((virt >> 30) & 0x1ff) as usize;
        let level1_index = ((virt >> 21) & 0x1ff) as usize;
        if root_index != 2 || level1_index >= LEVEL0_COUNT {
            return None;
        }
        let offset = virt & (MEGAPAGE_SIZE - 1);
        unsafe {
            let root_entry = (*self.root).entries[root_index];
            if root_entry & PTE_VALID == 0 {
                return None;
            }
            let level1_entry = (*self.level1).entries[level1_index];
            if level1_entry & PTE_VALID == 0 {
                return None;
            }
            let leaf = (*self.level0.add(level1_index)).entries[0];
            if leaf & PTE_VALID == 0 {
                return None;
            }
            Some(((leaf >> 10) << 12) + offset)
        }
    }

    pub unsafe fn activate(&self) {
        let satp = SV39_MODE | (self.root as u64 >> 12);
        core::arch::asm!("csrw satp, {0}", in(reg) satp, options(nostack));
        core::arch::asm!("sfence.vma", options(nostack));
    }

    fn map_2mib(&mut self, virt: u64, phys: u64) -> Result<(), MapError> {
        if virt % MEGAPAGE_SIZE != 0 || phys % MEGAPAGE_SIZE != 0 {
            return Err(MapError::Unaligned);
        }
        let root_index = ((virt >> 30) & 0x1ff) as usize;
        if root_index != 2 {
            return Err(MapError::UnsupportedRoot(root_index));
        }
        let level1_index = ((virt >> 21) & 0x1ff) as usize;
        if level1_index >= LEVEL0_COUNT {
            return Err(MapError::InvalidLevel1(level1_index));
        }

        let level1_phys = self.level1 as u64;
        let level0_phys = (self.level0 as u64) + (level1_index as u64) * 0x1000;
        let leaf_flags = PTE_VALID | PTE_READ | PTE_WRITE | PTE_EXECUTE | PTE_ACCESSED | PTE_DIRTY;
        unsafe {
            (*self.root).entries[root_index] = ((level1_phys >> 12) << 10) | PTE_VALID;
            (*self.level1).entries[level1_index] = ((level0_phys >> 12) << 10) | PTE_VALID;
            (*self.level0.add(level1_index)).entries[0] = ((phys >> 12) << 10) | leaf_flags;
        }
        Ok(())
    }
}

pub fn root_physical_address() -> u64 {
    PAGING_ROOT.load(Ordering::Acquire)
}
