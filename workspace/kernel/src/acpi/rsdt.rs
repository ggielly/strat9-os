//! Definitions for the ACPI RSDT and XSDT system tables.
//! Inspired by Theseus OS.

use super::sdt::Sdt;

pub const RSDT_SIGNATURE: &[u8; 4] = b"RSDT";
pub const XSDT_SIGNATURE: &[u8; 4] = b"XSDT";

pub enum RsdtXsdt {
    Regular(*const Sdt),
    Extended(*const Sdt),
}

impl RsdtXsdt {
    /// Build the root SDT view directly from RSDP contents.
    pub fn from_rsdp(rsdp_vaddr: u64, revision: u8) -> Option<Self> {
        // ACPI 2.0+: XSDT address at byte offset 24 in RSDP v2 struct.
        if revision >= 2 {
            let xsdt_phys = unsafe {
                core::ptr::read_unaligned((rsdp_vaddr as *const u8).add(24) as *const u64)
            };
            if xsdt_phys != 0 {
                crate::memory::paging::ensure_identity_map_range(
                    xsdt_phys,
                    core::mem::size_of::<Sdt>() as u64,
                );
                let xsdt_ptr = crate::memory::phys_to_virt(xsdt_phys) as *const Sdt;
                return Some(RsdtXsdt::Extended(xsdt_ptr));
            }
        }

        // ACPI 1.0 fallback: RSDT address at byte offset 16.
        let rsdt_phys =
            unsafe { core::ptr::read_unaligned((rsdp_vaddr as *const u8).add(16) as *const u32) }
                as u64;
        if rsdt_phys == 0 {
            return None;
        }
        crate::memory::paging::ensure_identity_map_range(
            rsdt_phys,
            core::mem::size_of::<Sdt>() as u64,
        );
        let rsdt_ptr = crate::memory::phys_to_virt(rsdt_phys) as *const Sdt;
        Some(RsdtXsdt::Regular(rsdt_ptr))
    }

    pub fn sdt(&self) -> &'static Sdt {
        match self {
            RsdtXsdt::Regular(ptr) => unsafe { &**ptr },
            RsdtXsdt::Extended(ptr) => unsafe { &**ptr },
        }
    }

    /// Returns an iterator over the physical addresses of the SDT entries
    pub fn addresses(&self) -> RsdtXsdtIter {
        let sdt = self.sdt();
        let header_size = core::mem::size_of::<Sdt>();
        if (sdt.length as usize) < header_size {
            return RsdtXsdtIter::Empty;
        }
        let data_ptr = (sdt as *const Sdt as u64 + header_size as u64) as *const u8;
        let data_len = sdt.length as usize - header_size;

        match self {
            RsdtXsdt::Regular(_) => RsdtXsdtIter::Regular {
                ptr: data_ptr as *const u32,
                count: data_len / 4,
                index: 0,
            },
            RsdtXsdt::Extended(_) => RsdtXsdtIter::Extended {
                ptr: data_ptr as *const u64,
                count: data_len / 8,
                index: 0,
            },
        }
    }
}

pub enum RsdtXsdtIter {
    Empty,
    Regular {
        ptr: *const u32,
        count: usize,
        index: usize,
    },
    Extended {
        ptr: *const u64,
        count: usize,
        index: usize,
    },
}

impl Iterator for RsdtXsdtIter {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            RsdtXsdtIter::Empty => None,
            RsdtXsdtIter::Regular { ptr, count, index } => {
                if index < count {
                    let addr = unsafe { core::ptr::read_unaligned(ptr.add(*index)) };
                    *index += 1;
                    Some(addr as u64)
                } else {
                    None
                }
            }
            RsdtXsdtIter::Extended { ptr, count, index } => {
                if index < count {
                    let addr = unsafe { core::ptr::read_unaligned(ptr.add(*index)) };
                    *index += 1;
                    Some(addr)
                } else {
                    None
                }
            }
        }
    }
}
