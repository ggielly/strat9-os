//! Kernel symbol table for panic backtrace resolution.
//!
//! Parses the kernel's own ELF `.symtab`/`.strtab` sections at boot time
//! to provide function name resolution during panics.

use core::sync::atomic::{AtomicBool, Ordering};

/// A single symbol entry: address, size, name offset in string table.
#[derive(Clone, Copy)]
struct KernelSymbol {
    addr: u64,
    size: u64,
    name_offset: u32,
}

/// Global sorted symbol table and string table.
static INITIALIZED: AtomicBool = AtomicBool::new(false);
static mut SYMBOLS: [KernelSymbol; 8192] = [KernelSymbol {
    addr: 0,
    size: 0,
    name_offset: 0,
}; 8192];
static mut SYMBOL_COUNT: usize = 0;
static mut STRTAB: [u8; 65536] = [0; 65536];
static mut STRTAB_LEN: usize = 0;

/// Initialize the symbol table from the kernel ELF. Called once during early boot.
pub fn init() {
    if INITIALIZED.load(Ordering::Relaxed) {
        return;
    }

    #[cfg(target_arch = "x86_64")]
    let elf_bytes = match super::limine::kernel_elf_bytes() {
        Some(b) => b,
        None => return,
    };
    #[cfg(not(target_arch = "x86_64"))]
    let elf_bytes: &[u8] = &[];

    let elf = match xmas_elf::ElfFile::new(elf_bytes) {
        Ok(e) => e,
        Err(_) => return,
    };

    // Find .strtab section
    let strtab_data = find_section_data(&elf, ".strtab");
    if strtab_data.is_empty() {
        return;
    }
    let copy_len = strtab_data.len().min(65536);
    unsafe {
        STRTAB[..copy_len].copy_from_slice(&strtab_data[..copy_len]);
        STRTAB_LEN = copy_len;
    }

    // Find .symtab section
    let symtab_data = find_section_data(&elf, ".symtab");
    if symtab_data.is_empty() {
        return;
    }

    // Parse symbol entries (each is 24 bytes for ELF64: st_name(4) + st_info(1) +
    // st_other(1) + st_shndx(2) + st_value(8) + st_size(8))
    let entry_size = 24;
    let count = symtab_data.len() / entry_size;
    let max = 8192;
    let mut n = 0usize;

    for i in 0..count.min(max) {
        let off = i * entry_size;
        if off + entry_size > symtab_data.len() {
            break;
        }
        let st_name = u32::from_le_bytes([
            symtab_data[off],
            symtab_data[off + 1],
            symtab_data[off + 2],
            symtab_data[off + 3],
        ]);
        let st_value = u64::from_le_bytes([
            symtab_data[off + 8],
            symtab_data[off + 9],
            symtab_data[off + 10],
            symtab_data[off + 11],
            symtab_data[off + 12],
            symtab_data[off + 13],
            symtab_data[off + 14],
            symtab_data[off + 15],
        ]);
        let st_size = u64::from_le_bytes([
            symtab_data[off + 16],
            symtab_data[off + 17],
            symtab_data[off + 18],
            symtab_data[off + 19],
            symtab_data[off + 20],
            symtab_data[off + 21],
            symtab_data[off + 22],
            symtab_data[off + 23],
        ]);

        // Skip undefined symbols (st_value == 0)
        if st_value == 0 {
            continue;
        }

        unsafe {
            SYMBOLS[n] = KernelSymbol {
                addr: st_value,
                size: st_size,
                name_offset: st_name,
            };
        }
        n += 1;
    }

    // Sort by address for binary search
    unsafe {
        SYMBOL_COUNT = n;
        let syms = &mut SYMBOLS[..n];
        syms.sort_unstable_by_key(|s| s.addr);
    }

    INITIALIZED.store(true, Ordering::Relaxed);
}

/// Find a section's data by name in the ELF.
fn find_section_data<'a>(elf: &xmas_elf::ElfFile<'a>, name: &str) -> &'a [u8] {
    match elf.find_section_by_name(name) {
        Some(section) => section.raw_data(elf),
        None => &[],
    }
}

/// Look up an address in the symbol table. Returns (name, offset_from_symbol).
/// Uses binary search for O(log n) lookup.
pub fn lookup(addr: u64) -> Option<(&'static str, u64)> {
    if !INITIALIZED.load(Ordering::Relaxed) {
        return None;
    }

    let syms = unsafe { &SYMBOLS[..SYMBOL_COUNT] };

    // Binary search: find the last symbol with addr <= target
    let idx = match syms.binary_search_by_key(&addr, |s| s.addr) {
        Ok(i) => i,
        Err(i) => {
            if i == 0 {
                return None;
            }
            i - 1
        }
    };

    let sym = &syms[idx];
    let offset = addr.saturating_sub(sym.addr);

    // Check if addr is within the symbol's size (if size > 0)
    if sym.size > 0 && offset >= sym.size {
        return None;
    }

    let name = get_symbol_name(sym.name_offset);
    Some((name, offset))
}

/// Get a symbol name from the string table.
fn get_symbol_name(offset: u32) -> &'static str {
    let off = offset as usize;
    let tab = unsafe { &STRTAB[..STRTAB_LEN] };
    if off >= tab.len() {
        return "<unknown>";
    }
    let end = tab[off..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| off + p)
        .unwrap_or(tab.len());
    core::str::from_utf8(&tab[off..end]).unwrap_or("<unknown>")
}
